//! The session controller: the single owner of the pending sign-in, the
//! generation counter and the session.
//!
//! Rules (see the plan and PROTOCOL.md):
//! - Network calls happen outside the lock, with the generation captured.
//! - Every state change happens inside the lock: check the generation, write
//!   the secret, then the profile, update memory, emit the event.
//! - `cancel_auth`, `sign_out` and revocation take the same lock before they
//!   bump the generation or clear, so an obsolete result can never be saved.
//! - A previous session is revoked on the server only after its replacement
//!   is stored; when storing fails, the new session is revoked instead.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use tokio::sync::Mutex;
use url::Url;

use crate::{
    callback::{parse_deep_link, parse_pasted, Callback, CallbackOutcome, Pasted},
    config::{Config, Transport},
    http::{HttpApi, SessionCheck, SessionData},
    models::{RequestAuthOptions, RequestAuthResult, SessionSnapshot, SignOutReason},
    pkce::{constant_time_eq, generate_pkce, generate_state},
    store::{
        profile::{ProfileStore, StoredProfile},
        SessionStore, StoreError, StoredSecret,
    },
    transport::{auto_transport, loopback::LoopbackServer},
    Error, Result,
};

/// Best-effort server calls (revoking a superseded session) get this long.
const BEST_EFFORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Wire protocol version sent on the sign-in URL.
const PROTOCOL_VERSION: &str = "1";

/// Where the controller reports to the app.
pub(crate) trait EventSink: Send + Sync + 'static {
    fn authenticated(&self, user: &Value);
    fn signed_out(&self, reason: SignOutReason);
    fn error(&self, error: &Error);
    fn focus(&self);
}

/// Opens the sign-in page.
pub(crate) trait BrowserOpener: Send + Sync + 'static {
    fn open(&self, url: &str) -> std::io::Result<()>;
}

/// The OS default browser.
pub(crate) struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &str) -> std::io::Result<()> {
        open::that_detached(url)
    }
}

struct Pending {
    state: String,
    verifier: String,
    transport: Transport,
    created_at: Instant,
    /// Dropping it stops the listener.
    _loopback: Option<LoopbackServer>,
}

#[derive(Clone)]
struct Current {
    secret: StoredSecret,
    user: Value,
    session: Value,
}

impl Current {
    fn snapshot(&self, offline: bool) -> SessionSnapshot {
        SessionSnapshot {
            user: self.user.clone(),
            session: self.session.clone(),
            offline,
        }
    }
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    generation: u64,
    /// Highest revision written or seen (secret, profile or tombstone).
    last_rev: u64,
    pending: Option<Pending>,
    current: Option<Current>,
}

pub(crate) struct Controller {
    config: Arc<Config>,
    http: HttpApi,
    store: Arc<dyn SessionStore>,
    profiles: Arc<dyn ProfileStore>,
    events: Arc<dyn EventSink>,
    opener: Arc<dyn BrowserOpener>,
    /// Whether the OS can deliver deep links to this process (`Auto`).
    deep_links_deliverable: bool,
    app_name: String,
    inner: Mutex<Inner>,
}

pub(crate) struct ControllerParts {
    pub config: Arc<Config>,
    pub http: HttpApi,
    pub store: Arc<dyn SessionStore>,
    pub profiles: Arc<dyn ProfileStore>,
    pub events: Arc<dyn EventSink>,
    pub opener: Arc<dyn BrowserOpener>,
    pub deep_links_deliverable: bool,
    pub app_name: String,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn valid_provider(provider: &str) -> bool {
    let mut chars = provider.chars();
    !provider.is_empty()
        && provider.len() <= 64
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

async fn blocking<T: Send + 'static>(
    task: impl FnOnce() -> std::result::Result<T, StoreError> + Send + 'static,
) -> std::result::Result<T, StoreError> {
    tokio::task::spawn_blocking(task)
        .await
        .unwrap_or_else(|_| Err(StoreError::Failed("the storage task panicked".into())))
}

impl Controller {
    pub fn new(parts: ControllerParts) -> Arc<Self> {
        Arc::new(Self {
            config: parts.config,
            http: parts.http,
            store: parts.store,
            profiles: parts.profiles,
            events: parts.events,
            opener: parts.opener,
            deep_links_deliverable: parts.deep_links_deliverable,
            app_name: parts.app_name,
            inner: Mutex::new(Inner::default()),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn http(&self) -> &HttpApi {
        &self.http
    }

    // ---------------------------------------------------------------- loading

    /// Loads the stored session once, applying the revision rules.
    async fn ensure_loaded(&self, inner: &mut Inner) {
        if inner.loaded {
            return;
        }
        inner.loaded = true;
        let store = self.store.clone();
        let profiles = self.profiles.clone();
        let secret = match blocking(move || store.load()).await {
            Ok(secret) => secret,
            Err(error) => {
                log::warn!("[better-auth] could not read the stored session: {error}");
                if matches!(error, StoreError::Unavailable(_)) {
                    self.events.error(&Error::from(error));
                }
                None
            }
        };
        let profile = blocking(move || profiles.load())
            .await
            .unwrap_or_else(|error| {
                log::warn!("[better-auth] could not read the stored profile: {error}");
                None
            });
        inner.last_rev = secret
            .as_ref()
            .map_or(0, |s| s.rev)
            .max(profile.as_ref().map_or(0, |p| p.rev));
        inner.current = match (secret, profile) {
            (None, _) => None,
            (Some(secret), Some(profile)) if profile.tombstone && profile.rev >= secret.rev => {
                // A sign-out could not delete the secret; never resurrect it.
                let store = self.store.clone();
                let _ = blocking(move || store.clear()).await;
                None
            }
            (Some(secret), Some(profile))
                if !profile.tombstone
                    && profile.rev == secret.rev
                    && profile.session_id == secret.session_id =>
            {
                Some(Current {
                    secret,
                    user: profile.user,
                    session: profile.session,
                })
            }
            // The profile is stale or missing: keep the credential, refresh
            // the user online.
            (Some(secret), _) => Some(Current {
                secret,
                user: Value::Null,
                session: Value::Null,
            }),
        };
    }

    /// The current generation (the bridge captures it before a sign-in).
    pub async fn generation(&self) -> u64 {
        self.inner.lock().await.generation
    }

    // ------------------------------------------------------------ the flow

    /// Starts a browser sign-in.
    pub async fn request_auth(
        self: &Arc<Self>,
        options: RequestAuthOptions,
    ) -> Result<RequestAuthResult> {
        if let Some(provider) = &options.provider {
            if !valid_provider(provider) {
                return Err(Error::InvalidRequest("invalid provider id".into()));
            }
        }
        let transport = match options.transport.unwrap_or(self.config.transport) {
            Transport::Auto => auto_transport(self.deep_links_deliverable),
            other => other,
        };
        let pkce = generate_pkce()?;
        let state = generate_state()?;

        let mut inner = self.inner.lock().await;
        inner.generation += 1;
        // Replacing the pending flow drops its loopback listener.
        inner.pending = None;

        let loopback = if transport == Transport::Loopback {
            let controller = Arc::downgrade(self);
            let claim = Arc::new(move |callback: Callback| {
                let controller = controller.clone();
                Box::pin(async move {
                    match controller.upgrade() {
                        Some(controller) => controller.claim_from_loopback(callback).await,
                        None => false,
                    }
                }) as Pin<Box<dyn Future<Output = bool> + Send>>
            });
            Some(
                LoopbackServer::start(
                    self.config.callback_path.clone(),
                    self.config.pending_ttl,
                    self.app_name.clone(),
                    claim,
                )
                .await?,
            )
        } else {
            None
        };

        let mut url: Url = self.config.sign_in_url.clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &self.config.client_id)
                .append_pair("state", &state)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("v", PROTOCOL_VERSION);
            if let Some(server) = &loopback {
                query.append_pair("redirect_uri", &server.redirect_uri);
            }
            if let Some(provider) = &options.provider {
                query.append_pair("provider", provider);
            }
        }

        inner.pending = Some(Pending {
            state,
            verifier: pkce.verifier,
            transport,
            created_at: Instant::now(),
            _loopback: loopback,
        });
        drop(inner);

        let opened = match self.opener.open(url.as_str()) {
            Ok(()) => true,
            Err(error) => {
                log::warn!("[better-auth] could not open the browser: {error}");
                false
            }
        };
        Ok(RequestAuthResult {
            url: url.into(),
            opened,
            transport,
        })
    }

    /// Cancels the pending sign-in, if any.
    pub async fn cancel_auth(&self) {
        let mut inner = self.inner.lock().await;
        inner.generation += 1;
        inner.pending = None;
    }

    /// Takes the pending flow if `state` matches. A mismatch leaves it alone.
    async fn claim(
        &self,
        state: &str,
        require: Option<Transport>,
    ) -> Result<(u64, String, String)> {
        let mut inner = self.inner.lock().await;
        let pending = inner.pending.as_ref().ok_or(Error::NoPendingFlow)?;
        if !constant_time_eq(&pending.state, state) {
            return Err(Error::InvalidCallback);
        }
        if require.is_some_and(|transport| transport != pending.transport) {
            return Err(Error::InvalidCallback);
        }
        if pending.created_at.elapsed() > self.config.pending_ttl {
            inner.pending = None;
            return Err(Error::FlowExpired);
        }
        let pending = inner.pending.take().ok_or(Error::NoPendingFlow)?;
        Ok((inner.generation, pending.state, pending.verifier))
    }

    /// Claims the pending flow without a state (a bare pasted code).
    async fn claim_current(&self) -> Result<(u64, String, String)> {
        let mut inner = self.inner.lock().await;
        let pending = inner.pending.as_ref().ok_or(Error::NoPendingFlow)?;
        if pending.created_at.elapsed() > self.config.pending_ttl {
            inner.pending = None;
            return Err(Error::FlowExpired);
        }
        let pending = inner.pending.take().ok_or(Error::NoPendingFlow)?;
        Ok((inner.generation, pending.state, pending.verifier))
    }

    /// Exchange + commit for a claimed flow.
    async fn finish(
        &self,
        generation: u64,
        state: String,
        verifier: String,
        outcome: CallbackOutcome,
    ) -> Result<SessionSnapshot> {
        let code = match outcome {
            CallbackOutcome::Code(code) => code,
            CallbackOutcome::Denied => return Err(Error::AccessDenied),
        };
        let exchanged = self
            .http
            .exchange(&self.config.client_id, &code, &state, &verifier)
            .await?;
        self.sign_in(exchanged.token, generation).await
    }

    /// Handles a deep link delivered by the OS. Background flow: reports
    /// through events, ignores links that are not for the current request.
    pub async fn handle_deep_link(self: &Arc<Self>, url: &str) {
        let Ok(parsed) = Url::parse(url) else { return };
        let Some(callback) =
            parse_deep_link(&parsed, &self.config.scheme, &self.config.callback_path)
        else {
            return;
        };
        let claimed = self.claim(&callback.state, None).await;
        let (generation, state, verifier) = match claimed {
            Ok(claimed) => claimed,
            Err(Error::NoPendingFlow) => {
                log::debug!(
                    "[better-auth] ignored a callback with no sign-in in progress. On Windows and \
                     Linux, register tauri-plugin-single-instance with the `deep-link` feature first, \
                     or the link starts a second app instance."
                );
                return;
            }
            Err(Error::InvalidCallback) => return,
            Err(error) => {
                self.events.error(&error);
                return;
            }
        };
        self.events.focus();
        if let Err(error) = self
            .finish(generation, state, verifier, callback.outcome)
            .await
        {
            if !matches!(error, Error::Superseded) {
                self.events.error(&error);
            }
        }
    }

    /// Called by the loopback listener. Returns whether the callback was
    /// claimed (then the listener closes); the exchange runs in the
    /// background and reports through events.
    pub(crate) async fn claim_from_loopback(self: Arc<Self>, callback: Callback) -> bool {
        let (generation, state, verifier) =
            match self.claim(&callback.state, Some(Transport::Loopback)).await {
                Ok(claimed) => claimed,
                Err(Error::FlowExpired) => {
                    self.events.error(&Error::FlowExpired);
                    return false;
                }
                Err(_) => return false,
            };
        self.events.focus();
        let controller = self.clone();
        tokio::spawn(async move {
            if let Err(error) = controller
                .finish(generation, state, verifier, callback.outcome)
                .await
            {
                if !matches!(error, Error::Superseded) {
                    controller.events.error(&error);
                }
            }
        });
        true
    }

    /// Completes a sign-in from a pasted code or link. Reports to the caller.
    pub async fn authenticate(&self, input: &str) -> Result<SessionSnapshot> {
        let (generation, state, verifier, outcome) =
            match parse_pasted(input, &self.config.scheme, &self.config.callback_path)? {
                Pasted::Callback(callback) => {
                    let (generation, state, verifier) = self.claim(&callback.state, None).await?;
                    (generation, state, verifier, callback.outcome)
                }
                Pasted::Code(code) => {
                    let (generation, state, verifier) = self.claim_current().await?;
                    (generation, state, verifier, CallbackOutcome::Code(code))
                }
            };
        self.finish(generation, state, verifier, outcome).await
    }

    // ------------------------------------------------------------- commits

    /// The shared sign-in commit for exchanges and bridged in-app sign-ins.
    pub async fn sign_in(&self, token: String, generation: u64) -> Result<SessionSnapshot> {
        // 1. Verify outside the lock. A host hook may have deleted the session
        //    after creating it; never store a dead token.
        let data = match self.http.get_session(&token).await {
            SessionCheck::Valid(data) => data,
            SessionCheck::Revoked => return Err(Error::SessionRejected),
            SessionCheck::Unreachable(reason) => {
                self.revoke_best_effort(&token).await;
                return Err(Error::Network(reason));
            }
        };

        // 2. Commit inside the lock.
        let mut inner = self.inner.lock().await;
        self.ensure_loaded(&mut inner).await;
        if inner.generation != generation {
            drop(inner);
            self.revoke_best_effort(&token).await;
            return Err(Error::Superseded);
        }
        let rev = inner.last_rev + 1;
        let secret = StoredSecret {
            rev,
            token: token.clone(),
            session_id: data.session_id.clone(),
            expires_at: data.expires_at,
        };
        {
            let store = self.store.clone();
            let secret = secret.clone();
            if let Err(error) = blocking(move || store.save(&secret)).await {
                // The old session stays untouched and usable.
                drop(inner);
                self.revoke_best_effort(&token).await;
                return Err(error.into());
            }
        }
        inner.last_rev = rev;
        self.save_profile(&StoredProfile {
            rev,
            session_id: data.session_id.clone(),
            user: data.user.clone(),
            session: data.session.clone(),
            tombstone: false,
        })
        .await;
        let previous = inner.current.replace(Current {
            secret,
            user: data.user.clone(),
            session: data.session.clone(),
        });
        inner.generation += 1;
        inner.pending = None;
        self.events.authenticated(&data.user);
        let snapshot = SessionSnapshot {
            user: data.user,
            session: data.session,
            offline: false,
        };
        drop(inner);

        // 3. Only now revoke the session it replaced.
        if let Some(previous) = previous {
            if previous.secret.session_id != data.session_id {
                self.revoke_best_effort(&previous.secret.token).await;
            }
        }
        Ok(snapshot)
    }

    async fn save_profile(&self, profile: &StoredProfile) {
        let profiles = self.profiles.clone();
        let profile = profile.clone();
        if let Err(error) = blocking(move || profiles.save(&profile)).await {
            // Not fatal: a stale profile is ignored by revision and refreshed online.
            log::warn!("[better-auth] could not write the profile: {error}");
        }
    }

    async fn revoke_best_effort(&self, token: &str) {
        let _ = tokio::time::timeout(BEST_EFFORT_TIMEOUT, self.http.sign_out(token)).await;
    }

    /// Clears the session (if it is still `expected`), emits `signed-out`.
    /// Returns the cleared token and any storage error.
    async fn clear(
        &self,
        expected_session_id: Option<&str>,
        reason: SignOutReason,
    ) -> (Option<String>, Option<Error>) {
        let mut inner = self.inner.lock().await;
        self.ensure_loaded(&mut inner).await;
        if let Some(expected) = expected_session_id {
            if inner.current.as_ref().map(|c| c.secret.session_id.as_str()) != Some(expected) {
                return (None, None);
            }
        }
        inner.generation += 1;
        inner.pending = None;
        let Some(previous) = inner.current.take() else {
            if reason == SignOutReason::User {
                self.events.signed_out(reason);
            }
            return (None, None);
        };
        let rev = inner.last_rev + 1;
        inner.last_rev = rev;

        let store = self.store.clone();
        let delete_error = blocking(move || store.clear()).await.err();
        // The tombstone forbids rehydrating a secret the store failed to delete,
        // and removes the user's data from disk.
        let profiles = self.profiles.clone();
        let tombstone = StoredProfile {
            rev,
            session_id: previous.secret.session_id.clone(),
            user: Value::Null,
            session: Value::Null,
            tombstone: true,
        };
        let tombstone_error = blocking(move || profiles.save(&tombstone)).await.err();
        self.events.signed_out(reason);

        let error = match (delete_error, tombstone_error) {
            (Some(error), _) => {
                log::warn!("[better-auth] could not delete the stored session: {error}");
                Some(Error::from(error))
            }
            (None, Some(error)) => {
                log::warn!("[better-auth] could not write the sign-out tombstone: {error}");
                None
            }
            (None, None) => None,
        };
        (Some(previous.secret.token), error)
    }

    /// Signs out: local state is always cleared; the server session is revoked
    /// best-effort. A storage failure is reported after the local sign-out.
    pub async fn sign_out(&self) -> Result<()> {
        let (token, error) = self.clear(None, SignOutReason::User).await;
        if let Some(token) = token {
            self.revoke_best_effort(&token).await;
        }
        match error {
            Some(error) => {
                self.events.error(&error);
                Err(error)
            }
            None => Ok(()),
        }
    }

    /// The current session. `cached_only` skips the network check.
    pub async fn session(&self, cached_only: bool) -> Result<Option<SessionSnapshot>> {
        let (current, generation) = {
            let mut inner = self.inner.lock().await;
            self.ensure_loaded(&mut inner).await;
            (inner.current.clone(), inner.generation)
        };
        let Some(current) = current else {
            return Ok(None);
        };
        if current
            .secret
            .expires_at
            .is_some_and(|expires| expires <= now_ms())
        {
            self.clear(Some(&current.secret.session_id), SignOutReason::Expired)
                .await;
            return Ok(None);
        }
        let has_profile = !current.user.is_null();
        if cached_only && has_profile {
            return Ok(Some(current.snapshot(false)));
        }
        match self.http.get_session(&current.secret.token).await {
            SessionCheck::Valid(data) => Ok(Some(self.refresh(&current, generation, data).await)),
            SessionCheck::Revoked => {
                self.clear(Some(&current.secret.session_id), SignOutReason::Revoked)
                    .await;
                Ok(None)
            }
            SessionCheck::Unreachable(reason) => {
                log::debug!("[better-auth] session check offline: {reason}");
                if has_profile {
                    Ok(Some(current.snapshot(true)))
                } else {
                    // A credential without a profile: we cannot show a user yet.
                    Ok(None)
                }
            }
        }
    }

    /// Applies a fresh `get-session` result if nothing changed meanwhile.
    async fn refresh(&self, seen: &Current, generation: u64, data: SessionData) -> SessionSnapshot {
        let snapshot = SessionSnapshot {
            user: data.user.clone(),
            session: data.session.clone(),
            offline: false,
        };
        let mut inner = self.inner.lock().await;
        let unchanged = inner.generation == generation
            && inner.current.as_ref().is_some_and(|c| {
                c.secret.session_id == seen.secret.session_id
                    && c.secret.session_id == data.session_id
            });
        if !unchanged {
            return snapshot;
        }
        let Some(current) = inner.current.as_mut() else {
            return snapshot;
        };
        let rev = current.secret.rev;
        let expiry_moved = match (current.secret.expires_at, data.expires_at) {
            (Some(old), Some(new)) => (new - old).abs() > 3_600_000,
            (None, Some(_)) => true,
            _ => false,
        };
        current.user = data.user.clone();
        current.session = data.session.clone();
        if expiry_moved {
            current.secret.expires_at = data.expires_at;
            let store = self.store.clone();
            let secret = current.secret.clone();
            if let Err(error) = blocking(move || store.save(&secret)).await {
                log::warn!("[better-auth] could not update the stored expiry: {error}");
            }
        }
        self.save_profile(&StoredProfile {
            rev,
            session_id: data.session_id,
            user: data.user,
            session: data.session,
            tombstone: false,
        })
        .await;
        snapshot
    }

    /// The bearer token for host Rust code. Never exposed to the webview.
    pub async fn bearer_token(&self) -> Option<String> {
        let mut inner = self.inner.lock().await;
        self.ensure_loaded(&mut inner).await;
        inner
            .current
            .as_ref()
            .map(|current| current.secret.token.clone())
    }
}

#[cfg(test)]
mod tests;
