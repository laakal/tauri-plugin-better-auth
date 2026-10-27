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

mod flow;
mod session;

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
}

#[cfg(test)]
mod tests;
