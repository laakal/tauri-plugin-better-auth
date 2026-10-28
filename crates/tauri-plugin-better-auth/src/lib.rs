//! # tauri-plugin-better-auth
//!
//! [Better Auth](https://better-auth.com) for Tauri 3 desktop apps: browser
//! sign-in with PKCE, a session held in Rust, and a webview that never sees a
//! token.
//!
//! - The app opens your sign-in page in the system browser.
//! - The page hands a single-use code back over a deep link or a loopback
//!   redirect.
//! - This plugin exchanges the code, verifies the session and stores it in
//!   the OS keychain.
//! - Webview code then talks to your auth server and API through
//!   `tauriFetch`, a bridge that adds the bearer token in Rust.
//!
//! Pair it with the `tauri-plugin-better-auth` npm package (server plugin,
//! hand-off page client, webview client). See the README for the full setup.
//!
//! ```rust,ignore
//! # fn main() {
//! tauri::Builder::default()
//!     // Tauri 3: pick a runtime (`tauri_runtime_cef::Cef` works too).
//!     .runtime(tauri_runtime_wry::Wry::default())
//!     // Register single-instance (with its `deep-link` feature) and deep-link first.
//!     .plugin(
//!         tauri_plugin_better_auth::Builder::new()
//!             .base_url("https://api.example.com/api/auth")
//!             .sign_in_url("https://example.com/desktop")
//!             .scheme("com.example.app")
//!             .client_id("com.example.app")
//!             .api_routes("https://api.example.com", ["/api/"])
//!             .build(),
//!     )
//!     .run(tauri::generate_context!())
//!     .expect("error while running tauri application");
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod bridge;
mod callback;
mod commands;
mod config;
mod controller;
mod error;
mod http;
mod models;
mod pkce;
mod store;
mod tls;
mod transport;

use std::{marker::PhantomData, path::PathBuf, sync::Arc, time::Duration};

use serde_json::Value;
use tauri::{
    AppHandle, Emitter, Listener, Manager, Runtime,
    plugin::{Builder as PluginBuilder, TauriPlugin},
};

use crate::{
    bridge::Bridge,
    config::{ExtraAuthRoute, RawConfig},
    controller::{BrowserOpener, Controller, ControllerParts, EventSink, SystemBrowser},
    http::{AppHeaders, HttpApi},
    store::profile::FileProfileStore,
};

pub use bridge::{BridgeBody, BridgeRequest, BridgeResponse};
pub use config::{AuthRouteKind, Transport};
pub use error::{Error, Result};
pub use models::{
    AuthenticatedPayload, RequestAuthOptions, RequestAuthResult, SessionSnapshot, SignOutReason,
    SignedOutPayload,
};
pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
#[cfg(feature = "keyring")]
#[cfg_attr(docsrs, doc(cfg(feature = "keyring")))]
pub use store::KeyringStore;
pub use store::{MemoryStore, SessionStore, StoreError, StoredSecret};

/// Emitted with [`AuthenticatedPayload`] after every successful sign-in.
pub const EVENT_AUTHENTICATED: &str = "better-auth://authenticated";
/// Emitted with [`SignedOutPayload`] when the session ends.
pub const EVENT_SIGNED_OUT: &str = "better-auth://signed-out";
/// Emitted with `{ code, message }` when a background sign-in fails.
pub const EVENT_ERROR: &str = "better-auth://error";

/// A session change, reported to [`Builder::on_session`].
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionEvent<'a> {
    /// A user signed in.
    Authenticated {
        /// The user object.
        user: &'a Value,
    },
    /// The session ended.
    SignedOut {
        /// Why.
        reason: SignOutReason,
    },
}

type HeadersFn<R> = Arc<dyn Fn(&AppHandle<R>) -> HeaderMap + Send + Sync>;
type SessionFn<R> = Arc<dyn Fn(&AppHandle<R>, SessionEvent<'_>) + Send + Sync>;
type OpenerFn = Arc<dyn Fn(&str) -> std::io::Result<()> + Send + Sync>;

struct CustomOpener(OpenerFn);

impl BrowserOpener for CustomOpener {
    fn open(&self, url: &str) -> std::io::Result<()> {
        (self.0)(url)
    }
}

/// Configures and builds the plugin. All values are set from Rust; nothing the
/// webview sends can change where the plugin talks to.
pub struct Builder<R: Runtime> {
    raw: RawConfig,
    store: Option<Arc<dyn SessionStore>>,
    headers: Option<HeadersFn<R>>,
    on_session: Option<SessionFn<R>>,
    opener: Option<OpenerFn>,
    profile_dir: Option<PathBuf>,
}

impl<R: Runtime> Default for Builder<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Runtime> Builder<R> {
    /// A builder with default settings.
    pub fn new() -> Self {
        Self {
            raw: RawConfig::default(),
            store: None,
            headers: None,
            on_session: None,
            opener: None,
            profile_dir: None,
        }
    }

    /// Required. Better Auth base URL, e.g. `https://api.example.com/api/auth`.
    /// `https`, or `http` on localhost only.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.raw.base_url = Some(url.into());
        self
    }

    /// Required. The hand-off page that runs `tauriProxyClient`.
    pub fn sign_in_url(mut self, url: impl Into<String>) -> Self {
        self.raw.sign_in_url = Some(url.into());
        self
    }

    /// Required. The custom URI scheme registered for deep links, e.g.
    /// `com.example.app`. It must also be listed in
    /// `plugins.deep-link.desktop.schemes`.
    pub fn scheme(mut self, scheme: impl Into<String>) -> Self {
        self.raw.scheme = Some(scheme.into());
        self
    }

    /// Callback path, `/auth/callback` by default.
    pub fn callback_path(mut self, path: impl Into<String>) -> Self {
        self.raw.callback_path = Some(path.into());
        self
    }

    /// Client id shared with the server plugin, `tauri` by default.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.raw.client_id = Some(client_id.into());
        self
    }

    /// Lets `tauriFetch` reach your app API: requests to `origin` whose path
    /// starts with one of `prefixes` are sent with the bearer token. The Better
    /// Auth base path is never part of an API route. Call it once per origin.
    pub fn api_routes<I, S>(mut self, origin: impl Into<String>, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.raw.api_routes.push((
            origin.into(),
            prefixes.into_iter().map(Into::into).collect(),
        ));
        self
    }

    /// Adds a Better Auth route to the bridge allowlist (e.g. a plugin
    /// endpoint). `/tauri/*` can never be added.
    pub fn auth_route(
        mut self,
        method: impl Into<String>,
        path: impl Into<String>,
        kind: AuthRouteKind,
    ) -> Self {
        self.raw.auth_routes.push(ExtraAuthRoute {
            method: method.into(),
            path: path.into(),
            kind,
        });
        self
    }

    /// How the browser returns to the app; [`Transport::Auto`] by default.
    pub fn transport(mut self, transport: Transport) -> Self {
        self.raw.transport = transport;
        self
    }

    /// How long a started sign-in waits for its callback (1–60 minutes,
    /// 10 by default).
    pub fn pending_ttl(mut self, ttl: Duration) -> Self {
        self.raw.pending_ttl = Some(ttl);
        self
    }

    /// Timeout of each request to the auth server (15 seconds by default).
    /// For a streamed API response it covers the wait for the headers; see
    /// [`Builder::stream_idle_timeout`] for the body.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.raw.timeout = Some(timeout);
        self
    }

    /// Longest gap between two chunks of a streamed API response before the
    /// stream fails (1 second to 60 minutes, 60 seconds by default).
    pub fn stream_idle_timeout(mut self, timeout: Duration) -> Self {
        self.raw.stream_idle_timeout = Some(timeout);
        self
    }

    /// Label of the window focused when a sign-in returns (`main`).
    pub fn main_window(mut self, label: impl Into<String>) -> Self {
        self.raw.main_window = Some(label.into());
        self
    }

    /// Where the session secret is stored. Defaults to the OS keychain
    /// ([`KeyringStore`]) with the `keyring` feature, otherwise memory.
    pub fn store(mut self, store: impl SessionStore) -> Self {
        self.store = Some(Arc::new(store));
        self
    }

    /// Extra headers sent with the code exchange and every bridged request,
    /// e.g. device context. Webview code cannot set or override them.
    pub fn headers<F>(mut self, headers: F) -> Self
    where
        F: Fn(&AppHandle<R>) -> HeaderMap + Send + Sync + 'static,
    {
        self.headers = Some(Arc::new(headers));
        self
    }

    /// Called from Rust on every sign-in and sign-out.
    pub fn on_session<F>(mut self, callback: F) -> Self
    where
        F: Fn(&AppHandle<R>, SessionEvent<'_>) + Send + Sync + 'static,
    {
        self.on_session = Some(Arc::new(callback));
        self
    }

    /// Replaces how the sign-in page is opened (the OS default browser by
    /// default), e.g. to pick a browser or to show the URL instead.
    pub fn opener<F>(mut self, open: F) -> Self
    where
        F: Fn(&str) -> std::io::Result<()> + Send + Sync + 'static,
    {
        self.opener = Some(Arc::new(open));
        self
    }

    /// Where the non-secret profile cache (user and tokenless session) is
    /// written; `<app data dir>/better-auth` by default.
    pub fn profile_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.profile_dir = Some(dir.into());
        self
    }

    /// Builds the plugin. Invalid configuration fails app startup with a
    /// message that names the setting.
    pub fn build(self) -> TauriPlugin<R> {
        let Builder {
            raw,
            store,
            headers,
            on_session,
            opener,
            profile_dir,
        } = self;
        PluginBuilder::<R>::new("better-auth")
            .invoke_handler(tauri::generate_handler![
                commands::request_auth,
                commands::authenticate,
                commands::cancel_auth,
                commands::get_session,
                commands::sign_out,
                commands::fetch,
                commands::fetch_stream,
                commands::fetch_cancel,
            ])
            .setup(move |app, _api| {
                let config = Arc::new(raw.validate()?);
                warn_if_scheme_unregistered(app, &config.scheme, config.transport);

                let store: Arc<dyn SessionStore> = match store {
                    Some(store) => store,
                    None => default_store(app, &config),
                };
                let data_dir = match profile_dir {
                    Some(dir) => dir,
                    None => app.path().app_data_dir()?.join("better-auth"),
                };
                let profiles = Arc::new(FileProfileStore::new(&data_dir, &config.namespace()));

                let package = app.package_info();
                let user_agent = format!(
                    "{}/{} tauri-plugin-better-auth/{}",
                    package.name.replace(|c: char| !c.is_ascii_graphic(), "-"),
                    package.version,
                    env!("CARGO_PKG_VERSION")
                );
                let app_headers: AppHeaders = match headers {
                    Some(headers) => {
                        let handle = app.clone();
                        Arc::new(move || headers(&handle))
                    }
                    None => Arc::new(HeaderMap::new),
                };
                let http = HttpApi::new(
                    config.base_url.clone(),
                    config.timeout,
                    &user_agent,
                    app_headers,
                )?;
                let events: Arc<dyn EventSink> = Arc::new(TauriEvents {
                    app: app.clone(),
                    main_window: config.main_window.clone(),
                    on_session,
                });
                let opener: Arc<dyn BrowserOpener> = match opener {
                    Some(open) => Arc::new(CustomOpener(open)),
                    None => Arc::new(SystemBrowser),
                };
                let controller = Controller::new(ControllerParts {
                    config: config.clone(),
                    http,
                    store,
                    profiles,
                    events,
                    opener,
                    deep_links_deliverable: transport::deep_links_deliverable(),
                    app_name: package.name.clone(),
                });
                let bridge = Bridge::new(controller.clone());
                app.manage(BetterAuth::<R> {
                    controller: controller.clone(),
                    bridge,
                    _runtime: PhantomData,
                });

                // Listening to the deep-link event works whatever order the
                // plugins were registered in (unlike `app.deep_link()`).
                app.listen("deep-link://new-url", move |event| {
                    let urls: Vec<String> =
                        serde_json::from_str(event.payload()).unwrap_or_default();
                    let controller = controller.clone();
                    tauri::async_runtime::spawn(async move {
                        for url in urls {
                            controller.handle_deep_link(&url).await;
                        }
                    });
                });
                Ok(())
            })
            .build()
    }
}

fn default_store<R: Runtime>(app: &AppHandle<R>, config: &config::Config) -> Arc<dyn SessionStore> {
    #[cfg(feature = "keyring")]
    {
        Arc::new(KeyringStore::new(
            app.config().identifier.clone(),
            config.namespace(),
        ))
    }
    #[cfg(not(feature = "keyring"))]
    {
        let _ = (app, config);
        Arc::new(MemoryStore::new())
    }
}

/// Warns when the scheme is missing from `plugins.deep-link.desktop.schemes`.
fn warn_if_scheme_unregistered<R: Runtime>(app: &AppHandle<R>, scheme: &str, transport: Transport) {
    if transport == Transport::Loopback {
        return;
    }
    let Some(deep_link) = app.config().plugins.0.get("deep-link") else {
        log::warn!(
            "[better-auth] tauri.conf.json has no `plugins.deep-link` section. Add \
             {{ \"desktop\": {{ \"schemes\": [\"{scheme}\"] }} }} and register tauri-plugin-deep-link, \
             or deep-link sign-ins will never reach the app."
        );
        return;
    };
    let schemes: Vec<String> = match deep_link.get("desktop") {
        Some(Value::Object(desktop)) => desktop
            .get("schemes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(|entry| entry.get("schemes").and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    if !schemes.iter().any(|s| s == scheme) {
        log::warn!(
            "[better-auth] the scheme \"{scheme}\" is not in plugins.deep-link.desktop.schemes \
             ({schemes:?}); deep-link sign-ins will not reach the app."
        );
    }
}

struct TauriEvents<R: Runtime> {
    app: AppHandle<R>,
    main_window: String,
    on_session: Option<SessionFn<R>>,
}

impl<R: Runtime> EventSink for TauriEvents<R> {
    fn authenticated(&self, user: &Value) {
        if let Err(error) = self.app.emit(
            EVENT_AUTHENTICATED,
            AuthenticatedPayload { user: user.clone() },
        ) {
            log::warn!("[better-auth] could not emit {EVENT_AUTHENTICATED}: {error}");
        }
        if let Some(callback) = &self.on_session {
            callback(&self.app, SessionEvent::Authenticated { user });
        }
    }

    fn signed_out(&self, reason: SignOutReason) {
        if let Err(error) = self.app.emit(EVENT_SIGNED_OUT, SignedOutPayload { reason }) {
            log::warn!("[better-auth] could not emit {EVENT_SIGNED_OUT}: {error}");
        }
        if let Some(callback) = &self.on_session {
            callback(&self.app, SessionEvent::SignedOut { reason });
        }
    }

    fn error(&self, error: &Error) {
        if let Err(emit_error) = self.app.emit(EVENT_ERROR, error) {
            log::warn!("[better-auth] could not emit {EVENT_ERROR}: {emit_error}");
        }
    }

    fn focus(&self) {
        if let Some(window) = self.app.get_webview_window(&self.main_window) {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

/// The plugin handle, available through [`BetterAuthExt::better_auth`].
pub struct BetterAuth<R: Runtime> {
    controller: Arc<Controller>,
    pub(crate) bridge: Arc<Bridge>,
    _runtime: PhantomData<fn() -> R>,
}

impl<R: Runtime> BetterAuth<R> {
    /// Opens the system browser on the sign-in page.
    pub async fn request_auth(&self, options: RequestAuthOptions) -> Result<RequestAuthResult> {
        self.controller.request_auth(options).await
    }

    /// Completes a sign-in from a pasted code or callback link.
    pub async fn authenticate(&self, code_or_link: &str) -> Result<SessionSnapshot> {
        self.controller.authenticate(code_or_link).await
    }

    /// Cancels the sign-in in progress.
    pub async fn cancel_auth(&self) {
        self.controller.cancel_auth().await;
    }

    /// The current session; `cached_only` skips the server check.
    pub async fn session(&self, cached_only: bool) -> Result<Option<SessionSnapshot>> {
        self.controller.session(cached_only).await
    }

    /// Signs out locally and, best-effort, on the server.
    pub async fn sign_out(&self) -> Result<()> {
        self.controller.sign_out().await
    }

    /// The bearer token, for your own Rust HTTP calls. Never send it to the
    /// webview.
    pub async fn bearer_token(&self) -> Option<String> {
        self.controller.bearer_token().await
    }

    /// Handles a deep link yourself (if you do not use tauri-plugin-deep-link).
    pub async fn handle_url(&self, url: &str) {
        self.controller.handle_deep_link(url).await;
    }
}

/// Access to the plugin from any [`Manager`] (`App`, `AppHandle`, `Window`…).
pub trait BetterAuthExt<R: Runtime> {
    /// The plugin handle. Panics if the plugin is not registered.
    fn better_auth(&self) -> &BetterAuth<R>;
}

impl<R: Runtime, T: Manager<R>> BetterAuthExt<R> for T {
    fn better_auth(&self) -> &BetterAuth<R> {
        self.state::<BetterAuth<R>>().inner()
    }
}
