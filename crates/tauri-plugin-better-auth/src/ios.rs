//! iOS: the sign-in page runs in an `ASWebAuthenticationSession` (see
//! `ios/Sources/BetterAuthPlugin.swift`).
//!
//! The system gives the callback link to the session itself, so no deep-link
//! plugin and no `Info.plist` scheme registration are involved. The link then
//! takes the same path as a deep link on desktop.

use std::sync::{Arc, OnceLock, Weak};

use crate::{
    callback::state_of_sign_in_url,
    controller::{BrowserOpener, Controller},
};
use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{mobile::PluginInvokeError, PluginApi, PluginHandle},
    Runtime,
};

tauri::ios_plugin_binding!(init_plugin_better_auth);

#[derive(Serialize)]
struct StartAuth {
    url: String,
    scheme: String,
}

#[derive(Deserialize)]
struct AuthResult {
    /// The callback link; absent when the user dismissed the sheet.
    #[serde(default)]
    url: Option<String>,
}

/// Opens the sign-in page in the system authentication sheet.
pub(crate) struct AuthSession<R: Runtime> {
    plugin: PluginHandle<R>,
    scheme: String,
    controller: OnceLock<Weak<Controller>>,
}

impl<R: Runtime> AuthSession<R> {
    /// Registers the Swift half of the plugin.
    pub fn register(
        api: &PluginApi<R, ()>,
        scheme: String,
    ) -> Result<Arc<Self>, PluginInvokeError> {
        Ok(Arc::new(Self {
            plugin: api.register_ios_plugin(init_plugin_better_auth)?,
            scheme,
            controller: OnceLock::new(),
        }))
    }

    /// Sets where the session reports to. The controller owns the opener, so
    /// it is attached after both exist.
    pub fn attach(&self, controller: &Arc<Controller>) {
        let _ = self.controller.set(Arc::downgrade(controller));
    }
}

impl<R: Runtime> BrowserOpener for AuthSession<R> {
    fn open(&self, url: &str) -> std::io::Result<()> {
        let controller = self
            .controller
            .get()
            .cloned()
            .ok_or_else(|| std::io::Error::other("the plugin is not ready"))?;
        let state = state_of_sign_in_url(url);
        let plugin = self.plugin.clone();
        let args = StartAuth {
            url: url.to_owned(),
            scheme: self.scheme.clone(),
        };
        // The native call returns when the sheet closes, so it runs in the
        // background and reports like a deep link does.
        tauri::async_runtime::spawn(async move {
            let result = plugin
                .run_mobile_plugin_async::<AuthResult>("startAuth", args)
                .await;
            let Some(controller) = controller.upgrade() else {
                return;
            };
            match result {
                Ok(AuthResult { url: Some(link) }) => controller.handle_deep_link(&link).await,
                Ok(AuthResult { url: None }) => controller.browser_closed(&state, None).await,
                Err(error) => {
                    controller
                        .browser_closed(&state, Some(error.to_string()))
                        .await
                }
            }
        });
        Ok(())
    }

    fn close(&self) {
        let plugin = self.plugin.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(error) = plugin.run_mobile_plugin_async::<()>("cancelAuth", ()).await {
                log::debug!("[better-auth] could not dismiss the sign-in sheet: {error}");
            }
        });
    }
}
