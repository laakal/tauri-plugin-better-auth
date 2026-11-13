//! Android: the sign-in page opens in a Custom Tab (see
//! `android/src/main/java/BetterAuthPlugin.kt`).
//!
//! The callback returns as an intent for the app's scheme, which
//! tauri-plugin-deep-link turns into the same deep-link event as on desktop.
//! Closing the tab does not end the sign-in: like a desktop browser window,
//! the flow stays open so a pasted code still works.

use std::sync::{Arc, OnceLock, Weak};

use serde::Serialize;
use tauri::{
    plugin::{mobile::PluginInvokeError, PluginApi, PluginHandle},
    Runtime,
};

use crate::{
    callback::state_of_sign_in_url,
    controller::{BrowserOpener, Controller},
};

const PLUGIN_PACKAGE: &str = "io.github.laakal.betterauth";

#[derive(Serialize)]
struct OpenAuth {
    url: String,
}

/// Opens the sign-in page in a Custom Tab.
pub(crate) struct AuthTab<R: Runtime> {
    plugin: PluginHandle<R>,
    controller: OnceLock<Weak<Controller>>,
}

impl<R: Runtime> AuthTab<R> {
    /// Registers the Kotlin half of the plugin.
    pub fn register(api: &PluginApi<R, ()>) -> Result<Arc<Self>, PluginInvokeError> {
        Ok(Arc::new(Self {
            plugin: api.register_android_plugin(PLUGIN_PACKAGE, "BetterAuthPlugin")?,
            controller: OnceLock::new(),
        }))
    }

    /// Sets where a failure to open is reported. The controller owns the
    /// opener, so it is attached after both exist.
    pub fn attach(&self, controller: &Arc<Controller>) {
        let _ = self.controller.set(Arc::downgrade(controller));
    }
}

impl<R: Runtime> BrowserOpener for AuthTab<R> {
    fn open(&self, url: &str) -> std::io::Result<()> {
        let controller = self
            .controller
            .get()
            .cloned()
            .ok_or_else(|| std::io::Error::other("the plugin is not ready"))?;
        let state = state_of_sign_in_url(url);
        let plugin = self.plugin.clone();
        let args = OpenAuth {
            url: url.to_owned(),
        };
        // The tab is started on the UI thread; a failure is reported like a
        // background sign-in error.
        tauri::async_runtime::spawn(async move {
            let result = plugin.run_mobile_plugin_async::<()>("openAuth", args).await;
            if let (Err(error), Some(controller)) = (result, controller.upgrade()) {
                controller
                    .browser_closed(&state, Some(error.to_string()))
                    .await;
            }
        });
        Ok(())
    }

    fn close(&self) {
        let plugin = self.plugin.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(error) = plugin.run_mobile_plugin_async::<()>("closeAuth", ()).await {
                log::debug!("[better-auth] could not close the sign-in tab: {error}");
            }
        });
    }
}
