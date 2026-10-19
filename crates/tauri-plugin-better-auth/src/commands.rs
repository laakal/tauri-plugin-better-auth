//! Webview commands. Thin wrappers: the logic lives in the controller and the
//! bridge. No command returns a token.

use tauri::{AppHandle, Runtime, command};

use crate::{
    BetterAuthExt, Result,
    bridge::{BridgeRequest, BridgeResponse},
    models::{RequestAuthOptions, RequestAuthResult, SessionSnapshot},
};

#[command]
pub(crate) async fn request_auth<R: Runtime>(
    app: AppHandle<R>,
    options: Option<RequestAuthOptions>,
) -> Result<RequestAuthResult> {
    app.better_auth()
        .request_auth(options.unwrap_or_default())
        .await
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
    app: AppHandle<R>,
    code: String,
) -> Result<SessionSnapshot> {
    app.better_auth().authenticate(&code).await
}

#[command]
pub(crate) async fn cancel_auth<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.better_auth().cancel_auth().await;
    Ok(())
}

#[command]
pub(crate) async fn get_session<R: Runtime>(
    app: AppHandle<R>,
    cached_only: Option<bool>,
) -> Result<Option<SessionSnapshot>> {
    app.better_auth()
        .session(cached_only.unwrap_or(false))
        .await
}

#[command]
pub(crate) async fn sign_out<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.better_auth().sign_out().await
}

#[command]
pub(crate) async fn fetch<R: Runtime>(
    app: AppHandle<R>,
    request: BridgeRequest,
) -> Result<BridgeResponse> {
    app.better_auth().bridge.fetch(request).await
}

#[command]
pub(crate) async fn fetch_cancel<R: Runtime>(app: AppHandle<R>, id: u32) -> Result<()> {
    app.better_auth().bridge.cancel(id);
    Ok(())
}
