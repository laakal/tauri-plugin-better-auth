//! Webview commands. Thin wrappers: the logic lives in the controller and the
//! bridge. No command returns a token.

use serde_json::json;
use tauri::{
    command,
    ipc::{Channel, InvokeResponseBody},
    AppHandle, Runtime, Webview,
};

use crate::{
    bridge::{BridgeRequest, BridgeResponse, StreamEvent, StreamSink},
    models::{RequestAuthOptions, RequestAuthResult, SessionSnapshot},
    BetterAuthExt, Result,
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
    webview: Webview<R>,
    request: BridgeRequest,
) -> Result<BridgeResponse> {
    app.better_auth()
        .bridge
        .fetch(webview.label(), request)
        .await
}

/// Like `fetch`; an app API body then arrives on `channel`: raw chunks, then
/// `{ "event": "end" }` or `{ "event": "error", code, message }`.
#[command]
pub(crate) async fn fetch_stream<R: Runtime>(
    app: AppHandle<R>,
    webview: Webview<R>,
    request: BridgeRequest,
    channel: Channel<InvokeResponseBody>,
) -> Result<BridgeResponse> {
    let sink: StreamSink = Box::new(move |event| {
        let body = match event {
            StreamEvent::Chunk(bytes) => InvokeResponseBody::Raw(bytes),
            StreamEvent::End => InvokeResponseBody::Json(json!({ "event": "end" }).to_string()),
            StreamEvent::Error { code, message } => InvokeResponseBody::Json(
                json!({ "event": "error", "code": code, "message": message }).to_string(),
            ),
        };
        channel.send(body).is_ok()
    });
    app.better_auth()
        .bridge
        .fetch_stream(webview.label(), request, sink)
        .await
}

#[command]
pub(crate) async fn fetch_cancel<R: Runtime>(
    app: AppHandle<R>,
    webview: Webview<R>,
    id: u32,
) -> Result<()> {
    app.better_auth().bridge.cancel(webview.label(), id);
    Ok(())
}
