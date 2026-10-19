//! The auth bridge: the only way webview code reaches the auth server and the
//! app API. The token is added here and never leaves Rust.
//!
//! Contract violations come back as HTTP-shaped JSON errors (`{ code,
//! message }`), so Better Auth and oRPC clients surface them normally.
//! Network failures and aborts reject the call, like a browser `fetch`.

pub(crate) mod projection;
pub(crate) mod routes;

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Method, Response, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::{
    config::RouteKind,
    controller::Controller,
    http::{bearer, header_token, network},
    Error, Result,
};

use self::{
    projection::{error_body, scrub, session_body, sign_in_body},
    routes::{classify, Route},
};

/// Largest request body the webview may send.
const MAX_REQUEST_BODY: usize = 4 * 1024 * 1024;
/// Largest auth response the bridge parses.
const MAX_AUTH_RESPONSE: usize = 4 * 1024 * 1024;
/// Largest app API response returned to the webview.
const MAX_API_RESPONSE: usize = 16 * 1024 * 1024;

/// A request from `tauriFetch`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeRequest {
    /// Identifies the request for `fetch_cancel`.
    pub id: u32,
    /// Absolute URL.
    pub url: String,
    /// HTTP method.
    pub method: String,
    /// Request headers. Credential, origin and app-owned headers are dropped.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Request body.
    #[serde(default)]
    pub body: Option<BridgeBody>,
}

/// A body crossing the IPC boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "encoding", content = "data", rename_all = "lowercase")]
pub enum BridgeBody {
    /// UTF-8 text.
    Text(String),
    /// Binary data, base64-encoded.
    Base64(String),
}

/// The response returned to `tauriFetch`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeResponse {
    /// HTTP status.
    pub status: u16,
    /// Reason phrase.
    pub status_text: String,
    /// Response headers (never `set-cookie` or `set-auth-token`).
    pub headers: Vec<(String, String)>,
    /// Response body, if any.
    pub body: Option<BridgeBody>,
}

/// Request headers the webview may never set.
fn is_blocked_request_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "cookie"
            | "cookie2"
            | "origin"
            | "referer"
            | "host"
            | "content-length"
            | "user-agent"
            | "accept-encoding"
            | "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
            | "expect"
            | "set-auth-token"
    ) || name.starts_with("sec-")
        || name.starts_with("proxy-")
}

/// Response headers the webview never sees.
fn is_blocked_response_header(name: &str) -> bool {
    matches!(
        name,
        "set-cookie"
            | "set-cookie2"
            | "set-auth-token"
            | "content-encoding"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
    ) || name.starts_with("proxy-")
}

fn json_response(status: StatusCode, body: &Value) -> BridgeResponse {
    BridgeResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or_default().to_owned(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: Some(BridgeBody::Text(body.to_string())),
    }
}

fn error_response(status: StatusCode, code: &str, message: &str) -> BridgeResponse {
    json_response(status, &error_body(code, message))
}

/// Maps a controller/contract error to a response. `None` means "reject".
fn error_to_response(error: &Error) -> Option<BridgeResponse> {
    let status = match error {
        Error::Network(_) | Error::Aborted => return None,
        Error::Server { status, .. } => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        Error::UnsupportedAuthOperation(_) | Error::ForbiddenUrl(_) | Error::SessionRejected => {
            StatusCode::FORBIDDEN
        }
        Error::InvalidRequest(_) => StatusCode::BAD_REQUEST,
        Error::Superseded => StatusCode::CONFLICT,
        Error::BridgeUnparseable => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Some(error_response(status, error.code(), &error.to_string()))
}

fn is_textual(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| {
        let ct = ct.to_ascii_lowercase();
        ct.starts_with("text/")
            || ct.contains("json")
            || ct.contains("xml")
            || ct.contains("javascript")
            || ct.contains("x-www-form-urlencoded")
    })
}

enum ReadError {
    TooLarge,
    Encoded,
    Network(Error),
}

async fn read_capped(
    mut response: Response,
    cap: usize,
) -> std::result::Result<Vec<u8>, ReadError> {
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value != "identity")
    {
        return Err(ReadError::Encoded);
    }
    if response
        .content_length()
        .is_some_and(|len| len > cap as u64)
    {
        return Err(ReadError::TooLarge);
    }
    let mut out = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ReadError::Network(network(error)))?
    {
        if out.len() + chunk.len() > cap {
            return Err(ReadError::TooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn read_error_response(error: ReadError) -> Result<BridgeResponse> {
    match error {
        ReadError::TooLarge => Ok(error_response(
            StatusCode::BAD_GATEWAY,
            "BRIDGE_RESPONSE_TOO_LARGE",
            "The response is larger than the bridge allows.",
        )),
        ReadError::Encoded => Ok(error_response(
            StatusCode::BAD_GATEWAY,
            Error::BridgeUnparseable.code(),
            "The server sent a compressed response the bridge cannot pass on.",
        )),
        ReadError::Network(error) => Err(error),
    }
}

/// The bridge, shared by all windows.
pub(crate) struct Bridge {
    controller: Arc<Controller>,
    app_header_names: Vec<String>,
    inflight: std::sync::Mutex<HashMap<u32, tokio::task::AbortHandle>>,
}

impl Bridge {
    pub fn new(controller: Arc<Controller>) -> Arc<Self> {
        let app_header_names = controller
            .http()
            .app_header_names()
            .into_iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        Arc::new(Self {
            controller,
            app_header_names,
            inflight: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Runs a bridged request; cancellable with [`Bridge::cancel`].
    pub async fn fetch(self: &Arc<Self>, request: BridgeRequest) -> Result<BridgeResponse> {
        let id = request.id;
        let bridge = self.clone();
        let task = tokio::spawn(async move { bridge.execute(request).await });
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.insert(id, task.abort_handle());
        }
        let result = task.await;
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.remove(&id);
        }
        match result {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Err(Error::Aborted),
            Err(_) => Err(Error::InvalidRequest("the bridged request failed".into())),
        }
    }

    /// Aborts an in-flight request.
    pub fn cancel(&self, id: u32) {
        if let Some(handle) = self
            .inflight
            .lock()
            .ok()
            .and_then(|mut inflight| inflight.remove(&id))
        {
            handle.abort();
        }
    }

    async fn execute(&self, request: BridgeRequest) -> Result<BridgeResponse> {
        match self.route_and_run(request).await {
            Ok(response) => Ok(response),
            Err(error) => error_to_response(&error).ok_or(error),
        }
    }

    async fn route_and_run(&self, request: BridgeRequest) -> Result<BridgeResponse> {
        let url =
            Url::parse(&request.url).map_err(|_| Error::InvalidRequest("invalid URL".into()))?;
        let method = request.method.to_ascii_uppercase();
        let method = match method.as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "PATCH" => Method::PATCH,
            "DELETE" => Method::DELETE,
            "HEAD" => Method::HEAD,
            other => {
                return Err(Error::InvalidRequest(format!(
                    "method {other} is not allowed"
                )))
            }
        };
        match classify(self.controller.config(), method.as_str(), &url)? {
            Route::Auth {
                kind: RouteKind::GetSession,
                ..
            } => {
                let snapshot = self.controller.session(false).await?;
                Ok(json_response(
                    StatusCode::OK,
                    &session_body(snapshot.as_ref()),
                ))
            }
            Route::Auth {
                kind: RouteKind::SignOut,
                ..
            } => {
                // Local sign-out always happens; a storage problem is reported
                // through the error event, not as a failed sign-out.
                let _ = self.controller.sign_out().await;
                Ok(json_response(StatusCode::OK, &json!({ "success": true })))
            }
            Route::Auth {
                kind: RouteKind::SignIn,
                ..
            } => {
                self.sign_in(method, url, &request.headers, request.body)
                    .await
            }
            Route::Auth {
                kind: RouteKind::Passthrough,
                ..
            } => {
                self.auth_passthrough(method, url, &request.headers, request.body)
                    .await
            }
            Route::Api => self.api(method, url, &request.headers, request.body).await,
        }
    }

    fn build(
        &self,
        method: Method,
        url: Url,
        headers: &[(String, String)],
        body: Option<BridgeBody>,
        token: Option<&str>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut map: HeaderMap = self.controller.http().base_headers();
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if is_blocked_request_header(&lower) || self.app_header_names.contains(&lower) {
                continue;
            }
            let name = HeaderName::from_bytes(lower.as_bytes())
                .map_err(|_| Error::InvalidRequest(format!("invalid header name {name}")))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| Error::InvalidRequest("invalid header value".into()))?;
            map.insert(name, value);
        }
        if let Some(token) = token {
            map.insert(AUTHORIZATION, bearer(token));
        }
        let bytes = match body {
            None => Vec::new(),
            Some(BridgeBody::Text(text)) => text.into_bytes(),
            Some(BridgeBody::Base64(data)) => STANDARD
                .decode(data)
                .map_err(|_| Error::InvalidRequest("invalid base64 body".into()))?,
        };
        if bytes.len() > MAX_REQUEST_BODY {
            return Err(Error::InvalidRequest(
                "the request body is too large".into(),
            ));
        }
        let builder = self
            .controller
            .http()
            .client()
            .request(method, url)
            .headers(map);
        Ok(if bytes.is_empty() {
            builder
        } else {
            builder.body(bytes)
        })
    }

    /// Reads an auth response as JSON (empty body → `null`).
    async fn auth_json(
        response: Response,
    ) -> std::result::Result<(StatusCode, Option<String>, Value), BridgeResponse> {
        let status = response.status();
        let token = header_token(&response);
        let is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("json"));
        let bytes = match read_capped(response, MAX_AUTH_RESPONSE).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(match read_error_response(error) {
                    Ok(response) => response,
                    Err(error) => {
                        error_response(StatusCode::BAD_GATEWAY, error.code(), &error.to_string())
                    }
                })
            }
        };
        if bytes.is_empty() {
            return Ok((status, token, Value::Null));
        }
        if !is_json {
            return Err(
                error_to_response(&Error::BridgeUnparseable).unwrap_or_else(|| {
                    error_response(
                        StatusCode::BAD_GATEWAY,
                        "BRIDGE_UNPARSEABLE",
                        "unreadable response",
                    )
                }),
            );
        }
        serde_json::from_slice(&bytes)
            .map(|value| (status, token, value))
            .map_err(|_| {
                error_response(
                    StatusCode::BAD_GATEWAY,
                    Error::BridgeUnparseable.code(),
                    &Error::BridgeUnparseable.to_string(),
                )
            })
    }

    async fn auth_passthrough(
        &self,
        method: Method,
        url: Url,
        headers: &[(String, String)],
        body: Option<BridgeBody>,
    ) -> Result<BridgeResponse> {
        let token = self.controller.bearer_token().await;
        let response = self
            .build(method, url, headers, body, token.as_deref())?
            .send()
            .await
            .map_err(network)?;
        match Self::auth_json(response).await {
            Ok((status, _, value)) => Ok(json_response(status, &scrub(value))),
            Err(response) => Ok(response),
        }
    }

    async fn sign_in(
        &self,
        method: Method,
        url: Url,
        headers: &[(String, String)],
        body: Option<BridgeBody>,
    ) -> Result<BridgeResponse> {
        let generation = self.controller.generation().await;
        // Sign-in requests never carry the current session.
        let response = self
            .build(method, url, headers, body, None)?
            .send()
            .await
            .map_err(network)?;
        let (status, header_token, value) = match Self::auth_json(response).await {
            Ok(parts) => parts,
            Err(response) => return Ok(response),
        };
        let token = header_token.or_else(|| {
            value
                .get("token")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        match (status.is_success(), token) {
            (true, Some(token)) => match self.controller.sign_in(token, generation).await {
                Ok(snapshot) => Ok(json_response(StatusCode::OK, &sign_in_body(&snapshot.user))),
                Err(Error::Network(message)) => {
                    Ok(error_response(StatusCode::BAD_GATEWAY, "NETWORK", &message))
                }
                Err(error) => Err(error),
            },
            // No session yet (e.g. email verification required), or an error.
            _ => Ok(json_response(status, &scrub(value))),
        }
    }

    async fn api(
        &self,
        method: Method,
        url: Url,
        headers: &[(String, String)],
        body: Option<BridgeBody>,
    ) -> Result<BridgeResponse> {
        let token = self.controller.bearer_token().await;
        let is_head = method == Method::HEAD;
        let response = self
            .build(method, url, headers, body, token.as_deref())?
            .send()
            .await
            .map_err(network)?;
        let status = response.status();
        let response_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(name, _)| !is_blocked_response_header(name.as_str()))
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = match read_capped(response, MAX_API_RESPONSE).await {
            Ok(bytes) => bytes,
            Err(error) => return read_error_response(error),
        };
        let no_body = is_head
            || matches!(
                status,
                StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
            );
        let body = if no_body {
            None
        } else if is_textual(content_type.as_deref()) {
            match String::from_utf8(bytes) {
                Ok(text) => Some(BridgeBody::Text(text)),
                Err(error) => Some(BridgeBody::Base64(STANDARD.encode(error.into_bytes()))),
            }
        } else {
            Some(BridgeBody::Base64(STANDARD.encode(bytes)))
        };
        Ok(BridgeResponse {
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or_default().to_owned(),
            headers: response_headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests;
