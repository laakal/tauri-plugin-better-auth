//! HTTP calls to the Better Auth server: the code exchange, session checks and
//! sign-out. Requests never follow redirects (a 307/308 must not forward the
//! verifier anywhere), always time out, send no cookies and no `Origin`.

use std::{sync::Arc, time::Duration};

use reqwest::{
    Client, Response, StatusCode,
    header::{ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue},
    redirect::Policy,
};
use serde_json::{Value, json};
use url::Url;

use crate::{Error, Result};

/// Extra headers the app sends with every auth request (e.g. device context).
pub(crate) type AppHeaders = Arc<dyn Fn() -> HeaderMap + Send + Sync>;

/// Headers the app callback may never set: the plugin owns them.
const RESERVED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "origin",
    "host",
    "content-length",
];

/// A successful code exchange. The user is re-read from `get-session`
/// before anything is stored, so only the token is kept.
pub(crate) struct Exchanged {
    pub token: String,
}

/// A session as reported by `GET /get-session`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SessionData {
    /// Session object without `token`.
    pub session: Value,
    pub user: Value,
    pub session_id: String,
    pub expires_at: Option<i64>,
}

/// Outcome of a session check.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SessionCheck {
    Valid(SessionData),
    /// The server answered and the session is gone (200 `null`, 401, 403).
    Revoked,
    /// The server could not give an answer (network, timeout, 5xx, 429…).
    Unreachable(String),
}

pub(crate) struct HttpApi {
    client: Client,
    base: Url,
    app_headers: AppHeaders,
}

impl HttpApi {
    pub fn new(
        base: Url,
        timeout: Duration,
        user_agent: &str,
        app_headers: AppHeaders,
    ) -> Result<Self> {
        let client = Client::builder()
            .tls_backend_preconfigured(crate::tls::client_config()?)
            .redirect(Policy::none())
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .user_agent(user_agent)
            .build()
            .map_err(|error| Error::Config(format!("HTTP client setup failed: {error}")))?;
        Ok(Self {
            client,
            base,
            app_headers,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// `base_url` + `path` (`path` starts with `/`).
    pub fn endpoint(&self, path: &str) -> Url {
        let mut url = self.base.clone();
        let base_path = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{base_path}{path}"));
        url
    }

    /// The app headers minus the ones the plugin owns, plus JSON defaults.
    pub fn base_headers(&self) -> HeaderMap {
        let mut headers = (self.app_headers)();
        for name in RESERVED_HEADERS {
            headers.remove(*name);
        }
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        headers
    }

    /// Names of the headers the app callback sets (the bridge strips them from
    /// webview requests so a page cannot spoof device context).
    pub fn app_header_names(&self) -> Vec<String> {
        (self.app_headers)()
            .keys()
            .map(|name| name.as_str().to_owned())
            .collect()
    }

    /// `POST /tauri/token`.
    pub async fn exchange(
        &self,
        client_id: &str,
        code: &str,
        state: &str,
        verifier: &str,
    ) -> Result<Exchanged> {
        let response = self
            .client
            .post(self.endpoint("/tauri/token"))
            .headers(self.base_headers())
            .header(CONTENT_TYPE, "application/json")
            .json(&json!({
                "client_id": client_id,
                "code": code,
                "state": state,
                "code_verifier": verifier,
            }))
            .send()
            .await
            .map_err(network)?;
        let status = response.status();
        let header_token = header_token(&response);
        let body = read_json(response).await?;
        if !status.is_success() {
            return Err(server_error(status, &body));
        }
        if body.get("user").is_none() {
            return Err(Error::BridgeUnparseable);
        }
        let token = header_token
            .or_else(|| body.get("token").and_then(Value::as_str).map(str::to_owned))
            .ok_or(Error::BridgeUnparseable)?;
        Ok(Exchanged { token })
    }

    /// `GET /get-session` with the bearer token.
    pub async fn get_session(&self, token: &str) -> SessionCheck {
        let response = match self
            .client
            .get(self.endpoint("/get-session"))
            .headers(self.base_headers())
            .header(AUTHORIZATION, bearer(token))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => return SessionCheck::Unreachable(network(error).to_string()),
        };
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return SessionCheck::Revoked;
        }
        if !status.is_success() {
            return SessionCheck::Unreachable(format!("the server answered {status}"));
        }
        match read_json(response).await {
            Ok(Value::Null) => SessionCheck::Revoked,
            Ok(body) => match parse_session_data(body) {
                Some(data) => SessionCheck::Valid(data),
                None => SessionCheck::Unreachable("unexpected get-session response".into()),
            },
            Err(error) => SessionCheck::Unreachable(error.to_string()),
        }
    }

    /// `POST /sign-out` with the bearer token.
    pub async fn sign_out(&self, token: &str) -> Result<()> {
        let response = self
            .client
            .post(self.endpoint("/sign-out"))
            .headers(self.base_headers())
            .header(AUTHORIZATION, bearer(token))
            .header(CONTENT_TYPE, "application/json")
            .body("{}")
            .send()
            .await
            .map_err(network)?;
        let status = response.status();
        if status.is_success() || status == StatusCode::UNAUTHORIZED {
            return Ok(());
        }
        let body = read_json(response).await.unwrap_or(Value::Null);
        Err(server_error(status, &body))
    }
}

pub(crate) fn bearer(token: &str) -> HeaderValue {
    let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
        .unwrap_or_else(|_| HeaderValue::from_static("Bearer invalid"));
    value.set_sensitive(true);
    value
}

pub(crate) fn network(error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::Network("the auth server did not answer in time".into())
    } else if error.is_connect() {
        Error::Network("could not connect to the auth server".into())
    } else {
        Error::Network(error.without_url().to_string())
    }
}

/// `set-auth-token`, set by Better Auth's `bearer()` plugin.
pub(crate) fn header_token(response: &Response) -> Option<String> {
    response
        .headers()
        .get("set-auth-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

async fn read_json(response: Response) -> Result<Value> {
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value != "identity")
    {
        return Err(Error::BridgeUnparseable);
    }
    let bytes = response.bytes().await.map_err(network)?;
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::BridgeUnparseable)
}

/// Maps a Better Auth error body (`{ code, message }`) to [`Error::Server`].
pub(crate) fn server_error(status: StatusCode, body: &Value) -> Error {
    let code = body
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("SERVER_ERROR")
        .to_owned();
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("The auth server answered {status}"));
    Error::Server {
        status: status.as_u16(),
        code,
        message,
    }
}

/// Reads `{ session, user }`; `None` if the shape is wrong.
pub(crate) fn parse_session_data(body: Value) -> Option<SessionData> {
    let session = body.get("session")?.clone();
    let user = body.get("user")?.clone();
    let session_id = session.get("id")?.as_str()?.to_owned();
    let expires_at = session
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(parse_iso8601_ms);
    Some(SessionData {
        session: crate::models::tokenless(session),
        user,
        session_id,
        expires_at,
    })
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)` into epoch milliseconds.
pub(crate) fn parse_iso8601_ms(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let [
        y0,
        y1,
        y2,
        y3,
        b'-',
        m0,
        m1,
        b'-',
        d0,
        d1,
        b'T' | b't' | b' ',
        h0,
        h1,
        b':',
        n0,
        n1,
        b':',
        s0,
        s1,
        suffix @ ..,
    ] = bytes
    else {
        return None;
    };
    let year = decimal(&[*y0, *y1, *y2, *y3])?;
    let month = decimal(&[*m0, *m1])?;
    let day = decimal(&[*d0, *d1])?;
    let hour = decimal(&[*h0, *h1])?;
    let minute = decimal(&[*n0, *n1])?;
    let second = decimal(&[*s0, *s1])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let (millis, timezone) = parse_fraction(suffix)?;
    let offset_minutes = parse_timezone(timezone)?;
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60;
    Some(seconds * 1_000 + millis)
}

/// Parses only ASCII decimal digits, including for timezone components.
fn decimal(bytes: &[u8]) -> Option<i64> {
    bytes.iter().try_fold(0, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + i64::from(byte - b'0'))
    })
}

fn parse_fraction(suffix: &[u8]) -> Option<(i64, &[u8])> {
    let Some(fraction) = suffix.strip_prefix(b".") else {
        return Some((0, suffix));
    };
    let count = fraction
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if count == 0 {
        return None;
    }
    let digits = fraction.get(..count)?;
    let millis = digits
        .iter()
        .take(3)
        .zip([100, 10, 1])
        .fold(0, |sum, (byte, scale)| sum + i64::from(byte - b'0') * scale);
    Some((millis, fraction.get(count..)?))
}

fn parse_timezone(timezone: &[u8]) -> Option<i64> {
    match timezone {
        b"Z" | b"z" => Some(0),
        [sign @ (b'+' | b'-'), h0, h1, b':', m0, m1] => {
            let hours = decimal(&[*h0, *h1])?;
            let minutes = decimal(&[*m0, *m1])?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let sign = if *sign == b'-' { -1 } else { 1 };
            Some(sign * (hours * 60 + minutes))
        }
        _ => None,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month_index + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, header_exists, method, path},
    };

    fn api(server: &MockServer) -> HttpApi {
        let base = Url::parse(&format!("{}/api/auth", server.uri())).unwrap();
        let headers: AppHeaders = Arc::new(|| {
            let mut map = HeaderMap::new();
            map.insert("x-device-id", HeaderValue::from_static("device-1"));
            // Ignored: the plugin owns these.
            map.insert("cookie", HeaderValue::from_static("a=b"));
            map.insert("authorization", HeaderValue::from_static("Bearer spoof"));
            map
        });
        HttpApi::new(base, Duration::from_secs(2), "TestApp/1.0", headers).unwrap()
    }

    #[test]
    fn parses_iso8601() {
        assert_eq!(parse_iso8601_ms("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_iso8601_ms("2026-10-16T12:34:56.789Z"),
            Some(1_792_154_096_789)
        );
        assert_eq!(
            parse_iso8601_ms("2026-10-16T12:34:56Z"),
            Some(1_792_154_096_000)
        );
        assert_eq!(
            parse_iso8601_ms("2026-10-16T14:34:56.789+02:00"),
            Some(1_792_154_096_789)
        );
        assert_eq!(
            parse_iso8601_ms("2000-02-29T00:00:00.5Z"),
            Some(951_782_400_500)
        );
        for (fraction, expected) in [("1", 100), ("12", 120), ("123", 123), ("123456", 123)] {
            assert_eq!(
                parse_iso8601_ms(&format!("1970-01-01T00:00:00.{fraction}Z")),
                Some(expected)
            );
        }
        assert_eq!(
            parse_iso8601_ms("1970-01-01T00:00:00-01:30"),
            Some(5_400_000)
        );
        for bad in [
            "",
            "2026-10-16",
            "2026-13-01T00:00:00Z",
            "2026-10-16T12:34:56.Z",
            "2026-10-16T12:34:56",
            "2026-10-16T12:34:56+é:00",
            "2026-10-16T12:34:56+0é00",
            "2026-10-16T12:34:56+24:00",
            "2026-10-16T12:34:56+00:60",
            "2026-10-16T12:34:56+-1:00",
            "2026-10-16T12:34:56.éZ",
        ] {
            assert_eq!(parse_iso8601_ms(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn exchange_sends_app_headers_and_no_cookie_or_origin() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tauri/token"))
            .and(header("x-device-id", "device-1"))
            .and(header("user-agent", "TestApp/1.0"))
            .and(header("accept-encoding", "identity"))
            .and(body_json(json!({
                "client_id": "app", "code": "c", "state": "s", "code_verifier": "v"
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-auth-token", "signed.token")
                    .set_body_json(
                        json!({ "token": "raw", "user": { "id": "u1" }, "protocol": 1 }),
                    ),
            )
            .mount(&server)
            .await;

        let exchanged = api(&server).exchange("app", "c", "s", "v").await.unwrap();
        assert_eq!(exchanged.token, "signed.token");

        let requests = server.received_requests().await.unwrap();
        let headers = &requests[0].headers;
        assert!(headers.get("cookie").is_none());
        assert!(headers.get("origin").is_none());
        assert!(headers.get("authorization").is_none());
    }

    #[tokio::test]
    async fn exchange_falls_back_to_the_body_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": "raw", "user": {} })),
            )
            .mount(&server)
            .await;
        assert_eq!(
            api(&server)
                .exchange("a", "b", "c", "d")
                .await
                .unwrap()
                .token,
            "raw"
        );
    }

    #[tokio::test]
    async fn exchange_maps_server_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "code": "DEVICE_LIMIT_REACHED", "message": "Too many devices"
            })))
            .mount(&server)
            .await;
        let error = api(&server)
            .exchange("a", "b", "c", "d")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "DEVICE_LIMIT_REACHED");
        assert_eq!(error.to_string(), "Too many devices");
    }

    #[tokio::test]
    async fn never_follows_redirects() {
        let server = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tauri/token"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/steal", elsewhere.uri())),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": "x", "user": {} })),
            )
            .mount(&elsewhere)
            .await;

        let error = api(&server)
            .exchange("a", "b", "c", "d")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "SERVER_ERROR");
        assert!(elsewhere.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn times_out() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        assert!(matches!(
            api(&server).get_session("t").await,
            SessionCheck::Unreachable(_)
        ));
    }

    #[tokio::test]
    async fn classifies_session_checks() {
        let session = json!({
            "session": { "id": "s1", "token": "raw", "expiresAt": "2026-10-16T12:34:56.789Z" },
            "user": { "id": "u1" }
        });
        for (status, body, expect_valid, expect_revoked) in [
            (200, session.clone(), true, false),
            (200, Value::Null, false, true),
            (401, json!({}), false, true),
            (403, json!({}), false, true),
            (500, json!({}), false, false),
            (429, json!({}), false, false),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/auth/get-session"))
                .and(header("authorization", "Bearer tok"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            let check = api(&server).get_session("tok").await;
            match check {
                SessionCheck::Valid(data) => {
                    assert!(expect_valid, "{status}");
                    assert_eq!(data.session_id, "s1");
                    assert_eq!(data.expires_at, Some(1_792_154_096_789));
                    assert!(data.session.get("token").is_none());
                }
                SessionCheck::Revoked => assert!(expect_revoked, "{status}"),
                SessionCheck::Unreachable(_) => {
                    assert!(!expect_valid && !expect_revoked, "{status}")
                }
            }
        }
    }

    #[tokio::test]
    async fn rejects_compressed_bodies() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(vec![0x1f, 0x8b]),
            )
            .mount(&server)
            .await;
        assert_eq!(
            api(&server)
                .exchange("a", "b", "c", "d")
                .await
                .err()
                .unwrap()
                .code(),
            "BRIDGE_UNPARSEABLE"
        );
    }

    #[tokio::test]
    async fn sign_out_sends_the_bearer_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/sign-out"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "success": true })))
            .mount(&server)
            .await;
        api(&server).sign_out("tok").await.unwrap();
    }
}
