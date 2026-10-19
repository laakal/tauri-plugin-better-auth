//! Bridge contract tests. One wiremock server plays both Better Auth (under
//! `/api/auth`) and the app API (under `/api/`).

use std::time::Duration;

use serde_json::json;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

use super::*;
use crate::{
    config::RawConfig,
    controller::{BrowserOpener, ControllerParts, EventSink},
    http::{AppHeaders, HttpApi},
    models::SignOutReason,
    store::{profile::MemoryProfileStore, MemoryStore},
};

struct Quiet;
impl EventSink for Quiet {
    fn authenticated(&self, _: &Value) {}
    fn signed_out(&self, _: SignOutReason) {}
    fn error(&self, _: &Error) {}
    fn focus(&self) {}
}
impl BrowserOpener for Quiet {
    fn open(&self, _: &str) -> std::io::Result<()> {
        Ok(())
    }
}

struct Harness {
    server: MockServer,
    bridge: Arc<Bridge>,
    controller: Arc<Controller>,
}

fn build(uri: &str) -> (Arc<Bridge>, Arc<Controller>) {
    let config = RawConfig {
        base_url: Some(format!("{uri}/api/auth")),
        sign_in_url: Some("http://localhost:3000/desktop".into()),
        scheme: Some("com.example.app".into()),
        api_routes: vec![(uri.to_owned(), vec!["/api/".into()])],
        ..RawConfig::default()
    }
    .validate()
    .unwrap();
    let headers: AppHeaders = Arc::new(|| {
        let mut map = HeaderMap::new();
        map.insert("x-device-id", HeaderValue::from_static("device-from-rust"));
        map
    });
    let http = HttpApi::new(
        config.base_url.clone(),
        Duration::from_secs(2),
        "Test/1.0",
        headers,
    )
    .unwrap();
    let controller = Controller::new(ControllerParts {
        config: Arc::new(config),
        http,
        store: Arc::new(MemoryStore::new()),
        profiles: Arc::new(MemoryProfileStore::default()),
        events: Arc::new(Quiet),
        opener: Arc::new(Quiet),
        deep_links_deliverable: true,
        app_name: "Test".into(),
    });
    (Bridge::new(controller.clone()), controller)
}

impl Harness {
    async fn new() -> Self {
        let server = MockServer::start().await;
        let (bridge, controller) = build(&server.uri());
        Self {
            server,
            bridge,
            controller,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.uri())
    }

    async fn fetch(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<BridgeBody>,
    ) -> Result<BridgeResponse> {
        self.bridge
            .fetch(BridgeRequest {
                id: 1,
                url: self.url(path),
                method: method.into(),
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).into(), (*v).into()))
                    .collect(),
                body,
            })
            .await
    }

    async fn mock_session(&self, token: &str) {
        Mock::given(method("GET"))
            .and(path("/api/auth/get-session"))
            .and(header("authorization", format!("Bearer {token}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "session": { "id": "s1", "token": token, "expiresAt": "2099-01-01T00:00:00.000Z" },
                "user": { "id": "u1", "email": "u1@example.com" }
            })))
            .mount(&self.server)
            .await;
    }

    /// Signs in through the bridge with email OTP.
    async fn sign_in(&self) -> BridgeResponse {
        Mock::given(method("POST"))
            .and(path("/api/auth/sign-in/email-otp"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-auth-token", "tok-1")
                    .insert_header("set-cookie", "better-auth.session_token=tok-1; HttpOnly")
                    .set_body_json(json!({ "token": "raw-1", "user": { "id": "u1" } })),
            )
            .mount(&self.server)
            .await;
        self.mock_session("tok-1").await;
        self.fetch(
            "POST",
            "/api/auth/sign-in/email-otp",
            &[("content-type", "application/json")],
            Some(BridgeBody::Text(
                json!({ "email": "u1@example.com", "otp": "123456" }).to_string(),
            )),
        )
        .await
        .unwrap()
    }

    async fn requests(&self, endpoint: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == endpoint)
            .collect()
    }
}

fn body_json(response: &BridgeResponse) -> Value {
    match &response.body {
        Some(BridgeBody::Text(text)) => serde_json::from_str(text).unwrap(),
        other => panic!("expected a JSON body, got {other:?}"),
    }
}

fn has_header(response: &BridgeResponse, name: &str) -> bool {
    response
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case(name))
}

#[tokio::test]
async fn an_in_app_sign_in_lands_in_rust_and_returns_no_token() {
    let h = Harness::new().await;
    let response = h.sign_in().await;
    assert_eq!(response.status, 200);
    assert_eq!(
        body_json(&response),
        json!({ "redirect": false, "user": { "id": "u1", "email": "u1@example.com" } })
    );
    assert!(!has_header(&response, "set-auth-token"));
    assert!(!has_header(&response, "set-cookie"));
    assert_eq!(h.controller.bearer_token().await.as_deref(), Some("tok-1"));

    let sign_in = &h.requests("/api/auth/sign-in/email-otp").await[0];
    assert!(
        sign_in.headers.get("authorization").is_none(),
        "sign-in never carries a session"
    );
    assert_eq!(
        sign_in.headers.get("x-device-id").unwrap(),
        "device-from-rust"
    );
}

#[tokio::test]
async fn get_session_is_answered_by_the_controller_without_the_token() {
    let h = Harness::new().await;
    let empty = h
        .fetch("GET", "/api/auth/get-session", &[], None)
        .await
        .unwrap();
    assert_eq!(body_json(&empty), Value::Null);

    h.sign_in().await;
    let response = h
        .fetch("GET", "/api/auth/get-session", &[], None)
        .await
        .unwrap();
    let body = body_json(&response);
    assert_eq!(body["user"]["id"], "u1");
    assert!(body["session"].get("token").is_none());
}

#[tokio::test]
async fn sign_out_always_clears_locally_even_offline() {
    let h = Harness::new().await;
    h.sign_in().await;
    // No sign-out mock: the server call fails, the local sign-out does not.
    let response = h
        .fetch(
            "POST",
            "/api/auth/sign-out",
            &[],
            Some(BridgeBody::Text("{}".into())),
        )
        .await
        .unwrap();
    assert_eq!(body_json(&response), json!({ "success": true }));
    assert_eq!(h.controller.bearer_token().await, None);
}

#[tokio::test]
async fn unknown_and_credential_minting_auth_routes_are_refused_without_a_request() {
    let h = Harness::new().await;
    h.sign_in().await;
    for (method_name, route) in [
        ("GET", "/api/auth/one-time-token/generate"),
        ("GET", "/api/auth/list-sessions"),
        ("POST", "/api/auth/tauri/authorize"),
        ("POST", "/api/auth/tauri/token"),
        ("POST", "/api/auth/sign-in/social"),
        ("GET", "/api/auth/token"),
    ] {
        let response = h.fetch(method_name, route, &[], None).await.unwrap();
        assert_eq!(response.status, 403, "{route}");
        assert_eq!(
            body_json(&response)["code"],
            "UNSUPPORTED_AUTH_OPERATION",
            "{route}"
        );
        assert!(
            h.requests(route).await.is_empty(),
            "{route} reached the server"
        );
    }
}

#[tokio::test]
async fn other_urls_are_forbidden() {
    let h = Harness::new().await;
    for url in ["/other", "/apix/thing"] {
        let response = h.fetch("GET", url, &[], None).await.unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["code"], "FORBIDDEN_URL");
    }
    let foreign = h
        .bridge
        .fetch(BridgeRequest {
            id: 2,
            url: "https://evil.example/api/x".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
        })
        .await
        .unwrap();
    assert_eq!(foreign.status, 403);
}

#[tokio::test]
async fn api_calls_get_the_bearer_and_app_headers_but_not_the_pages_credentials() {
    let h = Harness::new().await;
    h.sign_in().await;
    Mock::given(method("GET"))
        .and(path("/api/devices"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "tracking=1")
                .insert_header("set-auth-token", "should-not-leak")
                .insert_header("x-request-id", "r1")
                .set_body_json(json!([{ "id": "device-from-rust" }])),
        )
        .mount(&h.server)
        .await;

    let response = h
        .fetch(
            "GET",
            "/api/devices",
            &[
                ("authorization", "Bearer forged"),
                ("cookie", "better-auth.session_token=forged"),
                ("origin", "https://evil.example"),
                ("x-device-id", "forged-device"),
                ("sec-fetch-site", "cross-site"),
                ("accept", "application/json"),
            ],
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(!has_header(&response, "set-cookie"));
    assert!(!has_header(&response, "set-auth-token"));
    assert!(has_header(&response, "x-request-id"));

    let sent = &h.requests("/api/devices").await[0];
    assert_eq!(sent.headers.get("authorization").unwrap(), "Bearer tok-1");
    assert_eq!(sent.headers.get("x-device-id").unwrap(), "device-from-rust");
    assert!(sent.headers.get("cookie").is_none());
    assert!(sent.headers.get("origin").is_none());
    assert!(sent.headers.get("sec-fetch-site").is_none());
}

#[tokio::test]
async fn passthrough_auth_responses_are_scrubbed() {
    let h = Harness::new().await;
    h.sign_in().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/update-user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": true, "token": "leak", "url": "https://x", "redirect": true,
            "user": { "id": "u1", "accessToken": "leak" }
        })))
        .mount(&h.server)
        .await;
    let response = h
        .fetch(
            "POST",
            "/api/auth/update-user",
            &[],
            Some(BridgeBody::Text("{\"name\":\"N\"}".into())),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(&response),
        json!({ "status": true, "user": { "id": "u1" } })
    );
    assert_eq!(
        h.requests("/api/auth/update-user").await[0]
            .headers
            .get("authorization")
            .unwrap(),
        "Bearer tok-1"
    );
}

#[tokio::test]
async fn a_sign_in_without_a_session_passes_through_scrubbed() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/sign-up/email"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "token": null, "user": { "id": "u2" } })),
        )
        .mount(&h.server)
        .await;
    let response = h
        .fetch(
            "POST",
            "/api/auth/sign-up/email",
            &[],
            Some(BridgeBody::Text("{}".into())),
        )
        .await
        .unwrap();
    assert_eq!(body_json(&response), json!({ "user": { "id": "u2" } }));
    assert_eq!(h.controller.bearer_token().await, None);
}

#[tokio::test]
async fn server_errors_pass_through() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/sign-in/email-otp"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({ "code": "INVALID_OTP", "message": "Invalid OTP" })),
        )
        .mount(&h.server)
        .await;
    let response = h
        .fetch(
            "POST",
            "/api/auth/sign-in/email-otp",
            &[],
            Some(BridgeBody::Text("{}".into())),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 400);
    assert_eq!(body_json(&response)["code"], "INVALID_OTP");
}

#[tokio::test]
async fn unreadable_auth_responses_fail_closed() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/email-otp/send-verification-otp"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html>proxy error</html>")
                .insert_header("content-type", "text/html"),
        )
        .mount(&h.server)
        .await;
    let response = h
        .fetch(
            "POST",
            "/api/auth/email-otp/send-verification-otp",
            &[],
            Some(BridgeBody::Text("{}".into())),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 502);
    assert_eq!(body_json(&response)["code"], "BRIDGE_UNPARSEABLE");

    h.server.reset().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .insert_header("content-type", "application/json")
                .set_body_bytes(vec![0x1f, 0x8b, 0, 0]),
        )
        .mount(&h.server)
        .await;
    let response = h
        .fetch(
            "POST",
            "/api/auth/email-otp/send-verification-otp",
            &[],
            Some(BridgeBody::Text("{}".into())),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 502);
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let h = Harness::new().await;
    let big = "x".repeat(MAX_REQUEST_BODY + 1);
    let response = h
        .fetch("POST", "/api/upload", &[], Some(BridgeBody::Text(big)))
        .await
        .unwrap();
    assert_eq!(response.status, 400);
    assert_eq!(body_json(&response)["code"], "INVALID_REQUEST");

    Mock::given(method("POST"))
        .and(path("/api/auth/update-user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "blob": "y".repeat(MAX_AUTH_RESPONSE) })),
        )
        .mount(&h.server)
        .await;
    let response = h
        .fetch("POST", "/api/auth/update-user", &[], None)
        .await
        .unwrap();
    assert_eq!(response.status, 502);
    assert_eq!(body_json(&response)["code"], "BRIDGE_RESPONSE_TOO_LARGE");
}

#[tokio::test]
async fn binary_bodies_round_trip_as_base64() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/api/avatar"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "image/png")
                .set_body_bytes(vec![0x89, b'P', b'N', b'G']),
        )
        .mount(&h.server)
        .await;
    let response = h
        .fetch(
            "POST",
            "/api/avatar",
            &[],
            Some(BridgeBody::Base64(STANDARD.encode([0u8, 1, 2, 255]))),
        )
        .await
        .unwrap();
    assert_eq!(
        response.body,
        Some(BridgeBody::Base64(
            STANDARD.encode([0x89, b'P', b'N', b'G'])
        ))
    );
    assert_eq!(
        h.requests("/api/avatar").await[0].body,
        vec![0u8, 1, 2, 255]
    );
}

#[tokio::test]
async fn empty_responses_have_no_body() {
    let h = Harness::new().await;
    Mock::given(method("DELETE"))
        .and(path("/api/thing"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&h.server)
        .await;
    let response = h.fetch("DELETE", "/api/thing", &[], None).await.unwrap();
    assert_eq!(response.status, 204);
    assert_eq!(response.body, None);
}

#[tokio::test]
async fn requests_can_be_aborted() {
    let h = Harness::new().await;
    Mock::given(method("GET"))
        .and(path("/api/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&h.server)
        .await;
    let bridge = h.bridge.clone();
    let url = h.url("/api/slow");
    let request = tokio::spawn(async move {
        bridge
            .fetch(BridgeRequest {
                id: 42,
                url,
                method: "GET".into(),
                headers: vec![],
                body: None,
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.bridge.cancel(42);
    assert!(matches!(request.await.unwrap(), Err(Error::Aborted)));
}

#[tokio::test]
async fn network_failures_reject_like_fetch() {
    // A port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let uri = format!("http://127.0.0.1:{port}");
    let (bridge, _) = build(&uri);
    let result = bridge
        .fetch(BridgeRequest {
            id: 3,
            url: format!("{uri}/api/devices"),
            method: "GET".into(),
            headers: vec![],
            body: None,
        })
        .await;
    assert!(matches!(result, Err(Error::Network(_))));
}

#[tokio::test]
async fn disallowed_methods_are_refused() {
    let h = Harness::new().await;
    let response = h.fetch("TRACE", "/api/devices", &[], None).await.unwrap();
    assert_eq!(response.status, 400);
}
