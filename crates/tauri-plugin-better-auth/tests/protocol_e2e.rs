//! Protocol end-to-end test: the Rust plugin (on Tauri's MockRuntime) against
//! the real example server (`examples/basic/server`, Better Auth + the
//! `tauri()` server plugin from the npm package).
//!
//! Skipped unless `TPBA_E2E_URL` points at a running example server started
//! with `EXAMPLE_TEST_MODE=1`:
//!
//! ```sh
//! EXAMPLE_TEST_MODE=1 bun examples/basic/server/src/server.ts &
//! TPBA_E2E_URL=http://localhost:3000 cargo test --test protocol_e2e
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use serde_json::{Value, json};
use tauri::{
    Emitter, Listener,
    test::{mock_builder, mock_context, noop_assets},
};
use tauri_plugin_better_auth::{
    BetterAuthExt, Builder, MemoryStore, RequestAuthOptions, Transport,
};

const CLIENT_ID: &str = "com.example.betterauth";

fn query_value(url: &str, key: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

#[test]
fn protocol_round_trip_against_the_example_server() {
    let Ok(base) = std::env::var("TPBA_E2E_URL") else {
        eprintln!("skipped: set TPBA_E2E_URL to a running example server");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::new();
    let email = format!("e2e-{}@example.com", std::process::id());

    // 1. The "browser": signs in with an email code and keeps its cookies.
    let browser_cookie = browser_sign_in(&http, &base, &email);

    // 2. The app: the real plugin on MockRuntime.
    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let record = opened.clone();
    let profile_dir = std::env::temp_dir().join(format!("tpba-e2e-{}", std::process::id()));
    let app = mock_builder()
        .plugin(
            Builder::new()
                .base_url(format!("{base}/api/auth"))
                .sign_in_url(format!("{base}/desktop"))
                .scheme(CLIENT_ID)
                .client_id(CLIENT_ID)
                .api_routes(base.clone(), ["/api/"])
                .transport(Transport::DeepLink)
                .store(MemoryStore::new())
                .profile_dir(&profile_dir)
                .opener(move |url| {
                    record.lock().unwrap().push(url.to_owned());
                    Ok(())
                })
                .build(),
        )
        .build(mock_context(noop_assets()))
        .unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    app.listen("better-auth://authenticated", move |event| {
        tx.send(event.payload().to_owned()).unwrap();
    });
    let handle = app.handle().clone();
    tauri::async_runtime::block_on(
        handle
            .better_auth()
            .request_auth(RequestAuthOptions::default()),
    )
    .unwrap();
    let sign_in_url = opened.lock().unwrap()[0].clone();
    assert!(sign_in_url.starts_with(&format!("{base}/desktop?")));
    let state = query_value(&sign_in_url, "state");
    let challenge = query_value(&sign_in_url, "code_challenge");

    // 3. The hand-off page: authorizes the app's request for the signed-in user.
    let code = tauri::async_runtime::block_on(async {
        let response = http
            .post(format!("{base}/api/auth/tauri/authorize"))
            .header("cookie", &browser_cookie)
            .header("origin", &base)
            .json(&json!({
                "client_id": CLIENT_ID,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "authorize");
        let body: Value = response.json().await.unwrap();
        body["code"].as_str().unwrap().to_owned()
    });

    // 4. The browser opens the deep link; the plugin exchanges the code.
    app.emit(
        "deep-link://new-url",
        vec![format!(
            "{CLIENT_ID}://auth/callback?code={code}&state={state}"
        )],
    )
    .unwrap();
    let payload: Value =
        serde_json::from_str(&rx.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    assert_eq!(payload["user"]["email"], email);

    // 5. The stored session works against the protected API.
    let token = tauri::async_runtime::block_on(handle.better_auth().bearer_token()).unwrap();
    tauri::async_runtime::block_on(async {
        let me = http
            .get(format!("{base}/api/me"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(me.status(), 200);
        let body: Value = me.json().await.unwrap();
        assert_eq!(body["user"]["email"], email);
    });
    let snapshot = tauri::async_runtime::block_on(handle.better_auth().session(false))
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.user["email"], email);
    assert!(!snapshot.offline);
    assert!(snapshot.session.get("token").is_none());

    // 6. The code is single-use: a replay is refused by the server.
    tauri::async_runtime::block_on(async {
        let replay = http
            .post(format!("{base}/api/auth/tauri/token"))
            .json(&json!({ "client_id": CLIENT_ID, "code": code, "state": state, "code_verifier": "x".repeat(43) }))
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), 400);
    });

    // 7. Signing out kills the token on the server.
    tauri::async_runtime::block_on(handle.better_auth().sign_out()).unwrap();
    tauri::async_runtime::block_on(async {
        let me = http
            .get(format!("{base}/api/me"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(me.status(), 401);
    });
    std::fs::remove_dir_all(profile_dir).ok();
}

fn browser_sign_in(http: &reqwest::Client, base: &str, email: &str) -> String {
    tauri::async_runtime::block_on(async {
        let sent = http
            .post(format!("{base}/api/auth/email-otp/send-verification-otp"))
            .json(&json!({ "email": email, "type": "sign-in" }))
            .send()
            .await
            .unwrap();
        assert!(sent.status().is_success(), "send otp: {}", sent.status());
        let otp: Value = http
            .get(format!(
                "{base}/__test/otp?email={}",
                url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let otp = otp["otp"]
            .as_str()
            .expect("start the server with EXAMPLE_TEST_MODE=1");
        let signed_in = http
            .post(format!("{base}/api/auth/sign-in/email-otp"))
            .json(&json!({ "email": email, "otp": otp }))
            .send()
            .await
            .unwrap();
        assert!(signed_in.status().is_success());
        signed_in
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("; ")
    })
}
