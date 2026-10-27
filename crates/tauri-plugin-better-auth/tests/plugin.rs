//! Wiring test on Tauri's MockRuntime: the plugin listens to the deep-link
//! plugin's event, exchanges the code and emits `better-auth://authenticated`.

mod common;

use std::{
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use serde_json::json;
use tauri::{
    test::{mock_builder, mock_context, noop_assets},
    Emitter, Listener,
};
use tauri_plugin_better_auth::{
    BetterAuthExt, Builder, MemoryStore, RequestAuthOptions, Transport,
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const CODE: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

#[test]
fn deep_link_events_drive_the_sign_in() {
    let server = tauri::async_runtime::block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tauri/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "token": "tok-1", "user": {}, "protocol": 1 })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/auth/get-session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "session": { "id": "s1", "token": "tok-1", "expiresAt": "2099-01-01T00:00:00.000Z" },
                "user": { "id": "u1", "email": "u1@example.com" }
            })))
            .mount(&server)
            .await;
        server
    });

    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let record = opened.clone();
    let profile_dir = std::env::temp_dir().join(format!("tpba-plugin-test-{}", std::process::id()));
    let app = mock_builder()
        .plugin(
            Builder::new()
                .base_url(format!("{}/api/auth", server.uri()))
                .sign_in_url("http://localhost:3000/desktop")
                .scheme("com.example.app")
                .client_id("app")
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
        .expect("the plugin sets up");

    let (tx, rx) = mpsc::channel::<String>();
    app.listen("better-auth://authenticated", move |event| {
        tx.send(event.payload().to_owned()).unwrap();
    });

    let handle = app.handle().clone();
    let result = tauri::async_runtime::block_on(
        handle
            .better_auth()
            .request_auth(RequestAuthOptions::default()),
    )
    .unwrap();
    assert!(result.opened);
    let state = common::query_value(&opened.lock().unwrap()[0], "state");

    // A forged state produces no event.
    app.emit(
        "deep-link://new-url",
        vec![format!(
            "com.example.app://auth/callback?code={CODE}&state=forged-state-0123456789"
        )],
    )
    .unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());

    // The real callback signs in.
    app.emit(
        "deep-link://new-url",
        vec![format!(
            "com.example.app://auth/callback?code={CODE}&state={state}"
        )],
    )
    .unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(&rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert_eq!(payload["user"]["id"], "u1");
    assert!(
        payload.to_string().find("tok-1").is_none(),
        "events never carry the token"
    );

    let token = tauri::async_runtime::block_on(handle.better_auth().bearer_token());
    assert_eq!(token.as_deref(), Some("tok-1"));
    std::fs::remove_dir_all(profile_dir).ok();
}

#[test]
fn invalid_configuration_fails_setup() {
    let result = mock_builder()
        .plugin(
            Builder::new()
                .base_url("http://api.example.com/api/auth")
                .sign_in_url("https://example.com/desktop")
                .scheme("com.example.app")
                .store(MemoryStore::new())
                .build(),
        )
        .build(mock_context(noop_assets()));
    let error = match result {
        Ok(_) => panic!("plain http to a remote host must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("https"), "{error}");
}
