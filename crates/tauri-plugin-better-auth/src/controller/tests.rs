//! Controller tests: wiremock plays the Better Auth server; stores can block
//! mid-write or fail on demand, so races and failures are deterministic.

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Mutex as StdMutex,
};

use serde_json::json;
use wiremock::{
    matchers::{body_partial_json, header, method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

use super::*;
use crate::{
    config::RawConfig,
    http::AppHeaders,
    store::{profile::MemoryProfileStore, MemoryStore},
};

const CODE: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";
const FAR_FUTURE: &str = "2099-01-01T00:00:00.000Z";

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    Authenticated(String),
    SignedOut(SignOutReason),
    Error(String),
    Focus,
}

#[derive(Default)]
struct Events(StdMutex<Vec<Ev>>);

impl Events {
    fn all(&self) -> Vec<Ev> {
        self.0.lock().unwrap().clone()
    }
}

impl EventSink for Events {
    fn authenticated(&self, user: &Value) {
        let id = user["id"].as_str().unwrap_or_default().to_owned();
        self.0.lock().unwrap().push(Ev::Authenticated(id));
    }
    fn signed_out(&self, reason: SignOutReason) {
        self.0.lock().unwrap().push(Ev::SignedOut(reason));
    }
    fn error(&self, error: &Error) {
        self.0
            .lock()
            .unwrap()
            .push(Ev::Error(error.code().to_owned()));
    }
    fn focus(&self) {
        self.0.lock().unwrap().push(Ev::Focus);
    }
}

#[derive(Default)]
struct Opener {
    opened: StdMutex<Vec<String>>,
    fail: AtomicBool,
}

impl BrowserOpener for Opener {
    fn open(&self, url: &str) -> std::io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("no browser"));
        }
        self.opened.lock().unwrap().push(url.to_owned());
        Ok(())
    }
}

/// A session store that can block inside `save` or fail on demand.
#[derive(Default)]
struct TestStore {
    inner: MemoryStore,
    fail_save: AtomicBool,
    fail_clear: AtomicBool,
    saves: AtomicUsize,
    gate: StdMutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl TestStore {
    /// The next `save` signals `entered` and waits for `release`.
    fn block_next_save(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *self.gate.lock().unwrap() = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    fn secret(&self) -> Option<StoredSecret> {
        self.inner.load().unwrap()
    }
}

impl SessionStore for TestStore {
    fn load(&self) -> std::result::Result<Option<StoredSecret>, StoreError> {
        self.inner.load()
    }
    fn save(&self, secret: &StoredSecret) -> std::result::Result<(), StoreError> {
        if let Some((entered, release)) = self.gate.lock().unwrap().take() {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
        self.saves.fetch_add(1, Ordering::SeqCst);
        if self.fail_save.load(Ordering::SeqCst) {
            return Err(StoreError::Failed("keychain access denied".into()));
        }
        self.inner.save(secret)
    }
    fn clear(&self) -> std::result::Result<(), StoreError> {
        if self.fail_clear.load(Ordering::SeqCst) {
            return Err(StoreError::Failed("cannot delete".into()));
        }
        self.inner.clear()
    }
}

#[derive(Default)]
struct TestProfiles {
    inner: MemoryProfileStore,
    fail_save: AtomicBool,
}

impl TestProfiles {
    fn profile(&self) -> Option<StoredProfile> {
        self.inner.load().unwrap()
    }
}

impl ProfileStore for TestProfiles {
    fn load(&self) -> std::result::Result<Option<StoredProfile>, StoreError> {
        self.inner.load()
    }
    fn save(&self, profile: &StoredProfile) -> std::result::Result<(), StoreError> {
        if self.fail_save.load(Ordering::SeqCst) {
            return Err(StoreError::Failed("disk full".into()));
        }
        self.inner.save(profile)
    }
}

struct Harness {
    server: MockServer,
    controller: Arc<Controller>,
    store: Arc<TestStore>,
    profiles: Arc<TestProfiles>,
    events: Arc<Events>,
    opener: Arc<Opener>,
}

impl Harness {
    async fn new() -> Self {
        let server = MockServer::start().await;
        Self::with(
            server,
            Arc::new(TestStore::default()),
            Arc::new(TestProfiles::default()),
            Duration::from_secs(600),
        )
    }

    fn with(
        server: MockServer,
        store: Arc<TestStore>,
        profiles: Arc<TestProfiles>,
        ttl: Duration,
    ) -> Self {
        let mut config = RawConfig {
            base_url: Some(format!("{}/api/auth", server.uri())),
            sign_in_url: Some("http://localhost:3000/desktop".into()),
            scheme: Some("com.example.app".into()),
            client_id: Some("app".into()),
            ..RawConfig::default()
        }
        .validate()
        .unwrap();
        config.pending_ttl = ttl;
        let headers: AppHeaders = Arc::new(reqwest::header::HeaderMap::new);
        let http = HttpApi::new(
            config.base_url.clone(),
            Duration::from_secs(2),
            "Test/1.0",
            headers,
        )
        .unwrap();
        let events = Arc::new(Events::default());
        let opener = Arc::new(Opener::default());
        let controller = Controller::new(ControllerParts {
            config: Arc::new(config),
            http,
            store: store.clone(),
            profiles: profiles.clone(),
            events: events.clone(),
            opener: opener.clone(),
            deep_links_deliverable: true,
            app_name: "Test".into(),
        });
        Self {
            server,
            controller,
            store,
            profiles,
            events,
            opener,
        }
    }

    /// A second controller over the same stores and server: an app relaunch.
    fn relaunch(self) -> Self {
        Self::with(
            self.server,
            self.store,
            self.profiles,
            Duration::from_secs(600),
        )
    }

    async fn start(&self) -> String {
        self.controller
            .request_auth(RequestAuthOptions::default())
            .await
            .unwrap();
        let url = self.opener.opened.lock().unwrap().last().cloned().unwrap();
        Url::parse(&url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap()
    }

    fn link(state: &str) -> String {
        format!("com.example.app://auth/callback?code={CODE}&state={state}")
    }

    async fn mock_token(&self, token: &str, times: u64) {
        Mock::given(method("POST"))
            .and(path("/api/auth/tauri/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": token, "user": { "id": "ignored" }, "protocol": 1
            })))
            .up_to_n_times(times)
            .mount(&self.server)
            .await;
    }

    async fn mock_session(&self, token: &str, session_id: &str, user_id: &str) {
        Mock::given(method("GET"))
            .and(path("/api/auth/get-session"))
            .and(header("authorization", format!("Bearer {token}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "session": { "id": session_id, "token": token, "expiresAt": FAR_FUTURE, "userId": user_id },
                "user": { "id": user_id, "email": format!("{user_id}@example.com") }
            })))
            .mount(&self.server)
            .await;
    }

    async fn mock_sign_out(&self) {
        Mock::given(method("POST"))
            .and(path("/api/auth/sign-out"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "success": true })))
            .mount(&self.server)
            .await;
    }

    async fn requests(&self, endpoint: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == format!("/api/auth{endpoint}"))
            .collect()
    }

    async fn revoked_tokens(&self) -> Vec<String> {
        self.requests("/sign-out")
            .await
            .iter()
            .filter_map(|r| r.headers.get("authorization"))
            .map(|v| v.to_str().unwrap().trim_start_matches("Bearer ").to_owned())
            .collect()
    }

    /// Signs in as `user` with `token` through a deep link.
    async fn sign_in(&self, token: &str, session_id: &str, user: &str) {
        self.mock_token(token, 1).await;
        self.mock_session(token, session_id, user).await;
        let state = self.start().await;
        self.controller.handle_deep_link(&Self::link(&state)).await;
    }
}

// ------------------------------------------------------------- request_auth

#[tokio::test]
async fn request_auth_builds_the_sign_in_url() {
    let h = Harness::new().await;
    let result = h
        .controller
        .request_auth(RequestAuthOptions {
            provider: Some("github".into()),
            transport: Some(Transport::DeepLink),
        })
        .await
        .unwrap();
    assert!(result.opened);
    assert_eq!(result.transport, Transport::DeepLink);
    let url = Url::parse(&result.url).unwrap();
    assert_eq!(url.path(), "/desktop");
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(q["client_id"], "app");
    assert_eq!(q["state"].len(), 32);
    assert_eq!(q["code_challenge"].len(), 43);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["v"], "1");
    assert_eq!(q["provider"], "github");
    assert!(!q.contains_key("redirect_uri"));
}

#[tokio::test]
async fn request_auth_rejects_bad_providers_and_survives_a_missing_browser() {
    let h = Harness::new().await;
    let bad = h
        .controller
        .request_auth(RequestAuthOptions {
            provider: Some("Git Hub".into()),
            transport: None,
        })
        .await;
    assert!(matches!(bad, Err(Error::InvalidRequest(_))));

    h.opener.fail.store(true, Ordering::SeqCst);
    let result = h
        .controller
        .request_auth(RequestAuthOptions::default())
        .await
        .unwrap();
    assert!(!result.opened, "the app can show the URL to copy");
}

#[tokio::test]
async fn loopback_transport_adds_a_loopback_redirect_uri() {
    let h = Harness::new().await;
    let result = h
        .controller
        .request_auth(RequestAuthOptions {
            provider: None,
            transport: Some(Transport::Loopback),
        })
        .await
        .unwrap();
    let url = Url::parse(&result.url).unwrap();
    let redirect = url
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    assert!(redirect.starts_with("http://127.0.0.1:"));
    assert!(redirect.ends_with("/auth/callback"));
}

// ------------------------------------------------------------- callbacks

#[tokio::test]
async fn a_deep_link_signs_in_and_persists_both_records() {
    let h = Harness::new().await;
    h.sign_in("tok-1", "s1", "u1").await;

    assert_eq!(
        h.events.all(),
        vec![Ev::Focus, Ev::Authenticated("u1".into())]
    );
    let secret = h.store.secret().unwrap();
    assert_eq!(
        (
            secret.rev,
            secret.token.as_str(),
            secret.session_id.as_str()
        ),
        (1, "tok-1", "s1")
    );
    let profile = h.profiles.profile().unwrap();
    assert_eq!((profile.rev, profile.tombstone), (1, false));
    assert!(
        profile.session.get("token").is_none(),
        "the profile never holds the token"
    );

    let snapshot = h.controller.session(true).await.unwrap().unwrap();
    assert_eq!(snapshot.user["id"], "u1");
    assert!(snapshot.session.get("token").is_none());

    // The exchange sent the PKCE verifier for the pending state.
    let exchange = &h.requests("/tauri/token").await[0];
    let body: Value = serde_json::from_slice(&exchange.body).unwrap();
    assert_eq!(body["client_id"], "app");
    assert_eq!(body["code"], CODE);
    assert_eq!(body["code_verifier"].as_str().unwrap().len(), 43);
}

#[tokio::test]
async fn a_mismatched_state_is_ignored_and_keeps_the_pending_flow() {
    let h = Harness::new().await;
    h.mock_token("tok-1", 1).await;
    h.mock_session("tok-1", "s1", "u1").await;
    let state = h.start().await;

    h.controller
        .handle_deep_link(&Harness::link("forged-state-0123456789"))
        .await;
    h.controller
        .handle_deep_link("com.example.app://somewhere/else")
        .await;
    assert!(
        h.events.all().is_empty(),
        "no event, no focus for foreign links"
    );
    assert!(h.requests("/tauri/token").await.is_empty());

    h.controller.handle_deep_link(&Harness::link(&state)).await;
    assert!(h.events.all().contains(&Ev::Authenticated("u1".into())));
}

#[tokio::test]
async fn a_duplicated_callback_exchanges_once() {
    let h = Harness::new().await;
    h.mock_token("tok-1", 1).await;
    h.mock_session("tok-1", "s1", "u1").await;
    let state = h.start().await;
    let link = Harness::link(&state);
    let (a, b) = (h.controller.clone(), h.controller.clone());
    let (link_a, link_b) = (link.clone(), link.clone());
    tokio::join!(
        async move { a.handle_deep_link(&link_a).await },
        async move { b.handle_deep_link(&link_b).await }
    );
    assert_eq!(h.requests("/tauri/token").await.len(), 1);
    assert!(matches!(
        h.controller.authenticate(CODE).await,
        Err(Error::NoPendingFlow)
    ));
}

#[tokio::test]
async fn a_pasted_code_uses_the_pending_state() {
    let h = Harness::new().await;
    h.mock_token("tok-1", 1).await;
    h.mock_session("tok-1", "s1", "u1").await;
    let state = h.start().await;
    let snapshot = h
        .controller
        .authenticate(&format!("  {CODE}  "))
        .await
        .unwrap();
    assert_eq!(snapshot.user["id"], "u1");
    let body: Value = serde_json::from_slice(&h.requests("/tauri/token").await[0].body).unwrap();
    assert_eq!(body["state"], state);
}

#[tokio::test]
async fn pasting_without_a_sign_in_or_garbage_fails_clearly() {
    let h = Harness::new().await;
    assert!(matches!(
        h.controller.authenticate(CODE).await,
        Err(Error::NoPendingFlow)
    ));
    h.start().await;
    assert!(matches!(
        h.controller.authenticate("hello").await,
        Err(Error::InvalidCode)
    ));
}

#[tokio::test]
async fn an_expired_flow_is_dropped() {
    let server = MockServer::start().await;
    let h = Harness::with(
        server,
        Default::default(),
        Default::default(),
        Duration::from_millis(30),
    );
    h.start().await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(matches!(
        h.controller.authenticate(CODE).await,
        Err(Error::FlowExpired)
    ));
    assert!(matches!(
        h.controller.authenticate(CODE).await,
        Err(Error::NoPendingFlow)
    ));
}

#[tokio::test]
async fn a_browser_cancel_reports_access_denied_without_an_exchange() {
    let h = Harness::new().await;
    let state = h.start().await;
    h.controller
        .handle_deep_link(&format!(
            "com.example.app://auth/callback?error=access_denied&state={state}"
        ))
        .await;
    assert_eq!(
        h.events.all(),
        vec![Ev::Focus, Ev::Error("ACCESS_DENIED".into())]
    );
    assert!(h.requests("/tauri/token").await.is_empty());
}

#[tokio::test]
async fn a_cancel_without_the_right_state_is_ignored() {
    let h = Harness::new().await;
    h.start().await;
    h.controller
        .handle_deep_link(
            "com.example.app://auth/callback?error=access_denied&state=forged-state-0123456789",
        )
        .await;
    assert!(h.events.all().is_empty());
}

// ------------------------------------------------------------- races

#[tokio::test]
async fn cancelling_during_the_exchange_saves_nothing() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/tauri/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({ "token": "tok-1", "user": {} })),
        )
        .mount(&h.server)
        .await;
    h.mock_session("tok-1", "s1", "u1").await;
    h.mock_sign_out().await;
    let state = h.start().await;

    let controller = h.controller.clone();
    let flow =
        tokio::spawn(async move { controller.handle_deep_link(&Harness::link(&state)).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    h.controller.cancel_auth().await;
    flow.await.unwrap();

    assert!(h.store.secret().is_none());
    assert!(!h
        .events
        .all()
        .iter()
        .any(|e| matches!(e, Ev::Authenticated(_))));
    assert_eq!(
        h.revoked_tokens().await,
        vec!["tok-1"],
        "the orphaned session is revoked"
    );
}

#[tokio::test]
async fn a_sign_out_during_verification_wins() {
    let h = Harness::new().await;
    h.mock_token("tok-1", 1).await;
    Mock::given(method("GET"))
        .and(path("/api/auth/get-session"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({ "session": { "id": "s1", "expiresAt": FAR_FUTURE }, "user": { "id": "u1" } })),
        )
        .mount(&h.server)
        .await;
    h.mock_sign_out().await;
    let state = h.start().await;

    let controller = h.controller.clone();
    let flow =
        tokio::spawn(async move { controller.handle_deep_link(&Harness::link(&state)).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    h.controller.sign_out().await.unwrap();
    flow.await.unwrap();

    assert!(
        h.store.secret().is_none(),
        "the superseded sign-in never reaches storage"
    );
    assert_eq!(h.controller.session(true).await.unwrap(), None);
}

#[tokio::test]
async fn a_sign_out_issued_during_the_secret_write_runs_after_it() {
    let h = Harness::new().await;
    h.mock_token("tok-1", 1).await;
    h.mock_session("tok-1", "s1", "u1").await;
    h.mock_sign_out().await;
    let state = h.start().await;
    let (entered, release) = h.store.block_next_save();

    let controller = h.controller.clone();
    let flow =
        tokio::spawn(async move { controller.handle_deep_link(&Harness::link(&state)).await });
    tokio::task::spawn_blocking(move || entered.recv().unwrap())
        .await
        .unwrap();

    // The commit holds the lock past its generation check; sign-out must wait.
    let controller = h.controller.clone();
    let sign_out = tokio::spawn(async move { controller.sign_out().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!sign_out.is_finished());

    release.send(()).unwrap();
    flow.await.unwrap();
    sign_out.await.unwrap().unwrap();

    // Linearized: sign-in committed, then sign-out cleared it.
    let events = h.events.all();
    let signed_in = events
        .iter()
        .position(|e| *e == Ev::Authenticated("u1".into()))
        .unwrap();
    let signed_out = events
        .iter()
        .position(|e| *e == Ev::SignedOut(SignOutReason::User))
        .unwrap();
    assert!(signed_in < signed_out);
    assert!(h.store.secret().is_none());
    assert!(h.profiles.profile().unwrap().tombstone);
}

#[tokio::test]
async fn a_cancel_issued_during_the_secret_write_cannot_undo_the_commit() {
    let h = Harness::new().await;
    h.mock_token("tok-1", 1).await;
    h.mock_session("tok-1", "s1", "u1").await;
    let state = h.start().await;
    let (entered, release) = h.store.block_next_save();

    let controller = h.controller.clone();
    let flow =
        tokio::spawn(async move { controller.handle_deep_link(&Harness::link(&state)).await });
    tokio::task::spawn_blocking(move || entered.recv().unwrap())
        .await
        .unwrap();
    let controller = h.controller.clone();
    let cancel = tokio::spawn(async move { controller.cancel_auth().await });
    release.send(()).unwrap();
    flow.await.unwrap();
    cancel.await.unwrap();

    // Memory, secret and profile agree.
    let secret = h.store.secret().unwrap();
    let profile = h.profiles.profile().unwrap();
    assert_eq!(secret.rev, profile.rev);
    assert_eq!(h.controller.bearer_token().await.as_deref(), Some("tok-1"));
}

// ------------------------------------------------------------- persistence

#[tokio::test]
async fn a_denied_keychain_write_keeps_the_old_session_and_revokes_the_new_one() {
    let h = Harness::new().await;
    h.mock_sign_out().await;
    h.sign_in("tok-a", "sa", "ua").await;

    h.store.fail_save.store(true, Ordering::SeqCst);
    h.mock_token("tok-b", 1).await;
    h.mock_session("tok-b", "sb", "ub").await;
    let state = h.start().await;
    let result = h.controller.authenticate(&Harness::link(&state)).await;
    assert!(matches!(result, Err(Error::Store(_))));

    assert_eq!(h.controller.bearer_token().await.as_deref(), Some("tok-a"));
    assert_eq!(h.store.secret().unwrap().token, "tok-a");
    assert_eq!(h.revoked_tokens().await, vec!["tok-b"]);
}

#[tokio::test]
async fn an_account_switch_revokes_the_old_session_only_after_storing_the_new_one() {
    let h = Harness::new().await;
    h.mock_sign_out().await;
    h.sign_in("tok-a", "sa", "ua").await;
    assert!(h.revoked_tokens().await.is_empty());
    h.sign_in("tok-b", "sb", "ub").await;

    assert_eq!(h.store.secret().unwrap().token, "tok-b");
    assert_eq!(h.revoked_tokens().await, vec!["tok-a"]);
    assert_eq!(h.store.secret().unwrap().rev, 2);
}

#[tokio::test]
async fn a_failed_profile_write_is_not_fatal_and_is_repaired_online() {
    let h = Harness::new().await;
    h.profiles.fail_save.store(true, Ordering::SeqCst);
    h.sign_in("tok-1", "s1", "u1").await;
    assert!(h.events.all().contains(&Ev::Authenticated("u1".into())));
    assert!(h.profiles.profile().is_none());

    h.profiles.fail_save.store(false, Ordering::SeqCst);
    let h = h.relaunch();
    // No matching profile: the credential is kept and the user fetched online.
    let snapshot = h.controller.session(true).await.unwrap().unwrap();
    assert_eq!(snapshot.user["id"], "u1");
    assert_eq!(
        h.profiles.profile().unwrap().rev,
        h.store.secret().unwrap().rev
    );
}

#[tokio::test]
async fn a_failed_secret_delete_leaves_a_tombstone_that_blocks_rehydration() {
    let h = Harness::new().await;
    h.mock_sign_out().await;
    h.sign_in("tok-1", "s1", "u1").await;
    h.store.fail_clear.store(true, Ordering::SeqCst);

    let result = h.controller.sign_out().await;
    assert!(matches!(result, Err(Error::Store(_))));
    assert!(h.events.all().contains(&Ev::SignedOut(SignOutReason::User)));
    assert!(h.store.secret().is_some(), "the stale secret survived");
    assert_eq!(
        h.revoked_tokens().await,
        vec!["tok-1"],
        "but it is dead on the server"
    );

    let h = h.relaunch();
    assert_eq!(h.controller.session(true).await.unwrap(), None);
    assert_eq!(h.controller.bearer_token().await, None);
}

#[tokio::test]
async fn hydration_requires_matching_revisions() {
    let h = Harness::new().await;
    h.mock_session("tok-2", "s2", "u2").await;
    h.store
        .save(&StoredSecret {
            rev: 2,
            token: "tok-2".into(),
            session_id: "s2".into(),
            expires_at: None,
        })
        .unwrap();
    h.profiles
        .save(&StoredProfile {
            rev: 1,
            session_id: "s1".into(),
            user: json!({ "id": "stale" }),
            session: json!({ "id": "s1" }),
            tombstone: false,
        })
        .unwrap();
    // The stale profile is ignored; the user comes from the server.
    let snapshot = h.controller.session(true).await.unwrap().unwrap();
    assert_eq!(snapshot.user["id"], "u2");
}

// ------------------------------------------------------------- session checks

#[tokio::test]
async fn a_revoked_session_signs_out_and_clears_storage() {
    let h = Harness::new().await;
    h.sign_in("tok-1", "s1", "u1").await;
    h.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/auth/get-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(Value::Null))
        .mount(&h.server)
        .await;

    assert_eq!(h.controller.session(false).await.unwrap(), None);
    assert!(h
        .events
        .all()
        .contains(&Ev::SignedOut(SignOutReason::Revoked)));
    assert!(h.store.secret().is_none());
}

#[tokio::test]
async fn an_unreachable_server_keeps_the_cached_session() {
    let h = Harness::new().await;
    h.sign_in("tok-1", "s1", "u1").await;
    h.server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&h.server)
        .await;

    let snapshot = h.controller.session(false).await.unwrap().unwrap();
    assert!(snapshot.offline);
    assert_eq!(snapshot.user["id"], "u1");
    assert!(h.store.secret().is_some());
    assert!(!h.events.all().iter().any(|e| matches!(e, Ev::SignedOut(_))));
}

#[tokio::test]
async fn a_locally_expired_session_signs_out_without_the_network() {
    let h = Harness::new().await;
    h.store
        .save(&StoredSecret {
            rev: 1,
            token: "tok-1".into(),
            session_id: "s1".into(),
            expires_at: Some(1_000),
        })
        .unwrap();
    h.profiles
        .save(&StoredProfile {
            rev: 1,
            session_id: "s1".into(),
            user: json!({ "id": "u1" }),
            session: json!({ "id": "s1" }),
            tombstone: false,
        })
        .unwrap();
    assert_eq!(h.controller.session(false).await.unwrap(), None);
    assert!(h
        .events
        .all()
        .contains(&Ev::SignedOut(SignOutReason::Expired)));
    assert!(h.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_session_rejected_by_host_hooks_is_never_stored() {
    let h = Harness::new().await;
    h.mock_token("tok-1", 1).await;
    Mock::given(method("GET"))
        .and(path("/api/auth/get-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(Value::Null))
        .mount(&h.server)
        .await;
    let state = h.start().await;
    let result = h.controller.authenticate(&Harness::link(&state)).await;
    assert!(matches!(result, Err(Error::SessionRejected)));
    assert!(h.store.secret().is_none());
}

#[tokio::test]
async fn exchange_errors_pass_through_server_codes() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/tauri/token"))
        .and(body_partial_json(json!({ "client_id": "app" })))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "code": "DEVICE_LIMIT_REACHED", "message": "Too many devices"
        })))
        .mount(&h.server)
        .await;
    let state = h.start().await;
    h.controller.handle_deep_link(&Harness::link(&state)).await;
    assert!(h
        .events
        .all()
        .contains(&Ev::Error("DEVICE_LIMIT_REACHED".into())));
}
