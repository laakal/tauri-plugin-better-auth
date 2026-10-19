//! A one-shot HTTP listener on `127.0.0.1` (RFC 8252 §7.3).
//!
//! It answers only `GET <callback_path>?…` with a matching `Host` header, and
//! closes after the first callback the controller claims (or at the time
//! limit). Wrong states, wrong paths and stray requests get an error page and
//! leave it waiting, so another local process cannot shut it down.

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE, HOST},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, sync::Notify};

use crate::{
    callback::{parse_query, Callback, CallbackOutcome},
    Error, Result,
};

/// Claims a callback; `true` closes the listener.
pub(crate) type Claim =
    Arc<dyn Fn(Callback) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

/// A running listener. Dropping it stops the listener.
pub(crate) struct LoopbackServer {
    pub redirect_uri: String,
    stop: Arc<Notify>,
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.stop.notify_one();
    }
}

struct Shared {
    callback_path: String,
    host: String,
    app_name: String,
    claim: Claim,
    claimed: AtomicBool,
    done: Notify,
}

impl LoopbackServer {
    pub async fn start(
        callback_path: String,
        ttl: Duration,
        app_name: String,
        claim: Claim,
    ) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|error| {
            Error::Config(format!("could not start the loopback listener: {error}"))
        })?;
        let port = listener
            .local_addr()
            .map_err(|error| Error::Config(format!("loopback listener has no address: {error}")))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}{callback_path}");
        let shared = Arc::new(Shared {
            callback_path,
            host: format!("127.0.0.1:{port}"),
            app_name,
            claim,
            claimed: AtomicBool::new(false),
            done: Notify::new(),
        });
        let stop = Arc::new(Notify::new());

        let task_stop = stop.clone();
        tokio::spawn(async move {
            let deadline = tokio::time::sleep(ttl);
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    _ = task_stop.notified() => break,
                    _ = shared.done.notified() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            let service = service_fn(move |request| handle(request, shared.clone()));
                            let connection = http1::Builder::new()
                                .keep_alive(false)
                                .serve_connection(TokioIo::new(stream), service);
                            // Idle or slow connections (browser preconnects) must not linger.
                            let _ = tokio::time::timeout(Duration::from_secs(30), connection).await;
                        });
                    }
                }
            }
        });

        Ok(Self { redirect_uri, stop })
    }
}

async fn handle(
    request: Request<Incoming>,
    shared: Arc<Shared>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != Method::GET {
        return Ok(page(
            StatusCode::METHOD_NOT_ALLOWED,
            "Not allowed",
            "This address only accepts the sign-in redirect.",
        ));
    }
    let host_matches = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == shared.host);
    if !host_matches {
        return Ok(page(
            StatusCode::BAD_REQUEST,
            "Not allowed",
            "Unexpected host.",
        ));
    }
    if request.uri().path() != shared.callback_path {
        return Ok(page(StatusCode::NOT_FOUND, "Not found", "Nothing here."));
    }
    let query = request.uri().query().unwrap_or_default();
    let Some(callback) = parse_query(url::form_urlencoded::parse(query.as_bytes())) else {
        return Ok(page(
            StatusCode::BAD_REQUEST,
            "Invalid link",
            "This sign-in link is not valid. Start again from the app.",
        ));
    };
    if shared.claimed.load(Ordering::SeqCst) {
        return Ok(page(
            StatusCode::GONE,
            "Already used",
            "This sign-in link was already used.",
        ));
    }
    let denied = callback.outcome == CallbackOutcome::Denied;
    if !(shared.claim)(callback).await {
        return Ok(page(
            StatusCode::BAD_REQUEST,
            "Invalid link",
            "This sign-in link does not match the sign-in in progress. Start again from the app.",
        ));
    }
    shared.claimed.store(true, Ordering::SeqCst);
    shared.done.notify_one();
    let app = escape(&shared.app_name);
    Ok(if denied {
        page(
            StatusCode::OK,
            "Sign-in cancelled",
            &format!("You can close this tab and return to {app}."),
        )
    } else {
        page(
            StatusCode::OK,
            "Signed in",
            &format!("You can close this tab and return to {app}."),
        )
    })
}

fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

fn page(status: StatusCode, title: &str, message: &str) -> Response<Full<Bytes>> {
    let html = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>{title}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:20vh auto;padding:0 1rem;color:#222}}\
         @media (prefers-color-scheme:dark){{body{{background:#111;color:#eee}}}}</style>\
         <h1>{title}</h1><p>{message}</p></html>"
    );
    let mut response = Response::new(Full::new(Bytes::from(html)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const STATE: &str = "state-0123456789abcdef";
    const CODE: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

    async fn server(accept_state: &'static str) -> (LoopbackServer, Arc<Mutex<Vec<Callback>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let claim: Claim = Arc::new(move |callback: Callback| {
            let record = record.clone();
            Box::pin(async move {
                let ok = callback.state == accept_state;
                if ok {
                    record.lock().unwrap().push(callback);
                }
                ok
            })
        });
        let server = LoopbackServer::start(
            "/auth/callback".into(),
            Duration::from_secs(60),
            "Example <App>".into(),
            claim,
        )
        .await
        .unwrap();
        (server, seen)
    }

    fn client() -> reqwest::Client {
        // The crate builds reqwest without a default TLS provider: always
        // hand it the preconfigured rustls config.
        reqwest::Client::builder()
            .tls_backend_preconfigured(crate::tls::client_config().unwrap())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn keeps_waiting_through_bad_requests_then_closes_after_the_claim() {
        let (server, seen) = server(STATE).await;
        let base = server.redirect_uri.clone();
        assert!(base.starts_with("http://127.0.0.1:"));
        let http = client();

        // Wrong path, wrong state, malformed query, wrong method: all rejected.
        let root = base.replace("/auth/callback", "/");
        assert_eq!(http.get(&root).send().await.unwrap().status(), 404);
        let wrong_state = format!("{base}?code={CODE}&state=other-state-0123456789");
        assert_eq!(http.get(&wrong_state).send().await.unwrap().status(), 400);
        assert_eq!(
            http.get(format!("{base}?code=x"))
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(http.post(&base).send().await.unwrap().status(), 405);
        assert!(seen.lock().unwrap().is_empty());

        // The valid callback is claimed and answered…
        let good = format!("{base}?code={CODE}&state={STATE}");
        let response = http.get(&good).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(csp.contains("default-src 'none'"));
        let body = response.text().await.unwrap();
        assert!(body.contains("Example &lt;App&gt;"), "app name is escaped");
        assert_eq!(seen.lock().unwrap().len(), 1);

        // …and the listener closes.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(http.get(&good).send().await.is_err());
    }

    #[tokio::test]
    async fn rejects_a_foreign_host_header() {
        let (server, seen) = server(STATE).await;
        let response = client()
            .get(format!("{}?code={CODE}&state={STATE}", server.redirect_uri))
            .header("host", "evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stops_when_dropped() {
        let (server, _) = server(STATE).await;
        let url = format!("{}?code={CODE}&state={STATE}", server.redirect_uri);
        drop(server);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(client().get(&url).send().await.is_err());
    }
}
