//! Configuration: builder input, validated at startup.
//!
//! Every value comes from Rust. Nothing the webview sends can change where the
//! plugin talks to: a compromised page must not be able to point the code
//! exchange at another server.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::{Host, Origin, Url};

use crate::{Error, Result};

/// How the browser hands the sign-in result back to the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// Deep link when the OS can deliver it to this process, otherwise
    /// loopback: deep link for an installed macOS bundle and for release
    /// builds on Windows and Linux; loopback for `tauri dev`.
    #[default]
    Auto,
    /// The custom URI scheme (`<scheme>://auth/callback`).
    DeepLink,
    /// A one-shot HTTP listener on `127.0.0.1` (RFC 8252 §7.3).
    Loopback,
}

/// How the auth bridge treats an extra Better Auth route reached from the
/// webview (see [`crate::Builder::auth_route`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRouteKind {
    /// Forwarded with the bearer token; the JSON response is returned with
    /// credential fields scrubbed.
    Passthrough,
    /// A sign-in: a returned session token is captured into the Rust session
    /// and the webview only receives `{ redirect: false, user }`.
    SignIn,
}

/// What the bridge does for an auth route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteKind {
    GetSession,
    SignOut,
    Passthrough,
    SignIn,
}

/// The default auth bridge contract (see the README table).
pub(crate) const DEFAULT_AUTH_ROUTES: &[(&str, &str, RouteKind)] = &[
    ("GET", "/get-session", RouteKind::GetSession),
    ("POST", "/sign-out", RouteKind::SignOut),
    (
        "POST",
        "/email-otp/send-verification-otp",
        RouteKind::Passthrough,
    ),
    ("POST", "/sign-in/email-otp", RouteKind::SignIn),
    ("POST", "/sign-in/email", RouteKind::SignIn),
    ("POST", "/sign-up/email", RouteKind::SignIn),
    ("POST", "/email-otp/verify-email", RouteKind::SignIn),
    ("POST", "/update-user", RouteKind::Passthrough),
];

/// An app API reachable through the bridge.
#[derive(Debug, Clone)]
pub(crate) struct ApiRoute {
    pub origin: Origin,
    pub prefixes: Vec<String>,
}

/// An auth route added with [`crate::Builder::auth_route`].
#[derive(Debug, Clone)]
pub(crate) struct ExtraAuthRoute {
    pub method: String,
    pub path: String,
    pub kind: AuthRouteKind,
}

/// Builder input before validation.
#[derive(Debug, Clone, Default)]
pub(crate) struct RawConfig {
    pub base_url: Option<String>,
    pub sign_in_url: Option<String>,
    pub scheme: Option<String>,
    pub callback_path: Option<String>,
    pub client_id: Option<String>,
    pub api_routes: Vec<(String, Vec<String>)>,
    pub auth_routes: Vec<ExtraAuthRoute>,
    pub transport: Transport,
    pub pending_ttl: Option<Duration>,
    pub timeout: Option<Duration>,
    pub main_window: Option<String>,
}

/// Validated configuration.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// Better Auth base URL, without a trailing slash (e.g. `…/api/auth`).
    pub base_url: Url,
    pub sign_in_url: Url,
    pub scheme: String,
    pub callback_path: String,
    pub client_id: String,
    pub api_routes: Vec<ApiRoute>,
    pub auth_routes: Vec<(String, String, RouteKind)>,
    pub transport: Transport,
    pub pending_ttl: Duration,
    pub timeout: Duration,
    pub main_window: String,
}

impl Config {
    /// `base_url` path, e.g. `/api/auth`.
    pub fn auth_base_path(&self) -> &str {
        self.base_url.path().trim_end_matches('/')
    }

    /// Absolute URL of an auth endpoint (`path` starts with `/`).
    #[cfg(test)]
    pub fn auth_endpoint(&self, path: &str) -> Url {
        let mut url = self.base_url.clone();
        url.set_path(&format!("{}{}", self.auth_base_path(), path));
        url
    }

    /// The keychain account / profile namespace for this backend and client.
    pub fn namespace(&self) -> String {
        format!(
            "better-auth:{}@{}",
            self.client_id,
            self.base_url.origin().ascii_serialization()
        )
    }
}

impl RawConfig {
    pub fn validate(self) -> Result<Config> {
        let base_url = parse_http_url(
            "base_url",
            self.base_url.as_deref().ok_or_else(|| {
                missing(
                    "base_url",
                    "the Better Auth base URL, e.g. https://api.example.com/api/auth",
                )
            })?,
            false,
        )?;
        let base_url = {
            let mut url = base_url;
            let trimmed = url.path().trim_end_matches('/').to_owned();
            url.set_path(&trimmed);
            url
        };
        let sign_in_url = parse_http_url(
            "sign_in_url",
            self.sign_in_url.as_deref().ok_or_else(|| {
                missing(
                    "sign_in_url",
                    "the hand-off page, e.g. https://example.com/desktop",
                )
            })?,
            true,
        )?;
        let scheme = validate_scheme(self.scheme.as_deref().ok_or_else(|| {
            missing(
                "scheme",
                "the app's custom URI scheme, e.g. com.example.app",
            )
        })?)?;
        let callback_path =
            normalize_callback_path(self.callback_path.as_deref().unwrap_or("/auth/callback"))?;
        let client_id = validate_client_id(self.client_id.as_deref().unwrap_or("tauri"))?;

        let api_routes = validate_api_routes(self.api_routes)?;
        let auth_routes = validate_auth_routes(self.auth_routes)?;

        let pending_ttl = self.pending_ttl.unwrap_or(Duration::from_secs(600));
        if pending_ttl < Duration::from_secs(60) || pending_ttl > Duration::from_secs(3600) {
            return Err(Error::Config(
                "pending_ttl must be between 1 and 60 minutes".into(),
            ));
        }
        let timeout = self.timeout.unwrap_or(Duration::from_secs(15));
        if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(120) {
            return Err(Error::Config(
                "timeout must be between 1 and 120 seconds".into(),
            ));
        }

        Ok(Config {
            base_url,
            sign_in_url,
            scheme,
            callback_path,
            client_id,
            api_routes,
            auth_routes,
            transport: self.transport,
            pending_ttl,
            timeout,
            main_window: self.main_window.unwrap_or_else(|| "main".into()),
        })
    }
}

fn validate_api_routes(routes: Vec<(String, Vec<String>)>) -> Result<Vec<ApiRoute>> {
    let mut api_routes = Vec::with_capacity(routes.len());
    for (origin, prefixes) in routes {
        let url = parse_http_url("api_routes origin", &origin, false)?;
        if url.path() != "/" {
            return Err(Error::Config(format!(
                "api_routes origin \"{origin}\" must be a bare origin such as https://api.example.com"
            )));
        }
        for prefix in &prefixes {
            if !prefix.starts_with('/') || prefix.contains("..") {
                return Err(Error::Config(format!(
                    "api_routes prefix \"{prefix}\" must start with \"/\""
                )));
            }
        }
        api_routes.push(ApiRoute {
            origin: url.origin(),
            prefixes,
        });
    }

    Ok(api_routes)
}

fn validate_auth_routes(routes: Vec<ExtraAuthRoute>) -> Result<Vec<(String, String, RouteKind)>> {
    let mut auth_routes: Vec<(String, String, RouteKind)> = DEFAULT_AUTH_ROUTES
        .iter()
        .map(|(method, path, kind)| ((*method).to_owned(), (*path).to_owned(), *kind))
        .collect();
    for extra in routes {
        let method = extra.method.to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
            return Err(Error::Config(format!(
                "auth_route method \"{}\" is not supported",
                extra.method
            )));
        }
        if !extra.path.starts_with('/') || extra.path.contains("..") {
            return Err(Error::Config(format!(
                "auth_route path \"{}\" must start with \"/\"",
                extra.path
            )));
        }
        if extra.path == "/tauri" || extra.path.starts_with("/tauri/") {
            return Err(Error::Config(
                "the /tauri/* endpoints can never be exposed to the webview".into(),
            ));
        }
        if auth_routes
            .iter()
            .any(|(m, p, _)| *m == method && *p == extra.path)
        {
            continue;
        }
        let kind = match extra.kind {
            AuthRouteKind::Passthrough => RouteKind::Passthrough,
            AuthRouteKind::SignIn => RouteKind::SignIn,
        };
        auth_routes.push((method, extra.path, kind));
    }

    Ok(auth_routes)
}

fn missing(field: &str, hint: &str) -> Error {
    Error::Config(format!("`{field}` is required: {hint}"))
}

/// True for `localhost`, `127.0.0.0/8` and `::1`.
pub(crate) fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// An `https` URL, or `http` on a loopback host. No credentials or fragment;
/// a query only when `allow_query`.
pub(crate) fn parse_http_url(field: &str, value: &str, allow_query: bool) -> Result<Url> {
    let url = Url::parse(value)
        .map_err(|error| Error::Config(format!("`{field}` \"{value}\" is not a URL: {error}")))?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(&url) => {}
        "http" => {
            return Err(Error::Config(format!(
                "`{field}` must use https (plain http is only allowed for localhost): {value}"
            )));
        }
        _ => {
            return Err(Error::Config(format!(
                "`{field}` must be an http(s) URL: {value}"
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Config(format!(
            "`{field}` must not contain credentials"
        )));
    }
    if url.fragment().is_some() {
        return Err(Error::Config(format!(
            "`{field}` must not contain a #fragment"
        )));
    }
    if !allow_query && url.query().is_some() {
        return Err(Error::Config(format!(
            "`{field}` must not contain a ?query"
        )));
    }
    Ok(url)
}

const RESERVED_SCHEMES: &[&str] = &[
    "about",
    "asset",
    "blob",
    "data",
    "file",
    "ftp",
    "http",
    "https",
    "ipc",
    "javascript",
    "mailto",
    "tauri",
    "ws",
    "wss",
];

/// Lowercase custom scheme, `[a-z][a-z0-9+.-]{1,62}`, not a web/Tauri scheme.
pub(crate) fn validate_scheme(scheme: &str) -> Result<String> {
    let mut chars = scheme.chars();
    let valid = scheme.len() >= 2
        && scheme.len() <= 63
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
        && !RESERVED_SCHEMES.contains(&scheme);
    if valid {
        Ok(scheme.to_owned())
    } else {
        Err(Error::Config(format!(
            "invalid callback scheme \"{scheme}\": use a lowercase custom scheme such as \"com.example.app\" (RFC 8252 §7.1)"
        )))
    }
}

/// `/segment(/segment)*` of `[A-Za-z0-9_-]`, at most 64 characters.
pub(crate) fn normalize_callback_path(path: &str) -> Result<String> {
    let normalized = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let valid = normalized.len() <= 64
        && normalized.len() > 1
        && normalized
            .strip_prefix('/')
            .unwrap_or("")
            .split('/')
            .all(|segment| {
                !segment.is_empty()
                    && segment
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            });
    if valid {
        Ok(normalized)
    } else {
        Err(Error::Config(format!(
            "invalid callback path \"{path}\": use segments of letters, digits, \"_\" and \"-\", like \"/auth/callback\""
        )))
    }
}

/// `[A-Za-z0-9._-]{1,64}`.
pub(crate) fn validate_client_id(client_id: &str) -> Result<String> {
    let valid = !client_id.is_empty()
        && client_id.len() <= 64
        && client_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(client_id.to_owned())
    } else {
        Err(Error::Config(format!(
            "invalid client id \"{client_id}\": use 1–64 characters of letters, digits, \".\", \"_\" and \"-\""
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> RawConfig {
        RawConfig {
            base_url: Some("https://api.example.com/api/auth/".into()),
            sign_in_url: Some("https://example.com/desktop".into()),
            scheme: Some("com.example.app".into()),
            ..RawConfig::default()
        }
    }

    #[test]
    fn validates_and_normalizes_a_minimal_config() {
        let config = raw().validate().unwrap();
        assert_eq!(config.base_url.as_str(), "https://api.example.com/api/auth");
        assert_eq!(config.auth_base_path(), "/api/auth");
        assert_eq!(
            config.auth_endpoint("/tauri/token").as_str(),
            "https://api.example.com/api/auth/tauri/token"
        );
        assert_eq!(config.callback_path, "/auth/callback");
        assert_eq!(config.client_id, "tauri");
        assert_eq!(
            config.namespace(),
            "better-auth:tauri@https://api.example.com"
        );
        assert_eq!(config.main_window, "main");
    }

    #[test]
    fn requires_the_three_urls_and_scheme() {
        for clear in [
            |r: &mut RawConfig| r.base_url = None,
            |r: &mut RawConfig| r.sign_in_url = None,
            |r: &mut RawConfig| r.scheme = None,
        ] {
            let mut config = raw();
            clear(&mut config);
            assert!(matches!(config.validate(), Err(Error::Config(_))));
        }
    }

    #[test]
    fn requires_https_outside_loopback() {
        let mut config = raw();
        config.base_url = Some("http://api.example.com/api/auth".into());
        assert!(config.validate().is_err());

        for local in [
            "http://localhost:8080/api/auth",
            "http://127.0.0.1:8080/api/auth",
            "http://[::1]:8080/api/auth",
        ] {
            let mut config = raw();
            config.base_url = Some(local.into());
            assert!(config.validate().is_ok(), "{local}");
        }
    }

    #[test]
    fn rejects_credentials_fragments_and_base_queries() {
        for bad in [
            "https://user:pw@api.example.com/api/auth",
            "https://api.example.com/api/auth#x",
            "https://api.example.com/api/auth?x=1",
            "ftp://api.example.com/api/auth",
        ] {
            let mut config = raw();
            config.base_url = Some(bad.into());
            assert!(config.validate().is_err(), "{bad}");
        }
        let mut config = raw();
        config.sign_in_url = Some("https://example.com/desktop?lang=en".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn scheme_rules() {
        for good in ["com.example.app", "linequery", "my-app", "app+x"] {
            assert!(validate_scheme(good).is_ok(), "{good}");
        }
        for bad in [
            "https", "tauri", "file", "Com.App", "1app", "a", "my app", "app/x",
        ] {
            assert!(validate_scheme(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn callback_path_rules() {
        assert_eq!(
            normalize_callback_path("auth/callback").unwrap(),
            "/auth/callback"
        );
        for bad in ["/", "//", "/a//b", "/a/", "/a?b", "/a b", "/a.b"] {
            assert!(normalize_callback_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_id_rules() {
        assert!(validate_client_id("com.example.app").is_ok());
        assert!(validate_client_id("").is_err());
        assert!(validate_client_id("has space").is_err());
        assert!(validate_client_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn auth_routes_extend_the_defaults_but_never_expose_tauri_endpoints() {
        let mut config = raw();
        config.auth_routes.push(ExtraAuthRoute {
            method: "post".into(),
            path: "/change-password".into(),
            kind: AuthRouteKind::SignIn,
        });
        let config = config.validate().unwrap();
        assert!(
            config
                .auth_routes
                .iter()
                .any(|(m, p, k)| m == "POST" && p == "/change-password" && *k == RouteKind::SignIn)
        );

        let mut config = raw();
        config.auth_routes.push(ExtraAuthRoute {
            method: "POST".into(),
            path: "/tauri/token".into(),
            kind: AuthRouteKind::Passthrough,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn api_routes_need_bare_origins_and_absolute_prefixes() {
        let mut config = raw();
        config
            .api_routes
            .push(("https://api.example.com".into(), vec!["/api/".into()]));
        assert!(config.validate().is_ok());

        let mut config = raw();
        config
            .api_routes
            .push(("https://api.example.com/api".into(), vec!["/api/".into()]));
        assert!(config.validate().is_err());

        let mut config = raw();
        config
            .api_routes
            .push(("https://api.example.com".into(), vec!["api/".into()]));
        assert!(config.validate().is_err());
    }

    #[test]
    fn bounds_ttl_and_timeout() {
        let mut config = raw();
        config.pending_ttl = Some(Duration::from_secs(10));
        assert!(config.validate().is_err());
        let mut config = raw();
        config.timeout = Some(Duration::from_secs(600));
        assert!(config.validate().is_err());
    }
}
