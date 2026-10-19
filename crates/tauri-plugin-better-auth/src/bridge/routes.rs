//! Which bridged requests are allowed, and as what.

use url::Url;

use crate::{
    config::{Config, RouteKind},
    Error, Result,
};

/// A classified bridged request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Route {
    /// A Better Auth route from the allowlist.
    Auth { kind: RouteKind, path: String },
    /// An app API route on a configured origin and prefix.
    Api,
}

/// Classifies `method url`. Unknown auth routes and everything off the
/// configured origins are refused.
pub(crate) fn classify(config: &Config, method: &str, url: &Url) -> Result<Route> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::ForbiddenUrl(url.scheme().to_owned()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::ForbiddenUrl("credentials in URL".into()));
    }
    let path = url.path();
    if path
        .split('/')
        .any(|segment| segment == ".." || segment == ".")
    {
        return Err(Error::ForbiddenUrl(path.to_owned()));
    }

    let auth_origin = config.base_url.origin();
    let auth_base = config.auth_base_path();
    if url.origin() == auth_origin
        && (path == auth_base || path.starts_with(&format!("{auth_base}/")))
    {
        let relative = &path[auth_base.len()..];
        let method = method.to_ascii_uppercase();
        return config
            .auth_routes
            .iter()
            .find(|(m, p, _)| *m == method && p == relative)
            .map(|(_, _, kind)| Route::Auth {
                kind: *kind,
                path: relative.to_owned(),
            })
            .ok_or_else(|| Error::UnsupportedAuthOperation(format!("{method} {relative}")));
    }

    let allowed = config.api_routes.iter().any(|route| {
        url.origin() == route.origin
            && route
                .prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix.as_str()))
    });
    if allowed {
        Ok(Route::Api)
    } else {
        Err(Error::ForbiddenUrl(format!(
            "{}{}",
            url.origin().ascii_serialization(),
            path
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthRouteKind, ExtraAuthRoute, RawConfig};

    fn config() -> Config {
        RawConfig {
            base_url: Some("https://api.example.com/api/auth".into()),
            sign_in_url: Some("https://example.com/desktop".into()),
            scheme: Some("com.example.app".into()),
            api_routes: vec![("https://api.example.com".into(), vec!["/api/".into()])],
            auth_routes: vec![ExtraAuthRoute {
                method: "POST".into(),
                path: "/change-password".into(),
                kind: AuthRouteKind::SignIn,
            }],
            ..RawConfig::default()
        }
        .validate()
        .unwrap()
    }

    fn classify_str(method: &str, url: &str) -> Result<Route> {
        classify(&config(), method, &Url::parse(url).unwrap())
    }

    #[test]
    fn allowlisted_auth_routes() {
        assert_eq!(
            classify_str("GET", "https://api.example.com/api/auth/get-session").unwrap(),
            Route::Auth {
                kind: RouteKind::GetSession,
                path: "/get-session".into()
            }
        );
        assert_eq!(
            classify_str("post", "https://api.example.com/api/auth/sign-in/email-otp").unwrap(),
            Route::Auth {
                kind: RouteKind::SignIn,
                path: "/sign-in/email-otp".into()
            }
        );
        assert_eq!(
            classify_str("POST", "https://api.example.com/api/auth/change-password").unwrap(),
            Route::Auth {
                kind: RouteKind::SignIn,
                path: "/change-password".into()
            }
        );
    }

    #[test]
    fn denies_unknown_auth_routes_including_credential_minting_ones() {
        for (method, path) in [
            ("POST", "/tauri/token"),
            ("POST", "/tauri/authorize"),
            ("GET", "/one-time-token/generate"),
            ("GET", "/list-sessions"),
            ("POST", "/sign-in/social"),
            ("POST", "/oauth2/token"),
            ("GET", "/token"),
            ("POST", "/get-session"),
            ("GET", ""),
        ] {
            let url = format!("https://api.example.com/api/auth{path}");
            assert!(
                matches!(
                    classify_str(method, &url),
                    Err(Error::UnsupportedAuthOperation(_))
                ),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn api_routes_need_the_origin_and_a_prefix() {
        assert_eq!(
            classify_str("GET", "https://api.example.com/api/devices").unwrap(),
            Route::Api
        );
        for url in [
            "https://api.example.com/other",
            "https://evil.example/api/devices",
            "http://api.example.com/api/devices",
            "https://api.example.com:8443/api/devices",
            "https://user:pw@api.example.com/api/devices",
            "file:///etc/passwd",
        ] {
            assert!(classify_str("GET", url).is_err(), "{url}");
        }
    }

    #[test]
    fn auth_routes_take_precedence_over_api_prefixes() {
        // /api/ covers /api/auth/…, but auth paths are only reachable through
        // the allowlist.
        assert!(matches!(
            classify_str("GET", "https://api.example.com/api/auth/list-sessions"),
            Err(Error::UnsupportedAuthOperation(_))
        ));
    }
}
