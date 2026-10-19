//! Parsing of the values that hand a sign-in back to the app: deep links,
//! loopback query strings and pasted codes. Anything unexpected is rejected.

use url::Url;

use crate::{Error, Result};

/// What the browser reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallbackOutcome {
    /// An authorization code to exchange.
    Code(String),
    /// The user cancelled (`error=access_denied`).
    Denied,
}

/// A parsed callback. `state` has the protocol shape but is not yet matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Callback {
    pub state: String,
    pub outcome: CallbackOutcome,
}

/// A value pasted by the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pasted {
    /// A whole callback link (deep link or loopback URL).
    Callback(Callback),
    /// A bare 32-character code; the pending flow supplies the state.
    Code(String),
}

pub(crate) fn is_valid_code(code: &str) -> bool {
    code.len() == 32 && code.chars().all(|c| c.is_ascii_alphanumeric())
}

pub(crate) fn is_valid_state(state: &str) -> bool {
    (16..=128).contains(&state.len())
        && state
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
}

/// Parses `code`/`state`/`error` from a query string. Unknown parameters are
/// ignored (protocol v1 is additive); duplicates are rejected.
pub(crate) fn parse_query<'a>(
    pairs: impl Iterator<Item = (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)>,
) -> Option<Callback> {
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in pairs {
        let slot = match key.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
            _ => continue,
        };
        if slot.is_some() {
            return None;
        }
        *slot = Some(value.into_owned());
    }
    let state = state.filter(|s| is_valid_state(s))?;
    let outcome = match (code, error) {
        (Some(code), None) if is_valid_code(&code) => CallbackOutcome::Code(code),
        (None, Some(error)) if error == "access_denied" => CallbackOutcome::Denied,
        _ => return None,
    };
    Some(Callback { state, outcome })
}

/// Parses `<scheme>://auth/callback?…`. Also accepts `<scheme>:/auth/callback`
/// and `<scheme>:///auth/callback`, which some platforms produce.
pub(crate) fn parse_deep_link(url: &Url, scheme: &str, callback_path: &str) -> Option<Callback> {
    if url.scheme() != scheme {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return None;
    }
    if url.fragment().is_some() {
        return None;
    }
    let path = match url.host_str() {
        Some(host) if !host.is_empty() => format!("/{host}{}", url.path()),
        _ => url.path().to_owned(),
    };
    if path.trim_end_matches('/') != callback_path {
        return None;
    }
    parse_query(url.query_pairs())
}

/// Parses a pasted value: a callback link (deep link or loopback) or a bare
/// code. Whitespace around the value is ignored.
pub(crate) fn parse_pasted(input: &str, scheme: &str, callback_path: &str) -> Result<Pasted> {
    let input = input.trim();
    if is_valid_code(input) {
        return Ok(Pasted::Code(input.to_owned()));
    }
    let url = Url::parse(input).map_err(|_| Error::InvalidCode)?;
    if url.scheme() == scheme {
        return parse_deep_link(&url, scheme, callback_path)
            .map(Pasted::Callback)
            .ok_or(Error::InvalidCallback);
    }
    let is_loopback = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1") | Some("[::1]"))
        && url.path() == callback_path
        && url.fragment().is_none();
    if is_loopback {
        return parse_query(url.query_pairs())
            .map(Pasted::Callback)
            .ok_or(Error::InvalidCallback);
    }
    Err(Error::InvalidCode)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEME: &str = "com.example.app";
    const PATH: &str = "/auth/callback";
    const CODE: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";
    const STATE: &str = "state-0123456789abcdef";

    fn deep(url: &str) -> Option<Callback> {
        parse_deep_link(&Url::parse(url).unwrap(), SCHEME, PATH)
    }

    #[test]
    fn parses_a_code_callback_in_every_spelling() {
        for url in [
            format!("{SCHEME}://auth/callback?code={CODE}&state={STATE}"),
            format!("{SCHEME}:/auth/callback?code={CODE}&state={STATE}"),
            format!("{SCHEME}:///auth/callback?code={CODE}&state={STATE}"),
            format!("{SCHEME}://auth/callback/?code={CODE}&state={STATE}"),
            format!("{SCHEME}://auth/callback?state={STATE}&code={CODE}&extra=ignored"),
        ] {
            assert_eq!(
                deep(&url),
                Some(Callback {
                    state: STATE.into(),
                    outcome: CallbackOutcome::Code(CODE.into())
                }),
                "{url}"
            );
        }
    }

    #[test]
    fn parses_a_cancel_callback() {
        assert_eq!(
            deep(&format!(
                "{SCHEME}://auth/callback?error=access_denied&state={STATE}"
            )),
            Some(Callback {
                state: STATE.into(),
                outcome: CallbackOutcome::Denied
            })
        );
    }

    #[test]
    fn rejects_everything_else() {
        for url in [
            format!("other.app://auth/callback?code={CODE}&state={STATE}"),
            format!("{SCHEME}://auth/other?code={CODE}&state={STATE}"),
            format!("{SCHEME}://auth/callback/x?code={CODE}&state={STATE}"),
            format!("{SCHEME}://user@auth/callback?code={CODE}&state={STATE}"),
            format!("{SCHEME}://auth:99/callback?code={CODE}&state={STATE}"),
            format!("{SCHEME}://auth/callback?code={CODE}&state={STATE}#frag"),
            format!("{SCHEME}://auth/callback?code={CODE}"),
            format!("{SCHEME}://auth/callback?state={STATE}"),
            format!("{SCHEME}://auth/callback?code=short&state={STATE}"),
            format!("{SCHEME}://auth/callback?code={CODE}&state=short"),
            format!("{SCHEME}://auth/callback?code={CODE}&code={CODE}&state={STATE}"),
            format!("{SCHEME}://auth/callback?code={CODE}&state={STATE}&state={STATE}"),
            format!("{SCHEME}://auth/callback?code={CODE}&error=access_denied&state={STATE}"),
            format!("{SCHEME}://auth/callback?error=server_error&state={STATE}"),
        ] {
            assert_eq!(deep(&url), None, "{url}");
        }
    }

    #[test]
    fn parses_pasted_codes_and_links() {
        assert_eq!(
            parse_pasted(&format!("  {CODE}\n"), SCHEME, PATH).unwrap(),
            Pasted::Code(CODE.into())
        );
        assert!(matches!(
            parse_pasted(
                &format!("{SCHEME}://auth/callback?code={CODE}&state={STATE}"),
                SCHEME,
                PATH
            ),
            Ok(Pasted::Callback(_))
        ));
        assert!(matches!(
            parse_pasted(
                &format!("http://127.0.0.1:50000/auth/callback?code={CODE}&state={STATE}"),
                SCHEME,
                PATH
            ),
            Ok(Pasted::Callback(_))
        ));
        assert!(matches!(
            parse_pasted("https://evil.example/auth/callback?code=x", SCHEME, PATH),
            Err(Error::InvalidCode)
        ));
        assert!(matches!(
            parse_pasted("hello", SCHEME, PATH),
            Err(Error::InvalidCode)
        ));
        assert!(matches!(
            parse_pasted(
                &format!("{SCHEME}://auth/callback?code=bad&state={STATE}"),
                SCHEME,
                PATH
            ),
            Err(Error::InvalidCallback)
        ));
    }
}
