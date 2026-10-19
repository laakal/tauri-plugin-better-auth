//! Values crossing the IPC boundary. None of them carries a token.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Transport;

/// The signed-in user and session as the webview sees them: the session
/// object never contains `token`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionSnapshot {
    /// Better Auth user object.
    pub user: Value,
    /// Better Auth session object without `token`.
    pub session: Value,
    /// True when the server could not be reached and this is the cached copy.
    pub offline: bool,
}

/// Why the user is no longer signed in.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SignOutReason {
    /// The user signed out.
    User,
    /// The server no longer accepts the session.
    Revoked,
    /// The session expired.
    Expired,
}

/// Payload of `better-auth://authenticated`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthenticatedPayload {
    /// The signed-in user.
    pub user: Value,
}

/// Payload of `better-auth://signed-out`.
#[derive(Debug, Clone, Serialize)]
pub struct SignedOutPayload {
    /// Why.
    pub reason: SignOutReason,
}

/// Options of `request_auth`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAuthOptions {
    /// Social provider the hand-off page should start, if it allows it.
    pub provider: Option<String>,
    /// Overrides the configured transport for this sign-in.
    pub transport: Option<Transport>,
}

/// Result of `request_auth`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAuthResult {
    /// The sign-in URL. Show it when the browser could not be opened.
    pub url: String,
    /// Whether the system browser was opened.
    pub opened: bool,
    /// The transport chosen for this sign-in.
    pub transport: Transport,
}

/// Removes `token` from a Better Auth session object.
pub(crate) fn tokenless(mut session: Value) -> Value {
    if let Value::Object(map) = &mut session {
        map.remove("token");
    }
    session
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tokenless_drops_only_the_token() {
        let session = tokenless(json!({ "id": "s1", "token": "secret", "userId": "u1" }));
        assert_eq!(session, json!({ "id": "s1", "userId": "u1" }));
    }

    #[test]
    fn request_options_accept_camel_case() {
        let options: RequestAuthOptions =
            serde_json::from_value(json!({ "provider": "github", "transport": "loopback" }))
                .unwrap();
        assert_eq!(options.provider.as_deref(), Some("github"));
        assert_eq!(options.transport, Some(Transport::Loopback));
    }
}
