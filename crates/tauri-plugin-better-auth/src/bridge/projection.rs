//! What auth responses look like once they cross into the webview.
//!
//! Responses are rebuilt from known fields; passthrough bodies are scrubbed
//! of every credential-shaped key, at any depth.

use serde_json::{json, Map, Value};

use crate::models::SessionSnapshot;

/// Keys removed from passthrough auth responses, at any depth.
const CREDENTIAL_KEYS: &[&str] = &[
    "token",
    "accessToken",
    "access_token",
    "refreshToken",
    "refresh_token",
    "idToken",
    "id_token",
    "sessionToken",
    "session_token",
];

/// Removes credential keys recursively, and `url`/`redirect` at the top level
/// so a response can never ask the webview to navigate.
pub(crate) fn scrub(mut value: Value) -> Value {
    fn walk(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for key in CREDENTIAL_KEYS {
                    map.remove(*key);
                }
                for child in map.values_mut() {
                    walk(child);
                }
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    if let Value::Object(map) = &mut value {
        map.remove("url");
        map.remove("redirect");
    }
    value
}

/// `GET /get-session` as Better Auth's client expects it, minus the token.
pub(crate) fn session_body(snapshot: Option<&SessionSnapshot>) -> Value {
    match snapshot {
        Some(snapshot) => json!({ "session": snapshot.session, "user": snapshot.user }),
        None => Value::Null,
    }
}

/// A sign-in answer: no token, no redirect URL.
pub(crate) fn sign_in_body(user: &Value) -> Value {
    json!({ "redirect": false, "user": user })
}

/// `{ code, message }` error body, the shape Better Auth clients read.
pub(crate) fn error_body(code: &str, message: &str) -> Value {
    let mut map = Map::new();
    map.insert("code".into(), Value::String(code.into()));
    map.insert("message".into(), Value::String(message.into()));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_credentials_at_any_depth() {
        let scrubbed = scrub(json!({
            "token": "a",
            "url": "https://provider.example/authorize",
            "redirect": true,
            "user": { "id": "u1", "accessToken": "b" },
            "accounts": [{ "provider": "github", "refresh_token": "c", "id_token": "d" }],
            "nested": { "deeper": { "sessionToken": "e", "keep": 1 } },
            "status": true
        }));
        assert_eq!(
            scrubbed,
            json!({
                "user": { "id": "u1" },
                "accounts": [{ "provider": "github" }],
                "nested": { "deeper": { "keep": 1 } },
                "status": true
            })
        );
    }

    #[test]
    fn keeps_nested_url_fields() {
        // Only a top-level url/redirect pair drives Better Auth's redirect.
        assert_eq!(
            scrub(json!({ "user": { "image": "x", "url": "https://example.com/u" } })),
            json!({ "user": { "image": "x", "url": "https://example.com/u" } })
        );
    }

    #[test]
    fn builds_tokenless_bodies() {
        assert_eq!(
            sign_in_body(&json!({ "id": "u1" })),
            json!({ "redirect": false, "user": { "id": "u1" } })
        );
        assert_eq!(session_body(None), Value::Null);
        let snapshot = SessionSnapshot {
            user: json!({ "id": "u1" }),
            session: json!({ "id": "s1" }),
            offline: true,
        };
        assert_eq!(
            session_body(Some(&snapshot)),
            json!({ "session": { "id": "s1" }, "user": { "id": "u1" } })
        );
    }
}
