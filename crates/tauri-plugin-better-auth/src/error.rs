use serde::{Serialize, Serializer, ser::SerializeStruct};

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned to Rust callers and, serialized as `{ code, message }`, to
/// the webview. The `code` strings are stable within protocol v1; match on
/// them, never on messages. Messages never contain tokens or codes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A callback or pasted code arrived while no sign-in was in progress.
    #[error("No sign-in is in progress. Start again from the app.")]
    NoPendingFlow,
    /// The pending sign-in outlived its time limit.
    #[error("The sign-in request expired. Start again from the app.")]
    FlowExpired,
    /// The pasted value is neither an authorization code nor a callback link.
    #[error("That is not a valid sign-in code or link.")]
    InvalidCode,
    /// The callback link does not belong to this app.
    #[error("The callback link is not valid for this app.")]
    InvalidCallback,
    /// The user cancelled in the browser.
    #[error("The sign-in was cancelled in the browser.")]
    AccessDenied,
    /// A newer sign-in, a cancel or a sign-out happened while this one ran.
    #[error("The sign-in was cancelled or replaced by another one.")]
    Superseded,
    /// The system browser could not be opened.
    #[error("Could not open the browser: {0}")]
    OpenBrowser(String),
    /// The auth server could not be reached.
    #[error("Network error: {0}")]
    Network(String),
    /// The auth server answered with an error.
    #[error("{message}")]
    Server {
        /// HTTP status.
        status: u16,
        /// Better Auth error code, or `SERVER_ERROR`.
        code: String,
        /// Server message.
        message: String,
    },
    /// The new session was rejected, or deleted before it could be used.
    #[error("The server rejected the new session.")]
    SessionRejected,
    /// The session store failed.
    #[error("Session storage failed: {0}")]
    Store(String),
    /// The OS secure storage is not available (no keychain service).
    #[error("Secure storage is unavailable: {0}")]
    StoreUnavailable(String),
    /// The webview called an auth route outside the bridge allowlist.
    #[error("This auth operation is not available from the webview: {0}")]
    UnsupportedAuthOperation(String),
    /// The auth server sent a response the bridge cannot project safely.
    #[error("The auth server returned a response the bridge cannot read.")]
    BridgeUnparseable,
    /// The webview asked the bridge for a URL outside the allowed routes.
    #[error("Requests to this URL are not allowed: {0}")]
    ForbiddenUrl(String),
    /// A malformed request from the webview.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    /// The webview aborted a bridged request.
    #[error("The request was aborted.")]
    Aborted,
    /// Invalid plugin configuration (reported at startup).
    #[error("Invalid configuration: {0}")]
    Config(String),
}

impl Error {
    /// Stable machine-readable code.
    pub fn code(&self) -> &str {
        match self {
            Error::NoPendingFlow => "NO_PENDING_FLOW",
            Error::FlowExpired => "FLOW_EXPIRED",
            Error::InvalidCode => "INVALID_CODE",
            Error::InvalidCallback => "INVALID_CALLBACK",
            Error::AccessDenied => "ACCESS_DENIED",
            Error::Superseded => "SUPERSEDED",
            Error::OpenBrowser(_) => "OPEN_BROWSER_FAILED",
            Error::Network(_) => "NETWORK",
            Error::Server { code, .. } => code,
            Error::SessionRejected => "SESSION_REJECTED",
            Error::Store(_) => "STORE",
            Error::StoreUnavailable(_) => "STORE_UNAVAILABLE",
            Error::UnsupportedAuthOperation(_) => "UNSUPPORTED_AUTH_OPERATION",
            Error::BridgeUnparseable => "BRIDGE_UNPARSEABLE",
            Error::ForbiddenUrl(_) => "FORBIDDEN_URL",
            Error::InvalidRequest(_) => "INVALID_REQUEST",
            Error::Aborted => "ABORTED",
            Error::Config(_) => "CONFIG",
        }
    }
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Error", 2)?;
        state.serialize_field("code", self.code())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

impl From<crate::store::StoreError> for Error {
    fn from(error: crate::store::StoreError) -> Self {
        match error {
            crate::store::StoreError::Unavailable(message) => Error::StoreUnavailable(message),
            crate::store::StoreError::Failed(message) => Error::Store(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_code_and_message() {
        let json = serde_json::to_value(Error::NoPendingFlow).unwrap();
        assert_eq!(json["code"], "NO_PENDING_FLOW");
        assert!(json["message"].as_str().unwrap().contains("No sign-in"));
    }

    #[test]
    fn server_errors_keep_the_server_code() {
        let error = Error::Server {
            status: 403,
            code: "DEVICE_LIMIT_REACHED".into(),
            message: "Too many devices".into(),
        };
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(json["code"], "DEVICE_LIMIT_REACHED");
        assert_eq!(json["message"], "Too many devices");
    }
}
