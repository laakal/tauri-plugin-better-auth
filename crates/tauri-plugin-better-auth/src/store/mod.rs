//! Session persistence.
//!
//! Two records, written separately:
//! - the **secret** (`StoredSecret`): token, session id and expiry, in a
//!   [`SessionStore`] (the OS keychain by default). Small on purpose: Windows
//!   Credential Manager caps a secret at 2560 bytes.
//! - the **profile** (non-secret user and tokenless session), in a JSON file
//!   under the app data directory.
//!
//! Both carry the same revision number. The profile is only trusted when its
//! revision matches the secret's, and a profile tombstone at an equal or
//! higher revision means "signed out" even if a stale secret survived a failed
//! deletion.

#[cfg(feature = "keyring")]
mod keyring_store;
mod memory;
pub(crate) mod profile;

use serde::{Deserialize, Serialize};

#[cfg(feature = "keyring")]
pub use keyring_store::KeyringStore;
pub use memory::MemoryStore;

/// The secret half of a session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSecret {
    /// Revision shared with the profile record.
    pub rev: u64,
    /// Bearer token (`set-auth-token` value, or the raw session token).
    pub token: String,
    /// Better Auth session id.
    pub session_id: String,
    /// Session expiry, epoch milliseconds, if known.
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for StoredSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSecret")
            .field("rev", &self.rev)
            .field("token", &"[redacted]")
            .field("session_id", &self.session_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The backing service is missing or refuses access (e.g. no Secret
    /// Service on Linux, keychain access denied).
    #[error("{0}")]
    Unavailable(String),
    /// Any other failure.
    #[error("{0}")]
    Failed(String),
}

/// Where the session secret lives. Implement it to use another vault (for
/// example Tauri Stronghold); [`KeyringStore`] and [`MemoryStore`] are
/// provided.
///
/// Methods are called on a blocking thread, so they may block.
pub trait SessionStore: Send + Sync + 'static {
    /// Reads the secret, `Ok(None)` when there is none.
    fn load(&self) -> Result<Option<StoredSecret>, StoreError>;
    /// Writes the secret, replacing any previous one.
    fn save(&self, secret: &StoredSecret) -> Result<(), StoreError>;
    /// Deletes the secret. Deleting a missing secret is not an error.
    fn clear(&self) -> Result<(), StoreError>;
}
