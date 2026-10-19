use std::sync::Mutex;

use super::{SessionStore, StoreError, StoredSecret};

/// Keeps the secret in memory only: the user signs in again on every launch.
/// Useful in tests, in development, and for apps that opt out of persistence.
#[derive(Debug, Default)]
pub struct MemoryStore {
    secret: Mutex<Option<StoredSecret>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

fn poisoned() -> StoreError {
    StoreError::Failed("memory store lock poisoned".into())
}

impl SessionStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredSecret>, StoreError> {
        Ok(self.secret.lock().map_err(|_| poisoned())?.clone())
    }

    fn save(&self, secret: &StoredSecret) -> Result<(), StoreError> {
        *self.secret.lock().map_err(|_| poisoned())? = Some(secret.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), StoreError> {
        *self.secret.lock().map_err(|_| poisoned())? = None;
        Ok(())
    }
}
