use super::{SessionStore, StoreError, StoredSecret};

/// Stores the secret in the OS credential store: macOS Keychain, Windows
/// Credential Manager, or the Secret Service (GNOME Keyring, KWallet) on Linux.
///
/// The plugin creates one by default with the app identifier as `service` and
/// `better-auth:{client_id}@{origin}` as `account`, so a development backend
/// and production never share a credential.
///
/// Unsigned macOS development builds may ask for keychain access after every
/// rebuild, because the keychain ties access to the binary's signature.
#[derive(Debug, Clone)]
pub struct KeyringStore {
    service: String,
    account: String,
}

impl KeyringStore {
    /// A store for one keychain item.
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(&self.service, &self.account).map_err(map_error)
    }
}

fn map_error(error: keyring::Error) -> StoreError {
    match error {
        keyring::Error::NoStorageAccess(inner) => {
            StoreError::Unavailable(format!("no access to the credential store: {inner}"))
        }
        keyring::Error::NoDefaultStore => {
            StoreError::Unavailable("no credential store is available on this system".into())
        }
        keyring::Error::PlatformFailure(inner) => {
            StoreError::Unavailable(format!("the credential store failed: {inner}"))
        }
        keyring::Error::TooLong(field, limit) => StoreError::Failed(format!(
            "{field} exceeds the credential store limit of {limit}"
        )),
        other => StoreError::Failed(other.to_string()),
    }
}

impl SessionStore for KeyringStore {
    fn load(&self) -> Result<Option<StoredSecret>, StoreError> {
        match self.entry()?.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|_| StoreError::Failed("the stored session is unreadable".into())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(map_error(error)),
        }
    }

    fn save(&self, secret: &StoredSecret) -> Result<(), StoreError> {
        let json =
            serde_json::to_string(secret).map_err(|error| StoreError::Failed(error.to_string()))?;
        self.entry()?.set_password(&json).map_err(map_error)
    }

    fn clear(&self) -> Result<(), StoreError> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real OS credential store, so it is opt-in:
    /// `cargo test -- --ignored keyring_round_trip`.
    #[test]
    #[ignore = "uses the real OS credential store"]
    fn keyring_round_trip() {
        let store = KeyringStore::new(
            "tauri-plugin-better-auth.test",
            format!("round-trip-{}", std::process::id()),
        );
        let secret = StoredSecret {
            rev: 3,
            token: "t".repeat(120),
            session_id: "s1".into(),
            expires_at: Some(1_700_000_000_000),
        };
        store.save(&secret).unwrap();
        assert_eq!(store.load().unwrap(), Some(secret));
        store.clear().unwrap();
        assert_eq!(store.load().unwrap(), None);
        store.clear().unwrap();
    }
}
