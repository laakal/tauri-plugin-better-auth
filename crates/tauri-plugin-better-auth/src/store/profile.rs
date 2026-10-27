//! The non-secret half of a session: a JSON file written atomically.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::StoreError;

/// User and tokenless session, at the same revision as the secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StoredProfile {
    pub rev: u64,
    pub session_id: String,
    pub user: Value,
    pub session: Value,
    /// Set on sign-out: forbids rehydrating a secret at or below `rev`.
    pub tombstone: bool,
}

/// Where the profile lives. A trait so tests can inject failures.
pub(crate) trait ProfileStore: Send + Sync + 'static {
    fn load(&self) -> Result<Option<StoredProfile>, StoreError>;
    fn save(&self, profile: &StoredProfile) -> Result<(), StoreError>;
}

/// `<dir>/<sha256(namespace)[..16]>.json`, written via a temporary file and a
/// rename so a crash never leaves a half-written profile.
#[derive(Debug)]
pub(crate) struct FileProfileStore {
    path: PathBuf,
}

impl FileProfileStore {
    pub fn new(dir: &Path, namespace: &str) -> Self {
        let digest = Sha256::digest(namespace.as_bytes());
        let mut name = String::with_capacity(32);
        for byte in digest.iter().take(16) {
            for nibble in [byte >> 4, byte & 0x0f] {
                name.push(char::from(if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + nibble - 10
                }));
            }
        }
        Self {
            path: dir.join(format!("{name}.json")),
        }
    }
}

impl ProfileStore for FileProfileStore {
    fn load(&self) -> Result<Option<StoredProfile>, StoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Failed(format!(
                "cannot read the profile: {error}"
            ))),
        }
    }

    fn save(&self, profile: &StoredProfile) -> Result<(), StoreError> {
        let failed = |error: std::io::Error| {
            StoreError::Failed(format!("cannot write the profile: {error}"))
        };
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(failed)?;
        }
        let json =
            serde_json::to_vec(profile).map_err(|error| StoreError::Failed(error.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut file = fs::File::create(&tmp).map_err(failed)?;
            file.write_all(&json).map_err(failed)?;
            file.sync_all().map_err(failed)?;
        }
        fs::rename(&tmp, &self.path).map_err(failed)
    }
}

/// In-memory profile store for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct MemoryProfileStore {
    pub profile: std::sync::Mutex<Option<StoredProfile>>,
}

#[cfg(test)]
impl ProfileStore for MemoryProfileStore {
    fn load(&self) -> Result<Option<StoredProfile>, StoreError> {
        Ok(self
            .profile
            .lock()
            .map_err(|_| StoreError::Failed("lock poisoned".into()))?
            .clone())
    }

    fn save(&self, profile: &StoredProfile) -> Result<(), StoreError> {
        *self
            .profile
            .lock()
            .map_err(|_| StoreError::Failed("lock poisoned".into()))? = Some(profile.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(rev: u64) -> StoredProfile {
        StoredProfile {
            rev,
            session_id: "s1".into(),
            user: json!({ "id": "u1", "email": "a@example.com" }),
            session: json!({ "id": "s1" }),
            tombstone: false,
        }
    }

    #[test]
    fn round_trips_through_a_file_without_leaving_temp_files() {
        let dir = std::env::temp_dir().join(format!("tpba-profile-{}", std::process::id()));
        let store = FileProfileStore::new(&dir, "better-auth:app@https://api.example.com");
        assert_eq!(store.load().unwrap(), None);
        store.save(&profile(1)).unwrap();
        store.save(&profile(2)).unwrap();
        assert_eq!(store.load().unwrap(), Some(profile(2)));
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn namespaces_get_distinct_files() {
        let dir = Path::new("/tmp/x");
        let a = FileProfileStore::new(dir, "better-auth:app@http://localhost:8080");
        let b = FileProfileStore::new(dir, "better-auth:app@https://api.example.com");
        assert_ne!(a.path, b.path);
    }

    #[test]
    fn a_corrupt_profile_reads_as_missing() {
        let dir = std::env::temp_dir().join(format!("tpba-corrupt-{}", std::process::id()));
        let store = FileProfileStore::new(&dir, "ns");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&store.path, b"{ not json").unwrap();
        assert_eq!(store.load().unwrap(), None);
        fs::remove_dir_all(dir).ok();
    }
}
