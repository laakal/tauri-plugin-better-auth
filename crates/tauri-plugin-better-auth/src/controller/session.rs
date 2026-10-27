//! Controller session operations.

use super::*;

impl Controller {
    /// The shared sign-in commit for exchanges and bridged in-app sign-ins.
    pub async fn sign_in(&self, token: String, generation: u64) -> Result<SessionSnapshot> {
        // 1. Verify outside the lock. A host hook may have deleted the session
        //    after creating it; never store a dead token.
        let data = match self.http.get_session(&token).await {
            SessionCheck::Valid(data) => data,
            SessionCheck::Revoked => return Err(Error::SessionRejected),
            SessionCheck::Unreachable(reason) => {
                self.revoke_best_effort(&token).await;
                return Err(Error::Network(reason));
            }
        };

        // 2. Commit inside the lock.
        let mut inner = self.inner.lock().await;
        self.ensure_loaded(&mut inner).await;
        if inner.generation != generation {
            drop(inner);
            self.revoke_best_effort(&token).await;
            return Err(Error::Superseded);
        }
        let rev = inner.last_rev + 1;
        let secret = StoredSecret {
            rev,
            token: token.clone(),
            session_id: data.session_id.clone(),
            expires_at: data.expires_at,
        };
        {
            let store = self.store.clone();
            let secret = secret.clone();
            if let Err(error) = blocking(move || store.save(&secret)).await {
                // The old session stays untouched and usable.
                drop(inner);
                self.revoke_best_effort(&token).await;
                return Err(error.into());
            }
        }
        inner.last_rev = rev;
        self.save_profile(&StoredProfile {
            rev,
            session_id: data.session_id.clone(),
            user: data.user.clone(),
            session: data.session.clone(),
            tombstone: false,
        })
        .await;
        let previous = inner.current.replace(Current {
            secret,
            user: data.user.clone(),
            session: data.session.clone(),
        });
        inner.generation += 1;
        inner.pending = None;
        self.events.authenticated(&data.user);
        let snapshot = SessionSnapshot {
            user: data.user,
            session: data.session,
            offline: false,
        };
        drop(inner);

        // 3. Only now revoke the session it replaced.
        if let Some(previous) = previous
            && previous.secret.session_id != data.session_id
        {
            self.revoke_best_effort(&previous.secret.token).await;
        }
        Ok(snapshot)
    }

    pub(super) async fn save_profile(&self, profile: &StoredProfile) {
        let profiles = self.profiles.clone();
        let profile = profile.clone();
        if let Err(error) = blocking(move || profiles.save(&profile)).await {
            // Not fatal: a stale profile is ignored by revision and refreshed online.
            log::warn!("[better-auth] could not write the profile: {error}");
        }
    }

    pub(super) async fn revoke_best_effort(&self, token: &str) {
        let _ = tokio::time::timeout(BEST_EFFORT_TIMEOUT, self.http.sign_out(token)).await;
    }

    /// Clears the session (if it is still `expected`), emits `signed-out`.
    /// Returns the cleared token and any storage error.
    pub(super) async fn clear(
        &self,
        expected_session_id: Option<&str>,
        reason: SignOutReason,
    ) -> (Option<String>, Option<Error>) {
        let mut inner = self.inner.lock().await;
        self.ensure_loaded(&mut inner).await;
        if let Some(expected) = expected_session_id
            && inner.current.as_ref().map(|c| c.secret.session_id.as_str()) != Some(expected)
        {
            return (None, None);
        }
        inner.generation += 1;
        inner.pending = None;
        let Some(previous) = inner.current.take() else {
            if reason == SignOutReason::User {
                self.events.signed_out(reason);
            }
            return (None, None);
        };
        let rev = inner.last_rev + 1;
        inner.last_rev = rev;

        let store = self.store.clone();
        let delete_error = blocking(move || store.clear()).await.err();
        // The tombstone forbids rehydrating a secret the store failed to delete,
        // and removes the user's data from disk.
        let profiles = self.profiles.clone();
        let tombstone = StoredProfile {
            rev,
            session_id: previous.secret.session_id.clone(),
            user: Value::Null,
            session: Value::Null,
            tombstone: true,
        };
        let tombstone_error = blocking(move || profiles.save(&tombstone)).await.err();
        self.events.signed_out(reason);

        let error = match (delete_error, tombstone_error) {
            (Some(error), _) => {
                log::warn!("[better-auth] could not delete the stored session: {error}");
                Some(Error::from(error))
            }
            (None, Some(error)) => {
                log::warn!("[better-auth] could not write the sign-out tombstone: {error}");
                None
            }
            (None, None) => None,
        };
        (Some(previous.secret.token), error)
    }

    /// Signs out: local state is always cleared; the server session is revoked
    /// best-effort. A storage failure is reported after the local sign-out.
    pub async fn sign_out(&self) -> Result<()> {
        let (token, error) = self.clear(None, SignOutReason::User).await;
        if let Some(token) = token {
            self.revoke_best_effort(&token).await;
        }
        match error {
            Some(error) => {
                self.events.error(&error);
                Err(error)
            }
            None => Ok(()),
        }
    }

    /// The current session. `cached_only` skips the network check.
    pub async fn session(&self, cached_only: bool) -> Result<Option<SessionSnapshot>> {
        let (current, generation) = {
            let mut inner = self.inner.lock().await;
            self.ensure_loaded(&mut inner).await;
            (inner.current.clone(), inner.generation)
        };
        let Some(current) = current else {
            return Ok(None);
        };
        if current
            .secret
            .expires_at
            .is_some_and(|expires| expires <= now_ms())
        {
            self.clear(Some(&current.secret.session_id), SignOutReason::Expired)
                .await;
            return Ok(None);
        }
        let has_profile = !current.user.is_null();
        if cached_only && has_profile {
            return Ok(Some(current.snapshot(false)));
        }
        match self.http.get_session(&current.secret.token).await {
            SessionCheck::Valid(data) => Ok(Some(self.refresh(&current, generation, data).await)),
            SessionCheck::Revoked => {
                self.clear(Some(&current.secret.session_id), SignOutReason::Revoked)
                    .await;
                Ok(None)
            }
            SessionCheck::Unreachable(reason) => {
                log::debug!("[better-auth] session check offline: {reason}");
                if has_profile {
                    Ok(Some(current.snapshot(true)))
                } else {
                    // A credential without a profile: we cannot show a user yet.
                    Ok(None)
                }
            }
        }
    }

    /// Applies a fresh `get-session` result if nothing changed meanwhile.
    pub(super) async fn refresh(
        &self,
        seen: &Current,
        generation: u64,
        data: SessionData,
    ) -> SessionSnapshot {
        let snapshot = SessionSnapshot {
            user: data.user.clone(),
            session: data.session.clone(),
            offline: false,
        };
        let mut inner = self.inner.lock().await;
        let unchanged = inner.generation == generation
            && inner.current.as_ref().is_some_and(|c| {
                c.secret.session_id == seen.secret.session_id
                    && c.secret.session_id == data.session_id
            });
        if !unchanged {
            return snapshot;
        }
        let Some(current) = inner.current.as_mut() else {
            return snapshot;
        };
        let rev = current.secret.rev;
        let expiry_moved = match (current.secret.expires_at, data.expires_at) {
            (Some(old), Some(new)) => (new - old).abs() > 3_600_000,
            (None, Some(_)) => true,
            _ => false,
        };
        current.user = data.user.clone();
        current.session = data.session.clone();
        if expiry_moved {
            current.secret.expires_at = data.expires_at;
            let store = self.store.clone();
            let secret = current.secret.clone();
            if let Err(error) = blocking(move || store.save(&secret)).await {
                log::warn!("[better-auth] could not update the stored expiry: {error}");
            }
        }
        self.save_profile(&StoredProfile {
            rev,
            session_id: data.session_id,
            user: data.user,
            session: data.session,
            tombstone: false,
        })
        .await;
        snapshot
    }

    /// The bearer token for host Rust code. Never exposed to the webview.
    pub async fn bearer_token(&self) -> Option<String> {
        let mut inner = self.inner.lock().await;
        self.ensure_loaded(&mut inner).await;
        inner
            .current
            .as_ref()
            .map(|current| current.secret.token.clone())
    }
}
