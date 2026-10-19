//! PKCE (RFC 7636, S256 only) and random values.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// A PKCE verifier and its S256 challenge.
pub(crate) struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl std::fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkcePair")
            .field("verifier", &"[redacted]")
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// `bytes` random bytes from the OS CSPRNG, base64url without padding.
pub(crate) fn random_token(bytes: usize) -> Result<String> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|error| Error::Config(format!("the OS random source failed: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

/// A fresh PKCE pair: 32 random bytes → 43-character verifier.
pub(crate) fn generate_pkce() -> Result<PkcePair> {
    let verifier = random_token(32)?;
    let challenge = challenge_s256(&verifier);
    Ok(PkcePair {
        verifier,
        challenge,
    })
}

/// A fresh OAuth state: 24 random bytes → 32 characters.
pub(crate) fn generate_state() -> Result<String> {
    random_token(24)
}

/// `BASE64URL(SHA256(verifier))` without padding (RFC 7636 §4.2).
pub(crate) fn challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..])
}

/// Constant-time string comparison (length is not secret).
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_7636_appendix_b_vector() {
        assert_eq!(
            challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_values_have_the_protocol_shape() {
        let is_unreserved = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        for _ in 0..64 {
            let pair = generate_pkce().unwrap();
            assert_eq!(pair.verifier.len(), 43);
            assert!(pair.verifier.chars().all(is_unreserved));
            assert_eq!(pair.challenge.len(), 43);
            assert_eq!(pair.challenge, challenge_s256(&pair.verifier));

            let state = generate_state().unwrap();
            assert_eq!(state.len(), 32);
            assert!(state.chars().all(is_unreserved));
        }
    }

    #[test]
    fn values_are_unique() {
        let a = generate_state().unwrap();
        let b = generate_state().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_eq_compares_content_and_length() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn debug_redacts_the_verifier() {
        let pair = generate_pkce().unwrap();
        let debug = format!("{pair:?}");
        assert!(!debug.contains(&pair.verifier));
        assert!(debug.contains("[redacted]"));
    }
}
