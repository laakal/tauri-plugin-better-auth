//! TLS: rustls with the `ring` provider (no C toolchain needed) and the OS
//! certificate verifier, so corporate and user-installed roots behave like
//! they do in the browser. Android uses the bundled Mozilla roots instead.

use std::sync::Arc;

use crate::{Error, Result};

/// Makes `ring` the process default provider when the app has not chosen one.
///
/// This crate turns on reqwest's `rustls-no-provider` feature, and cargo
/// unifies it into every reqwest client of the app. On mobile, Tauri itself
/// builds one (it proxies the dev server through reqwest) and panics without
/// a default provider, so the app would not start under `tauri ios dev`.
#[cfg(mobile)]
pub(crate) fn install_default_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Fails only when another thread installed one first.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

pub(crate) fn client_config() -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::Config(format!("TLS setup failed: {error}")))?;
    let mut config = with_verifier(builder)?.with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

type Builder = rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>;
type VerifiedBuilder = rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>;

#[cfg(not(target_os = "android"))]
fn with_verifier(builder: Builder) -> Result<VerifiedBuilder> {
    use rustls_platform_verifier::BuilderVerifierExt;

    builder
        .with_platform_verifier()
        .map_err(|error| Error::Config(format!("TLS verifier setup failed: {error}")))
}

/// Android: the bundled Mozilla roots. The OS verifier needs a Kotlin
/// component added to the app's Gradle build, which a plugin cannot do for
/// the app; user-installed certificates are therefore not trusted.
#[cfg(target_os = "android")]
fn with_verifier(builder: Builder) -> Result<VerifiedBuilder> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(builder.with_root_certificates(roots))
}
