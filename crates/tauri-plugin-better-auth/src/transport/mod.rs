//! How the browser hands the result back: custom-scheme deep links or a
//! loopback listener.

pub(crate) mod loopback;

use crate::config::Transport;

/// Resolves [`Transport::Auto`].
pub(crate) fn auto_transport(deep_links_deliverable: bool) -> Transport {
    if deep_links_deliverable {
        Transport::DeepLink
    } else {
        Transport::Loopback
    }
}

/// Whether the OS can deliver deep links to this process.
///
/// - macOS: only an installed `.app` bundle receives deep links, so `tauri dev`
///   cannot: it runs a bare binary under `target/`. A bundle run in place from
///   `target/` counts as dev too, since macOS may never have registered it.
/// - Windows and Linux: release builds are installed with their scheme
///   registered; debug builds usually are not.
pub(crate) fn deep_links_deliverable() -> bool {
    if cfg!(target_os = "macos") {
        std::env::current_exe()
            .map(|path| is_installed_app_bundle(&path.to_string_lossy()))
            .unwrap_or(false)
    } else {
        !cfg!(debug_assertions)
    }
}

/// An `.app` bundle outside a cargo `target/` directory. Bundles under
/// `target/` (a build run in place, or a dev bundle on Tauri 3's CEF runtime)
/// are not reliably registered with LaunchServices, so they use loopback.
fn is_installed_app_bundle(path: &str) -> bool {
    path.contains(".app/Contents/MacOS/") && !path.contains("/target/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_prefers_deep_links_when_deliverable() {
        assert_eq!(auto_transport(true), Transport::DeepLink);
        assert_eq!(auto_transport(false), Transport::Loopback);
    }

    #[test]
    fn detects_installed_app_bundles() {
        assert!(is_installed_app_bundle(
            "/Applications/Example.app/Contents/MacOS/example"
        ));
        assert!(is_installed_app_bundle(
            "/Users/me/Applications/Example.app/Contents/MacOS/example"
        ));
    }

    #[test]
    fn dev_builds_are_not_installed_bundles() {
        // wry: a bare binary.
        assert!(!is_installed_app_bundle(
            "/Users/me/project/target/debug/example"
        ));
        // A bundle run in place from `target/` (and Tauri 3's CEF dev bundle).
        assert!(!is_installed_app_bundle(
            "/Users/me/project/src-tauri/target/debug/bundle/macos/Example.app/Contents/MacOS/example"
        ));
    }
}
