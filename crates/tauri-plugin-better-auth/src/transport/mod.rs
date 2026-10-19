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
///   cannot: wry runs a bare binary under `target/`, and the CEF runtime runs a
///   dev `.app` bundle that is also under `target/` and never registered.
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

/// An `.app` bundle outside a cargo `target/` directory: the dev bundle the
/// CEF runtime builds for `tauri dev` lives under `target/` and is not
/// registered with LaunchServices.
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
        // CEF: `tauri dev` runs a dev bundle under `target/`.
        assert!(!is_installed_app_bundle(
            "/Users/me/project/src-tauri/target/debug/bundle/macos/Example.app/Contents/MacOS/example"
        ));
    }
}
