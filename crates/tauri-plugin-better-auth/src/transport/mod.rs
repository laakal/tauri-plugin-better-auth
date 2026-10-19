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
///   (a bare binary under `target/`) cannot.
/// - Windows and Linux: release builds are installed with their scheme
///   registered; debug builds usually are not.
pub(crate) fn deep_links_deliverable() -> bool {
    if cfg!(target_os = "macos") {
        std::env::current_exe()
            .map(|path| is_inside_app_bundle(&path.to_string_lossy()))
            .unwrap_or(false)
    } else {
        !cfg!(debug_assertions)
    }
}

fn is_inside_app_bundle(path: &str) -> bool {
    path.contains(".app/Contents/MacOS/")
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
    fn detects_app_bundles() {
        assert!(is_inside_app_bundle(
            "/Applications/Example.app/Contents/MacOS/example"
        ));
        assert!(!is_inside_app_bundle(
            "/Users/me/project/target/debug/example"
        ));
    }
}
