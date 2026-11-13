//! Generates the ACL permission files for the plugin commands and wires the
//! native halves: the Swift package under `ios/` and the Android library under
//! `android/`.

const COMMANDS: &[&str] = &[
    "request_auth",
    "authenticate",
    "cancel_auth",
    "get_session",
    "sign_out",
    "fetch",
    "fetch_stream",
    "fetch_cancel",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
