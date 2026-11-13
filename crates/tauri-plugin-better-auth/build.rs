//! Generates the ACL permission files for the plugin commands and, for iOS,
//! builds and links the Swift package under `ios/`.

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
    tauri_plugin::Builder::new(COMMANDS).ios_path("ios").build();
}
