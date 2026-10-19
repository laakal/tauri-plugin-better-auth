//! Generates the ACL permission files for the plugin commands.

const COMMANDS: &[&str] = &[
    "request_auth",
    "authenticate",
    "cancel_auth",
    "get_session",
    "sign_out",
    "fetch",
    "fetch_cancel",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
