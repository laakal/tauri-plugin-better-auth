#[cfg(desktop)]
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    // Tauri 3: choose the webview runtime (wry = the system webview).
    let mut builder = tauri::Builder::default().runtime(tauri_runtime_wry::Wry::default());

    // 1. single-instance first: on Windows and Linux a deep link starts a new
    //    process; this forwards it to the running app instead.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }));
    }

    builder
        // 2. deep-link: delivers `com.example.betterauth://…` URLs.
        .plugin(tauri_plugin_deep_link::init())
        // 3. better-auth: every value is fixed here, never by the webview.
        .plugin(
            tauri_plugin_better_auth::Builder::new()
                .base_url("http://localhost:3000/api/auth")
                .sign_in_url("http://localhost:3000/desktop")
                .scheme("com.example.betterauth")
                .client_id("com.example.betterauth")
                .api_routes("http://localhost:3000", ["/api/"])
                .build(),
        )
        .run(tauri::generate_context!())
}
