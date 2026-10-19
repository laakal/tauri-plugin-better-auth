# Basic example

A runnable demo of every part of the plugin:

- **`server/`** runs on Bun with Better Auth (SQLite).
  - Sign-in is by email code; codes are printed to the console.
  - It uses `bearer()` and `tauri()`.
  - It serves the `/desktop` hand-off page and a protected `/api/me` route.
- **`tauri-app/`** is a Tauri 3 app on the wry runtime.
  - It signs in through the browser, by pasting a code, or in-app with an
    email code.
  - It calls `/api/me` through the Rust bridge and can sign out.

## Run it

```sh
# from the repository root
bun install
bun run build                                   # builds the npm package the examples import

bun --cwd examples/basic/server run dev         # http://localhost:3000
bun --cwd examples/basic/tauri-app run tauri dev
```

1. Click **Continue in browser**. The hand-off page opens.
2. Enter any email address and use the code printed by the server. Then click
   **Continue to the app**.
3. The app signs you in:
   - **`tauri dev`** uses the **loopback** transport. The browser returns to
     `http://127.0.0.1:<port>`, because deep links cannot reach a development
     binary on macOS.
   - **Installed builds use the deep link.** Run `bun run tauri build --debug`,
     open the built `.app`, `.msi` or `.deb` once, and the browser returns
     through `com.example.betterauth://auth/callback`.
   - **If the app does not come back,** open "The app did not open?" on the page
     and paste the code into the app.
4. Click **Call /api/me through the bridge**: the request carries the bearer
   token, added in Rust.
5. Restart the app: you are still signed in (OS keychain). Then **Sign out**.

## Protocol end-to-end test

The Rust crate has a test that drives the real plugin against this server:

```sh
EXAMPLE_TEST_MODE=1 EXAMPLE_DB=/tmp/e2e.db bun examples/basic/server/src/server.ts &
TPBA_E2E_URL=http://localhost:3000 cargo test -p tauri-plugin-better-auth --test protocol_e2e
```

`EXAMPLE_TEST_MODE=1` exposes `/__test/otp`, which lets the test read sign-in
codes. Never set it anywhere real.
