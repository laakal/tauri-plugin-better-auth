# Wire protocol, version 1

This is how the Tauri app, the hand-off page and the Better Auth server talk.
It's stable for everything released under protocol v1, and **changes within v1
are additive only**: new optional parameters or response fields. Installed
desktop apps update much more slowly than servers, so an app built for v1 must
keep working against any newer v1 server.

Words: **app** = the Rust plugin. **page** = the hand-off page with
`tauriProxyClient`. **server** = Better Auth with the `tauri()` plugin. Paths
are relative to the Better Auth base URL, for example
`https://api.example.com/api/auth`.

## 1. Sign-in request (app → browser → page)

The app opens `sign_in_url` with these query parameters:

| Parameter               | Value                                                                     |
| ----------------------- | ------------------------------------------------------------------------- |
| `client_id`             | The configured client id, `[A-Za-z0-9._-]{1,64}`                          |
| `state`                 | 32 random base64url characters; must match `[A-Za-z0-9._~-]{16,128}`      |
| `code_challenge`        | `BASE64URL(SHA256(code_verifier))`, 43 characters (RFC 7636 S256)         |
| `code_challenge_method` | `S256` (the only method)                                                  |
| `v`                     | `1`                                                                       |
| `redirect_uri`          | Only for the loopback transport: `http://127.0.0.1:<port><callback_path>` |
| `provider`              | Optional: a social provider id the page may start automatically           |

How each side handles it:

- **The app** keeps `state` and `code_verifier` (43 characters, from 32 random
  bytes) in memory only. One sign-in is pending at a time, for at most
  `pending_ttl` (10 minutes by default).
- **The page** rejects the request if:
  - `client_id` differs from its own
  - `v` is not `1`
  - the method is not `S256`
  - `redirect_uri` is anything but exactly
    `http://127.0.0.1:<port><callback_path>` or `http://[::1]:<port><callback_path>`,
    with no userinfo, query or fragment
- **The page** ignores a `provider` that is not on its allowlist.

## 2. `POST /tauri/authorize` (page → server)

Requires the user's session (cookie). It is checked against the database,
bypassing the cookie cache, and is JSON only.

```json
{
  "client_id": "com.example.app",
  "state": "…",
  "code_challenge": "…",
  "code_challenge_method": "S256"
}
```

**What the server checks:**

- the `Origin` is in `authorizeOrigins`, when that is configured
- `client_id`
- the shapes of `state` and `code_challenge`

**What it stores:** under `tauri:<code>` in the verification store, with a
`codeExpiresIn` expiry (300 s by default):
`{ userId, clientId, codeChallenge, state }`. `code` is 32 characters of
`[A-Za-z0-9]`.

```json
200 { "code": "…32 chars…" }
```

**Errors** (HTTP status, then code):

| Status | Codes                                                          |
| ------ | -------------------------------------------------------------- |
| 401    | `UNAUTHORIZED`                                                 |
| 403    | `ORIGIN_NOT_ALLOWED`                                           |
| 400    | `INVALID_CLIENT_ID`, `INVALID_STATE`, `INVALID_CODE_CHALLENGE` |
| 415    | Non-JSON body                                                  |

## 3. Callback (browser → app)

After the user clicks "Continue", the page navigates to one of these.

Success:

```
<scheme>://<callback_path without its leading "/">?code=<code>&state=<state>
http://127.0.0.1:<port><callback_path>?code=<code>&state=<state>      (loopback)
```

The user cancelled:

```
…?error=access_denied&state=<state>
```

**How the app handles callbacks:**

- **Unknown parameters are ignored. Duplicate `code`, `state` or `error`
  parameters are rejected.**
- **Spellings accepted for the deep link:** `<scheme>://auth/callback`,
  `<scheme>:/auth/callback` and `<scheme>:///auth/callback`.
- **Matching:** `state` must equal the pending state (constant-time
  comparison).
  - A match **claims** the pending sign-in atomically, so a callback can be used
    only once.
  - A mismatch is ignored without side effects: no event, no window focus, and
    the pending sign-in survives.
- **Paste:** the user can paste the 32-character `code` (the pending `state` is
  implied) or the whole callback link.

## 4. `POST /tauri/token` (app → server)

The request has no cookies and no `Origin` header (Better Auth only checks the
origin of cookie-bearing requests), and it is JSON only. The app adds its own
headers (for example a device id) and a `User-Agent` of
`<app>/<version> tauri-plugin-better-auth/<version>`. It never follows
redirects.

```json
{
  "client_id": "com.example.app",
  "code": "…",
  "state": "…",
  "code_verifier": "…"
}
```

**Server steps, in order:**

1. Reject shapes that don't match the patterns, without touching the code.
2. **Consume** `tauri:<code>` atomically. A failure here or in any later step
   leaves the code burned.
3. Compare `client_id` and `state` (constant-time).
4. Check `BASE64URL(SHA256(code_verifier)) == codeChallenge`.
5. Load the user.
6. Create a session in this request's context. Host `databaseHooks.session.create.*`
   run here and may throw, which rejects the exchange, or return `false`.
7. Set the session cookie, which the `bearer()` plugin mirrors into
   `set-auth-token`.

```json
200 { "token": "…", "user": { … }, "protocol": 1 }
```

The response carries `Cache-Control: no-store` and a `set-auth-token` header.
The app prefers `set-auth-token` and falls back to `token`.

**Errors:**

| Status | Codes                                                                                                                                                    |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400    | `INVALID_CLIENT_ID`, `INVALID_STATE`, `INVALID_CODE_VERIFIER`, `INVALID_OR_EXPIRED_CODE`, `STATE_MISMATCH`, `PKCE_VERIFICATION_FAILED`, `USER_NOT_FOUND` |
| 403    | `SESSION_REJECTED`                                                                                                                                       |
| any    | A host hook's own `APIError` code                                                                                                                        |

## 5. After the exchange (app)

1. `GET /get-session` with `Authorization: Bearer <token>` must return the
   session. Otherwise the app reports `SESSION_REJECTED` and stores nothing.
2. The app stores `{ rev, token, session_id, expires_at }` in its secret store
   and `{ rev, session_id, user, session without token, tombstone }` in the
   profile file.
3. Only after a successful store does it revoke a previous session
   (`POST /sign-out` with the old token).

**Session checks:**

| Answer to `GET /get-session`     | Meaning                                                    |
| -------------------------------- | ---------------------------------------------------------- |
| 200 with a session               | Valid                                                      |
| 200 `null`, 401 or 403           | Revoked                                                    |
| Network error, timeout, 5xx, 429 | Unreachable: the cached session is kept, flagged `offline` |

**Sign-out:**

1. Clear locally.
2. Write a tombstone at a new revision.
3. `POST /sign-out` with the bearer token, best effort.

## Compatibility rules

- Servers must keep accepting every request shape listed here for as long as v1
  is supported.
- New fields in responses are allowed; apps ignore fields they don't know.
- A breaking change bumps the protocol to v2. The app sends `v=2`, a v1 page
  rejects the request with `status: 'invalid', problem: 'version'`, and the
  server keeps the v1 endpoints alongside v2.
