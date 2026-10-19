/**
 * Wire protocol v1, shared by the server plugin, the web hand-off client and
 * the Rust plugin. Documented in PROTOCOL.md. Within v1, changes are additive
 * only: installed desktop apps lag behind servers and must keep working.
 *
 * This module has no runtime dependencies so every entry point can import it.
 */

/** Protocol version sent as `v` on the sign-in URL and returned by `/tauri/token`. */
export const PROTOCOL_VERSION = 1;

/** Default client id when none is configured. */
export const DEFAULT_CLIENT_ID = 'tauri';

/** Default path of the app callback (`<scheme>://auth/callback`). */
export const DEFAULT_CALLBACK_PATH = '/auth/callback';

/** Prefix of the verification identifier that stores an authorization code. */
export const CODE_IDENTIFIER_PREFIX = 'tauri:';

/** OAuth `state`: 16–128 unreserved characters (RFC 3986). */
export const STATE_PATTERN: RegExp = /^[A-Za-z0-9._~-]{16,128}$/;

/** PKCE S256 challenge: base64url of a SHA-256 digest, no padding. */
export const CODE_CHALLENGE_PATTERN: RegExp = /^[A-Za-z0-9_-]{43}$/;

/** PKCE verifier: 43–128 unreserved characters (RFC 7636 §4.1). */
export const CODE_VERIFIER_PATTERN: RegExp = /^[A-Za-z0-9._~-]{43,128}$/;

/** Authorization code minted by `/tauri/authorize`. */
export const CODE_PATTERN: RegExp = /^[A-Za-z0-9]{32}$/;

/** Client id shared by the server, the hand-off page and the app. */
export const CLIENT_ID_PATTERN: RegExp = /^[A-Za-z0-9._-]{1,64}$/;

/** Social provider id forwarded from the app to the hand-off page. */
export const PROVIDER_PATTERN: RegExp = /^[a-z0-9][a-z0-9-]{0,63}$/;

const SCHEME_PATTERN = /^[a-z][a-z0-9+.-]{1,62}$/;
const CALLBACK_PATH_PATTERN = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;

/**
 * Schemes that must never be used for the app callback: they are either
 * web schemes, browser-internal, or Tauri's own.
 */
const RESERVED_SCHEMES: ReadonlySet<string> = new Set([
  'about',
  'asset',
  'blob',
  'data',
  'file',
  'ftp',
  'http',
  'https',
  'ipc',
  'javascript',
  'mailto',
  'tauri',
  'ws',
  'wss',
]);

/** Thrown when a configuration value breaks a protocol rule. */
export class TauriConfigError extends Error {
  override name = 'TauriConfigError';
}

/** Returns true for a custom URI scheme the app can register. */
export function isValidScheme(scheme: string): boolean {
  return SCHEME_PATTERN.test(scheme) && !RESERVED_SCHEMES.has(scheme);
}

/** Validates a scheme, throwing {@link TauriConfigError} with the reason. */
export function assertScheme(scheme: string): string {
  if (!isValidScheme(scheme)) {
    throw new TauriConfigError(
      `Invalid callback scheme "${scheme}". Use a lowercase custom scheme ` +
        'such as "com.example.app" (RFC 8252 §7.1); web and Tauri schemes ' +
        'are not allowed.',
    );
  }
  return scheme;
}

/** Normalizes and validates the callback path (`/auth/callback`). */
export function normalizeCallbackPath(path: string): string {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  if (!CALLBACK_PATH_PATTERN.test(normalized) || normalized.length > 64) {
    throw new TauriConfigError(
      `Invalid callback path "${path}". Use 1–64 characters of letters, ` +
        'digits, "_", "-" and "/" segments, like "/auth/callback".',
    );
  }
  return normalized;
}

/** Validates a client id, throwing {@link TauriConfigError} with the reason. */
export function assertClientId(clientId: string): string {
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    throw new TauriConfigError(
      `Invalid client id "${clientId}". Use 1–64 characters of letters, ` +
        'digits, ".", "_" and "-".',
    );
  }
  return clientId;
}

/**
 * Returns true when `uri` is a loopback redirect the hand-off page may follow:
 * exactly `http://127.0.0.1:<port><callbackPath>` or
 * `http://[::1]:<port><callbackPath>`, with no userinfo, query or fragment.
 *
 * Anything else is rejected so that a crafted sign-in link cannot send an
 * authorization code to a remote server (RFC 8252 §7.3, §8.3).
 */
export function isLoopbackRedirectUri(
  uri: string,
  callbackPath: string,
): boolean {
  // Require the literal form: URL parsing would also accept encodings such as
  // `http://2130706433:…` or `http://0x7f.1:…` for 127.0.0.1.
  if (
    !uri.startsWith('http://127.0.0.1:') &&
    !uri.startsWith('http://[::1]:')
  ) {
    return false;
  }
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:') return false;
  if (url.username !== '' || url.password !== '') return false;
  if (url.search !== '' || url.hash !== '') return false;
  if (uri.includes('?') || uri.includes('#')) return false;
  if (url.hostname !== '127.0.0.1' && url.hostname !== '[::1]') return false;
  if (url.port === '') return false;
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1024 || port > 65_535) return false;
  return url.pathname === callbackPath;
}

/** Where the hand-off page sends the browser after authorizing. */
export type CallbackTarget =
  | { kind: 'scheme'; scheme: string; callbackPath: string }
  | { kind: 'loopback'; redirectUri: string };

/** Parameters carried back to the app. */
export type CallbackParams =
  | { code: string; state: string }
  | { error: 'access_denied'; state: string };

/**
 * Builds the URL the browser opens to hand the result back to the app:
 * `<scheme>://auth/callback?code=…&state=…` or the loopback redirect URI.
 */
export function buildCallbackUrl(
  target: CallbackTarget,
  params: CallbackParams,
): string {
  const search = new URLSearchParams(params).toString();
  if (target.kind === 'loopback') {
    return `${target.redirectUri}?${search}`;
  }
  // `scheme://auth/callback`: the first segment parses as the URL host.
  return `${target.scheme}://${target.callbackPath.slice(1)}?${search}`;
}
