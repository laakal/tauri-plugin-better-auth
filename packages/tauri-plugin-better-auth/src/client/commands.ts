import { invoke } from '@tauri-apps/api/core';

/** How the browser hands the sign-in back to the app. */
export type Transport = 'auto' | 'deep-link' | 'loopback';

/** The signed-in user (Better Auth user object). */
export type TauriUser = Record<string, unknown> & {
  id: string;
  email?: string;
  name?: string;
  image?: string | null;
};

/** The current session as the webview sees it: never contains a token. */
export interface TauriSessionSnapshot<
  U = TauriUser,
  S = Record<string, unknown>,
> {
  user: U;
  /** Better Auth session object without `token`. */
  session: S;
  /** True when the server could not be reached and this is the cached copy. */
  offline: boolean;
}

export interface RequestAuthOptions {
  /** Social provider the hand-off page should start (if it allows it). */
  provider?: string;
  /** Overrides the transport configured in Rust for this sign-in. */
  transport?: Transport;
}

export interface RequestAuthResult {
  /** The sign-in URL: show it when the browser could not be opened. */
  url: string;
  /** Whether the system browser was opened. */
  opened: boolean;
  /** The transport chosen for this sign-in. */
  transport: Transport;
}

/** Error raised by the plugin commands; `code` is stable (see the README). */
export class TauriAuthError extends Error {
  override name = 'TauriAuthError';
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/** True for errors raised by this plugin. */
export function isTauriAuthError(error: unknown): error is TauriAuthError {
  return error instanceof TauriAuthError;
}

function toError(error: unknown): Error {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
  ) {
    const message =
      'message' in error && typeof error.message === 'string'
        ? error.message
        : error.code;
    return new TauriAuthError(error.code, message);
  }
  return error instanceof Error ? error : new Error(String(error));
}

/** `invoke` for this plugin, with errors mapped to {@link TauriAuthError}. */
export async function call<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invoke<T>(`plugin:better-auth|${command}`, args);
  } catch (error) {
    throw toError(error);
  }
}

/**
 * Opens the system browser on your sign-in page. The result arrives later as
 * an `authenticated` event (deep link or loopback), or through
 * {@link authenticate} when the user pastes the code.
 */
export function requestAuth(
  options: RequestAuthOptions = {},
): Promise<RequestAuthResult> {
  return call('request_auth', { options });
}

/** Completes a sign-in with a pasted code or callback link. */
export function authenticate<U = TauriUser>(
  codeOrLink: string,
): Promise<TauriSessionSnapshot<U>> {
  return call('authenticate', { code: codeOrLink });
}

/** Cancels the sign-in in progress. */
export function cancelAuth(): Promise<void> {
  return call('cancel_auth');
}

/**
 * The current session, verified with the server. With `cachedOnly`, returns
 * the last known session without a network call (fast, for startup guards).
 * When the server is unreachable the cached copy comes back with `offline`.
 */
export function getSession<U = TauriUser>(
  options: { cachedOnly?: boolean } = {},
): Promise<TauriSessionSnapshot<U> | null> {
  return call('get_session', { cachedOnly: options.cachedOnly ?? false });
}

/** Signs out locally (always) and on the server (best effort). */
export function signOut(): Promise<void> {
  return call('sign_out');
}
