/**
 * Tauri webview side of `tauri-plugin-better-auth`. Requires the Rust plugin
 * (`tauri-plugin-better-auth` crate) and `@tauri-apps/api`.
 *
 * @module
 */
export {
  authenticate,
  cancelAuth,
  getSession,
  isTauriAuthError,
  requestAuth,
  signOut,
  TauriAuthError,
} from './commands';
export type {
  RequestAuthOptions,
  RequestAuthResult,
  TauriSessionSnapshot,
  TauriUser,
  Transport,
} from './commands';
export {
  EVENT_AUTHENTICATED,
  EVENT_ERROR,
  EVENT_SIGNED_OUT,
  onAuthenticated,
  onAuthError,
  onSignedOut,
} from './events';
export type { SignOutReason, TauriAuthErrorEvent } from './events';
export { tauriFetch } from './fetch';
export { tauriClient, withTauri } from './plugin';
export type { WithTauri } from './plugin';
export { asTauriClient } from './types';
export type {
  TauriAuthClient,
  TauriSignInMethod,
  TauriUnsupportedAction,
  Tokenless,
} from './types';
