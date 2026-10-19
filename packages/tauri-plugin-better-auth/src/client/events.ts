import type { UnlistenFn } from '@tauri-apps/api/event';

import { listen } from '@tauri-apps/api/event';

import type { TauriUser } from './commands';

/** Why the user is no longer signed in. */
export type SignOutReason = 'user' | 'revoked' | 'expired';

/** Payload of the error event. */
export interface TauriAuthErrorEvent {
  code: string;
  message: string;
}

export const EVENT_AUTHENTICATED = 'better-auth://authenticated';
export const EVENT_SIGNED_OUT = 'better-auth://signed-out';
export const EVENT_ERROR = 'better-auth://error';

/** Fires after every successful sign-in (browser or in-app). */
export function onAuthenticated<U = TauriUser>(
  callback: (user: U) => void,
): Promise<UnlistenFn> {
  return listen<{ user: U }>(EVENT_AUTHENTICATED, (event) =>
    callback(event.payload.user),
  );
}

/** Fires when the session ends: signed out, revoked by the server, or expired. */
export function onSignedOut(
  callback: (event: { reason: SignOutReason }) => void,
): Promise<UnlistenFn> {
  return listen<{ reason: SignOutReason }>(EVENT_SIGNED_OUT, (event) =>
    callback(event.payload),
  );
}

/** Fires when a background sign-in (deep link or loopback) fails. */
export function onAuthError(
  callback: (error: TauriAuthErrorEvent) => void,
): Promise<UnlistenFn> {
  return listen<TauriAuthErrorEvent>(EVENT_ERROR, (event) =>
    callback(event.payload),
  );
}
