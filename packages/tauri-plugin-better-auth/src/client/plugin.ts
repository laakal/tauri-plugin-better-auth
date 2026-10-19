import type {
  BetterAuthClientOptions,
  BetterAuthClientPlugin,
} from '@better-auth/core';

import { isTauri } from '@tauri-apps/api/core';

import {
  authenticate,
  cancelAuth,
  getSession,
  requestAuth,
  signOut,
} from './commands';
import { onAuthenticated, onSignedOut } from './events';
import { tauriFetch } from './fetch';

/**
 * Better Auth client plugin for the Tauri webview. Refreshes `useSession()`
 * when a browser sign-in completes or the session ends, and adds
 * `authClient.tauri.*` actions. Added for you by {@link withTauri}.
 */
export const tauriClient = () =>
  ({
    id: 'tauri',
    getActions: (_$fetch, $store) => {
      if (typeof window !== 'undefined' && isTauri()) {
        const refresh = () => $store.notify('$sessionSignal');
        void onAuthenticated(refresh);
        void onSignedOut(refresh);
      }
      return {
        tauri: {
          /** Opens the system browser on the sign-in page. */
          requestAuth,
          /** Completes a sign-in with a pasted code or link. */
          authenticate,
          /** Cancels the sign-in in progress. */
          cancelAuth,
          /** The current session from Rust (with offline fallback). */
          getSession,
          /** Signs out locally and on the server. */
          signOut,
        },
      };
    },
  }) satisfies BetterAuthClientPlugin;

type PluginsOf<O> = O extends { plugins: infer P extends readonly unknown[] }
  ? P
  : [];

/** Options returned by {@link withTauri}. */
export type WithTauri<O extends BetterAuthClientOptions> = Omit<
  O,
  'plugins' | 'fetchOptions' | 'disableDefaultFetchPlugins'
> & {
  plugins: [...PluginsOf<O>, ReturnType<typeof tauriClient>];
  fetchOptions: Omit<NonNullable<O['fetchOptions']>, 'customFetchImpl'> & {
    customFetchImpl: typeof tauriFetch;
  };
  disableDefaultFetchPlugins: true;
};

/**
 * Adapts Better Auth client options for the Tauri webview. Pass the result to
 * the `createAuthClient` of your framework.
 *
 * - every request goes through the Rust bridge (`tauriFetch`): the token is
 *   added in Rust and never reaches the page;
 * - Better Auth's redirect plugin is disabled, so no response can navigate
 *   the webview away from the app (start social sign-in with
 *   `authClient.tauri.requestAuth({ provider })` instead);
 * - `useSession()` refreshes after browser sign-ins and sign-outs.
 *
 * @example
 * ```ts
 * import { createAuthClient } from 'better-auth/react';
 * import { emailOTPClient } from 'better-auth/client/plugins';
 * import { asTauriClient, withTauri } from 'tauri-plugin-better-auth/client';
 *
 * export const authClient = asTauriClient(
 *   createAuthClient(withTauri({ baseURL: 'https://api.example.com/api/auth', plugins: [emailOTPClient()] })),
 * );
 * ```
 */
export function withTauri<O extends BetterAuthClientOptions>(
  options: O,
): WithTauri<O> {
  return {
    ...options,
    disableDefaultFetchPlugins: true,
    fetchOptions: { ...options.fetchOptions, customFetchImpl: tauriFetch },
    plugins: [...(options.plugins ?? []), tauriClient()],
  } as unknown as WithTauri<O>;
}
