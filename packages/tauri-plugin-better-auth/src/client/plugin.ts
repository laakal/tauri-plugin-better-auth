import type {
  BetterAuthClientOptions,
  BetterAuthClientPlugin,
} from '@better-auth/core';

import { isTauri } from '@tauri-apps/api/core';

import {
  authenticate,
  cancelAuth,
  getSession,
  isTauriAuthError,
  requestAuth,
  signOut,
} from './commands';
import { onAuthenticated, onSignedOut } from './events';
import { tauriFetch } from './fetch';

/** A browser sign-in started with `signIn.social()` (not an ID-token sign-in). */
async function socialProvider(request: Request): Promise<string | null> {
  if (
    request.method !== 'POST' ||
    !new URL(request.url).pathname.endsWith('/sign-in/social')
  ) {
    return null;
  }
  const body = (await request
    .clone()
    .json()
    .catch(() => null)) as { provider?: unknown; idToken?: unknown } | null;
  if (!body || body.idToken !== undefined) return null;
  return typeof body.provider === 'string' ? body.provider : '';
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * The `fetch` that {@link withTauri} gives Better Auth: `tauriFetch`, except
 * that `authClient.signIn.social({ provider })` starts a browser sign-in with
 * `requestAuth({ provider })`. The bridge refuses that route, because the
 * webview must never follow an OAuth redirect.
 *
 * `signIn.social()` then resolves once the browser is open, with
 * `{ url, redirect: false }`; the session arrives with the `authenticated`
 * event, which refreshes `useSession()`. `callbackURL` and the other redirect
 * options are ignored: the app stays where it is.
 */
export const tauriAuthFetch: typeof fetch = async (input, init) => {
  const request = new Request(input, init);
  const provider = await socialProvider(request);
  if (provider === null) return tauriFetch(request);
  try {
    const result = await requestAuth(provider ? { provider } : {});
    return json(200, {
      url: result.url,
      redirect: false,
      opened: result.opened,
      transport: result.transport,
    });
  } catch (error) {
    const code = isTauriAuthError(error) ? error.code : 'REQUEST_AUTH_FAILED';
    const message = error instanceof Error ? error.message : String(error);
    return json(code === 'INVALID_REQUEST' ? 400 : 500, { code, message });
  }
};

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
    customFetchImpl: typeof tauriAuthFetch;
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
 *   the webview away from the app;
 * - `authClient.signIn.social({ provider })` opens the system browser, like
 *   `authClient.tauri.requestAuth({ provider })` (see {@link tauriAuthFetch});
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
    fetchOptions: { ...options.fetchOptions, customFetchImpl: tauriAuthFetch },
    plugins: [...(options.plugins ?? []), tauriClient()],
  } as unknown as WithTauri<O>;
}
