import type { BetterAuthClientPlugin } from '@better-auth/core';
import type { BetterFetch, BetterFetchOption } from '@better-fetch/fetch';

import type { tauri } from './index';
import type { CallbackTarget } from './protocol';

import {
  assertClientId,
  assertScheme,
  buildCallbackUrl,
  CLIENT_ID_PATTERN,
  CODE_CHALLENGE_PATTERN,
  DEFAULT_CALLBACK_PATH,
  DEFAULT_CLIENT_ID,
  isLoopbackRedirectUri,
  normalizeCallbackPath,
  PROTOCOL_VERSION,
  PROVIDER_PATTERN,
  STATE_PATTERN,
} from './protocol';

/** Options of {@link tauriProxyClient}. */
export interface TauriProxyClientOptions {
  /** Custom URI scheme the app registers, e.g. `"com.example.app"`. */
  scheme: string;
  /**
   * Must match the server plugin and the Rust plugin.
   *
   * @default "tauri"
   */
  clientID?: string | undefined;
  /**
   * Path of the app callback, `<scheme>://auth/callback`.
   *
   * @default "/auth/callback"
   */
  callbackPath?: string | undefined;
  /**
   * Social providers the page may start automatically when the app asks for
   * one (`requestAuth({ provider })`). Other values are ignored.
   */
  providers?: string[] | undefined;
  /**
   * Seconds a captured request survives in `sessionStorage`, covering OAuth
   * round trips in the same tab.
   *
   * @default 600
   */
  requestTTL?: number | undefined;
}

/** A desktop sign-in request captured from the hand-off URL. */
export interface TauriAuthRequest {
  clientId: string;
  state: string;
  codeChallenge: string;
  /** Loopback redirect chosen by the app, or `null` for the custom scheme. */
  redirectUri: string | null;
  /** Allowed social provider the app asked for, or `null`. */
  provider: string | null;
  /** Wire protocol version requested by the app. */
  version: number;
  /** Epoch milliseconds when the request was captured. */
  capturedAt: number;
}

/** Why a hand-off URL was rejected. */
export type TauriRequestProblem =
  | 'client_id'
  | 'state'
  | 'code_challenge'
  | 'redirect_uri'
  | 'version'
  | 'expired';

/** Result of {@link TauriProxyActions.getRequest}. */
export type TauriRequestResult =
  | { status: 'ok'; request: TauriAuthRequest }
  | { status: 'none' }
  | { status: 'invalid'; problem: TauriRequestProblem };

/** Result of {@link TauriProxyActions.handoff}. */
export type TauriHandoffResult =
  | { data: { code: string; redirectTo: string }; error: null }
  | {
      data: null;
      error: { status: number; code?: string | undefined; message: string };
    };

/** Actions added under `authClient.tauri`. */
export interface TauriProxyActions {
  /**
   * Reads the desktop sign-in request from the current URL (and stores it in
   * `sessionStorage`, then removes it from the address bar), or from storage
   * on later page loads in the same tab.
   */
  getRequest(): TauriRequestResult;
  /**
   * After the user has signed in **and consented**, mints a single-use code
   * for the app and returns the URL that hands it back. Call it from a click
   * handler, then pass `redirectTo` to {@link openApp}.
   */
  handoff(
    fetchOptions?: BetterFetchOption | undefined,
  ): Promise<TauriHandoffResult>;
  /**
   * The URL that tells the app the user cancelled (`error=access_denied`),
   * or `null` when there is no request. Clears the request.
   */
  cancelLink(): string | null;
  /** Navigates to a URL returned by {@link handoff} or {@link cancelLink}. */
  openApp(url: string): void;
  /** Forgets the stored request. */
  clear(): void;
}

const QUERY_KEYS = [
  'client_id',
  'state',
  'code_challenge',
  'code_challenge_method',
  'redirect_uri',
  'provider',
  'v',
] as const;

interface ResolvedProxyOptions {
  scheme: string;
  clientID: string;
  callbackPath: string;
  providers: ReadonlySet<string>;
  requestTTL: number;
  storageKey: string;
}

function resolve(options: TauriProxyClientOptions): ResolvedProxyOptions {
  const clientID = assertClientId(options.clientID ?? DEFAULT_CLIENT_ID);
  return {
    scheme: assertScheme(options.scheme),
    clientID,
    callbackPath: normalizeCallbackPath(
      options.callbackPath ?? DEFAULT_CALLBACK_PATH,
    ),
    providers: new Set(options.providers ?? []),
    requestTTL: options.requestTTL ?? 600,
    storageKey: `tauri-plugin-better-auth:request:${clientID}`,
  };
}

/** Parses the hand-off query string. Pure: safe to call anywhere. */
function parseRequest(
  search: string,
  opts: ResolvedProxyOptions,
  now: number,
): TauriRequestResult {
  const params = new URLSearchParams(search);
  if (!params.has('client_id')) return { status: 'none' };

  const clientId = params.get('client_id') ?? '';
  if (!CLIENT_ID_PATTERN.test(clientId) || clientId !== opts.clientID) {
    return { status: 'invalid', problem: 'client_id' };
  }
  const version = Number(params.get('v') ?? PROTOCOL_VERSION);
  if (version !== PROTOCOL_VERSION) {
    return { status: 'invalid', problem: 'version' };
  }
  const state = params.get('state') ?? '';
  if (!STATE_PATTERN.test(state)) {
    return { status: 'invalid', problem: 'state' };
  }
  const codeChallenge = params.get('code_challenge') ?? '';
  const method = params.get('code_challenge_method');
  if (
    !CODE_CHALLENGE_PATTERN.test(codeChallenge) ||
    (method !== null && method !== 'S256')
  ) {
    return { status: 'invalid', problem: 'code_challenge' };
  }
  const redirectUri = params.get('redirect_uri');
  if (
    redirectUri !== null &&
    !isLoopbackRedirectUri(redirectUri, opts.callbackPath)
  ) {
    return { status: 'invalid', problem: 'redirect_uri' };
  }
  const rawProvider = params.get('provider');
  const provider =
    rawProvider !== null &&
    PROVIDER_PATTERN.test(rawProvider) &&
    opts.providers.has(rawProvider)
      ? rawProvider
      : null;

  return {
    status: 'ok',
    request: {
      clientId,
      state,
      codeChallenge,
      redirectUri,
      provider,
      version,
      capturedAt: now,
    },
  };
}

function storage(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

function readStored(
  opts: ResolvedProxyOptions,
  now: number,
): TauriRequestResult {
  const raw = storage()?.getItem(opts.storageKey);
  if (!raw) return { status: 'none' };
  let request: TauriAuthRequest;
  try {
    request = JSON.parse(raw) as TauriAuthRequest;
  } catch {
    storage()?.removeItem(opts.storageKey);
    return { status: 'none' };
  }
  if (now - request.capturedAt > opts.requestTTL * 1000) {
    storage()?.removeItem(opts.storageKey);
    return { status: 'invalid', problem: 'expired' };
  }
  // Re-validate: storage is writable by any script on the page.
  const search = new URLSearchParams({
    client_id: request.clientId,
    state: request.state,
    code_challenge: request.codeChallenge,
    v: String(request.version),
    ...(request.redirectUri ? { redirect_uri: request.redirectUri } : {}),
    ...(request.provider ? { provider: request.provider } : {}),
  }).toString();
  const parsed = parseRequest(search, opts, request.capturedAt);
  if (parsed.status !== 'ok') storage()?.removeItem(opts.storageKey);
  return parsed;
}

function stripQuery(): void {
  if (typeof window === 'undefined') return;
  const url = new URL(window.location.href);
  for (const key of QUERY_KEYS) url.searchParams.delete(key);
  window.history.replaceState(window.history.state, '', url.toString());
}

function callbackTarget(
  request: TauriAuthRequest,
  opts: ResolvedProxyOptions,
): CallbackTarget {
  return request.redirectUri
    ? { kind: 'loopback', redirectUri: request.redirectUri }
    : { kind: 'scheme', scheme: opts.scheme, callbackPath: opts.callbackPath };
}

/**
 * Better Auth client plugin for the web page that hands a sign-in to a Tauri
 * app. Add it to the auth client used by that page.
 *
 * @example
 * ```ts
 * const authClient = createAuthClient({
 *   plugins: [tauriProxyClient({ scheme: 'com.example.app', clientID: 'com.example.app' })],
 * });
 * const result = authClient.tauri.getRequest();
 * // …after sign-in and the user's click on "Continue":
 * const { data } = await authClient.tauri.handoff();
 * if (data) authClient.tauri.openApp(data.redirectTo);
 * ```
 */
export const tauriProxyClient = (options: TauriProxyClientOptions) => {
  const opts = resolve(options);

  return {
    id: 'tauri-proxy',
    $InferServerPlugin: {} as ReturnType<typeof tauri>,
    pathMethods: { '/tauri/authorize': 'POST' },
    getActions: ($fetch: BetterFetch) => {
      const getRequest = (): TauriRequestResult => {
        if (typeof window === 'undefined') return { status: 'none' };
        const now = Date.now();
        const fromUrl = parseRequest(window.location.search, opts, now);
        if (fromUrl.status === 'none') return readStored(opts, now);
        if (fromUrl.status === 'ok') {
          storage()?.setItem(opts.storageKey, JSON.stringify(fromUrl.request));
        }
        stripQuery();
        return fromUrl;
      };

      const actions: TauriProxyActions = {
        getRequest,

        async handoff(fetchOptions) {
          const current = getRequest();
          if (current.status !== 'ok') {
            return {
              data: null,
              error: {
                status: 400,
                code: 'NO_DESKTOP_REQUEST',
                message:
                  current.status === 'invalid'
                    ? `The desktop sign-in request is invalid (${current.problem}). Start again from the app.`
                    : 'There is no desktop sign-in request. Start again from the app.',
              },
            };
          }
          const { request } = current;
          const res = await $fetch<{ code: string }>('/tauri/authorize', {
            ...fetchOptions,
            method: 'POST',
            body: {
              client_id: request.clientId,
              state: request.state,
              code_challenge: request.codeChallenge,
              code_challenge_method: 'S256',
            },
          });
          if (res.error || !res.data) {
            const error = res.error as {
              status?: number;
              code?: string;
              message?: string;
            } | null;
            return {
              data: null,
              error: {
                status: error?.status ?? 500,
                code: error?.code,
                message: error?.message ?? 'Authorization failed',
              },
            };
          }
          storage()?.removeItem(opts.storageKey);
          return {
            data: {
              code: res.data.code,
              redirectTo: buildCallbackUrl(callbackTarget(request, opts), {
                code: res.data.code,
                state: request.state,
              }),
            },
            error: null,
          };
        },

        cancelLink() {
          const current = getRequest();
          if (current.status !== 'ok') return null;
          storage()?.removeItem(opts.storageKey);
          return buildCallbackUrl(callbackTarget(current.request, opts), {
            error: 'access_denied',
            state: current.request.state,
          });
        },

        openApp(url) {
          if (typeof window === 'undefined') return;
          const allowed =
            url.startsWith(`${opts.scheme}://`) ||
            url.startsWith('http://127.0.0.1:') ||
            url.startsWith('http://[::1]:');
          if (!allowed) {
            throw new Error(
              'openApp only navigates to the app callback returned by handoff() or cancelLink().',
            );
          }
          window.location.href = url;
        },

        clear() {
          storage()?.removeItem(opts.storageKey);
        },
      };

      return { tauri: actions };
    },
  } satisfies BetterAuthClientPlugin;
};

export type { CallbackTarget } from './protocol';
