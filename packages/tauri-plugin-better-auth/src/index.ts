import type { BetterAuthPlugin } from 'better-auth';

import type {
  ResolvedHandoffPage,
  ResolvedTauriOptions,
  TauriHandoffPageOptions,
  TauriOptions,
} from './types';

import { TAURI_ERROR_CODES } from './error-codes';
import {
  assertClientId,
  assertScheme,
  DEFAULT_CALLBACK_PATH,
  DEFAULT_CLIENT_ID,
  normalizeCallbackPath,
  PROVIDER_PATTERN,
  TauriConfigError,
} from './protocol';
import {
  createAuthorizeEndpoint,
  createHandoffPageEndpoint,
  createTokenEndpoint,
} from './routes';
import { VERSION } from './version';

function resolveHandoffPage(
  page: TauriHandoffPageOptions,
): ResolvedHandoffPage {
  const appName = page.appName?.trim() ?? '';
  if (!appName || appName.length > 100) {
    throw new TauriConfigError(
      'handoffPage.appName must be 1–100 characters, e.g. "Example".',
    );
  }
  const providers = page.socialProviders ?? true;
  if (Array.isArray(providers)) {
    for (const id of providers) {
      if (!PROVIDER_PATTERN.test(id)) {
        throw new TauriConfigError(
          `handoffPage.socialProviders entry "${id}" is not a provider id such as "github".`,
        );
      }
    }
  }
  let signInURL: string | null = null;
  if (page.signInURL !== undefined) {
    let parsed: URL;
    try {
      parsed = new URL(page.signInURL);
    } catch {
      throw new TauriConfigError(
        `handoffPage.signInURL "${page.signInURL}" is not an absolute URL.`,
      );
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new TauriConfigError(
        `handoffPage.signInURL "${page.signInURL}" must be an http(s) URL.`,
      );
    }
    signInURL = parsed.toString();
  }
  const signInCallbackParam = page.signInCallbackParam ?? 'callbackURL';
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(signInCallbackParam)) {
    throw new TauriConfigError(
      `handoffPage.signInCallbackParam "${signInCallbackParam}" is not a query parameter name.`,
    );
  }
  return {
    appName,
    scheme: assertScheme(page.scheme),
    callbackPath: normalizeCallbackPath(
      page.callbackPath ?? DEFAULT_CALLBACK_PATH,
    ),
    socialProviders: providers,
    signInURL,
    signInCallbackParam,
  };
}

function resolveOptions(options: TauriOptions = {}): ResolvedTauriOptions {
  const clientID = assertClientId(options.clientID ?? DEFAULT_CLIENT_ID);
  const codeExpiresIn = options.codeExpiresIn ?? 300;
  if (
    !Number.isInteger(codeExpiresIn) ||
    codeExpiresIn < 30 ||
    codeExpiresIn > 3600
  ) {
    throw new TauriConfigError(
      `codeExpiresIn must be a whole number of seconds between 30 and 3600, got ${codeExpiresIn}.`,
    );
  }
  const authorizeOrigins = options.authorizeOrigins?.map((origin) => {
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      throw new TauriConfigError(
        `authorizeOrigins entry "${origin}" is not a valid URL origin.`,
      );
    }
    if (
      parsed.origin === 'null' ||
      parsed.origin !== origin.replace(/\/$/, '')
    ) {
      throw new TauriConfigError(
        `authorizeOrigins entry "${origin}" must be a bare origin such as "https://example.com".`,
      );
    }
    return parsed.origin;
  });
  return {
    clientID,
    codeExpiresIn,
    authorizeOrigins,
    rateLimit: options.rateLimit ?? { window: 60, max: 10 },
    handoffPage: options.handoffPage
      ? resolveHandoffPage(options.handoffPage)
      : undefined,
  };
}

/** What `init` needs from Better Auth's context. */
interface InitContext {
  hasPlugin(pluginId: string): boolean;
  logger: { warn(message: string, ...args: unknown[]): void };
}

/**
 * Better Auth server plugin for Tauri desktop apps.
 *
 * Adds two endpoints:
 * - `POST /tauri/authorize`: called by your hand-off web page for the signed-in
 *   user; returns a single-use code bound to the app's PKCE challenge.
 * - `POST /tauri/token`: called by the app's Rust plugin; exchanges the code
 *   and PKCE verifier for a new session created in the app's own request.
 *
 * With `handoffPage`, also serves a ready-made hand-off page at
 * `GET /tauri/handoff`.
 *
 * Pair it with the `bearer()` plugin: the app authenticates with
 * `Authorization: Bearer`, never with cookies.
 *
 * @example
 * ```ts
 * import { betterAuth } from 'better-auth';
 * import { bearer } from 'better-auth/plugins';
 * import { tauri } from 'tauri-plugin-better-auth';
 *
 * export const auth = betterAuth({
 *   plugins: [
 *     bearer(),
 *     tauri({ clientID: 'com.example.app', authorizeOrigins: ['https://example.com'] }),
 *   ],
 * });
 * ```
 */
export const tauri = (options?: TauriOptions) => {
  const opts = resolveOptions(options);
  const endpoints = {
    tauriAuthorize: createAuthorizeEndpoint(opts),
    tauriToken: createTokenEndpoint(opts),
    ...(opts.handoffPage
      ? { tauriHandoffPage: createHandoffPageEndpoint(opts.handoffPage, opts) }
      : {}),
  };
  const isTauriPath = (path: string): boolean =>
    path === '/tauri/authorize' || path === '/tauri/token';

  return {
    id: 'tauri',
    version: VERSION,
    // A minimal structural context type: the plugin's public type must not
    // depend on Better Auth's internal AuthContext shape.
    init(ctx: InitContext) {
      if (!ctx.hasPlugin('bearer')) {
        ctx.logger.warn(
          '[tauri-plugin-better-auth] The bearer() plugin is not registered. ' +
            'Tauri apps authenticate with "Authorization: Bearer"; add ' +
            'bearer() from "better-auth/plugins" to your plugins.',
        );
      }
    },
    endpoints,
    rateLimit:
      opts.rateLimit === false
        ? undefined
        : [
            {
              window: opts.rateLimit.window,
              max: opts.rateLimit.max,
              pathMatcher: isTauriPath,
            },
          ],
    options: opts,
    $ERROR_CODES: TAURI_ERROR_CODES,
  } satisfies BetterAuthPlugin;
};

declare module '@better-auth/core' {
  // oxlint-disable-next-line typescript/no-unused-vars -- signature fixed by Better Auth
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    tauri: {
      creator: typeof tauri;
    };
  }
}

export { TAURI_ERROR_CODES } from './error-codes';
export {
  PROTOCOL_VERSION,
  TauriConfigError,
  isLoopbackRedirectUri,
  isValidScheme,
} from './protocol';
export type { TauriTokenResponse } from './routes';
export type {
  ResolvedHandoffPage,
  ResolvedTauriOptions,
  TauriHandoffPageOptions,
  TauriOptions,
} from './types';
export { VERSION } from './version';
