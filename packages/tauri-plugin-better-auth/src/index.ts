import type { BetterAuthPlugin } from 'better-auth';

import type { ResolvedTauriOptions, TauriOptions } from './types';

import { TAURI_ERROR_CODES } from './error-codes';
import {
  assertClientId,
  DEFAULT_CLIENT_ID,
  TauriConfigError,
} from './protocol';
import { createAuthorizeEndpoint, createTokenEndpoint } from './routes';
import { VERSION } from './version';

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
export type { ResolvedTauriOptions, TauriOptions } from './types';
export { VERSION } from './version';
