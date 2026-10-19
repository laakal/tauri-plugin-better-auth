import type { User } from 'better-auth';

import { APIError } from '@better-auth/core/error';
import {
  createAuthEndpoint,
  sensitiveSessionMiddleware,
} from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { constantTimeEqual, generateRandomString } from 'better-auth/crypto';
import { parseUserOutput } from 'better-auth/db';
import { generateCodeChallenge } from 'better-auth/oauth2';
import * as z from 'zod';

import type { ResolvedTauriOptions } from './types';

import { TAURI_ERROR_CODES as ERR } from './error-codes';
import {
  CODE_CHALLENGE_PATTERN,
  CODE_IDENTIFIER_PREFIX,
  CODE_PATTERN,
  CODE_VERIFIER_PATTERN,
  PROTOCOL_VERSION,
  STATE_PATTERN,
} from './protocol';

/** Response body of `POST /tauri/token`. */
export interface TauriTokenResponse {
  /** Session token, used as `Authorization: Bearer` by the app. */
  token: string;
  /** The signed-in user, filtered by `parseUserOutput`. */
  user: User & Record<string, unknown>;
  /** Wire protocol version (see PROTOCOL.md). */
  protocol: typeof PROTOCOL_VERSION;
}

// Bodies are parsed permissively (bounded strings) and checked by hand so each
// failure carries a specific, stable error code instead of a generic
// validation error.
const authorizeBody = z.object({
  client_id: z.string().max(64),
  state: z.string().max(256),
  code_challenge: z.string().max(256),
  code_challenge_method: z.string().max(16).optional(),
});

const tokenBody = z.object({
  client_id: z.string().max(64),
  code: z.string().max(256),
  state: z.string().max(256),
  code_verifier: z.string().max(256),
});

/** What `/tauri/authorize` stores under `tauri:<code>`. */
const storedGrant = z.object({
  userId: z.string().min(1),
  clientId: z.string().min(1),
  codeChallenge: z.string().regex(CODE_CHALLENGE_PATTERN),
  state: z.string().regex(STATE_PATTERN),
});

function parseStoredGrant(value: string) {
  try {
    return storedGrant.safeParse(JSON.parse(value));
  } catch {
    return null;
  }
}

export const createAuthorizeEndpoint = (opts: ResolvedTauriOptions) =>
  createAuthEndpoint(
    '/tauri/authorize',
    {
      method: 'POST',
      body: authorizeBody,
      // Authoritative database lookup: a browser session revoked while its
      // cookie cache is still warm must not mint native credentials.
      use: [sensitiveSessionMiddleware],
      allowedMediaTypes: ['application/json'],
      metadata: {
        noStore: true,
        openapi: {
          operationId: 'tauriAuthorize',
          description:
            "Mint a single-use code that hands the signed-in user's sign-in to a Tauri app. Called by the hand-off page after the user consents.",
          responses: {
            200: {
              description: 'A single-use authorization code',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: { code: { type: 'string' } },
                    required: ['code'],
                  },
                },
              },
            },
          },
        },
      },
    },
    async (ctx) => {
      if (opts.authorizeOrigins && ctx.request) {
        const origin = ctx.request.headers.get('origin');
        if (!origin || !opts.authorizeOrigins.includes(origin)) {
          throw APIError.from('FORBIDDEN', ERR.ORIGIN_NOT_ALLOWED);
        }
      }
      const { client_id, state, code_challenge, code_challenge_method } =
        ctx.body;
      if (client_id !== opts.clientID) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_CLIENT_ID);
      }
      if (!STATE_PATTERN.test(state)) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_STATE);
      }
      if (
        !CODE_CHALLENGE_PATTERN.test(code_challenge) ||
        (code_challenge_method !== undefined &&
          code_challenge_method !== 'S256')
      ) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_CODE_CHALLENGE);
      }

      const code = generateRandomString(32, 'a-z', 'A-Z', '0-9');
      await ctx.context.internalAdapter.createVerificationValue({
        identifier: `${CODE_IDENTIFIER_PREFIX}${code}`,
        value: JSON.stringify({
          userId: ctx.context.session.user.id,
          clientId: client_id,
          codeChallenge: code_challenge,
          state,
        }),
        expiresAt: new Date(Date.now() + opts.codeExpiresIn * 1000),
      });
      return ctx.json({ code });
    },
  );

export const createTokenEndpoint = (opts: ResolvedTauriOptions) =>
  createAuthEndpoint(
    '/tauri/token',
    {
      method: 'POST',
      body: tokenBody,
      allowedMediaTypes: ['application/json'],
      metadata: {
        // Reachable over HTTP (the app calls it), hidden from the browser
        // client's inferred API: a web page has no business calling it.
        scope: 'http',
        noStore: true,
        openapi: {
          operationId: 'tauriToken',
          description:
            'Exchange a single-use authorization code and PKCE verifier for a new session. Called by the Tauri app, never by a browser.',
          responses: {
            200: {
              description: 'The new session token and the user',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      token: { type: 'string' },
                      user: { $ref: '#/components/schemas/User' },
                      protocol: { type: 'number' },
                    },
                    required: ['token', 'user', 'protocol'],
                  },
                },
              },
            },
          },
        },
      },
    },
    async (ctx) => {
      const { client_id, code, state, code_verifier } = ctx.body;
      if (client_id !== opts.clientID) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_CLIENT_ID);
      }
      if (!CODE_PATTERN.test(code)) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_OR_EXPIRED_CODE);
      }
      if (!STATE_PATTERN.test(state)) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_STATE);
      }
      if (!CODE_VERIFIER_PATTERN.test(code_verifier)) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_CODE_VERIFIER);
      }

      // Burn the code before any other check: a wrong verifier or state costs
      // the attacker the code, so there is no oracle to retry against.
      // Atomic on database adapters and on secondary storage with an atomic
      // getAndDelete; also returns null once expired.
      const record = await ctx.context.internalAdapter.consumeVerificationValue(
        `${CODE_IDENTIFIER_PREFIX}${code}`,
      );
      if (!record) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_OR_EXPIRED_CODE);
      }
      const grant = parseStoredGrant(record.value);
      if (!grant?.success) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_OR_EXPIRED_CODE);
      }
      if (!constantTimeEqual(grant.data.clientId, client_id)) {
        throw APIError.from('BAD_REQUEST', ERR.INVALID_CLIENT_ID);
      }
      if (!constantTimeEqual(grant.data.state, state)) {
        throw APIError.from('BAD_REQUEST', ERR.STATE_MISMATCH);
      }
      const challenge = await generateCodeChallenge(code_verifier);
      if (!constantTimeEqual(challenge, grant.data.codeChallenge)) {
        throw APIError.from('BAD_REQUEST', ERR.PKCE_VERIFICATION_FAILED);
      }

      const user = await ctx.context.internalAdapter.findUserById(
        grant.data.userId,
      );
      if (!user) {
        throw APIError.from('BAD_REQUEST', ERR.USER_NOT_FOUND);
      }

      // Runs the host's databaseHooks.session.create.before/after with this
      // request's context (path "/tauri/token", the app's headers). A hook may
      // throw an APIError, which passes through, or return false, which makes
      // createSession return null.
      const session = (await ctx.context.internalAdapter.createSession(
        user.id,
      )) as Awaited<
        ReturnType<typeof ctx.context.internalAdapter.createSession>
      > | null;
      if (!session) {
        throw APIError.from('FORBIDDEN', ERR.SESSION_REJECTED);
      }

      // Sets the session cookie on this response; bearer() turns it into the
      // `set-auth-token` header and host after-hooks see ctx.context.newSession.
      await setSessionCookie(ctx, { session, user });

      return ctx.json({
        token: session.token,
        user: parseUserOutput(ctx.context.options, user) as User &
          Record<string, unknown>,
        protocol: PROTOCOL_VERSION,
      } satisfies TauriTokenResponse);
    },
  );
