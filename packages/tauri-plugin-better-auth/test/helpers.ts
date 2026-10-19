import type { BetterAuthOptions } from 'better-auth';

import { getTestInstance } from 'better-auth/test';
import { createHash, randomBytes } from 'node:crypto';

import type { TauriOptions } from '../src/types';

import { tauri } from '../src/index';

export const CLIENT_ID = 'com.example.app';
export const BASE = 'http://localhost:3000/api/auth';

/** A fresh PKCE pair (RFC 7636 S256). */
export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/** A fresh OAuth state value. */
export function newState(): string {
  return randomBytes(24).toString('base64url');
}

type TestDatabase = 'sqlite' | 'postgres';

/**
 * A Better Auth test instance with the tauri() plugin and a signed-in browser
 * session, plus helpers that speak raw HTTP to the two endpoints.
 */
export async function setup(
  options: Partial<BetterAuthOptions> = {},
  pluginOptions: TauriOptions = {},
  testWith: TestDatabase = 'sqlite',
) {
  const instance = await getTestInstance(
    {
      ...options,
      plugins: [
        tauri({ clientID: CLIENT_ID, ...pluginOptions }),
        ...(options.plugins ?? []),
      ],
    },
    { testWith },
  );
  const call = (path: string, init: RequestInit = {}) =>
    instance.auth.handler(new Request(`${BASE}${path}`, init));

  // Sign in over raw HTTP so the browser cookie jar holds every cookie the
  // server set (session token and, with cookieCache, the cached session data).
  const signIn = await call('/sign-in/email', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email: instance.testUser.email,
      password: instance.testUser.password,
    }),
  });
  if (signIn.status !== 200) {
    throw new Error(`sign-in failed: ${signIn.status} ${await signIn.text()}`);
  }
  const browserCookie = signIn.headers
    .getSetCookie()
    .map((cookie) => cookie.split(';')[0])
    .join('; ');
  const sessionRes = await call('/get-session', {
    headers: { cookie: browserCookie },
  });
  const signedIn = (await sessionRes.json()) as {
    session: { id: string; token: string };
    user: { id: string; email: string };
  };

  const authorize = (
    body: Record<string, unknown>,
    init: { cookie?: string; headers?: Record<string, string> } = {},
  ) =>
    call('/tauri/authorize', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: init.cookie ?? browserCookie,
        ...init.headers,
      },
      body: JSON.stringify(body),
    });

  const token = (
    body: Record<string, unknown>,
    headers: Record<string, string> = {},
  ) =>
    call('/tauri/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });

  /** authorize → returns the code, its state and the PKCE verifier. */
  const grant = async () => {
    const { verifier, challenge } = pkce();
    const state = newState();
    const res = await authorize({
      client_id: CLIENT_ID,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    if (res.status !== 200) {
      throw new Error(`authorize failed: ${res.status} ${await res.text()}`);
    }
    const { code } = (await res.json()) as { code: string };
    return { code, state, verifier };
  };

  const exchange = async (
    g: { code: string; state: string; verifier: string },
    headers: Record<string, string> = {},
  ) =>
    token(
      {
        client_id: CLIENT_ID,
        code: g.code,
        state: g.state,
        code_verifier: g.verifier,
      },
      headers,
    );

  const context = await instance.auth.$context;

  return {
    ...instance,
    signedIn,
    browserCookie,
    call,
    authorize,
    token,
    grant,
    exchange,
    context,
  };
}

/** Reads `{ code }` from a Better Auth error response. */
export async function errorCode(res: Response): Promise<string | undefined> {
  const body = (await res.json()) as { code?: string };
  return body.code;
}
