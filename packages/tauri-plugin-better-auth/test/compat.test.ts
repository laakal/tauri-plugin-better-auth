import { memoryAdapter } from 'better-auth/adapters/memory';
import { betterAuth } from 'better-auth/minimal';
import { bearer } from 'better-auth/plugins';
import { describe, expect, it, vi } from 'vitest';

import { TAURI_ERROR_CODES as ERR } from '../src/error-codes';
import { tauri } from '../src/index';
import { CLIENT_ID, errorCode, newState, pkce, setup } from './helpers';

/**
 * Postgres runs when TEST_POSTGRES=1 and a server listens on
 * postgres://user:password@localhost:5432/better_auth (getTestInstance's fixed
 * connection string). CI provides it as a service container.
 */
const withPostgres = process.env.TEST_POSTGRES === '1';

describe.runIf(withPostgres)('Postgres', () => {
  it('completes the flow', async () => {
    const t = await setup({}, {}, 'postgres');
    const res = await t.exchange(await t.grant());
    expect(res.status).toBe(200);
  });

  it('lets exactly one of many concurrent exchanges of one code win', async () => {
    const t = await setup({}, {}, 'postgres');
    const g = await t.grant();
    const results = await Promise.all(
      Array.from({ length: 8 }, () => t.exchange(g)),
    );
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 400)).toHaveLength(7);
  });

  it('rejects a revoked session behind a warm cookie cache', async () => {
    const t = await setup(
      { session: { cookieCache: { enabled: true, maxAge: 300 } } },
      {},
      'postgres',
    );
    await t.context.internalAdapter.deleteSession(t.signedIn.session.token);
    const res = await t.authorize({
      client_id: CLIENT_ID,
      state: newState(),
      code_challenge: pkce().challenge,
    });
    expect(res.status).toBe(401);
  });
});

describe('secondaryStorage', () => {
  /** In-memory secondary storage; JS is single-threaded, so getAndDelete is atomic. */
  function memoryStorage() {
    const values = new Map<string, string>();
    return {
      get: (key: string) => values.get(key) ?? null,
      set: (key: string, value: string) => {
        values.set(key, value);
      },
      delete: (key: string) => {
        values.delete(key);
      },
      getAndDelete: (key: string) => {
        const value = values.get(key) ?? null;
        values.delete(key);
        return value;
      },
      increment: (key: string) => {
        const next = Number(values.get(key) ?? 0) + 1;
        values.set(key, String(next));
        return next;
      },
    };
  }

  it('keeps codes single-use when verification lives in secondary storage', async () => {
    const t = await setup({ secondaryStorage: memoryStorage() });
    const g = await t.grant();
    const results = await Promise.all([t.exchange(g), t.exchange(g)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    const replay = await t.exchange(g);
    expect(await errorCode(replay)).toBe(ERR.INVALID_OR_EXPIRED_CODE.code);
  });
});

describe('better-auth/minimal', () => {
  function minimalAuth(
    withBearer: boolean,
    log?: (level: string, message: string) => void,
  ) {
    return betterAuth({
      baseURL: 'http://localhost:3000',
      secret: 'a-test-secret-that-is-long-enough-1234567890',
      database: memoryAdapter({
        user: [],
        session: [],
        account: [],
        verification: [],
      }),
      emailAndPassword: { enabled: true },
      logger: log
        ? { log: (level, message) => log(level, message) }
        : undefined,
      plugins: [
        ...(withBearer ? [bearer()] : []),
        tauri({ clientID: CLIENT_ID }),
      ],
    });
  }

  it('works with the minimal build and the memory adapter', async () => {
    const auth = minimalAuth(true);
    const base = 'http://localhost:3000/api/auth';
    const post = (
      path: string,
      body: unknown,
      headers: Record<string, string> = {},
    ) =>
      auth.handler(
        new Request(`${base}${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...headers },
          body: JSON.stringify(body),
        }),
      );

    const signUp = await post('/sign-up/email', {
      email: 'minimal@example.com',
      password: 'password-1234',
      name: 'Minimal',
    });
    expect(signUp.status).toBe(200);
    const cookie = signUp.headers
      .getSetCookie()
      .map((c) => c.split(';')[0])
      .join('; ');

    const { verifier, challenge } = pkce();
    const state = newState();
    const authorize = await post(
      '/tauri/authorize',
      { client_id: CLIENT_ID, state, code_challenge: challenge },
      { cookie },
    );
    expect(authorize.status).toBe(200);
    const { code } = (await authorize.json()) as { code: string };

    const token = await post('/tauri/token', {
      client_id: CLIENT_ID,
      code,
      state,
      code_verifier: verifier,
    });
    expect(token.status).toBe(200);
    const body = (await token.json()) as { user: { email: string } };
    expect(body.user.email).toBe('minimal@example.com');
  });

  it('warns at startup when bearer() is missing', async () => {
    const log = vi.fn();
    const auth = minimalAuth(false, log);
    await auth.$context;
    expect(log).toHaveBeenCalledWith(
      'warn',
      expect.stringContaining('bearer() plugin is not registered'),
    );
  });

  it('does not warn when bearer() is present', async () => {
    const log = vi.fn();
    const auth = minimalAuth(true, log);
    await auth.$context;
    expect(log).not.toHaveBeenCalledWith(
      'warn',
      expect.stringContaining('bearer() plugin is not registered'),
    );
  });
});
