import { APIError } from '@better-auth/core/error';
import { createAuthMiddleware } from 'better-auth/api';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { TAURI_ERROR_CODES as ERR } from '../src/error-codes';
import { tauri } from '../src/index';
import { CLIENT_ID, errorCode, newState, pkce, setup } from './helpers';

afterEach(() => {
  vi.useRealTimers();
});

describe('POST /tauri/authorize', () => {
  it('requires a session', async () => {
    const t = await setup();
    const { challenge } = pkce();
    const res = await t.authorize(
      { client_id: CLIENT_ID, state: newState(), code_challenge: challenge },
      { cookie: '' },
    );
    expect(res.status).toBe(401);
  });

  it('returns a 32-character code and forbids caching', async () => {
    const t = await setup();
    const { challenge } = pkce();
    const res = await t.authorize({
      client_id: CLIENT_ID,
      state: newState(),
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const { code } = (await res.json()) as { code: string };
    expect(code).toMatch(/^[A-Za-z0-9]{32}$/);
  });

  it('rejects a revoked session even while its cookie cache is still valid', async () => {
    const t = await setup({
      session: { cookieCache: { enabled: true, maxAge: 300 } },
    });
    await t.context.internalAdapter.deleteSession(t.signedIn.session.token);

    // The cookie cache alone still vouches for the deleted session …
    const cached = await t.call('/get-session', {
      headers: { cookie: t.browserCookie },
    });
    expect(await cached.json()).not.toBeNull();

    // … but authorize checks the database.
    const { challenge } = pkce();
    const res = await t.authorize({
      client_id: CLIENT_ID,
      state: newState(),
      code_challenge: challenge,
    });
    expect(res.status).toBe(401);
  });

  it.each([
    ['unknown client', { client_id: 'other.app' }, ERR.INVALID_CLIENT_ID.code],
    ['short state', { state: 'short' }, ERR.INVALID_STATE.code],
    [
      'state with spaces',
      { state: 'has spaces in it 1234' },
      ERR.INVALID_STATE.code,
    ],
    [
      'bad challenge',
      { code_challenge: 'x'.repeat(42) },
      ERR.INVALID_CODE_CHALLENGE.code,
    ],
    [
      'plain method',
      { code_challenge_method: 'plain' },
      ERR.INVALID_CODE_CHALLENGE.code,
    ],
  ])('rejects %s', async (_, override, code) => {
    const t = await setup();
    const res = await t.authorize({
      client_id: CLIENT_ID,
      state: newState(),
      code_challenge: pkce().challenge,
      ...override,
    });
    expect(res.status).toBe(400);
    expect(await errorCode(res)).toBe(code);
  });

  it('accepts only JSON bodies', async () => {
    const t = await setup();
    const res = await t.call('/tauri/authorize', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: t.browserCookie,
      },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        state: newState(),
        code_challenge: pkce().challenge,
      }).toString(),
    });
    expect(res.status).toBe(415);
  });

  it('enforces authorizeOrigins', async () => {
    const t = await setup(
      {},
      { authorizeOrigins: ['https://www.example.com'] },
    );
    const body = {
      client_id: CLIENT_ID,
      state: newState(),
      code_challenge: pkce().challenge,
    };

    const foreign = await t.authorize(body, {
      headers: { origin: 'https://docs.example.com' },
    });
    expect(foreign.status).toBe(403);
    expect(await errorCode(foreign)).toBe(ERR.ORIGIN_NOT_ALLOWED.code);

    const missing = await t.authorize(body);
    expect(missing.status).toBe(403);

    const allowed = await t.authorize(body, {
      headers: { origin: 'https://www.example.com' },
    });
    expect(allowed.status).toBe(200);
  });
});

describe('POST /tauri/token', () => {
  it('exchanges a code for a new session usable as a bearer token', async () => {
    const t = await setup();
    const res = await t.exchange(await t.grant(), {
      'user-agent': 'ExampleApp/1.0',
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('set-auth-token')).toBeTruthy();

    const body = (await res.json()) as {
      token: string;
      user: { id: string; email: string };
      protocol: number;
    };
    expect(body.protocol).toBe(1);
    expect(body.user.id).toBe(t.signedIn.user.id);
    expect(body.token).not.toBe(t.signedIn.session.token);

    const session = await t.call('/get-session', {
      headers: { authorization: `Bearer ${body.token}` },
    });
    const data = (await session.json()) as {
      session: { id: string; userAgent: string };
      user: { email: string };
    };
    expect(data.user.email).toBe(t.signedIn.user.email);
    expect(data.session.id).not.toBe(t.signedIn.session.id);
    // The session is created in the app's request: its headers are recorded.
    expect(data.session.userAgent).toBe('ExampleApp/1.0');
  });

  it('burns the code on a wrong verifier (no retry oracle)', async () => {
    const t = await setup();
    const g = await t.grant();

    const wrong = await t.exchange({ ...g, verifier: pkce().verifier });
    expect(wrong.status).toBe(400);
    expect(await errorCode(wrong)).toBe(ERR.PKCE_VERIFICATION_FAILED.code);

    const retry = await t.exchange(g);
    expect(retry.status).toBe(400);
    expect(await errorCode(retry)).toBe(ERR.INVALID_OR_EXPIRED_CODE.code);
  });

  it('rejects a replayed code', async () => {
    const t = await setup();
    const g = await t.grant();
    expect((await t.exchange(g)).status).toBe(200);
    const replay = await t.exchange(g);
    expect(replay.status).toBe(400);
    expect(await errorCode(replay)).toBe(ERR.INVALID_OR_EXPIRED_CODE.code);
  });

  it('lets exactly one of two concurrent exchanges win', async () => {
    const t = await setup();
    const g = await t.grant();
    const results = await Promise.all([t.exchange(g), t.exchange(g)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
  });

  it('rejects an expired code', async () => {
    const t = await setup({}, { codeExpiresIn: 30 });
    const g = await t.grant();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 31_000);
    const res = await t.exchange(g);
    expect(res.status).toBe(400);
    expect(await errorCode(res)).toBe(ERR.INVALID_OR_EXPIRED_CODE.code);
  });

  it('rejects a state that does not match the grant', async () => {
    const t = await setup();
    const g = await t.grant();
    const res = await t.exchange({ ...g, state: newState() });
    expect(res.status).toBe(400);
    expect(await errorCode(res)).toBe(ERR.STATE_MISMATCH.code);
  });

  it.each([
    ['unknown client', { client_id: 'other.app' }, ERR.INVALID_CLIENT_ID.code],
    [
      'malformed code',
      { code: 'not-a-code' },
      ERR.INVALID_OR_EXPIRED_CODE.code,
    ],
    ['malformed state', { state: 'x' }, ERR.INVALID_STATE.code],
    [
      'short verifier',
      { code_verifier: 'abc' },
      ERR.INVALID_CODE_VERIFIER.code,
    ],
  ])('rejects %s before touching the code', async (_, override, code) => {
    const t = await setup();
    const g = await t.grant();
    const res = await t.token({
      client_id: CLIENT_ID,
      code: g.code,
      state: g.state,
      code_verifier: g.verifier,
      ...override,
    });
    expect(res.status).toBe(400);
    expect(await errorCode(res)).toBe(code);
    // Format errors are rejected before consumption: the code still works.
    expect((await t.exchange(g)).status).toBe(200);
  });

  it('hides user fields marked returned: false', async () => {
    const t = await setup({
      user: {
        additionalFields: {
          internalNote: {
            type: 'string',
            required: false,
            returned: false,
            defaultValue: 'secret',
          },
        },
      },
    });
    const res = await t.exchange(await t.grant());
    const body = (await res.json()) as { user: Record<string, unknown> };
    expect(body.user).not.toHaveProperty('internalNote');
  });
});

describe('host hooks', () => {
  it('sees the new session in hooks.after with the app headers', async () => {
    let seen: { path: string; device: string | null; user: string } | undefined;
    const t = await setup({
      hooks: {
        after: createAuthMiddleware(async (ctx) => {
          if (ctx.path === '/tauri/token' && ctx.context.newSession) {
            seen = {
              path: ctx.path,
              device: ctx.headers?.get('x-device-id') ?? null,
              user: ctx.context.newSession.user.id,
            };
          }
        }),
      },
    });
    await t.exchange(await t.grant(), { 'x-device-id': 'device-1' });
    expect(seen).toEqual({
      path: '/tauri/token',
      device: 'device-1',
      user: t.signedIn.user.id,
    });
  });

  it('passes through an APIError thrown by session.create.before and creates no session', async () => {
    const t = await setup({
      databaseHooks: {
        session: {
          create: {
            before: async (_session, ctx) => {
              if (ctx?.path === '/tauri/token') {
                throw APIError.from('FORBIDDEN', {
                  code: 'DEVICE_CONTEXT_REQUIRED',
                  message: 'Device headers are required',
                });
              }
            },
          },
        },
      },
    });
    const before = await t.context.internalAdapter.listSessions(
      t.signedIn.user.id,
    );
    const res = await t.exchange(await t.grant());
    expect(res.status).toBe(403);
    expect(await errorCode(res)).toBe('DEVICE_CONTEXT_REQUIRED');
    const after = await t.context.internalAdapter.listSessions(
      t.signedIn.user.id,
    );
    expect(after).toHaveLength(before.length);
  });

  it('maps a before-hook returning false to SESSION_REJECTED', async () => {
    const t = await setup({
      databaseHooks: {
        session: {
          create: {
            before: async (_session, ctx) =>
              ctx?.path === '/tauri/token' ? false : undefined,
          },
        },
      },
    });
    const before = await t.context.internalAdapter.listSessions(
      t.signedIn.user.id,
    );
    const res = await t.exchange(await t.grant());
    expect(res.status).toBe(403);
    expect(await errorCode(res)).toBe(ERR.SESSION_REJECTED.code);
    expect(
      await t.context.internalAdapter.listSessions(t.signedIn.user.id),
    ).toHaveLength(before.length);
  });
});

describe('rate limiting', () => {
  it('limits /tauri/token per client IP', async () => {
    const t = await setup(
      { rateLimit: { enabled: true, window: 60, max: 1000 } },
      { rateLimit: { window: 60, max: 3 } },
    );
    const ip = { 'x-forwarded-for': '203.0.113.7' };
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await t.token(
        {
          client_id: CLIENT_ID,
          code: 'a'.repeat(32),
          state: newState(),
          code_verifier: pkce().verifier,
        },
        ip,
      );
      statuses.push(res.status);
    }
    expect(statuses).toEqual([400, 400, 400, 429]);
  });
});

describe('plugin options', () => {
  it.each([
    [{ clientID: 'bad id' }],
    [{ codeExpiresIn: 5 }],
    [{ codeExpiresIn: 7200 }],
    [{ authorizeOrigins: ['https://example.com/path'] }],
    [{ authorizeOrigins: ['not a url'] }],
  ])('rejects %j at startup', (options) => {
    expect(() => tauri(options)).toThrow();
  });

  it('normalizes a trailing slash on authorizeOrigins', () => {
    expect(
      tauri({ authorizeOrigins: ['https://example.com/'] }).options
        .authorizeOrigins,
    ).toEqual(['https://example.com']);
  });
});
