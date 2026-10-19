import { getTestInstance } from 'better-auth/test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { tauri } from '../src/index';
import { tauriProxyClient } from '../src/proxy';
import { CLIENT_ID, newState, pkce } from './helpers';

const SCHEME = 'com.example.app';
const STORAGE_KEY = `tauri-plugin-better-auth:request:${CLIENT_ID}`;

function actions(
  options: Parameters<typeof tauriProxyClient>[0] = {
    scheme: SCHEME,
    clientID: CLIENT_ID,
  },
) {
  const plugin = tauriProxyClient(options);
  const $fetch = vi.fn() as never;
  return plugin.getActions($fetch).tauri;
}

function visit(params: Record<string, string>, extra = '') {
  const query = new URLSearchParams(params).toString();
  window.history.replaceState(null, '', `/desktop?${query}${extra}`);
}

function validParams(overrides: Record<string, string> = {}) {
  return {
    client_id: CLIENT_ID,
    state: newState(),
    code_challenge: pkce().challenge,
    code_challenge_method: 'S256',
    v: '1',
    ...overrides,
  };
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState(null, '', '/desktop');
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('getRequest', () => {
  it('returns none when the page was not opened by the app', () => {
    expect(actions().getRequest()).toEqual({ status: 'none' });
  });

  it('captures the request, stores it and cleans the address bar', () => {
    const params = validParams();
    visit(params, '&utm=keep');
    const result = actions().getRequest();
    expect(result).toMatchObject({
      status: 'ok',
      request: {
        clientId: CLIENT_ID,
        state: params.state,
        codeChallenge: params.code_challenge,
        redirectUri: null,
        provider: null,
        version: 1,
      },
    });
    expect(window.location.search).toBe('?utm=keep');
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toContain(params.state);
    // Later page loads in the same tab (e.g. after an OAuth round trip).
    expect(actions().getRequest()).toMatchObject({ status: 'ok' });
  });

  it.each([
    ['client_id', { client_id: 'other.app' }],
    ['state', { state: 'short' }],
    ['code_challenge', { code_challenge: 'x' }],
    ['code_challenge', { code_challenge_method: 'plain' }],
    ['redirect_uri', { redirect_uri: 'https://evil.example/auth/callback' }],
    ['redirect_uri', { redirect_uri: 'http://127.0.0.1:50000/other' }],
    ['version', { v: '2' }],
  ])('rejects a bad %s', (problem, override) => {
    visit(validParams(override));
    expect(actions().getRequest()).toEqual({ status: 'invalid', problem });
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(window.location.search).toBe('');
  });

  it('accepts a loopback redirect_uri', () => {
    visit(
      validParams({ redirect_uri: 'http://127.0.0.1:50123/auth/callback' }),
    );
    expect(actions().getRequest()).toMatchObject({
      status: 'ok',
      request: { redirectUri: 'http://127.0.0.1:50123/auth/callback' },
    });
  });

  it('keeps only allowed providers', () => {
    const client = () =>
      actions({ scheme: SCHEME, clientID: CLIENT_ID, providers: ['github'] });
    visit(validParams({ provider: 'github' }));
    expect(client().getRequest()).toMatchObject({
      request: { provider: 'github' },
    });
    visit(validParams({ provider: 'google' }));
    expect(client().getRequest()).toMatchObject({
      request: { provider: null },
    });
  });

  it('expires stored requests', () => {
    visit(validParams());
    actions({
      scheme: SCHEME,
      clientID: CLIENT_ID,
      requestTTL: 60,
    }).getRequest();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 61_000);
    expect(
      actions({
        scheme: SCHEME,
        clientID: CLIENT_ID,
        requestTTL: 60,
      }).getRequest(),
    ).toEqual({ status: 'invalid', problem: 'expired' });
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('re-validates a tampered stored request', () => {
    visit(validParams());
    actions().getRequest();
    const stored = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY)!);
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        ...stored,
        redirectUri: 'https://evil.example/auth/callback',
      }),
    );
    expect(actions().getRequest()).toEqual({
      status: 'invalid',
      problem: 'redirect_uri',
    });
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});

describe('cancelLink and openApp', () => {
  it('builds a state-carrying cancel link and clears the request', () => {
    const params = validParams();
    visit(params);
    const link = actions().cancelLink();
    expect(link).toBe(
      `${SCHEME}://auth/callback?error=access_denied&state=${params.state}`,
    );
    expect(actions().getRequest()).toEqual({ status: 'none' });
  });

  it('returns null without a request', () => {
    expect(actions().cancelLink()).toBeNull();
  });

  it('refuses to navigate anywhere but the app callback', () => {
    const target = { href: '' };
    vi.spyOn(window, 'location', 'get').mockReturnValue(target as Location);
    expect(() => actions().openApp('https://evil.example/')).toThrow();
    actions().openApp(`${SCHEME}://auth/callback?code=x&state=y`);
    expect(target.href).toBe(`${SCHEME}://auth/callback?code=x&state=y`);
  });
});

describe('handoff (in-process against the server plugin)', () => {
  async function server(redirectUri?: string) {
    const instance = await getTestInstance(
      { plugins: [tauri({ clientID: CLIENT_ID })] },
      {
        clientOptions: {
          plugins: [tauriProxyClient({ scheme: SCHEME, clientID: CLIENT_ID })],
        },
      },
    );
    // happy-dom follows the Fetch spec: scripts can neither send Cookie nor
    // read Set-Cookie. Authenticate the page's requests with the session
    // token from the sign-in body instead (the test instance has bearer()).
    const signIn = await instance.client.signIn.email({
      email: instance.testUser.email,
      password: instance.testUser.password,
    });
    const headers = { authorization: `Bearer ${signIn.data?.token}` };
    const { verifier, challenge } = pkce();
    const state = newState();
    visit({
      client_id: CLIENT_ID,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      v: '1',
      ...(redirectUri ? { redirect_uri: redirectUri } : {}),
    });
    return { instance, headers, verifier, state };
  }

  it('fails clearly without a request', async () => {
    const instance = await getTestInstance(
      { plugins: [tauri({ clientID: CLIENT_ID })] },
      {
        clientOptions: {
          plugins: [tauriProxyClient({ scheme: SCHEME, clientID: CLIENT_ID })],
        },
      },
    );
    const result = await instance.client.tauri.handoff();
    expect(result).toMatchObject({
      data: null,
      error: { code: 'NO_DESKTOP_REQUEST' },
    });
  });

  it('mints a code the app can exchange with its verifier', async () => {
    const { instance, headers, verifier, state } = await server();
    const result = await instance.client.tauri.handoff({ headers });
    expect(result.error).toBeNull();
    const { code, redirectTo } = result.data!;
    expect(redirectTo).toBe(
      `${SCHEME}://auth/callback?code=${code}&state=${encodeURIComponent(state)}`,
    );
    // The request is single-use on the page.
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();

    const token = await instance.auth.handler(
      new Request('http://localhost:3000/api/auth/tauri/token', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_id: CLIENT_ID,
          code,
          state,
          code_verifier: verifier,
        }),
      }),
    );
    expect(token.status).toBe(200);
  });

  it('hands back through the loopback redirect when the app asked for it', async () => {
    const { instance, headers } = await server(
      'http://127.0.0.1:51234/auth/callback',
    );
    const result = await instance.client.tauri.handoff({ headers });
    expect(result.data?.redirectTo).toMatch(
      /^http:\/\/127\.0\.0\.1:51234\/auth\/callback\?code=[A-Za-z0-9]{32}&state=/,
    );
  });

  it('surfaces server errors', async () => {
    const { instance } = await server();
    const result = await instance.client.tauri.handoff({
      headers: { authorization: 'Bearer invalid' },
    });
    expect(result).toMatchObject({ data: null, error: { status: 401 } });
  });
});
