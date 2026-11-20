import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { HandoffPageConfig } from '../src/handoff-page';

import { renderHandoffPage, runHandoffPage } from '../src/handoff-page';
import {
  CLIENT_ID_PATTERN,
  CODE_CHALLENGE_PATTERN,
  PROVIDER_PATTERN,
  STATE_PATTERN,
} from '../src/protocol';
import { CLIENT_ID, newState, pkce } from './helpers';

const STORAGE_KEY = `tauri-plugin-better-auth:request:${CLIENT_ID}`;
const PAGE = 'http://localhost:3000/api/auth/tauri/handoff';
const CODE = 'abcdefghijklmnopqrstuvwxyzABCDEF';

function config(overrides: Partial<HandoffPageConfig> = {}): HandoffPageConfig {
  return {
    appName: 'Example',
    scheme: 'com.example.app',
    callbackPath: '/auth/callback',
    clientID: CLIENT_ID,
    protocolVersion: 1,
    authBase: '/api/auth',
    signInURL: null,
    signInCallbackParam: 'callbackURL',
    providers: [{ id: 'github', name: 'GitHub' }],
    requestTTL: 600,
    patterns: {
      clientId: CLIENT_ID_PATTERN.source,
      state: STATE_PATTERN.source,
      codeChallenge: CODE_CHALLENGE_PATTERN.source,
      provider: PROVIDER_PATTERN.source,
    },
    ...overrides,
  };
}

/** The page's markup with its config, without the executable script. */
function mount(cfg: HandoffPageConfig) {
  const html = renderHandoffPage(cfg, 'nonce123');
  const body = /<body>([\s\S]*)<\/body>/.exec(html)![1]!;
  document.body.innerHTML = body.replace(/<script nonce[\s\S]*?<\/script>/, '');
}

function visit(params: Record<string, string> | string) {
  const query =
    typeof params === 'string'
      ? params
      : new URLSearchParams(params).toString();
  window.history.replaceState(null, '', `${PAGE}${query ? `?${query}` : ''}`);
}

function request(overrides: Record<string, string> = {}) {
  return {
    client_id: CLIENT_ID,
    state: newState(),
    code_challenge: pkce().challenge,
    code_challenge_method: 'S256',
    v: '1',
    ...overrides,
  };
}

type Call = { path: string; method: string; body: unknown };

/** A fake Better Auth server: `routes` maps a path to its JSON answer. */
function server(routes: Record<string, unknown>) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: string, init: RequestInit = {}) => {
    const path = input.replace('/api/auth', '');
    calls.push({
      path,
      method: init.method ?? 'GET',
      body: init.body ? JSON.parse(String(init.body)) : undefined,
    });
    const answer = routes[path];
    if (answer instanceof Response) return answer;
    return new Response(JSON.stringify(answer ?? null), {
      status: answer === undefined ? 404 : 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  window.fetch = fetchMock as unknown as typeof fetch;
  return calls;
}

const text = (id: string) => document.getElementById(id)!.textContent;
const buttons = () =>
  [...document.querySelectorAll('#tpba-actions > *')] as HTMLElement[];
const button = (label: string) =>
  buttons().find((b) => b.textContent === label)!;

async function run(cfg = config()) {
  mount(cfg);
  const go = vi.fn();
  await runHandoffPage(window, document, go);
  return go;
}

beforeEach(() => {
  window.sessionStorage.clear();
  visit('');
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('built-in hand-off page', () => {
  it('rejects a link without a valid request', async () => {
    visit(request({ client_id: 'other.app' }));
    server({});
    await run();
    expect(text('tpba-title')).toBe('This sign-in link is not valid');
    expect(buttons()).toHaveLength(0);
  });

  it('rejects a loopback redirect that is not the local callback', async () => {
    for (const redirect of [
      'http://evil.example.com:4321/auth/callback',
      'http://127.0.0.1:4321/other',
      'http://127.0.0.1:80/auth/callback',
    ]) {
      window.sessionStorage.clear();
      visit(request({ redirect_uri: redirect }));
      server({});
      await run();
      expect(text('tpba-title'), redirect).toBe(
        'This sign-in link is not valid',
      );
    }
  });

  it('asks a signed-in user for consent, then hands the code to the app', async () => {
    const req = request();
    visit(req);
    const calls = server({
      '/get-session': { user: { id: 'u1', email: 'ada@example.com' } },
      '/tauri/authorize': { code: CODE },
    });
    const go = await run();

    // The request left the address bar but stays in this tab.
    expect(window.location.search).toBe('');
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toContain(req.state);

    expect(text('tpba-title')).toBe('Continue to Example?');
    expect(text('tpba-text')).toBe('You are signed in as ada@example.com.');
    expect(go).not.toHaveBeenCalled();

    button('Continue to Example').click();
    await vi.waitFor(() => expect(go).toHaveBeenCalled());
    expect(calls.at(-1)).toEqual({
      path: '/tauri/authorize',
      method: 'POST',
      body: {
        client_id: CLIENT_ID,
        state: req.state,
        code_challenge: req.code_challenge,
        code_challenge_method: 'S256',
      },
    });
    expect(go).toHaveBeenCalledWith(
      `com.example.app://auth/callback?code=${CODE}&state=${req.state}`,
    );
    expect(text('tpba-code')).toBe(CODE);
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('hands the code to a loopback redirect', async () => {
    const req = request({
      redirect_uri: 'http://127.0.0.1:4321/auth/callback',
    });
    visit(req);
    server({
      '/get-session': { user: { id: 'u1', name: 'Ada' } },
      '/tauri/authorize': { code: CODE },
    });
    const go = await run();
    expect(text('tpba-text')).toBe('You are signed in as Ada.');
    button('Continue to Example').click();
    await vi.waitFor(() =>
      expect(go).toHaveBeenCalledWith(
        `http://127.0.0.1:4321/auth/callback?code=${CODE}&state=${req.state}`,
      ),
    );
  });

  it('tells the app when the user cancels', async () => {
    const req = request();
    visit(req);
    server({ '/get-session': { user: { id: 'u1', email: 'a@b.c' } } });
    const go = await run();
    button('Cancel').click();
    expect(go).toHaveBeenCalledWith(
      `com.example.app://auth/callback?error=access_denied&state=${req.state}`,
    );
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('signs out to switch accounts and keeps the request', async () => {
    const req = request();
    visit(req);
    const calls = server({
      '/get-session': { user: { id: 'u1', email: 'a@b.c' } },
      '/sign-out': { success: true },
    });
    const go = await run();
    button('Use another account').click();
    await vi.waitFor(() => expect(go).toHaveBeenCalledWith(PAGE));
    expect(calls.at(-1)).toMatchObject({ path: '/sign-out', method: 'POST' });
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toContain(req.state);
  });

  it('starts the provider the app asked for, once', async () => {
    const req = request({ provider: 'github' });
    visit(req);
    const calls = server({
      '/get-session': null,
      '/sign-in/social': {
        url: 'https://github.com/login/oauth',
        redirect: true,
      },
    });
    const go = await run();
    expect(calls.at(-1)).toEqual({
      path: '/sign-in/social',
      method: 'POST',
      body: {
        provider: 'github',
        callbackURL: PAGE,
        newUserCallbackURL: PAGE,
        errorCallbackURL: PAGE,
        disableRedirect: true,
      },
    });
    expect(go).toHaveBeenCalledWith('https://github.com/login/oauth');

    // Back from GitHub with an error: offer the options instead of looping.
    visit('error=access_denied');
    const again = await run();
    expect(again).not.toHaveBeenCalled();
    expect(text('tpba-title')).toBe('Sign in to continue to Example');
    expect(text('tpba-text')).toContain('did not complete');
    expect(button('Continue with GitHub')).toBeDefined();
  });

  it('ignores a provider that is not offered', async () => {
    visit(request({ provider: 'gitlab' }));
    const calls = server({ '/get-session': null });
    const go = await run();
    expect(go).not.toHaveBeenCalled();
    expect(calls.map((c) => c.path)).toEqual(['/get-session']);
  });

  it('offers social buttons and your sign-in page to signed-out users', async () => {
    visit(request());
    server({ '/get-session': null });
    await run(config({ signInURL: 'https://example.com/login?x=1' }));
    expect(buttons().map((b) => b.textContent)).toEqual([
      'Continue with GitHub',
      'Other sign-in options',
      'Cancel',
    ]);
    const link = button('Other sign-in options') as HTMLAnchorElement;
    const url = new URL(link.href);
    expect(url.origin + url.pathname).toBe('https://example.com/login');
    expect(url.searchParams.get('x')).toBe('1');
    expect(url.searchParams.get('callbackURL')).toBe(PAGE);
  });

  it('keeps the request across reloads in the same tab, until it expires', async () => {
    const req = request();
    visit(req);
    server({ '/get-session': { user: { id: 'u1', email: 'a@b.c' } } });
    await run();

    visit('');
    await run();
    expect(text('tpba-title')).toBe('Continue to Example?');

    const stored = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY)!);
    stored.capturedAt -= 601_000;
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
    await run();
    expect(text('tpba-title')).toBe('This sign-in link is not valid');
  });

  it('re-validates a stored request', async () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        state: newState(),
        codeChallenge: pkce().challenge,
        redirectUri: 'https://evil.example.com/steal',
        provider: null,
        capturedAt: Date.now(),
      }),
    );
    server({ '/get-session': { user: { id: 'u1' } } });
    await run();
    expect(text('tpba-title')).toBe('This sign-in link is not valid');
  });

  it('shows server errors from authorize as text', async () => {
    visit(request());
    server({
      '/get-session': { user: { id: 'u1', email: 'a@b.c' } },
      '/tauri/authorize': new Response(
        JSON.stringify({ message: '<img src=x onerror=alert(1)>' }),
        { status: 403 },
      ),
    });
    const go = await run();
    button('Continue to Example').click();
    await vi.waitFor(() =>
      expect(text('tpba-title')).toBe('Something went wrong'),
    );
    expect(text('tpba-text')).toBe('<img src=x onerror=alert(1)>');
    expect(document.querySelector('img')).toBeNull();
    expect(go).not.toHaveBeenCalled();
  });

  it('runs as the serialized script in the page', async () => {
    // The HTML embeds runHandoffPage.toString(): it must not need anything
    // from this module.
    const html = renderHandoffPage(config(), 'n');
    const script = /<script nonce="n">([\s\S]*?)<\/script>/.exec(html)![1]!;
    mount(config());
    visit(request({ client_id: 'other.app' }));
    server({});
    await new Function(
      'window',
      'document',
      `return ${script.replace(/;$/, '')}`,
    )(window, document);
    expect(text('tpba-title')).toBe('This sign-in link is not valid');
  });
});
