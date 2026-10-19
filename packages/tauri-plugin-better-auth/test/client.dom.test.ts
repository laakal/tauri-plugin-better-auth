import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { createAuthClient } from 'better-auth/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  isTauriAuthError,
  onAuthenticated,
  onSignedOut,
  requestAuth,
  tauriFetch,
  TauriAuthError,
  withTauri,
} from '../src/client/index';

type Call = { cmd: string; payload: Record<string, unknown> | undefined };

let calls: Call[] = [];

function mock(handler: (cmd: string, payload: any) => unknown) {
  calls = [];
  mockIPC(
    (cmd, payload) => {
      calls.push({ cmd, payload: payload as Record<string, unknown> });
      return handler(cmd, payload);
    },
    { shouldMockEvents: true },
  );
}

function bridged(
  status: number,
  body: unknown,
  headers: [string, string][] = [['content-type', 'application/json']],
) {
  return {
    status,
    statusText: 'OK',
    headers,
    body:
      body === null
        ? null
        : {
            encoding: 'text',
            data: typeof body === 'string' ? body : JSON.stringify(body),
          },
  };
}

beforeEach(() => {
  (globalThis as { isTauri?: boolean }).isTauri = true;
});

afterEach(() => {
  clearMocks();
  vi.restoreAllMocks();
});

describe('tauriFetch', () => {
  it('sends the request through the bridge and rebuilds the response', async () => {
    mock((cmd) =>
      cmd === 'plugin:better-auth|fetch'
        ? bridged(201, { ok: true }, [
            ['content-type', 'application/json'],
            ['x-request-id', 'r1'],
          ])
        : null,
    );
    const response = await tauriFetch('https://api.example.com/api/things', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-trace': 't1' },
      body: JSON.stringify({ name: 'a' }),
    });
    expect(response.status).toBe(201);
    expect(response.headers.get('x-request-id')).toBe('r1');
    expect(await response.json()).toEqual({ ok: true });

    const request = calls[0]!.payload!.request as {
      url: string;
      method: string;
      headers: [string, string][];
      body: unknown;
    };
    expect(request.url).toBe('https://api.example.com/api/things');
    expect(request.method).toBe('POST');
    expect(request.headers).toContainEqual(['x-trace', 't1']);
    expect(request.body).toEqual({ encoding: 'text', data: '{"name":"a"}' });
  });

  it('round-trips binary bodies as base64', async () => {
    mock(() => ({
      status: 200,
      statusText: 'OK',
      headers: [['content-type', 'image/png']],
      body: {
        encoding: 'base64',
        data: btoa(String.fromCharCode(137, 80, 78, 71)),
      },
    }));
    const response = await tauriFetch('https://api.example.com/api/avatar', {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
      body: new Uint8Array([0, 1, 2, 255]),
    });
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(
      new Uint8Array([137, 80, 78, 71]),
    );
    const request = calls[0]!.payload!.request as {
      body: { encoding: string; data: string };
    };
    expect(request.body).toEqual({
      encoding: 'base64',
      data: btoa(String.fromCharCode(0, 1, 2, 255)),
    });
  });

  it('returns a null body for 204', async () => {
    mock(() => bridged(204, null, []));
    const response = await tauriFetch('https://api.example.com/api/thing', {
      method: 'DELETE',
    });
    expect(response.status).toBe(204);
    expect(response.body).toBeNull();
  });

  it('rejects network failures with a TypeError, like fetch', async () => {
    mock(() => {
      throw {
        code: 'NETWORK',
        message: 'could not connect to the auth server',
      };
    });
    await expect(tauriFetch('https://api.example.com/api/x')).rejects.toThrow(
      TypeError,
    );
  });

  it('cancels the bridged request on abort', async () => {
    let release: (value: unknown) => void = () => {};
    mock((cmd) => {
      if (cmd === 'plugin:better-auth|fetch') {
        return new Promise((resolve) => {
          release = resolve;
        });
      }
      return null;
    });
    const controller = new AbortController();
    const pending = tauriFetch('https://api.example.com/api/slow', {
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    controller.abort();
    release({ code: 'ABORTED', message: 'aborted' });
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(calls.map((c) => c.cmd)).toContain(
      'plugin:better-auth|fetch_cancel',
    );
    const cancel = calls.find(
      (c) => c.cmd === 'plugin:better-auth|fetch_cancel',
    );
    expect(cancel!.payload!.id).toBe(
      (calls[0]!.payload!.request as { id: number }).id,
    );
  });
});

describe('commands and events', () => {
  it('maps plugin errors to TauriAuthError', async () => {
    mock(() => {
      throw { code: 'OPEN_BROWSER_FAILED', message: 'no browser' };
    });
    const error = await requestAuth().catch((e: unknown) => e);
    expect(isTauriAuthError(error)).toBe(true);
    expect((error as TauriAuthError).code).toBe('OPEN_BROWSER_FAILED');
  });

  it('passes options to request_auth', async () => {
    mock(() => ({ url: 'http://x', opened: true, transport: 'loopback' }));
    await requestAuth({ provider: 'github', transport: 'loopback' });
    expect(calls[0]).toEqual({
      cmd: 'plugin:better-auth|request_auth',
      payload: { options: { provider: 'github', transport: 'loopback' } },
    });
  });

  it('delivers authenticated and signed-out events', async () => {
    mock(() => null);
    const users: unknown[] = [];
    const reasons: unknown[] = [];
    await onAuthenticated((user) => users.push(user));
    await onSignedOut((event) => reasons.push(event.reason));
    await emit('better-auth://authenticated', { user: { id: 'u1' } });
    await emit('better-auth://signed-out', { reason: 'revoked' });
    expect(users).toEqual([{ id: 'u1' }]);
    expect(reasons).toEqual(['revoked']);
  });
});

describe('withTauri', () => {
  const baseURL = 'https://api.example.com/api/auth';

  it('routes Better Auth through the bridge with redirects disabled', () => {
    const options = withTauri({ baseURL, fetchOptions: { timeout: 5000 } });
    expect(options.disableDefaultFetchPlugins).toBe(true);
    expect(options.fetchOptions.customFetchImpl).toBe(tauriFetch);
    expect(options.fetchOptions).toMatchObject({ timeout: 5000 });
    expect(options.plugins.map((p) => p.id)).toEqual(['tauri']);
  });

  it('never navigates the webview on { url, redirect: true }', async () => {
    mock((cmd) =>
      cmd === 'plugin:better-auth|fetch'
        ? bridged(200, {
            url: 'https://evil.example/',
            redirect: true,
            user: { id: 'u1' },
          })
        : null,
    );
    const before = window.location.href;
    const client = createAuthClient(withTauri({ baseURL }));
    await client.signIn.email({
      email: 'a@example.com',
      password: 'secret-1234',
    });
    expect(window.location.href).toBe(before);
    const request = calls.find((c) => c.cmd === 'plugin:better-auth|fetch')!
      .payload!.request as { url: string };
    expect(request.url).toBe(`${baseURL}/sign-in/email`);
  });

  it('refreshes useSession when a browser sign-in completes', async () => {
    let signedIn = false;
    mock((cmd, payload) => {
      if (cmd !== 'plugin:better-auth|fetch') return null;
      const { url } = payload.request as { url: string };
      if (url.endsWith('/get-session')) {
        return bridged(
          200,
          signedIn ? { session: { id: 's1' }, user: { id: 'u1' } } : null,
        );
      }
      return bridged(404, {});
    });
    const client = createAuthClient(withTauri({ baseURL }));
    const seen: unknown[] = [];
    const unsubscribe = client.useSession.subscribe((state) => {
      if (!state.isPending) seen.push(state.data);
    });
    await vi.waitFor(() => expect(seen).toContainEqual(null));

    signedIn = true;
    await emit('better-auth://authenticated', { user: { id: 'u1' } });
    await vi.waitFor(() =>
      expect(seen).toContainEqual({
        session: { id: 's1' },
        user: { id: 'u1' },
      }),
    );
    unsubscribe();
  });
});
