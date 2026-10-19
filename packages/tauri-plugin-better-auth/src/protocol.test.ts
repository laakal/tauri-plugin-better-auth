import { describe, expect, it } from 'vitest';

import {
  assertClientId,
  assertScheme,
  buildCallbackUrl,
  isLoopbackRedirectUri,
  isValidScheme,
  normalizeCallbackPath,
  TauriConfigError,
} from './protocol';

describe('isValidScheme', () => {
  it.each(['com.example.app', 'linequery', 'my-app', 'app+test'])(
    'accepts %s',
    (scheme) => expect(isValidScheme(scheme)).toBe(true),
  );

  it.each([
    'http',
    'https',
    'file',
    'javascript',
    'tauri',
    'ipc',
    'asset',
    'data',
    'Com.Example',
    '1app',
    'a',
    'app scheme',
    'app/x',
  ])('rejects %s', (scheme) => expect(isValidScheme(scheme)).toBe(false));

  it('assertScheme throws a TauriConfigError with guidance', () => {
    expect(() => assertScheme('https')).toThrow(TauriConfigError);
    expect(() => assertScheme('https')).toThrow(/RFC 8252/);
  });
});

describe('normalizeCallbackPath', () => {
  it('adds the leading slash', () => {
    expect(normalizeCallbackPath('auth/callback')).toBe('/auth/callback');
  });

  it.each([
    '/',
    '//',
    '/auth//callback',
    '/auth/callback/',
    '/a?b',
    '/a#b',
    '/a b',
  ])('rejects %s', (path) =>
    expect(() => normalizeCallbackPath(path)).toThrow(TauriConfigError),
  );

  it('rejects paths longer than 64 characters', () => {
    expect(() => normalizeCallbackPath(`/${'a'.repeat(64)}`)).toThrow();
  });
});

describe('assertClientId', () => {
  it('accepts reverse-DNS ids', () => {
    expect(assertClientId('com.example.app')).toBe('com.example.app');
  });

  it.each(['', 'has space', 'x'.repeat(65), 'a/b'])('rejects %j', (id) =>
    expect(() => assertClientId(id)).toThrow(TauriConfigError),
  );
});

describe('isLoopbackRedirectUri', () => {
  const path = '/auth/callback';

  it.each([
    'http://127.0.0.1:49152/auth/callback',
    'http://[::1]:61000/auth/callback',
  ])('accepts %s', (uri) =>
    expect(isLoopbackRedirectUri(uri, path)).toBe(true),
  );

  it.each([
    ['https', 'https://127.0.0.1:49152/auth/callback'],
    ['localhost name', 'http://localhost:49152/auth/callback'],
    ['remote host', 'http://evil.example:49152/auth/callback'],
    ['no port', 'http://127.0.0.1/auth/callback'],
    ['privileged port', 'http://127.0.0.1:80/auth/callback'],
    ['userinfo', 'http://user@127.0.0.1:49152/auth/callback'],
    ['query', 'http://127.0.0.1:49152/auth/callback?x=1'],
    ['empty query', 'http://127.0.0.1:49152/auth/callback?'],
    ['fragment', 'http://127.0.0.1:49152/auth/callback#x'],
    ['wrong path', 'http://127.0.0.1:49152/other'],
    ['path prefix', 'http://127.0.0.1:49152/auth/callback/x'],
    ['decimal host trick', 'http://2130706433:49152/auth/callback'],
    ['not a URL', 'not a url'],
  ])('rejects %s', (_, uri) =>
    expect(isLoopbackRedirectUri(uri, path)).toBe(false),
  );
});

describe('buildCallbackUrl', () => {
  it('builds a custom-scheme callback with the path as host + path', () => {
    const url = buildCallbackUrl(
      {
        kind: 'scheme',
        scheme: 'com.example.app',
        callbackPath: '/auth/callback',
      },
      { code: 'abc', state: 'state-value-123456' },
    );
    expect(url).toBe(
      'com.example.app://auth/callback?code=abc&state=state-value-123456',
    );
    const parsed = new URL(url);
    expect(parsed.host).toBe('auth');
    expect(parsed.pathname).toBe('/callback');
  });

  it('builds a loopback callback', () => {
    expect(
      buildCallbackUrl(
        {
          kind: 'loopback',
          redirectUri: 'http://127.0.0.1:50000/auth/callback',
        },
        { error: 'access_denied', state: 's' },
      ),
    ).toBe('http://127.0.0.1:50000/auth/callback?error=access_denied&state=s');
  });

  it('percent-encodes parameter values', () => {
    const url = buildCallbackUrl(
      { kind: 'scheme', scheme: 'app', callbackPath: '/cb' },
      { code: 'a&b=c', state: '~._-' },
    );
    expect(url).toBe('app://cb?code=a%26b%3Dc&state=%7E._-');
  });
});
