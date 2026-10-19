import { describe, expect, it, vi } from 'vitest';

import { tauriProxyClient } from '../src/proxy';

describe('tauriProxyClient on the server (no window)', () => {
  const tauri = tauriProxyClient({ scheme: 'com.example.app' }).getActions(
    vi.fn() as never,
  ).tauri;

  it('reports no request instead of throwing', () => {
    expect(typeof window).toBe('undefined');
    expect(tauri.getRequest()).toEqual({ status: 'none' });
    expect(tauri.cancelLink()).toBeNull();
    expect(() => tauri.clear()).not.toThrow();
  });

  it('rejects invalid options at construction', () => {
    expect(() => tauriProxyClient({ scheme: 'https' })).toThrow();
    expect(() =>
      tauriProxyClient({ scheme: 'com.example.app', callbackPath: '/a b' }),
    ).toThrow();
  });
});
