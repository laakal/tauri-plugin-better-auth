/**
 * Compile-time guarantees of the Tauri client types. Checked by
 * `bun run typecheck`, never bundled. A failing expectation is a type error.
 */
import { createAuthClient } from 'better-auth/client';
import { emailOTPClient } from 'better-auth/client/plugins';

import { asTauriClient, withTauri } from './index';

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false;
type Expect<T extends true> = T;
type Has<T, K extends PropertyKey> = K extends keyof T ? true : false;

const client = asTauriClient(
  createAuthClient(
    withTauri({
      baseURL: 'http://localhost:3000/api/auth',
      plugins: [emailOTPClient()],
    }),
  ),
);

type Session = typeof client.$Infer.Session;

export type Checks = [
  // Sessions never advertise the token…
  Expect<Equal<Has<Session['session'], 'token'>, false>>,
  // …but keep everything else.
  Expect<Equal<Has<Session['session'], 'id'>, true>>,
  Expect<Equal<Has<Session['user'], 'email'>, true>>,
  // In-app sign-in: only what the bridge allows.
  Expect<Equal<Has<typeof client.signIn, 'email'>, true>>,
  Expect<Equal<Has<typeof client.signIn, 'emailOtp'>, true>>,
  Expect<Equal<Has<typeof client.signIn, 'social'>, false>>,
  // Credential-reading actions are gone.
  Expect<Equal<Has<typeof client, 'listSessions'>, false>>,
  Expect<Equal<Has<typeof client, 'revokeSessions'>, false>>,
  // Plugin actions stay.
  Expect<Equal<Has<typeof client, 'emailOtp'>, true>>,
  Expect<Equal<Has<typeof client, 'tauri'>, true>>,
];

export async function getSessionIsTokenless(): Promise<void> {
  const { data } = await client.getSession();
  if (data) {
    void data.session.id;
    // @ts-expect-error the token never reaches the webview
    void data.session.token;
  }
}

export function useSessionIsTokenless(): void {
  const state = client.useSession.get();
  if (state.data) {
    void state.data.user.email;
    // @ts-expect-error the token never reaches the webview
    void state.data.session.token;
  }
}

export async function tauriActionsAreTyped(): Promise<void> {
  const result = await client.tauri.requestAuth({ provider: 'github' });
  void result.opened;
  // @ts-expect-error unknown transport
  await client.tauri.requestAuth({ transport: 'carrier-pigeon' });
}
