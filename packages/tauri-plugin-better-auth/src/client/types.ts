/**
 * Types that describe a Better Auth client as it behaves inside a Tauri
 * webview: sessions carry no token, and only the operations the Rust bridge
 * allows are present.
 */

/** A `{ session, user }` pair without `session.token`. */
export type Tokenless<T> = T extends { session: infer S; user: infer U }
  ? { session: Omit<S, 'token'>; user: U }
  : T;

type TokenlessData<D> = D extends { session: unknown; user: unknown }
  ? Tokenless<D>
  : D;

/** Maps `{ data: … }` (a hook result or a fetch response) to tokenless data. */
type MapData<T> = T extends { data: infer D }
  ? Omit<T, 'data'> & { data: TokenlessData<D> }
  : T;

/** React/Vue/Svelte hooks are functions; the vanilla client exposes an atom. */
type MapUseSession<U> = U extends (...args: infer A) => infer R
  ? (...args: A) => MapData<R>
  : U extends { get(): infer V }
    ? Omit<U, 'get' | 'value' | 'subscribe' | 'listen'> & {
        get(): MapData<V>;
        readonly value: MapData<V> | undefined;
        subscribe(listener: (value: MapData<V>) => void): () => void;
        listen(listener: (value: MapData<V>) => void): () => void;
      }
    : U;

type MapGetSession<G> = G extends (...args: infer A) => Promise<infer R>
  ? (...args: A) => Promise<MapData<R>>
  : G;

type Restrict<T, K extends string> = T extends object
  ? Pick<T, Extract<keyof T, K>>
  : never;

/** Sign-in methods the bridge accepts by default. */
export type TauriSignInMethod = 'email' | 'emailOtp';

/**
 * Client actions the bridge refuses: they read or mint credentials, or need
 * browser redirects. Use `authClient.tauri.requestAuth()` for browser flows.
 */
export type TauriUnsupportedAction =
  | 'listSessions'
  | 'revokeSession'
  | 'revokeSessions'
  | 'revokeOtherSessions'
  | 'oneTimeToken'
  | 'linkSocial'
  | 'unlinkAccount'
  | 'getAccessToken'
  | 'refreshToken'
  | 'accountInfo'
  | 'multiSession'
  | 'token';

/**
 * A Better Auth client as seen in the Tauri webview: tokenless sessions,
 * in-app sign-in limited to `email` and `emailOtp` (plus `ExtraSignIn`, for
 * routes you allowed in Rust with `Builder::auth_route`).
 */
export type TauriAuthClient<C, ExtraSignIn extends string = never> = Omit<
  C,
  | 'useSession'
  | 'getSession'
  | 'hydrateSession'
  | '$Infer'
  | 'signIn'
  | 'signUp'
  | TauriUnsupportedAction
> & {
  useSession: C extends { useSession: infer U } ? MapUseSession<U> : never;
  getSession: C extends { getSession: infer G } ? MapGetSession<G> : never;
  signIn: C extends { signIn: infer S }
    ? Restrict<S, TauriSignInMethod | ExtraSignIn>
    : never;
  signUp: C extends { signUp: infer S } ? Restrict<S, 'email'> : never;
  $Infer: (C extends { $Infer: infer I } ? Omit<I, 'Session'> : {}) & {
    Session: C extends { $Infer: { Session: infer S } } ? Tokenless<S> : never;
  };
};

/**
 * Narrows a client created with `withTauri` to {@link TauriAuthClient}.
 * Runtime no-op: the bridge already enforces all of this.
 */
export function asTauriClient<C, ExtraSignIn extends string = never>(
  client: C,
): TauriAuthClient<C, ExtraSignIn> {
  return client as unknown as TauriAuthClient<C, ExtraSignIn>;
}
