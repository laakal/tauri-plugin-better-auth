/**
 * The built-in hand-off page (`GET /tauri/handoff`). Point the Rust plugin's
 * `sign_in_url` at `<baseURL>/tauri/handoff`.
 */
export interface TauriHandoffPageOptions {
  /** Your app's name, shown as "Continue to <appName>". */
  appName: string;
  /** The app's custom URI scheme. Must match the Rust plugin. */
  scheme: string;
  /**
   * Must match the Rust plugin.
   *
   * @default "/auth/callback"
   */
  callbackPath?: string | undefined;
  /**
   * Social providers offered to signed-out users, and the ones
   * `requestAuth({ provider })` may start: `true` for every provider in your
   * `socialProviders`, a list of provider ids, or `false` for none.
   *
   * @default true
   */
  socialProviders?: boolean | string[] | undefined;
  /**
   * Your own sign-in page, offered to signed-out users (email and password,
   * passkeys, 2FA…). It receives this page's URL in `signInCallbackParam`;
   * send the user back there once they are signed in.
   */
  signInURL?: string | undefined;
  /**
   * Query parameter of `signInURL` that carries the return URL.
   *
   * @default "callbackURL"
   */
  signInCallbackParam?: string | undefined;
}

/** Options of the {@link tauri} server plugin. */
export interface TauriOptions {
  /**
   * Identifies the desktop app. Must match the Rust plugin and the hand-off
   * page client.
   *
   * @default "tauri"
   */
  clientID?: string | undefined;
  /**
   * Seconds an authorization code stays valid. Codes are single-use.
   *
   * @default 300
   */
  codeExpiresIn?: number | undefined;
  /**
   * Origins allowed to call `POST /tauri/authorize`, normally just the origin
   * of your hand-off page. When unset, any origin Better Auth trusts may call
   * it, which widens the attack surface to every trusted site.
   */
  authorizeOrigins?: string[] | undefined;
  /**
   * Rate limit for both `/tauri/*` endpoints, per client IP. Better Auth only
   * enforces rate limits when its own `rateLimit` is enabled (by default in
   * production). Pass `false` to rely on your global rules instead.
   *
   * @default { window: 60, max: 10 }
   */
  rateLimit?: { window: number; max: number } | false | undefined;
  /**
   * Serves a ready-made hand-off page at `GET /tauri/handoff`, so you do not
   * have to build one with `tauriProxyClient`. Its own origin may always call
   * `/tauri/authorize`.
   */
  handoffPage?: TauriHandoffPageOptions | undefined;
}

/** Resolved {@link TauriHandoffPageOptions}. */
export interface ResolvedHandoffPage {
  appName: string;
  scheme: string;
  callbackPath: string;
  socialProviders: boolean | string[];
  signInURL: string | null;
  signInCallbackParam: string;
}

/** Fully resolved options, exposed as `plugin.options`. */
export interface ResolvedTauriOptions {
  clientID: string;
  codeExpiresIn: number;
  authorizeOrigins: string[] | undefined;
  rateLimit: { window: number; max: number } | false;
  handoffPage: ResolvedHandoffPage | undefined;
}
