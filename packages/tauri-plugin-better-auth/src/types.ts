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
}

/** Fully resolved options, exposed as `plugin.options`. */
export interface ResolvedTauriOptions {
  clientID: string;
  codeExpiresIn: number;
  authorizeOrigins: string[] | undefined;
  rateLimit: { window: number; max: number } | false;
}
