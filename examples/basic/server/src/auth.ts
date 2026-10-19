import { betterAuth } from 'better-auth';
import { bearer, emailOTP } from 'better-auth/plugins';
import { Database } from 'bun:sqlite';
import { tauri } from 'tauri-plugin-better-auth';

/** Where this server runs. The hand-off page is served from the same origin. */
export const ORIGIN = process.env.EXAMPLE_ORIGIN ?? 'http://localhost:3000';

/** Shared with the Tauri app (`src-tauri/src/lib.rs`) and the hand-off page. */
export const CLIENT_ID = 'com.example.betterauth';

/** Development only: the last code sent to each address. */
export const latestOtp = new Map<string, string>();

export const auth = betterAuth({
  baseURL: ORIGIN,
  secret:
    process.env.BETTER_AUTH_SECRET ??
    'development-only-secret-change-me-0123456789',
  database: new Database(process.env.EXAMPLE_DB ?? 'example.db'),
  trustedOrigins: [ORIGIN],
  emailAndPassword: { enabled: true },
  plugins: [
    // The Tauri app authenticates with `Authorization: Bearer`.
    bearer(),
    emailOTP({
      async sendVerificationOTP({ email, otp }) {
        // Development only: a real app sends an email and never logs codes.
        latestOtp.set(email, otp);
        console.log(`[example] sign-in code for ${email}: ${otp}`);
      },
    }),
    // Only the hand-off page (this origin) may authorize desktop sign-ins.
    tauri({ clientID: CLIENT_ID, authorizeOrigins: [ORIGIN] }),
  ],
});
