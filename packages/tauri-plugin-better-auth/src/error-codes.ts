import { defineErrorCodes } from '@better-auth/core/utils/error-codes';

/**
 * Error codes returned by the `/tauri/*` endpoints. Stable within protocol v1:
 * the Rust plugin and apps switch on `code`, never on `message`.
 */
export const TAURI_ERROR_CODES = defineErrorCodes({
  INVALID_CLIENT_ID: 'Unknown client id',
  ORIGIN_NOT_ALLOWED: 'This origin may not authorize a desktop sign-in',
  INVALID_STATE: 'Invalid state parameter',
  INVALID_CODE_CHALLENGE: 'Invalid PKCE code challenge (S256 required)',
  INVALID_CODE_VERIFIER: 'Invalid PKCE code verifier',
  INVALID_OR_EXPIRED_CODE: 'Invalid or expired authorization code',
  STATE_MISMATCH: 'State does not match the authorization request',
  PKCE_VERIFICATION_FAILED: 'PKCE verification failed',
  USER_NOT_FOUND: 'The user for this authorization no longer exists',
  SESSION_REJECTED: 'The server rejected the new session',
});
