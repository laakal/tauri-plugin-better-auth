import { invoke } from '@tauri-apps/api/core';

type BridgeBody =
  | { encoding: 'text'; data: string }
  | { encoding: 'base64'; data: string };

interface BridgeResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  body: BridgeBody | null;
}

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);
const MAX_ID = 0xffff_ffff;
let nextId = 1;

function takeId(): number {
  const id = nextId;
  nextId = nextId >= MAX_ID ? 1 : nextId + 1;
  return id;
}

function isTextual(contentType: string | null): boolean {
  if (!contentType) return false;
  const value = contentType.toLowerCase();
  return (
    value.startsWith('text/') ||
    value.includes('json') ||
    value.includes('xml') ||
    value.includes('javascript') ||
    value.includes('x-www-form-urlencoded')
  );
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(data: string): Uint8Array<ArrayBuffer> {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function encodeBody(request: Request): Promise<BridgeBody | null> {
  if (request.method === 'GET' || request.method === 'HEAD') return null;
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength === 0) return null;
  if (isTextual(request.headers.get('content-type'))) {
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return { encoding: 'text', data: text };
    } catch {
      // Not valid UTF-8 after all: send the raw bytes.
    }
  }
  return { encoding: 'base64', data: toBase64(bytes) };
}

function abortError(signal: AbortSignal | null | undefined): unknown {
  return (
    signal?.reason ??
    new DOMException('The operation was aborted.', 'AbortError')
  );
}

/**
 * A `fetch` that sends the request through the plugin's Rust bridge.
 *
 * Rust adds the session's bearer token and your app headers, refuses anything
 * outside the configured auth operations and API routes, never follows
 * redirects, and strips `set-cookie`/`set-auth-token` from responses. The
 * webview never sees a token.
 *
 * Use it as Better Auth's `customFetchImpl` (see `withTauri`) and as the
 * `fetch` of your API client. Bodies are buffered (no streaming).
 */
export const tauriFetch: typeof fetch = async (input, init) => {
  const request = new Request(input, init);
  const signal = init?.signal ?? request.signal;
  if (signal?.aborted) throw abortError(signal);

  const id = takeId();
  const headers: [string, string][] = [];
  request.headers.forEach((value, name) => headers.push([name, value]));
  const body = await encodeBody(request);

  const onAbort = () => {
    void invoke('plugin:better-auth|fetch_cancel', { id }).catch(() => {});
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    const response = await invoke<BridgeResponse>('plugin:better-auth|fetch', {
      request: { id, url: request.url, method: request.method, headers, body },
    });
    const payload =
      response.body === null || NULL_BODY_STATUSES.has(response.status)
        ? null
        : response.body.encoding === 'text'
          ? response.body.data
          : fromBase64(response.body.data);
    return new Response(payload, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch (error) {
    if (signal?.aborted) throw abortError(signal);
    const code =
      typeof error === 'object' && error !== null && 'code' in error
        ? String(error.code)
        : undefined;
    if (code === 'ABORTED') throw abortError(signal);
    // Like a browser fetch: network failures reject with a TypeError.
    const message =
      typeof error === 'object' && error !== null && 'message' in error
        ? String(error.message)
        : String(error);
    throw new TypeError(`Failed to fetch: ${message}`, { cause: error });
  } finally {
    signal?.removeEventListener('abort', onAbort);
  }
};
