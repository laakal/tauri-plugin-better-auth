import { Channel, invoke } from '@tauri-apps/api/core';

type BridgeBody =
  | { encoding: 'text'; data: string }
  | { encoding: 'base64'; data: string };

interface BridgeResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  body: BridgeBody | null;
  /** The body follows on the channel (`fetch_stream`, app API routes). */
  streamed?: boolean;
}

/** A streamed body: raw chunks, then an end or an error message. */
type StreamMessage =
  | ArrayBuffer
  | ArrayBufferView
  | number[]
  | { event: 'end' }
  | { event: 'error'; code: string; message: string };

/** The bytes of a chunk (an `ArrayBuffer`, or a number array on IPC fallbacks). */
function chunkBytes(message: StreamMessage): Uint8Array | null {
  if (message instanceof ArrayBuffer) return new Uint8Array(message);
  if (ArrayBuffer.isView(message)) {
    return new Uint8Array(
      message.buffer.slice(
        message.byteOffset,
        message.byteOffset + message.byteLength,
      ),
    );
  }
  if (Array.isArray(message)) return Uint8Array.from(message);
  return null;
}

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);
const MAX_ID = 0xffff_ffff;
let nextId = 1;

/**
 * Set once `fetch_stream` is refused: an older crate without it, or a
 * capability that lists commands without `allow-fetch-stream`. Requests then
 * use the buffered `fetch`, as before streaming existed.
 */
let streamingUnavailable = false;

function isStreamRefused(error: unknown): boolean {
  return typeof error === 'string' && /fetch[_-]stream not allowed/.test(error);
}

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

/** Like a browser fetch: network failures reject with a TypeError. */
function networkError(error: unknown): TypeError {
  const message =
    typeof error === 'object' && error !== null && 'message' in error
      ? String(error.message)
      : String(error);
  return new TypeError(`Failed to fetch: ${message}`, { cause: error });
}

function bufferedPayload(
  response: BridgeResponse,
): string | Uint8Array<ArrayBuffer> | null {
  if (response.body === null || NULL_BODY_STATUSES.has(response.status)) {
    return null;
  }
  return response.body.encoding === 'text'
    ? response.body.data
    : fromBase64(response.body.data);
}

/**
 * A body fed by the Rust bridge. Chunks may arrive before `fetch_stream`
 * answers; the stream queues them until the response is read. The channel is
 * created only when `fetch_stream` is tried.
 */
function bridgeStream(onDone: () => void, onCancel: () => void) {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let done = false;
  const finish = (action: () => void) => {
    if (done) return;
    done = true;
    action();
    onDone();
  };
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
    },
    cancel() {
      finish(onCancel);
    },
  });
  const channel = () =>
    new Channel<StreamMessage>((message) => {
      if (done) return;
      const chunk = chunkBytes(message);
      if (chunk) {
        controller.enqueue(chunk);
      } else if ('event' in message && message.event === 'end') {
        finish(() => controller.close());
      } else {
        finish(() => controller.error(networkError(message)));
      }
    });
  return {
    stream,
    channel,
    /** The body broke off (abort, network failure). */
    fail: (reason: unknown) => finish(() => controller.error(reason)),
    /** The response was not streamed: this body is never used. */
    dispose: () => finish(() => controller.close()),
  };
}

/** Options for {@link createTauriFetch}. */
export interface TauriFetchOptions {
  /**
   * Stream app API response bodies (default `true`). With `false`, every
   * response is read whole in Rust before the promise resolves: errors
   * surface at the call instead of while reading the body, and API responses
   * are capped at 16 MiB.
   */
  stream?: boolean;
}

/**
 * Creates a `fetch` that sends requests through the plugin's Rust bridge.
 * {@link tauriFetch} is `createTauriFetch()`; use this for a variant, such as
 * a buffered client: `createTauriFetch({ stream: false })`.
 */
export function createTauriFetch(
  options: TauriFetchOptions = {},
): typeof fetch {
  const stream = options.stream ?? true;
  return async (input, init) => {
    const request = new Request(input, init);
    const signal = init?.signal ?? request.signal;
    if (signal?.aborted) throw abortError(signal);

    const id = takeId();
    const headers: [string, string][] = [];
    request.headers.forEach((value, name) => headers.push([name, value]));
    const bridged = {
      id,
      url: request.url,
      method: request.method,
      headers,
      body: await encodeBody(request),
    };

    const cancel = () => {
      void invoke('plugin:better-auth|fetch_cancel', { id }).catch(() => {});
    };
    const body = bridgeStream(
      () => signal?.removeEventListener('abort', onAbort),
      cancel,
    );
    function onAbort() {
      cancel();
      body.fail(abortError(signal));
    }
    signal?.addEventListener('abort', onAbort, { once: true });

    try {
      const response = await send(bridged, stream ? body.channel : null);
      if (!response.streamed) {
        body.dispose();
        return new Response(bufferedPayload(response), {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      }
      return new Response(body.stream, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } catch (error) {
      body.fail(error);
      if (signal?.aborted) throw abortError(signal);
      const code =
        typeof error === 'object' && error !== null && 'code' in error
          ? String(error.code)
          : undefined;
      if (code === 'ABORTED') throw abortError(signal);
      throw networkError(error);
    }
  };
}

/**
 * A `fetch` that sends the request through the plugin's Rust bridge.
 *
 * Rust adds the session's bearer token and your app headers, refuses anything
 * outside the configured auth operations and API routes, never follows
 * redirects, and strips `set-cookie`/`set-auth-token` from responses. The
 * webview never sees a token.
 *
 * App API responses stream: the promise resolves once the headers arrive and
 * the body is read as it comes in (SSE, AI SDK streams). Auth responses are
 * read whole, since Rust scrubs them first. Request bodies are buffered. For
 * a client that reads every response whole, use
 * `createTauriFetch({ stream: false })`.
 *
 * Use it as Better Auth's `customFetchImpl` (see `withTauri`) and as the
 * `fetch` of your API client.
 */
export const tauriFetch: typeof fetch = createTauriFetch();

/** Tries `fetch_stream` when a channel is given, else the buffered `fetch`. */
async function send(
  request: Record<string, unknown>,
  channel: (() => Channel<StreamMessage>) | null,
): Promise<BridgeResponse> {
  if (channel && !streamingUnavailable) {
    try {
      return await invoke<BridgeResponse>('plugin:better-auth|fetch_stream', {
        request,
        channel: channel(),
      });
    } catch (error) {
      if (!isStreamRefused(error)) throw error;
      streamingUnavailable = true;
    }
  }
  return invoke<BridgeResponse>('plugin:better-auth|fetch', { request });
}
