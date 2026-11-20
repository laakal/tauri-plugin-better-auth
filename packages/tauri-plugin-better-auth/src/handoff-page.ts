/**
 * The built-in hand-off page, `GET /tauri/handoff`: a consent page served by
 * the server plugin, so an app does not have to build its own (see the
 * README's "Hand-off page" for building one with `tauriProxyClient`).
 *
 * The page logic is {@link runHandoffPage}, a self-contained function that is
 * serialized into the HTML: it may use only its parameters and browser
 * globals, never imports or module-level values.
 */

/** Data the page script reads from `<script id="tpba-config">`. */
export interface HandoffPageConfig {
  appName: string;
  scheme: string;
  callbackPath: string;
  clientID: string;
  protocolVersion: number;
  /** Path of the Better Auth handler on this origin, e.g. `/api/auth`. */
  authBase: string;
  signInURL: string | null;
  signInCallbackParam: string;
  providers: { id: string; name: string }[];
  /** Seconds a captured request survives an OAuth round trip. */
  requestTTL: number;
  patterns: {
    clientId: string;
    state: string;
    codeChallenge: string;
    provider: string;
  };
}

interface PageRequest {
  state: string;
  codeChallenge: string;
  redirectUri: string | null;
  provider: string | null;
  capturedAt: number;
}

interface PageAction {
  label: string;
  primary?: boolean;
  href?: string;
  onClick?: () => void;
}

/**
 * Runs the hand-off page: captures the app's request, signs the user in
 * (social buttons or your sign-in page), asks for consent, then hands a
 * single-use code back to the app. `go` navigates (replaced in tests).
 */
export async function runHandoffPage(
  win: Window,
  doc: Document,
  go: (url: string) => void = (url) => {
    win.location.href = url;
  },
): Promise<void> {
  const config = JSON.parse(
    doc.getElementById('tpba-config')?.textContent ?? '{}',
  ) as HandoffPageConfig;
  const app = config.appName;
  const key = `tauri-plugin-better-auth:request:${config.clientID}`;
  const autoKey = `${key}:auto`;
  const keys = [
    'client_id',
    'state',
    'code_challenge',
    'code_challenge_method',
    'redirect_uri',
    'provider',
    'v',
  ];

  const byId = (id: string) => doc.getElementById(id) as HTMLElement;
  let busy = false;
  const show = (view: {
    title: string;
    text?: string;
    actions?: PageAction[];
    note?: string;
    code?: string;
  }) => {
    byId('tpba-title').textContent = view.title;
    byId('tpba-text').textContent = view.text ?? '';
    byId('tpba-note').textContent = view.note ?? '';
    const code = byId('tpba-code');
    code.textContent = view.code ?? '';
    code.hidden = !view.code;
    const box = byId('tpba-actions');
    box.replaceChildren();
    for (const action of view.actions ?? []) {
      const node = doc.createElement(action.href ? 'a' : 'button');
      node.textContent = action.label;
      if (action.primary) node.className = 'primary';
      if (action.href) {
        (node as HTMLAnchorElement).href = action.href;
      } else {
        (node as HTMLButtonElement).type = 'button';
        node.addEventListener('click', () => {
          if (busy) return;
          action.onClick?.();
        });
      }
      box.append(node);
    }
  };

  const store = (() => {
    try {
      return win.sessionStorage;
    } catch {
      return null;
    }
  })();

  const isLoopback = (uri: string) => {
    if (
      !uri.startsWith('http://127.0.0.1:') &&
      !uri.startsWith('http://[::1]:')
    ) {
      return false;
    }
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      return false;
    }
    const port = Number(url.port);
    return (
      url.protocol === 'http:' &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === '' &&
      !uri.includes('?') &&
      !uri.includes('#') &&
      (url.hostname === '127.0.0.1' || url.hostname === '[::1]') &&
      Number.isInteger(port) &&
      port >= 1024 &&
      port <= 65_535 &&
      url.pathname === config.callbackPath
    );
  };

  const parse = (params: URLSearchParams): PageRequest | null => {
    const clientId = params.get('client_id') ?? '';
    if (
      !new RegExp(config.patterns.clientId).test(clientId) ||
      clientId !== config.clientID
    ) {
      return null;
    }
    if (
      Number(params.get('v') ?? config.protocolVersion) !==
      config.protocolVersion
    ) {
      return null;
    }
    const state = params.get('state') ?? '';
    if (!new RegExp(config.patterns.state).test(state)) return null;
    const codeChallenge = params.get('code_challenge') ?? '';
    const method = params.get('code_challenge_method');
    if (
      !new RegExp(config.patterns.codeChallenge).test(codeChallenge) ||
      (method !== null && method !== 'S256')
    ) {
      return null;
    }
    const redirectUri = params.get('redirect_uri');
    if (redirectUri !== null && !isLoopback(redirectUri)) return null;
    const raw = params.get('provider');
    const provider =
      raw !== null &&
      new RegExp(config.patterns.provider).test(raw) &&
      config.providers.some((p) => p.id === raw)
        ? raw
        : null;
    return { state, codeChallenge, redirectUri, provider, capturedAt: 0 };
  };

  const toParams = (request: PageRequest) =>
    new URLSearchParams({
      client_id: config.clientID,
      state: request.state,
      code_challenge: request.codeChallenge,
      v: String(config.protocolVersion),
      ...(request.redirectUri ? { redirect_uri: request.redirectUri } : {}),
      ...(request.provider ? { provider: request.provider } : {}),
    });

  // 1. The app's request: from the URL (then kept for OAuth round trips and
  //    removed from the address bar), or from this tab's storage.
  const query = new URLSearchParams(win.location.search);
  const oauthError = query.get('error');
  let request: PageRequest | null = null;
  if (query.has('client_id')) {
    request = parse(query);
    if (request) {
      request.capturedAt = Date.now();
      store?.setItem(key, JSON.stringify(request));
      store?.removeItem(autoKey);
    } else {
      store?.removeItem(key);
    }
  } else {
    try {
      const saved = JSON.parse(store?.getItem(key) ?? 'null') as PageRequest;
      if (saved && Date.now() - saved.capturedAt <= config.requestTTL * 1000) {
        // Re-validate: any script on this origin can write sessionStorage.
        request = parse(toParams(saved));
        if (request) request.capturedAt = saved.capturedAt;
      }
    } catch {
      request = null;
    }
    if (!request) store?.removeItem(key);
  }
  const page = new URL(win.location.href);
  for (const name of [...keys, 'error', 'error_description']) {
    page.searchParams.delete(name);
  }
  win.history.replaceState(win.history.state, '', page.toString());
  const pageURL = page.toString();

  if (!request) {
    show({
      title: 'This sign-in link is not valid',
      text: `It may have expired or been used already. Start again from ${app}.`,
    });
    return;
  }
  const current = request;

  const api = async (path: string, body?: unknown) => {
    const res = await win.fetch(`${config.authBase}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = (await res.json().catch(() => null)) as Record<
      string,
      unknown
    > | null;
    return { ok: res.ok, data };
  };

  const callback = (params: Record<string, string>) => {
    const search = new URLSearchParams(params).toString();
    return current.redirectUri
      ? `${current.redirectUri}?${search}`
      : `${config.scheme}://${config.callbackPath.slice(1)}?${search}`;
  };

  const failed = (message: string) =>
    show({
      title: 'Something went wrong',
      text: message,
      actions: [
        { label: 'Try again', primary: true, onClick: () => go(pageURL) },
      ],
    });

  const startSocial = async (provider: string) => {
    busy = true;
    show({ title: 'Opening the sign-in page…' });
    try {
      const { ok, data } = await api('/sign-in/social', {
        provider,
        callbackURL: pageURL,
        newUserCallbackURL: pageURL,
        errorCallbackURL: pageURL,
        disableRedirect: true,
      });
      busy = false;
      if (ok && data && typeof data.url === 'string') {
        go(data.url);
        return;
      }
      failed(
        typeof data?.message === 'string'
          ? data.message
          : 'The sign-in could not start.',
      );
    } catch {
      busy = false;
      failed('The server could not be reached.');
    }
  };

  const cancel = () => {
    store?.removeItem(key);
    const url = callback({ error: 'access_denied', state: current.state });
    show({ title: 'Sign-in cancelled', text: 'You can close this tab.' });
    go(url);
  };

  const authorize = async () => {
    busy = true;
    show({ title: `Opening ${app}…` });
    try {
      const { ok, data } = await api('/tauri/authorize', {
        client_id: config.clientID,
        state: current.state,
        code_challenge: current.codeChallenge,
        code_challenge_method: 'S256',
      });
      busy = false;
      if (!ok || !data || typeof data.code !== 'string') {
        failed(
          typeof data?.message === 'string'
            ? data.message
            : 'The sign-in could not be completed.',
        );
        return;
      }
      store?.removeItem(key);
      const url = callback({ code: data.code, state: current.state });
      show({
        title: `Opening ${app}…`,
        text: 'You can close this tab once the app has opened.',
        actions: [{ label: `Open ${app} again`, onClick: () => go(url) }],
        note: `${app} did not open? Paste this code into it. Never share this code; use it only in ${app} on this computer.`,
        code: data.code,
      });
      go(url);
    } catch {
      busy = false;
      failed('The server could not be reached.');
    }
  };

  // 2. Who is signed in on this browser?
  let user: Record<string, unknown> | null = null;
  try {
    const { ok, data } = await api('/get-session');
    const found = ok && data ? data.user : null;
    user =
      found && typeof found === 'object'
        ? (found as Record<string, unknown>)
        : null;
  } catch {
    failed('The server could not be reached.');
    return;
  }

  // 3. Signed in: ask for consent, every time. Any local app can register the
  //    scheme and start a sign-in; the click binds it to the user's app.
  if (user) {
    const who =
      typeof user.email === 'string' && user.email
        ? user.email
        : typeof user.name === 'string' && user.name
          ? user.name
          : 'your account';
    show({
      title: `Continue to ${app}?`,
      text: `You are signed in as ${who}.`,
      actions: [
        { label: `Continue to ${app}`, primary: true, onClick: authorize },
        { label: 'Cancel', onClick: cancel },
        {
          label: 'Use another account',
          onClick: async () => {
            busy = true;
            await api('/sign-out', {}).catch(() => null);
            busy = false;
            go(pageURL);
          },
        },
      ],
      note: `Only continue if you started this sign-in from ${app} on this computer.`,
    });
    return;
  }

  // 4. Signed out: start the provider the app asked for (once), or offer the
  //    configured sign-in methods.
  if (
    current.provider &&
    !oauthError &&
    store?.getItem(autoKey) !== current.state
  ) {
    store?.setItem(autoKey, current.state);
    await startSocial(current.provider);
    return;
  }
  const actions: PageAction[] = config.providers.map((p) => ({
    label: `Continue with ${p.name}`,
    primary: config.providers.length === 1 && !config.signInURL,
    onClick: () => void startSocial(p.id),
  }));
  if (config.signInURL) {
    const signIn = new URL(config.signInURL);
    signIn.searchParams.set(config.signInCallbackParam, pageURL);
    actions.push({
      label: config.providers.length ? 'Other sign-in options' : 'Sign in',
      primary: config.providers.length === 0,
      href: signIn.toString(),
    });
  }
  actions.push({ label: 'Cancel', onClick: cancel });
  show({
    title: `Sign in to continue to ${app}`,
    text:
      oauthError !== null
        ? 'The sign-in did not complete. Try again or choose another option.'
        : actions.length > 1
          ? ''
          : 'Sign in on the website first, then open this page again.',
    actions,
  });
}

const escapeHtml = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ]!,
  );

/** JSON that is safe inside a `<script>` element. */
const LINE_SEPARATOR = String.fromCharCode(0x2028);
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029);
const scriptJson = (value: unknown) =>
  JSON.stringify(value)
    .replaceAll('<', '\\u003c')
    .replaceAll(LINE_SEPARATOR, '\\u2028')
    .replaceAll(PARAGRAPH_SEPARATOR, '\\u2029');

const STYLE = `
:root { color-scheme: light dark; --bg: #f6f6f7; --card: #fff; --text: #18181b; --muted: #52525b; --line: #e4e4e7; --accent: #18181b; --accent-text: #fff; }
@media (prefers-color-scheme: dark) { :root { --bg: #09090b; --card: #18181b; --text: #fafafa; --muted: #a1a1aa; --line: #3f3f46; --accent: #fafafa; --accent-text: #18181b; } }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { width: 100%; max-width: 400px; background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 28px; }
h1 { margin: 0 0 8px; font-size: 20px; font-weight: 600; }
p { margin: 0 0 16px; color: var(--muted); }
p:empty { display: none; }
#tpba-actions { display: grid; gap: 8px; margin: 20px 0 0; }
button, a { display: block; width: 100%; padding: 10px 14px; border: 1px solid var(--line); border-radius: 8px; background: transparent; color: var(--text); font: inherit; text-align: center; text-decoration: none; cursor: pointer; }
.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); font-weight: 600; }
#tpba-code { margin: 16px 0 0; padding: 10px; border-radius: 8px; background: var(--bg); font: 600 16px/1.4 ui-monospace, monospace; letter-spacing: 0.04em; text-align: center; user-select: all; word-break: break-all; }
#tpba-note { margin: 16px 0 0; font-size: 13px; }
`;

/** The complete page. `nonce` must be fresh per response (it is in the CSP). */
export function renderHandoffPage(
  config: HandoffPageConfig,
  nonce: string,
): string {
  const title = escapeHtml(`Sign in to ${config.appName}`);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${title}</title>
<style nonce="${nonce}">${STYLE}</style>
</head>
<body>
<main aria-live="polite">
<h1 id="tpba-title">${title}</h1>
<p id="tpba-text">Loading…</p>
<div id="tpba-code" hidden></div>
<div id="tpba-actions"></div>
<p id="tpba-note"></p>
<noscript><p>This page needs JavaScript.</p></noscript>
</main>
<script type="application/json" id="tpba-config">${scriptJson(config)}</script>
<script nonce="${nonce}">(${runHandoffPage.toString()})(window, document);</script>
</body>
</html>`;
}

/** Response headers: no framing (clickjacking the consent click), no caching. */
export function handoffPageHeaders(nonce: string): Record<string, string> {
  return {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "connect-src 'self'",
      "img-src 'self' data:",
      "form-action 'none'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
    ].join('; '),
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'cross-origin-opener-policy': 'same-origin',
  };
}
