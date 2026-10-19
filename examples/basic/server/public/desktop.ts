import { createAuthClient } from 'better-auth/client';
import { emailOTPClient } from 'better-auth/client/plugins';
import { tauriProxyClient } from 'tauri-plugin-better-auth/proxy';

const SCHEME = 'com.example.betterauth';

const authClient = createAuthClient({
  baseURL: location.origin,
  plugins: [
    emailOTPClient(),
    tauriProxyClient({ scheme: SCHEME, clientID: SCHEME }),
  ],
});

const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;

const views = ['no-request', 'email-form', 'code-form', 'consent', 'done'];
function show(view: string, status = '') {
  for (const id of views) $(id).hidden = id !== view;
  $('status').textContent = status;
}

let email = '';
let redirectTo = '';

async function render() {
  const request = authClient.tauri.getRequest();
  if (request.status !== 'ok') {
    show(
      'no-request',
      request.status === 'invalid'
        ? `This sign-in link is not valid (${request.problem}).`
        : '',
    );
    return;
  }
  const { data } = await authClient.getSession();
  if (data) {
    // Consent after every login, including fresh ones.
    $('consent-email').textContent = data.user.email;
    show('consent');
  } else {
    show('email-form', 'Sign in to continue to the app.');
  }
}

$('email-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  email = $<HTMLInputElement>('email').value.trim();
  const { error } = await authClient.emailOtp.sendVerificationOtp({
    email,
    type: 'sign-in',
  });
  if (error) {
    $('status').textContent = error.message ?? 'Could not send the code.';
    return;
  }
  show('code-form', `We sent a code to ${email}.`);
});

$('code-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const otp = $<HTMLInputElement>('otp').value.trim();
  const { error } = await authClient.signIn.emailOtp({ email, otp });
  if (error) {
    $('status').textContent = error.message ?? 'That code did not work.';
    return;
  }
  await render();
});

$('continue').addEventListener('click', async () => {
  const { data, error } = await authClient.tauri.handoff();
  if (error) {
    $('status').textContent = error.message;
    return;
  }
  redirectTo = data.redirectTo;
  $('code').textContent = data.code;
  show('done', 'Opening the app…');
  authClient.tauri.openApp(redirectTo);
});

$('open-again').addEventListener('click', () => {
  if (redirectTo) authClient.tauri.openApp(redirectTo);
});

$('copy').addEventListener('click', async () => {
  await navigator.clipboard.writeText($('code').textContent ?? '');
  $('status').textContent = 'Code copied. Paste it into the app.';
});

$('switch').addEventListener('click', async () => {
  await authClient.signOut();
  show('email-form', 'Sign in with another account.');
});

$('cancel').addEventListener('click', () => {
  const link = authClient.tauri.cancelLink();
  show('no-request', 'Sign-in cancelled. You can close this tab.');
  if (link) authClient.tauri.openApp(link);
});

void render();
