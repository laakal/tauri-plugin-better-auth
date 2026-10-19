import { createAuthClient } from 'better-auth/client';
import { emailOTPClient } from 'better-auth/client/plugins';
import {
  asTauriClient,
  authenticate,
  cancelAuth,
  getSession,
  isTauriAuthError,
  onAuthenticated,
  onAuthError,
  onSignedOut,
  requestAuth,
  signOut,
  tauriFetch,
  withTauri,
} from 'tauri-plugin-better-auth/client';

const API = 'http://localhost:3000';

// Every request goes through the Rust bridge: the token never reaches here.
const authClient = asTauriClient(
  createAuthClient(
    withTauri({ baseURL: `${API}/api/auth`, plugins: [emailOTPClient()] }),
  ),
);

const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const output = (value: unknown) => {
  $('output').textContent =
    typeof value === 'string' ? value : JSON.stringify(value, null, 2);
};
const report = (error: unknown) =>
  output(
    isTauriAuthError(error)
      ? `${error.code}: ${error.message}`
      : error instanceof Error
        ? error.message
        : String(error),
  );

async function refresh(cachedOnly = false) {
  const session = await getSession({ cachedOnly });
  $('signed-in').hidden = !session;
  $('signed-out').hidden = Boolean(session);
  $('waiting').hidden = true;
  $('status').textContent = session
    ? `Signed in as ${String(session.user.email)}${session.offline ? ' (offline)' : ''}`
    : 'Signed out';
}

$('browser').addEventListener('click', async () => {
  try {
    const result = await requestAuth();
    $('waiting').hidden = false;
    if (!result.opened)
      output(`Open this link in your browser:\n${result.url}`);
  } catch (error) {
    report(error);
  }
});

$('paste-submit').addEventListener('click', async () => {
  try {
    await authenticate($<HTMLInputElement>('paste').value);
  } catch (error) {
    report(error);
  }
});

$('cancel').addEventListener('click', async () => {
  await cancelAuth();
  $('waiting').hidden = true;
});

$('send-otp').addEventListener('click', async () => {
  const { error } = await authClient.emailOtp.sendVerificationOtp({
    email: $<HTMLInputElement>('email').value,
    type: 'sign-in',
  });
  output(error ? error.message : 'Code sent (see the server console).');
});

$('verify-otp').addEventListener('click', async () => {
  const { error } = await authClient.signIn.emailOtp({
    email: $<HTMLInputElement>('email').value,
    otp: $<HTMLInputElement>('otp').value,
  });
  if (error) output(error.message);
});

$('me').addEventListener('click', async () => {
  const response = await tauriFetch(`${API}/api/me`);
  output({ status: response.status, body: await response.json() });
});

$('sign-out').addEventListener('click', async () => {
  await signOut().catch(report);
});

void onAuthenticated(() => {
  output('Signed in.');
  void refresh();
});
void onSignedOut(({ reason }) => {
  output(`Signed out (${reason}).`);
  void refresh(true);
});
void onAuthError((error) => output(`${error.code}: ${error.message}`));

// Fast start from the cache, then verify with the server.
void refresh(true).then(() => refresh());
