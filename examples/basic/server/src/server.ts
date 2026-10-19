import desktop from '../public/desktop.html';
import { auth, latestOtp } from './auth';

// Creates the Better Auth tables in example.db on first start.
await (await auth.$context).runMigrations();

const testMode = process.env.EXAMPLE_TEST_MODE === '1';

const server = Bun.serve({
  port: Number(process.env.PORT ?? 3000),
  development: process.env.NODE_ENV !== 'production',
  routes: {
    // The hand-off page the app opens in the system browser.
    '/desktop': desktop,

    // A protected API route the app calls through `tauriFetch`.
    '/api/me': async (request) => {
      const session = await auth.api.getSession({ headers: request.headers });
      return session
        ? Response.json({ user: session.user })
        : Response.json({ code: 'UNAUTHORIZED' }, { status: 401 });
    },

    // Lets the protocol end-to-end test read sign-in codes. Off unless
    // EXAMPLE_TEST_MODE=1; never enable it in production.
    '/__test/otp': (request) => {
      if (!testMode) return new Response('Not found', { status: 404 });
      const email = new URL(request.url).searchParams.get('email') ?? '';
      return Response.json({ otp: latestOtp.get(email) ?? null });
    },
  },
  fetch(request) {
    if (new URL(request.url).pathname.startsWith('/api/auth')) {
      return auth.handler(request);
    }
    return new Response('Not found', { status: 404 });
  },
});

console.log(`[example] auth server on ${server.url.origin}`);
console.log(`[example] hand-off page: ${server.url.origin}/desktop`);
