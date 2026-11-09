// Runs the full Authorization Code + PKCE flow through the real app and the
// real openid-client against an in-process mock provider (test/helpers/mock-op.js).
// No Keycloak or Docker needed; the Keycloak-backed browser test lives in e2e/.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { startMockOp } from './helpers/mock-op.js';
import { startApp } from './helpers/start-app.js';

/** fetch wrapper with a one-cookie jar and no automatic redirects. */
function browser() {
  let sid;
  return {
    get sid() { return sid; },
    async go(url, init = {}) {
      const headers = { accept: 'text/html', ...(init.headers ?? {}) };
      if (sid && url.startsWith(this.appBase)) headers.cookie = `sid=${sid}`;
      const res = await fetch(url, { ...init, headers, redirect: 'manual' });
      for (const c of res.headers.getSetCookie()) {
        const m = /^sid=([^;]*)/.exec(c);
        if (m) sid = m[1] || undefined;
      }
      return res;
    },
  };
}

async function loginAs(b, op, username, start = '/login') {
  const toLogin = await b.go(`${b.appBase}${start}`);
  assert.equal(toLogin.status, 302);
  const authorizeUrl = new URL(toLogin.headers.get('location'));
  assert.equal(authorizeUrl.origin, new URL(op.issuer).origin);
  const form = await b.go(authorizeUrl.href);
  assert.equal(form.status, 200);
  const body = new URLSearchParams({ ...Object.fromEntries(authorizeUrl.searchParams), username });
  const back = await b.go(`${op.issuer}/authorize`, { method: 'POST', body });
  assert.equal(back.status, 302);
  return back.headers.get('location');
}

let op;
let app;
before(async () => {
  op = await startMockOp({ clientId: 'demo-app' });
  app = await startApp({ issuer: op.issuer });
});
after(async () => {
  await app?.close();
  await op?.close();
});

test('admin user: protected route -> login -> callback -> admin page -> logout', async () => {
  const b = browser();
  b.appBase = app.baseUrl;

  const anon = await b.go(`${app.baseUrl}/admin`);
  assert.equal(anon.status, 302);
  assert.equal(anon.headers.get('location'), '/login?returnTo=%2Fadmin');

  const callbackUrl = await loginAs(b, op, 'bob', '/login?returnTo=%2Fadmin');
  const preLoginSid = b.sid;
  assert.ok(preLoginSid, 'session cookie set before redirecting to the IdP');

  // The authorization request carried PKCE S256, state and nonce.
  const authz = op.calls.authorize.at(-1);
  assert.equal(authz.code_challenge_method, 'S256');
  assert.match(authz.code_challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(authz.state && authz.nonce);
  assert.equal(authz.scope, 'openid profile email');

  const cb = await b.go(callbackUrl);
  assert.equal(cb.status, 302);
  assert.equal(cb.headers.get('location'), '/admin');
  assert.notEqual(b.sid, preLoginSid, 'session id is regenerated after login');
  assert.ok(op.calls.token.at(-1).code_verifier, 'token request sent the PKCE verifier');

  const admin = await b.go(`${app.baseUrl}/admin`);
  assert.equal(admin.status, 200);
  assert.match(await admin.text(), /Admin area/);

  const me = await b.go(`${app.baseUrl}/api/me`, { headers: { accept: 'application/json' } });
  assert.deepEqual(await me.json(), {
    sub: 'u-bob', username: 'bob', email: 'bob@example.test', roles: ['user', 'admin'],
  });

  const logout = await b.go(`${app.baseUrl}/logout`, { method: 'POST' });
  assert.equal(logout.status, 302);
  const endSession = new URL(logout.headers.get('location'));
  assert.equal(endSession.href.split('?')[0], `${op.issuer}/logout`);
  assert.equal(endSession.searchParams.get('client_id'), 'demo-app');
  assert.equal(endSession.searchParams.get('post_logout_redirect_uri'), `${app.baseUrl}/`);
  assert.ok(endSession.searchParams.get('id_token_hint'));
  assert.equal(b.sid, undefined, 'session cookie cleared');

  const afterLogout = await b.go(`${app.baseUrl}/profile`);
  assert.equal(afterLogout.status, 302);
});

test('non-admin user gets 403 on /admin but can see /profile', async () => {
  const b = browser();
  b.appBase = app.baseUrl;
  await b.go(await loginAs(b, op, 'alice'));
  assert.equal((await b.go(`${app.baseUrl}/admin`)).status, 403);
  const profile = await b.go(`${app.baseUrl}/profile`);
  assert.equal(profile.status, 200);
  const html = await profile.text();
  assert.match(html, /<span id="roles">user<\/span>/);
  assert.match(html, /alice@example\.test/);
});

test('tampered state is rejected', async () => {
  const b = browser();
  b.appBase = app.baseUrl;
  const cb = new URL(await loginAs(b, op, 'bob'));
  cb.searchParams.set('state', 'attacker-state');
  const res = await b.go(cb.href);
  assert.equal(res.status, 401);
  assert.equal((await b.go(`${app.baseUrl}/api/me`, { headers: { accept: 'application/json' } })).status, 401);
});

test('callback without a login in progress is rejected (no session)', async () => {
  const b = browser();
  b.appBase = app.baseUrl;
  const cbUrl = await loginAs(b, op, 'bob');
  const stranger = browser();
  stranger.appBase = app.baseUrl;
  assert.equal((await stranger.go(cbUrl)).status, 400);
});

test('open redirect via returnTo is neutralised', async () => {
  const b = browser();
  b.appBase = app.baseUrl;
  const cb = await b.go(await loginAs(b, op, 'bob', '/login?returnTo=%2F%2Fevil.example'));
  assert.equal(cb.headers.get('location'), '/');
});

test('ID token with the wrong nonce is rejected', async () => {
  const badOp = await startMockOp({ clientId: 'demo-app', tamper: { nonce: 'not-the-nonce' } });
  const badApp = await startApp({ issuer: badOp.issuer });
  try {
    const b = browser();
    b.appBase = badApp.baseUrl;
    const res = await b.go(await loginAs(b, badOp, 'bob'));
    assert.equal(res.status, 401);
  } finally {
    await badApp.close();
    await badOp.close();
  }
});
