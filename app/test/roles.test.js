import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, getRoles, requireAuth, requireRole, safeReturnTo } from '../src/roles.js';

// Minimal req/res doubles that record what the middleware did.
function makeReq({ user, method = 'GET', accept = 'text/html', url = '/admin' } = {}) {
  return { session: user ? { user } : {}, method, headers: { accept }, originalUrl: url };
}

function makeRes() {
  const res = { statusCode: 200, body: undefined, redirectedTo: undefined, contentType: undefined };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  res.send = (body) => { res.body = body; return res; };
  res.type = (t) => { res.contentType = t; return res; };
  res.redirect = (url) => { res.statusCode = 302; res.redirectedTo = url; return res; };
  return res;
}

function run(middleware, req) {
  const res = makeRes();
  let nextCalled = false;
  middleware(req, res, () => { nextCalled = true; });
  return { res, nextCalled };
}

test('getRoles reads flat and nested claim paths', () => {
  assert.deepEqual(getRoles({ roles: ['user', 'admin'] }), ['user', 'admin']);
  assert.deepEqual(getRoles({ realm_access: { roles: ['user'] } }, 'realm_access.roles'), ['user']);
  assert.deepEqual(getRoles({ roles: 'admin' }), ['admin']);
});

test('getRoles is defensive about missing or odd data', () => {
  assert.deepEqual(getRoles(undefined), []);
  assert.deepEqual(getRoles({}), []);
  assert.deepEqual(getRoles({ roles: null }), []);
  assert.deepEqual(getRoles({ roles: { admin: true } }), []);
  assert.deepEqual(getRoles({ roles: ['user', 42, null] }), ['user']);
  assert.deepEqual(getRoles({ realm_access: 'x' }, 'realm_access.roles'), []);
  // Inherited properties must not count as claims.
  assert.deepEqual(getRoles({}, 'constructor'), []);
});

test('requireRole lets a user with the role through', () => {
  const { nextCalled, res } = run(requireRole('admin'), makeReq({ user: { roles: ['user', 'admin'] } }));
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
});

test('requireRole accepts any one of several roles', () => {
  const { nextCalled } = run(requireRole('admin', 'auditor'), makeReq({ user: { roles: ['auditor'] } }));
  assert.equal(nextCalled, true);
});

test('requireRole returns 403 HTML for a browser without the role', () => {
  const { nextCalled, res } = run(requireRole('admin'), makeReq({ user: { roles: ['user'] } }));
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.contentType, 'html');
  assert.match(res.body, /403/);
});

test('requireRole returns 403 JSON for API clients', () => {
  const { res } = run(requireRole('admin'), makeReq({ user: { roles: [] }, accept: 'application/json' }));
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { error: 'forbidden', requiredRoles: ['admin'] });
});

test('requireRole treats a user with no roles array as having none', () => {
  const { nextCalled, res } = run(requireRole('admin'), makeReq({ user: { sub: 'x' } }));
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test('requireRole sends anonymous browsers to login with returnTo', () => {
  const { nextCalled, res } = run(requireRole('admin'), makeReq({ url: '/admin?tab=1' }));
  assert.equal(nextCalled, false);
  assert.equal(res.redirectedTo, '/login?returnTo=%2Fadmin%3Ftab%3D1');
});

test('requireAuth returns 401 JSON for anonymous API calls', () => {
  const { res } = run(requireAuth, makeReq({ accept: 'application/json', url: '/api/me' }));
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: 'unauthenticated' });
});

test('requireAuth returns 401 for anonymous non-GET requests even from browsers', () => {
  const { res } = run(requireAuth, makeReq({ method: 'POST' }));
  assert.equal(res.statusCode, 401);
});

test('requireRole without roles is a programming error', () => {
  assert.throws(() => requireRole(), /at least one role/);
});

test('403 page escapes role names', () => {
  const { res } = run(requireRole('<script>'), makeReq({ user: { roles: [] } }));
  assert.doesNotMatch(res.body, /<script>/);
  assert.match(res.body, /&lt;script&gt;/);
});

test('safeReturnTo only allows same-origin relative paths', () => {
  assert.equal(safeReturnTo('/admin'), '/admin');
  assert.equal(safeReturnTo('/profile?x=1'), '/profile?x=1');
  assert.equal(safeReturnTo('//evil.example'), '/');
  assert.equal(safeReturnTo('/\\evil.example'), '/');
  assert.equal(safeReturnTo('https://evil.example'), '/');
  assert.equal(safeReturnTo(undefined), '/');
  assert.equal(safeReturnTo(['/a', '/b']), '/');
});

test('escapeHtml escapes the five significant characters', () => {
  assert.equal(escapeHtml(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
});
