import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ConfigError, loadConfig } from '../src/config.js';

const valid = {
  OIDC_ISSUER: 'http://localhost:8089/realms/demo',
  OIDC_CLIENT_ID: 'demo-app',
  APP_BASE_URL: 'http://localhost:3009',
  SESSION_SECRET: 'x'.repeat(32),
};

function problemsFor(env) {
  try {
    loadConfig(env);
  } catch (err) {
    assert.ok(err instanceof ConfigError);
    return err.problems;
  }
  assert.fail('expected ConfigError');
}

test('valid localhost config loads with dev defaults', () => {
  const c = loadConfig(valid);
  assert.equal(c.issuer.href, 'http://localhost:8089/realms/demo');
  assert.equal(c.clientId, 'demo-app');
  assert.equal(c.redirectUri, 'http://localhost:3009/callback');
  assert.equal(c.postLogoutRedirectUri, 'http://localhost:3009/');
  assert.equal(c.port, 3009);
  assert.equal(c.rolesClaim, 'roles');
  assert.equal(c.cookieSecure, false);
  assert.equal(c.trustProxy, false);
  assert.equal(c.allowInsecureIssuer, true);
  assert.ok(Object.isFrozen(c));
});

test('trailing slash on APP_BASE_URL is normalised', () => {
  const c = loadConfig({ ...valid, APP_BASE_URL: 'http://localhost:3009/' });
  assert.equal(c.redirectUri, 'http://localhost:3009/callback');
});

test('https base URL turns on secure cookies by default', () => {
  const c = loadConfig({
    ...valid,
    OIDC_ISSUER: 'https://sso.example.com/realms/demo',
    APP_BASE_URL: 'https://app.example.com',
  });
  assert.equal(c.cookieSecure, true);
  assert.equal(c.allowInsecureIssuer, false);
});

test('COOKIE_SECURE and TRUST_PROXY overrides are parsed', () => {
  const c = loadConfig({ ...valid, COOKIE_SECURE: 'true', TRUST_PROXY: 'yes' });
  assert.equal(c.cookieSecure, true);
  assert.equal(c.trustProxy, true);
});

test('reports every missing required variable at once', () => {
  const problems = problemsFor({});
  assert.deepEqual(problems, [
    'OIDC_ISSUER is required',
    'APP_BASE_URL is required',
    'OIDC_CLIENT_ID is required',
    'SESSION_SECRET is required',
  ]);
});

test('rejects malformed URLs and non-http schemes', () => {
  assert.match(problemsFor({ ...valid, OIDC_ISSUER: 'not a url' })[0], /absolute URL/);
  assert.match(problemsFor({ ...valid, APP_BASE_URL: 'ftp://localhost' })[0], /http or https/);
});

test('rejects plain http for non-localhost hosts', () => {
  const problems = problemsFor({
    ...valid,
    OIDC_ISSUER: 'http://sso.example.com/realms/demo',
    APP_BASE_URL: 'http://app.example.com',
  });
  assert.equal(problems.length, 2);
  assert.match(problems[0], /OIDC_ISSUER must use https/);
  assert.match(problems[1], /APP_BASE_URL must use https/);
});

test('rejects short and placeholder session secrets', () => {
  assert.match(problemsFor({ ...valid, SESSION_SECRET: 'short' })[0], /at least 32/);
  assert.match(problemsFor({ ...valid, SESSION_SECRET: 'replace-with-a-long-random-string' })[0], /placeholder/);
});

test('rejects invalid PORT and boolean values', () => {
  assert.match(problemsFor({ ...valid, PORT: '70000' })[0], /PORT/);
  assert.match(problemsFor({ ...valid, PORT: 'abc' })[0], /PORT/);
  assert.match(problemsFor({ ...valid, COOKIE_SECURE: 'maybe' })[0], /COOKIE_SECURE/);
});

test('accepts dotted roles claim paths, rejects junk', () => {
  assert.equal(loadConfig({ ...valid, OIDC_ROLES_CLAIM: 'realm_access.roles' }).rolesClaim, 'realm_access.roles');
  assert.match(problemsFor({ ...valid, OIDC_ROLES_CLAIM: 'a..b' })[0], /OIDC_ROLES_CLAIM/);
});
