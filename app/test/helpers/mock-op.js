// A deliberately tiny OpenID Provider for tests. It implements just enough
// of discovery, authorize, token (with PKCE S256 verification), JWKS and
// end_session for the demo app's real openid-client code to run end to end.
// It is NOT a security reference; never use it outside tests.
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

const USERS = {
  alice: { sub: 'u-alice', name: 'Alice Example', email: 'alice@example.test', roles: ['user'] },
  bob: { sub: 'u-bob', name: 'Bob Example', email: 'bob@example.test', roles: ['user', 'admin'] },
};

const b64url = (buf) => buf.toString('base64url');

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => resolve(new URLSearchParams(data)));
    req.on('error', reject);
  });
}

/**
 * @param {{ clientId: string, tamper?: { nonce?: string } }} opts
 */
export async function startMockOp({ clientId, tamper = {} }) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };
  const codes = new Map();
  const calls = { authorize: [], token: [], endSession: [] };

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, issuer);
      const send = (status, body, type = 'application/json') => {
        res.writeHead(status, { 'content-type': type });
        res.end(typeof body === 'string' ? body : JSON.stringify(body));
      };
      const redirect = (to) => { res.writeHead(302, { location: to }); res.end(); };

      if (url.pathname === '/.well-known/openid-configuration') {
        return send(200, {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          end_session_endpoint: `${issuer}/logout`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['none'],
        });
      }
      if (url.pathname === '/jwks') return send(200, { keys: [jwk] });

      if (url.pathname === '/authorize' && req.method === 'GET') {
        const p = Object.fromEntries(url.searchParams);
        calls.authorize.push(p);
        if (p.client_id !== clientId || p.response_type !== 'code' || p.code_challenge_method !== 'S256' ||
            !p.code_challenge || !p.state || !p.nonce || !p.redirect_uri) {
          return send(400, { error: 'invalid_request', got: p });
        }
        const hidden = Object.entries(p)
          .map(([k, v]) => `<input type="hidden" name="${k}" value="${v.replaceAll('"', '&quot;')}">`).join('');
        return send(200, `<!doctype html><meta name="viewport" content="width=device-width">
          <title>Mock IdP</title><form method="post" action="/authorize">${hidden}
          <label>Username <input id="username" name="username"></label>
          <label>Password <input id="password" name="password" type="password"></label>
          <button id="kc-login" type="submit">Sign in</button></form>`, 'text/html');
      }

      if (url.pathname === '/authorize' && req.method === 'POST') {
        const p = Object.fromEntries(await readBody(req));
        const user = USERS[p.username];
        if (!user) return send(401, 'unknown user', 'text/plain');
        const code = b64url(randomBytes(24));
        codes.set(code, { user, challenge: p.code_challenge, nonce: p.nonce, redirectUri: p.redirect_uri });
        const back = new URL(p.redirect_uri);
        back.searchParams.set('code', code);
        back.searchParams.set('state', p.state);
        return redirect(back.href);
      }

      if (url.pathname === '/token' && req.method === 'POST') {
        const p = Object.fromEntries(await readBody(req));
        calls.token.push(p);
        const entry = codes.get(p.code);
        codes.delete(p.code); // single use
        if (!entry || p.grant_type !== 'authorization_code' || p.redirect_uri !== entry.redirectUri ||
            p.client_id !== clientId) {
          return send(400, { error: 'invalid_grant' });
        }
        const expected = b64url(createHash('sha256').update(p.code_verifier ?? '').digest());
        if (expected !== entry.challenge) return send(400, { error: 'invalid_grant', error_description: 'PKCE' });
        const { user } = entry;
        const idToken = await new SignJWT({
          nonce: tamper.nonce ?? entry.nonce,
          name: user.name,
          preferred_username: Object.keys(USERS).find((k) => USERS[k] === user),
          email: user.email,
          roles: user.roles,
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
          .setIssuer(issuer).setAudience(clientId).setSubject(user.sub)
          .setIssuedAt().setExpirationTime('5m')
          .sign(privateKey);
        return send(200, { access_token: b64url(randomBytes(16)), token_type: 'Bearer', expires_in: 300, id_token: idToken });
      }

      if (url.pathname === '/logout') {
        const p = Object.fromEntries(url.searchParams);
        calls.endSession.push(p);
        return redirect(p.post_logout_redirect_uri ?? issuer);
      }

      send(404, { error: 'not_found' });
    } catch (err) {
      res.writeHead(500);
      res.end(String(err));
    }
  });

  await new Promise((resolve) => server.listen(0, resolve));
  const issuer = `http://localhost:${server.address().port}`;
  return { issuer, calls, close: () => new Promise((r) => server.close(r)) };
}
