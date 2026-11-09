import express from 'express';
import session from 'express-session';
import { escapeHtml, getRoles, requireAuth, requireRole, safeReturnTo } from './roles.js';

const css = `
  :root { color-scheme: light dark; --fg:#1d2433; --muted:#5b6475; --bg:#f6f7f9; --card:#fff; --line:#dde1e8; --accent:#2457d6; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e7eaf0; --muted:#9aa3b2; --bg:#12151b; --card:#1b2029; --line:#2c3340; --accent:#7aa2ff; } }
  * { box-sizing: border-box; }
  body { margin:0; font:16px/1.5 system-ui, sans-serif; color:var(--fg); background:var(--bg); }
  header, main { max-width: 760px; margin: 0 auto; padding: 16px; }
  header { display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between; }
  nav { display:flex; flex-wrap:wrap; gap:12px; align-items:center; }
  a { color: var(--accent); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; margin-bottom:16px; }
  .muted { color: var(--muted); }
  .role { display:inline-block; border:1px solid var(--line); border-radius:999px; padding:0 10px; margin:2px; font-size:14px; }
  pre { overflow-x:auto; font-size:13px; background:var(--bg); padding:12px; border-radius:6px; }
  button, .button { font:inherit; cursor:pointer; border:1px solid var(--accent); background:var(--accent); color:#fff; border-radius:6px; padding:6px 14px; text-decoration:none; display:inline-block; }
  form { margin:0; }
`;

function page(title, user, body) {
  const nav = user
    ? `<a href="/profile">Profile</a><a href="/admin">Admin</a>
       <form method="post" action="/logout"><button type="submit" id="logout">Log out</button></form>`
    : `<a class="button" href="/login" id="login">Log in</a>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} - Keycloak SSO demo</title><style>${css}</style></head>
<body><header><strong><a href="/">Keycloak SSO demo</a></strong><nav>${nav}</nav></header>
<main>${body}</main></body></html>`;
}

/**
 * @param {object} deps
 * @param {ReturnType<import('./config.js').loadConfig>} deps.config
 * @param {Awaited<ReturnType<import('./oidc.js').createOidc>>} deps.oidc
 * @param {import('express-session').Store} [deps.sessionStore] defaults to MemoryStore (dev only)
 */
export function createApp({ config, oidc, sessionStore }) {
  const app = express();
  app.disable('x-powered-by');
  // Needed behind a TLS-terminating proxy so secure cookies are issued.
  if (config.trustProxy) app.set('trust proxy', 1);

  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; form-action 'self' " +
        new URL(config.issuer).origin,
    });
    next();
  });

  app.use(
    session({
      name: 'sid',
      secret: config.sessionSecret,
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: {
        httpOnly: true,
        // Lax lets the cookie ride along on the top-level redirect back from
        // Keycloak, while blocking it on cross-site POSTs (e.g. forged logout).
        sameSite: 'lax',
        secure: config.cookieSecure,
        maxAge: 30 * 60 * 1000,
        path: '/',
      },
    }),
  );

  app.get('/', (req, res) => {
    const user = req.session.user;
    const body = user
      ? `<div class="card"><h1>Hello, ${escapeHtml(user.name)}</h1>
         <p>You are signed in via OpenID Connect.</p>
         <p>Roles: ${user.roles.map((r) => `<span class="role">${escapeHtml(r)}</span>`).join('') || '<span class="muted">none</span>'}</p>
         <p><a href="/profile">See all ID token claims</a> · <a href="/admin">Try the admin-only page</a></p></div>`
      : `<div class="card"><h1>Not signed in</h1>
         <p>This demo logs in against Keycloak using Authorization Code + PKCE.</p>
         <p class="muted">Dev users: <code>alice</code> (user) and <code>bob</code> (user, admin).
         Passwords are in the README and are for local development only.</p></div>`;
    res.type('html').send(page('Home', user, body));
  });

  app.get('/login', async (req, res, next) => {
    try {
      const { url, transaction } = await oidc.startLogin();
      req.session.oidc = { ...transaction, returnTo: safeReturnTo(req.query.returnTo) };
      req.session.save((err) => (err ? next(err) : res.redirect(url.href)));
    } catch (err) {
      next(err);
    }
  });

  app.get('/callback', async (req, res, next) => {
    const transaction = req.session.oidc;
    if (!transaction) {
      return res.status(400).type('html').send(page('Login error', null,
        `<div class="card"><h1>Login expired</h1><p>No login in progress for this browser session.</p>
         <p><a href="/login">Start again</a></p></div>`));
    }
    delete req.session.oidc;
    try {
      // Build the URL from configuration, never from the Host header.
      const currentUrl = new URL(req.originalUrl, config.baseUrl);
      const { claims, idToken } = await oidc.finishLogin(currentUrl, transaction);
      const user = {
        sub: claims.sub,
        name: claims.name ?? claims.preferred_username ?? claims.sub,
        username: claims.preferred_username,
        email: claims.email,
        roles: getRoles(claims, config.rolesClaim),
        claims,
      };
      // New session id after login prevents session fixation.
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.user = user;
        req.session.idToken = idToken;
        req.session.save((saveErr) => (saveErr ? next(saveErr) : res.redirect(transaction.returnTo)));
      });
    } catch (err) {
      console.warn('OIDC callback rejected:', err.code ?? err.name, err.message);
      res.status(401).type('html').send(page('Login failed', null,
        `<div class="card"><h1>Login failed</h1><p>The response from the identity provider could not be verified.</p>
         <p><a href="/login">Try again</a></p></div>`));
    }
  });

  app.get('/profile', requireAuth, (req, res) => {
    const { user } = req.session;
    res.type('html').send(page('Profile', user,
      `<div class="card"><h1>Profile</h1>
       <p><strong>${escapeHtml(user.name)}</strong> <span class="muted">${escapeHtml(user.email ?? '')}</span></p>
       <p>Roles (from <code>${escapeHtml(config.rolesClaim)}</code>): <span id="roles">${escapeHtml(user.roles.join(', ') || 'none')}</span></p>
       <h2>ID token claims</h2><pre id="claims">${escapeHtml(JSON.stringify(user.claims, null, 2))}</pre></div>`));
  });

  app.get('/admin', requireRole('admin'), (req, res) => {
    res.type('html').send(page('Admin', req.session.user,
      `<div class="card"><h1 id="admin-heading">Admin area</h1>
       <p>Only users with the <code>admin</code> role can see this page.</p></div>`));
  });

  app.get('/api/me', requireAuth, (req, res) => {
    const { sub, username, email, roles } = req.session.user;
    res.json({ sub, username, email, roles });
  });

  app.post('/logout', (req, res, next) => {
    const idToken = req.session.idToken;
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie('sid', { path: '/', httpOnly: true, sameSite: 'lax', secure: config.cookieSecure });
      // Ends the Keycloak SSO session too, then Keycloak sends the user back to "/".
      res.redirect(oidc.logoutUrl(idToken) ?? '/');
    });
  });

  // Express recognises error handlers by their four parameters.
  app.use((err, req, res, _next) => {
    console.error(err);
    res.status(500).type('html').send(page('Error', null,
      '<div class="card"><h1>Something went wrong</h1><p>Check the server log.</p></div>'));
  });

  return app;
}
