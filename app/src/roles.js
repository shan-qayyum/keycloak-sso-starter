// Role extraction and route protection.

/**
 * Reads roles from ID token claims. `path` is a claim name or a dotted path,
 * e.g. "roles" (this starter's mapper) or "realm_access.roles" (Keycloak's
 * default access-token layout).
 * @returns {string[]}
 */
export function getRoles(claims, path = 'roles') {
  if (!claims || typeof claims !== 'object') return [];
  let value = claims;
  for (const key of path.split('.')) {
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) return [];
    value = value[key];
  }
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((r) => typeof r === 'string');
}

export function hasAnyRole(userRoles, required) {
  return required.some((role) => userRoles.includes(role));
}

function wantsHtml(req) {
  return req.method === 'GET' && (req.headers.accept ?? '').includes('text/html');
}

/** Requires a logged-in session. Browsers are sent to /login, API calls get 401. */
export function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  if (wantsHtml(req)) {
    const returnTo = encodeURIComponent(req.originalUrl ?? '/');
    return res.redirect(`/login?returnTo=${returnTo}`);
  }
  return res.status(401).json({ error: 'unauthenticated' });
}

/**
 * Requires a logged-in session holding at least one of the given roles.
 * Unauthenticated -> same as requireAuth. Authenticated but missing role -> 403.
 */
export function requireRole(...required) {
  if (required.length === 0) throw new Error('requireRole needs at least one role');
  return function roleCheck(req, res, next) {
    const user = req.session?.user;
    if (!user) return requireAuth(req, res, next);
    if (hasAnyRole(user.roles ?? [], required)) return next();
    res.status(403);
    if (wantsHtml(req)) {
      return res.type('html').send(
        `<!doctype html><meta charset="utf-8"><title>Forbidden</title>` +
          `<p>403 - this page needs one of these roles: ${required.map(escapeHtml).join(', ')}.</p>` +
          `<p><a href="/">Back</a></p>`,
      );
    }
    return res.json({ error: 'forbidden', requiredRoles: required });
  };
}

/** Only allow same-origin relative paths as post-login redirect targets. */
export function safeReturnTo(value) {
  if (typeof value !== 'string') return '/';
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
  return value;
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
