// Loads and validates configuration from environment variables.
// Fails fast with every problem listed at once, so a misconfigured
// deployment never starts half-working.

export class ConfigError extends Error {
  constructor(problems) {
    super(`Invalid configuration:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

const MIN_SECRET_LENGTH = 32;
const PLACEHOLDER_SECRETS = new Set([
  'change-me',
  'changeme',
  'replace-with-a-long-random-string',
  'secret',
]);

function parseUrl(value, name, problems) {
  if (!value) {
    problems.push(`${name} is required`);
    return undefined;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    problems.push(`${name} must be an absolute URL (got "${value}")`);
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    problems.push(`${name} must use http or https (got "${url.protocol}")`);
    return undefined;
  }
  return url;
}

function parseBool(value, name, problems) {
  if (value === undefined || value === '') return undefined;
  if (['true', '1', 'yes'].includes(value.toLowerCase())) return true;
  if (['false', '0', 'no'].includes(value.toLowerCase())) return false;
  problems.push(`${name} must be true or false (got "${value}")`);
  return undefined;
}

const isLocalhost = (url) =>
  ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);

/**
 * @param {Record<string, string | undefined>} env usually process.env
 */
export function loadConfig(env) {
  const problems = [];

  const issuer = parseUrl(env.OIDC_ISSUER, 'OIDC_ISSUER', problems);
  const baseUrl = parseUrl(env.APP_BASE_URL, 'APP_BASE_URL', problems);

  const clientId = (env.OIDC_CLIENT_ID ?? '').trim();
  if (!clientId) problems.push('OIDC_CLIENT_ID is required');

  const sessionSecret = env.SESSION_SECRET ?? '';
  if (!sessionSecret) {
    problems.push('SESSION_SECRET is required');
  } else if (PLACEHOLDER_SECRETS.has(sessionSecret.toLowerCase())) {
    problems.push('SESSION_SECRET is still the placeholder value; generate a random one');
  } else if (sessionSecret.length < MIN_SECRET_LENGTH) {
    problems.push(`SESSION_SECRET must be at least ${MIN_SECRET_LENGTH} characters`);
  }

  let port = 3009;
  if (env.PORT !== undefined && env.PORT !== '') {
    port = Number(env.PORT);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      problems.push(`PORT must be an integer between 1 and 65535 (got "${env.PORT}")`);
    }
  }

  const rolesClaim = (env.OIDC_ROLES_CLAIM ?? 'roles').trim();
  if (!/^[A-Za-z0-9_\-:]+(\.[A-Za-z0-9_\-:]+)*$/.test(rolesClaim)) {
    problems.push(`OIDC_ROLES_CLAIM must be a claim name or dotted path (got "${rolesClaim}")`);
  }

  const cookieSecureOverride = parseBool(env.COOKIE_SECURE, 'COOKIE_SECURE', problems);
  const trustProxy = parseBool(env.TRUST_PROXY, 'TRUST_PROXY', problems) ?? false;

  // Plain-HTTP OIDC is only tolerated for local development.
  if (issuer && issuer.protocol === 'http:' && !isLocalhost(issuer)) {
    problems.push('OIDC_ISSUER must use https unless it points at localhost');
  }
  if (baseUrl && baseUrl.protocol === 'http:' && !isLocalhost(baseUrl)) {
    problems.push('APP_BASE_URL must use https unless it points at localhost');
  }

  if (problems.length > 0) throw new ConfigError(problems);

  const base = baseUrl.href.replace(/\/$/, '');
  return Object.freeze({
    issuer,
    clientId,
    baseUrl: base,
    redirectUri: `${base}/callback`,
    postLogoutRedirectUri: `${base}/`,
    sessionSecret,
    port,
    rolesClaim,
    // Secure cookies whenever the app is served over https, unless overridden.
    cookieSecure: cookieSecureOverride ?? baseUrl.protocol === 'https:',
    trustProxy,
    allowInsecureIssuer: issuer.protocol === 'http:',
  });
}
