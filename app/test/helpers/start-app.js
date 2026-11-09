import http from 'node:http';
import { loadConfig } from '../../src/config.js';
import { createOidc } from '../../src/oidc.js';
import { createApp } from '../../src/app.js';

/** Starts the demo app on a free port against the given issuer. */
export async function startApp({ issuer, clientId = 'demo-app', env = {} }) {
  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, resolve));
  const baseUrl = `http://localhost:${server.address().port}`;
  const config = loadConfig({
    OIDC_ISSUER: issuer,
    OIDC_CLIENT_ID: clientId,
    APP_BASE_URL: baseUrl,
    SESSION_SECRET: 'test-only-session-secret-0123456789abcdef',
    ...env,
  });
  const oidc = await createOidc(config);
  server.on('request', createApp({ config, oidc }));
  return { baseUrl, close: () => new Promise((r) => server.close(r)) };
}
