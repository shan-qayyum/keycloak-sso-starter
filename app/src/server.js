import { ConfigError, loadConfig } from './config.js';
import { createOidc } from './oidc.js';
import { createApp } from './app.js';

let config;
try {
  config = loadConfig(process.env);
} catch (err) {
  if (err instanceof ConfigError) {
    console.error(err.message);
    console.error('Copy .env.example to .env and fill it in.');
    process.exit(1);
  }
  throw err;
}

let oidc;
try {
  oidc = await createOidc(config);
} catch (err) {
  console.error(`Could not load OIDC discovery from ${config.issuer.href}: ${err.message}`);
  console.error('Is Keycloak running? Try: docker compose up -d   (then wait for it to become healthy)');
  process.exit(1);
}

if (process.env.NODE_ENV === 'production') {
  console.warn('Warning: using the in-memory session store. Use a shared store (Redis, Postgres) in production.');
}

createApp({ config, oidc }).listen(config.port, () => {
  console.log(`Demo app on ${config.baseUrl} (issuer ${config.issuer.href})`);
});
