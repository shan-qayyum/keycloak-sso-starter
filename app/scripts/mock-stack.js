// Runs the demo app against the in-process test IdP, for UI work without
// Docker/Keycloak. Prints the app URL. Users: alice (user), bob (user, admin);
// the mock ignores passwords. Test tooling only.
import { startMockOp } from '../test/helpers/mock-op.js';
import { startApp } from '../test/helpers/start-app.js';

const op = await startMockOp({ clientId: 'demo-app' });
const app = await startApp({ issuer: op.issuer });
console.log(`Mock IdP: ${op.issuer}`);
console.log(`APP_URL=${app.baseUrl}`);

const stop = async () => {
  await app.close();
  await op.close();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
