// Browser end-to-end test: real Chrome, real login form, real redirects.
//
// Against the docker-compose Keycloak:
//   docker compose up -d            (repo root, wait until healthy)
//   npm start                       (in app/, another terminal)
//   npm install --no-save playwright-core@1.65.0
//   npm run test:e2e
//
// Env: APP_URL (default http://localhost:3009), ALICE_PASSWORD / BOB_PASSWORD
// (default to the dev-only passwords from realm/demo-realm.json),
// PLAYWRIGHT_CORE (module specifier or file:// URL, default "playwright-core"),
// BROWSER_CHANNEL (default "chrome"), SCREENSHOT_DIR (optional).
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

const APP_URL = (process.env.APP_URL ?? 'http://localhost:3009').replace(/\/$/, '');
const PASSWORDS = {
  alice: process.env.ALICE_PASSWORD ?? 'alice-dev-only',
  bob: process.env.BOB_PASSWORD ?? 'bob-dev-only',
};
const SHOTS = process.env.SCREENSHOT_DIR;

const { chromium } = await import(process.env.PLAYWRIGHT_CORE ?? 'playwright-core');
const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL ?? 'chrome', headless: true });

async function shot(page, name) {
  if (!SHOTS) return;
  await mkdir(SHOTS, { recursive: true });
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}

async function signIn(page, username) {
  // Keycloak's login theme uses these ids (#username, #password, #kc-login).
  await page.waitForSelector('#username');
  await page.fill('#username', username);
  await page.fill('#password', PASSWORDS[username]);
  await page.click('#kc-login');
}

const results = [];
async function step(name, fn) {
  try {
    await fn();
    results.push(`ok   ${name}`);
  } catch (err) {
    results.push(`FAIL ${name}: ${err.message}`);
    throw err;
  }
}

try {
  for (const viewport of [{ width: 1280, height: 800, tag: 'desktop' }, { width: 390, height: 844, tag: 'phone' }]) {
    const context = await browser.newContext({ viewport });
    const page = await context.newPage();

    await step(`[${viewport.tag}] bob: /admin -> IdP login -> back on /admin`, async () => {
      await page.goto(`${APP_URL}/admin`);
      assert.notEqual(new URL(page.url()).origin, new URL(APP_URL).origin, 'expected redirect to the IdP');
      await shot(page, `${viewport.tag}-1-idp-login`);
      await signIn(page, 'bob');
      await page.waitForURL(`${APP_URL}/admin`);
      assert.equal(await page.textContent('#admin-heading'), 'Admin area');
      await shot(page, `${viewport.tag}-2-admin`);
    });

    await step(`[${viewport.tag}] bob: profile shows claims and both roles`, async () => {
      await page.goto(`${APP_URL}/profile`);
      // Keycloak may add its own default roles (e.g. default-roles-demo), so check inclusion.
      const roles = (await page.textContent('#roles')).split(', ');
      assert.ok(roles.includes('user') && roles.includes('admin'), `roles were: ${roles}`);
      const claims = JSON.parse(await page.textContent('#claims'));
      assert.equal(claims.preferred_username, 'bob');
      await shot(page, `${viewport.tag}-3-profile`);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
      assert.equal(overflow, false, 'page scrolls horizontally');
    });

    await step(`[${viewport.tag}] bob: logout ends the app and IdP sessions`, async () => {
      await page.click('#logout');
      await page.waitForURL(`${APP_URL}/`);
      assert.ok(await page.isVisible('#login'), 'login button visible after logout');
      await page.goto(`${APP_URL}/login`);
      // If the IdP session survived, we would bounce straight back without a form.
      await page.waitForSelector('#username');
      await shot(page, `${viewport.tag}-4-after-logout`);
    });

    await step(`[${viewport.tag}] alice: /admin is forbidden (403)`, async () => {
      await signIn(page, 'alice');
      await page.waitForURL(`${APP_URL}/`);
      const res = await page.goto(`${APP_URL}/admin`);
      assert.equal(res.status(), 403);
      await shot(page, `${viewport.tag}-5-forbidden`);
    });

    await context.close();
  }
} finally {
  await browser.close();
  console.log(results.join('\n'));
}
