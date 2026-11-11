// Exercises the compiled frontend against the real server and disposable PostgreSQL.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { execFileSync, spawn } = require('node:child_process');
const { chromium } = require('../web/node_modules/playwright');

const project = path.resolve(__dirname, '..');
const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1'], {
  cwd: project,
  encoding: 'utf8',
  windowsHide: true,
}));
const artifacts = path.join(metadata.target_directory, 'phase5', 'browser-e2e');
const origin = process.env.CASDOG_E2E_BASE_URL || 'http://localhost:18085';
const database = process.env.CASDOG_TEST_DATABASE_URL;
assert.ok(database, 'CASDOG_TEST_DATABASE_URL must identify a migrated disposable database');

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const character of secret.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(character).toString(2).padStart(5, '0');
  }
  const key = Buffer.from(bits.match(/.{8}/g).map(byte => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = crypto.createHmac('sha1', key).update(counter).digest();
  const offset = digest.at(-1) & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}

async function main() {
  await fs.mkdir(artifacts, { recursive: true });
  const mail = [];
  const mailServer = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    mail.push(JSON.parse(Buffer.concat(chunks).toString()));
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{}');
  });
  await new Promise(resolve => mailServer.listen(0, '127.0.0.1', resolve));
  const mailEndpoint = `http://127.0.0.1:${mailServer.address().port}/mail`;
  let server, browser, page, runtimeImage;
  const serverOutput = [];
  const checks = [];
  const runtimeErrors = [];
  try {
    if (!process.env.CASDOG_E2E_BASE_URL) {
      const url = new URL(origin);
      const probe = net.createServer();
      await new Promise((resolve, reject) => probe.once('error', reject).listen(Number(url.port), '127.0.0.1', resolve));
      await new Promise(resolve => probe.close(resolve));
      const binaryName = process.platform === 'win32' ? 'casdog.exe' : 'casdog';
      runtimeImage = path.join(artifacts, `${Date.now()}-${binaryName}`);
      await fs.copyFile(path.join(metadata.target_directory, 'debug', binaryName), runtimeImage);
      server = spawn(runtimeImage, [], {
        cwd: path.join(project, 'crates', 'casdog'),
        windowsHide: true,
        env: {
          ...process.env,
          CASDOG__DATABASE__URL: database,
          CASDOG__SERVER__HOST: '127.0.0.1',
          CASDOG__SERVER__PORT: url.port,
          CASDOG__SERVER__PUBLIC_URL: origin,
          CASDOG__JWT__SECRET: crypto.randomBytes(32).toString('hex'),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      server.stdout.on('data', chunk => serverOutput.push(chunk.toString()));
      server.stderr.on('data', chunk => serverOutput.push(chunk.toString()));
      server.on('error', error => serverOutput.push(error.message));
    }
    let ready = false;
    for (let attempt = 0; attempt < 200; attempt++) {
      try {
        ready = (await fetch(`${origin}/api/health`)).ok;
      } catch {}
      if (ready) break;
      if (server?.exitCode !== null && server?.exitCode !== undefined) break;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    assert.ok(ready, `Backend did not start. ${serverOutput.join('').slice(-3000)}`);
    browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'msedge', headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    page = await context.newPage();
    page.on('pageerror', error => runtimeErrors.push(error.message));
    page.on('console', event => {
      if (event.type() === 'error' && event.text().includes('Glory')) runtimeErrors.push(event.text());
    });
    async function api(method, endpoint, body, token) {
      const response = await context.request.fetch(`${origin}${endpoint}`, {
        method,
        data: body,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const value = await response.json();
      assert.ok(response.ok() && value.status !== 'error', `${method} ${endpoint} returned ${response.status()} ${JSON.stringify(value)}`);
      return value;
    }
    async function fill(name, value, secret = false) {
      const input = secret ? page.getByLabel(name, { exact: true }) : page.getByRole('textbox', { name, exact: true });
      await input.fill(value);
      await page.evaluate(() => new Promise(requestAnimationFrame));
    }
    async function navigate(name, heading) {
      await page.getByRole('button', { name, exact: true }).first().click();
      if (heading) await page.getByRole('heading', { name: heading, exact: true }).waitFor();
    }
    async function signIn(password) {
      await navigate('Sign in', 'Sign in');
      await fill('Username', username);
      await fill('Password', password, true);
      await page.getByRole('button', { name: 'Sign in', exact: true }).last().click();
    }
    const suffix = crypto.randomBytes(5).toString('hex');
    const username = `browser-${suffix}`;
    const email = `${username}@example.test`;
    const password = 'BrowserPassword42!';
    const admin = await api('POST', '/api/login', { owner: 'built-in', name: 'admin', password: '123' });
    assert.ok(admin.token, 'Disposable database admin must be initialized');
    await api('POST', '/api/providers', {
      owner: 'built-in', name: `browser-mail-${suffix}`, display_name: 'Browser mail fixture',
      category: 'Email', type: 'Custom HTTP', endpoint: mailEndpoint,
    }, admin.token);

    await page.goto(origin);
    await navigate('Sign up', 'Create account');
    await fill('Username', username);
    await fill('Display name', 'Browser user');
    await fill('Email', email);
    await fill('Password', password, true);
    await fill('Confirm password', password, true);
    await page.getByRole('button', { name: 'Sign up', exact: true }).last().click();
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor();
    await signIn(password);
    await page.getByRole('heading', { name: 'Identity and access management' }).waitFor();
    let token = await page.evaluate(() => JSON.parse(localStorage.getItem('casdog.auth.token')));
    assert.ok(token);
    checks.push('Browser signup and password login persisted a real user/session');

    await navigate('Account', 'Account settings');
    await page.getByRole('heading', { name: 'Profile', exact: true }).waitFor();
    await fill('Display name', 'Browser profile saved');
    await page.getByRole('button', { name: 'Save profile', exact: true }).click();
    await page.getByText('Profile saved.', { exact: true }).waitFor();
    assert.equal((await api('GET', '/api/get-account', undefined, token)).display_name, 'Browser profile saved');
    checks.push('Profile changes persisted through the authenticated API');

    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
      },
    });
    await page.getByRole('button', { name: 'WebAuthn', exact: true }).click();
    await fill('Credential name', 'Browser passkey');
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
    const cancelledBegin = page.waitForResponse(response => response.url().endsWith('/api/webauthn/signup/begin'));
    await page.getByRole('button', { name: 'Register passkey', exact: true }).click();
    await cancelledBegin;
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await page.getByRole('button', { name: 'Cancel passkey request', exact: true }).click();
    await page.getByText('Passkey registration was cancelled or timed out. Try again when ready.', { exact: true }).waitFor();
    assert.deepEqual(await api('GET', '/api/webauthn/credentials', undefined, token), []);
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
    checks.push('Cancelling a native WebAuthn request leaves no enrolled credential and permits retry');
    await page.getByRole('button', { name: 'Register passkey', exact: true }).click();
    await page.getByText('Passkey registered.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Remove Browser passkey', exact: true }).waitFor();
    const credentials = await api('GET', '/api/webauthn/credentials', undefined, token);
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].name, 'Browser passkey');
    assert.equal((await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials.length, 1);
    checks.push('Native navigator.credentials.create attestation verified and persisted by PostgreSQL');
    const passkeyLogin = await page.evaluate(async ({ username }) => {
      const begin = await (await fetch(`/api/webauthn/signin/begin?owner=built-in&name=${encodeURIComponent(username)}`)).json();
      const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0));
      const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const source = begin.options.publicKey ?? begin.options;
      const publicKey = typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
        ? PublicKeyCredential.parseRequestOptionsFromJSON(source)
        : { ...source, challenge: decode(source.challenge), allowCredentials: source.allowCredentials.map(value => ({ ...value, id: decode(value.id) })) };
      const credential = await navigator.credentials.get({ publicKey });
      const response = credential.response;
      return await (await fetch(`/api/webauthn/signin/finish?requestId=${encodeURIComponent(begin.requestId)}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: credential.id, rawId: encode(credential.rawId), type: credential.type,
          response: { clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData), signature: encode(response.signature), userHandle: response.userHandle ? encode(response.userHandle) : null },
          extensions: credential.getClientExtensionResults(),
        }),
      })).json();
    }, { username });
    assert.ok(passkeyLogin.token, JSON.stringify(passkeyLogin));
    assert.equal((await api('GET', '/api/get-account', undefined, passkeyLogin.token)).name, username);
    checks.push('Native navigator.credentials.get assertion completed a real passkey login');
    await page.screenshot({ path: path.join(artifacts, 'webauthn-registered.png'), fullPage: true });

    const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
    const deviceApplication = await api('POST', '/api/applications', {
      owner: 'admin', name: `browser-device-${suffix}`, display_name: 'Browser device application',
      organization: 'built-in', grant_types: [deviceGrant, 'refresh_token'],
      enable_password: true, enable_signin_session: true,
      providers: [{ name: `built-in/browser-mail-${suffix}`, rule: 'Forget' }],
    }, admin.token);
    const client = { client_id: deviceApplication.client_id, client_secret: deviceApplication.client_secret };
    const device = await api('POST', '/api/device-auth', { ...client, scope: 'profile' });
    await page.goto(device.verification_uri_complete);
    await page.getByRole('heading', { name: 'Device authorization', exact: true }).waitFor();
    assert.equal(await page.getByRole('textbox', { name: 'User code', exact: true }).inputValue(), device.user_code);
    await page.getByRole('button', { name: 'Verify user code', exact: true }).click();
    await page.getByText('Review the application before approving access.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Approve device', exact: true }).click();
    await page.getByText('Device approved.', { exact: true }).waitFor();
    const deviceTokens = await api('POST', '/api/login/oauth/access_token', { ...client, grant_type: deviceGrant, device_code: device.device_code });
    assert.ok(deviceTokens.access_token && deviceTokens.refresh_token);
    assert.equal((await api('GET', '/api/get-account', undefined, deviceTokens.access_token)).name, username);
    const completedDevice = await api('POST', '/api/device-auth-complete', { deviceCode: device.device_code });
    assert.equal(completedDevice.user.name, username);
    const replay = await context.request.post(`${origin}/api/device-auth-complete`, { data: { deviceCode: device.device_code } });
    assert.ok(!replay.ok(), 'Device completion must reject replay');
    const cancelledDevice = await api('POST', '/api/device-auth', { ...client, scope: 'profile' });
    await api('POST', '/api/cancel-device-auth', { userCode: cancelledDevice.user_code, cancelToken: cancelledDevice.cancel_token });
    const deniedGrant = await context.request.post(`${origin}/api/login/oauth/access_token`, {
      data: { ...client, grant_type: deviceGrant, device_code: cancelledDevice.device_code },
    });
    assert.equal(deniedGrant.status(), 400);
    checks.push('Device browser approval, real OAuth token issuance, single-use completion and cancellation persisted');
    await navigate('Account', 'Account settings');

    await page.getByRole('button', { name: 'MFA', exact: true }).click();
    const setupResponse = page.waitForResponse(response => response.url().endsWith('/api/mfa/setup') && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Set up authenticator', exact: true }).click();
    const setup = await (await setupResponse).json();
    await fill('Authenticator code', 'invalid');
    await page.getByRole('button', { name: 'Verify and enable MFA' }).click();
    await page.getByText('The verification code is invalid or expired. Try the current code from your authenticator.').waitFor();
    await fill('Authenticator code', totp(setup.secret));
    await page.getByRole('button', { name: 'Verify and enable MFA' }).click();
    await page.getByText('MFA enabled. Save your one-use recovery codes.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor();
    await fill('Username', username);
    await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
    await page.getByRole('combobox', { name: 'Verification method' }).waitFor();
    assert.equal(await page.evaluate(() => localStorage.getItem('casdog.auth.token')), null);
    await fill('Verification code', totp(setup.secret));
    await page.getByRole('button', { name: 'Sign in', exact: true }).last().click();
    await page.getByRole('heading', { name: 'Identity and access management' }).waitFor();
    checks.push('Passkey sign-in through the UI enforces enrolled MFA before issuing a browser session');
    token = await page.evaluate(() => JSON.parse(localStorage.getItem('casdog.auth.token')));
    await navigate('Account', 'Account settings');
    await page.getByRole('button', { name: 'WebAuthn', exact: true }).click();
    await page.getByRole('button', { name: 'Remove Browser passkey', exact: true }).click();
    await page.getByText('Credential removed.', { exact: true }).waitFor();
    assert.deepEqual(await api('GET', '/api/webauthn/credentials', undefined, token), []);
    checks.push('Credential deletion persisted and refreshed the browser list');

    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor();
    await signIn(password);
    await page.getByRole('combobox', { name: 'Verification method' }).waitFor();
    assert.equal(await page.evaluate(() => localStorage.getItem('casdog.auth.token')), null);
    await fill('Verification code', 'invalid');
    const badProof = page.waitForResponse(response => response.url().endsWith('/api/auth/password/session') && response.request().postData()?.includes('invalid'));
    await page.getByRole('button', { name: 'Sign in', exact: true }).last().click();
    assert.equal((await badProof).ok(), false);
    await fill('Verification code', totp(setup.secret));
    await page.getByRole('button', { name: 'Sign in', exact: true }).last().click();
    await page.getByRole('heading', { name: 'Identity and access management' }).waitFor();
    token = await page.evaluate(() => JSON.parse(localStorage.getItem('casdog.auth.token')));
    checks.push('TOTP enrollment, failed proof rejection and password MFA login completed in the browser');
    await navigate('Account', 'Account settings');
    await page.getByRole('button', { name: 'MFA', exact: true }).click();
    await page.getByRole('button', { name: 'Disable authenticator', exact: true }).click();
    await page.getByText('MFA disabled.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor();

    await navigate('Recover password', 'Recover password');
    await fill('Email', email);
    await fill('Application', `admin/browser-device-${suffix}`);
    await page.getByRole('button', { name: 'Send reset code', exact: true }).click();
    await page.getByRole('textbox', { name: 'Reset code', exact: true }).waitFor();
    for (let attempt = 0; attempt < 100 && !mail.some(value => value.to === email); attempt++) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const delivery = mail.find(value => value.to === email);
    assert.ok(delivery, 'Local email provider must receive the recovery proof');
    const proof = delivery.body.split('\n')[1];
    await fill('Reset code', proof);
    const recoveredPassword = 'RecoveredBrowser42!';
    await fill('New password', recoveredPassword, true);
    await fill('Confirm new password', recoveredPassword, true);
    await page.getByRole('button', { name: 'Reset password', exact: true }).click();
    await page.getByText('Password reset. Sign in with your new password.', { exact: true }).waitFor();
    await signIn(recoveredPassword);
    await page.getByRole('heading', { name: 'Identity and access management' }).waitFor();
    checks.push('Password recovery delivered through a local HTTP email provider and new password login succeeded');
    assert.deepEqual(runtimeErrors, []);
    await fs.writeFile(path.join(artifacts, 'results.json'), JSON.stringify({ passed: true, checks, runtimeErrors, apiInterception: false }, null, 2));
    console.log(`Real backend browser E2E passed (${checks.length} checks)`);
  } catch (error) {
    await fs.writeFile(path.join(artifacts, 'results.json'), JSON.stringify({ passed: false, checks, runtimeErrors, error: error.message }, null, 2));
    if (page) {
      await fs.writeFile(path.join(artifacts, 'failure.html'), await page.content());
      await page.screenshot({ path: path.join(artifacts, 'failure.png'), fullPage: true });
    }
    throw error;
  } finally {
    if (browser) await browser.close();
    if (server?.pid && server.exitCode === null) {
      const closed = new Promise(resolve => server.once('close', resolve));
      server.kill();
      await closed;
    }
    if (runtimeImage) await fs.unlink(runtimeImage).catch(() => {});
    await fs.writeFile(path.join(artifacts, 'server.log'), serverOutput.join(''));
    await new Promise(resolve => mailServer.close(resolve));
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
