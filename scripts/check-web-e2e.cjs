// Exercises the compiled frontend against the real server and disposable PostgreSQL.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { execFileSync, spawn } = require('node:child_process');
const { chromium } = require('../web/node_modules/playwright');
const { startDirectory } = require('./ldap-browser-fixture.cjs');

const project = path.resolve(__dirname, '..');
const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1'], {
  cwd: project,
  encoding: 'utf8',
  windowsHide: true,
}));
const artifacts = path.join(metadata.target_directory, 'phase7', 'browser-e2e');
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
  const appBundle = Buffer.from(JSON.stringify({manifest:{id:'browser-portal',type:'app',version:'1.0',variables:[{name:'appUrl',label:{en:'Application URL'},type:'url',required:true}]},files:{'application.json':{redirectUris:['{{appUrl}}/callback']}}}));
  const providerBundle = Buffer.from(JSON.stringify({manifest:{id:'browser-provider',type:'provider',version:'1.0',variables:[]},files:{'provider.json':{category:'OAuth',type:'GitHub',scopes:'user:email'}}}));
  const registry = {integrations:[
    {id:'browser-portal',name:{en:'Browser portal'},type:'app',latest:'1.0',versions:[{version:'1.0',url:'app.json',sha256:crypto.createHash('sha256').update(appBundle).digest('hex')}]},
    {id:'browser-provider',name:{en:'Browser provider'},type:'provider',latest:'1.0',versions:[{version:'1.0',url:'provider.json',sha256:crypto.createHash('sha256').update(providerBundle).digest('hex')}]},
  ]};
  const mailServer = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (request.method === 'GET') {
      const body = {'/marketplace/index.json':JSON.stringify(registry),'/marketplace/app.json':appBundle,'/marketplace/provider.json':providerBundle}[pathname];
      response.writeHead(body ? 200 : 404, {'Content-Type':'application/json'});
      response.end(body || '{}');
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    mail.push(JSON.parse(Buffer.concat(chunks).toString()));
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{}');
  });
  await new Promise(resolve => mailServer.listen(0, '127.0.0.1', resolve));
  const mailEndpoint = `http://127.0.0.1:${mailServer.address().port}/mail`;
  let directoryUsername='';
  const directory=await startDirectory(()=>directoryUsername);
  let server, browser, page, runtimeImage;
  const serverOutput = [];
  const checks = [];
  const runtimeErrors = [];
  const secretsThatMustNotBeLogged=[];
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
          CASDOG_MARKETPLACE_URL: `http://127.0.0.1:${mailServer.address().port}/marketplace`,
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
    directoryUsername=username;
    const email = `${username}@example.test`;
    const password = 'BrowserPassword42!';
    let admin = await api('POST', '/api/login', { owner: 'built-in', name: 'admin', password: '123' });
    assert.ok(admin.token, 'Disposable database admin must be initialized');
    await api('POST', '/api/providers', {
      owner: 'built-in', name: `browser-mail-${suffix}`, display_name: 'Browser mail fixture',
      category: 'Email', type: 'Custom HTTP', endpoint: mailEndpoint,
    }, admin.token);

    await page.goto(origin);
    await navigate('Sign in', 'Sign in');
    await fill('Username', 'admin');
    await fill('Password', '123', true);
    await page.getByRole('button', {name:'Sign in', exact:true}).last().click();
    await page.getByRole('heading', {name:'Identity and access management'}).waitFor();
    await navigate('API keys','API keys');
    await fill('Key name',`user-key-${suffix}`);
    await page.getByRole('button',{name:'Save API key',exact:true}).click();
    await page.getByText('API key saved.',{exact:true}).waitFor();
    const accessKey=await page.getByRole('textbox',{name:'Access key',exact:true}).inputValue();
    const accessSecret=await page.getByLabel('Access secret',{exact:true}).inputValue();
    secretsThatMustNotBeLogged.push(accessSecret);
    const keyHeaders={Authorization:`Basic ${Buffer.from(`${accessKey}:${accessSecret}`).toString('base64')}`};
    assert.ok((await context.request.get(`${origin}/api/users`,{headers:keyHeaders})).ok());
    assert.ok((await context.request.get(`${origin}/api/users?${new URLSearchParams({accessKey,accessSecret})}`)).ok());
    const disabled=page.waitForResponse(response=>response.url().endsWith('/api/update-key'));
    await page.getByRole('combobox',{name:'Key state',exact:true}).selectOption('Inactive');
    await page.getByRole('button',{name:'Save API key',exact:true}).click();
    assert.ok((await disabled).ok());
    await page.waitForFunction(()=>Array.from(document.querySelectorAll('button')).some(button=>button.textContent==='Save API key'&&button.getAttribute('aria-busy')==='false'));
    assert.equal((await context.request.get(`${origin}/api/users`,{headers:keyHeaders})).status(),401);
    const enabled=page.waitForResponse(response=>response.url().endsWith('/api/update-key'));
    await page.getByRole('combobox',{name:'Key state',exact:true}).selectOption('Active');
    await page.getByRole('button',{name:'Save API key',exact:true}).click();
    assert.ok((await enabled).ok());
    await page.waitForFunction(()=>Array.from(document.querySelectorAll('button')).some(button=>button.textContent==='Save API key'&&button.getAttribute('aria-busy')==='false'));
    assert.ok((await context.request.get(`${origin}/api/users`,{headers:keyHeaders})).ok());
    await page.getByRole('button',{name:'Delete API key',exact:true}).click();
    await page.getByText('API key deleted.',{exact:true}).waitFor();
    assert.equal((await context.request.get(`${origin}/api/users`,{headers:keyHeaders})).status(),401);
    checks.push('API key UI creates real credentials; Basic/query authenticate without JWT and disable/delete revoke immediately');
    await navigate('Marketplace', 'Marketplace integrations');
    await page.getByRole('button', {name:'Load marketplace',exact:true}).click();
    await page.getByRole('button', {name:'Preview Browser portal',exact:true}).click();
    await fill('Application URL', 'https://browser.example.test');
    await fill('Installation name', `market-app-${suffix}`);
    await page.getByRole('button', {name:'Install integration',exact:true}).click();
    await page.getByText('Integration installed.',{exact:true}).waitFor();
    const installedApp = await api('GET', `/api/get-application?id=built-in/market-app-${suffix}`, undefined, admin.token);
    assert.ok(installedApp.data.id);
    assert.deepEqual(JSON.parse(installedApp.data.redirectUris || installedApp.data.redirect_uris), ['https://browser.example.test/callback']);
    await navigate('API keys','API keys');
    await fill('Reviewed application ID or owner/name',`built-in/market-app-${suffix}`);
    await page.getByRole('button',{name:'Trust static application',exact:true}).click();
    await page.getByText('Static application credentials trusted.',{exact:true}).waitFor();
    const applicationHeaders={Authorization:`Basic ${Buffer.from(`${installedApp.data.clientId}:${installedApp.data.clientSecret}`).toString('base64')}`};
    assert.ok((await context.request.get(`${origin}/api/get-global-users`,{headers:applicationHeaders})).ok());
    assert.equal((await context.request.get(`${origin}/api/get-account`,{headers:applicationHeaders})).status(),403);
    checks.push('Reviewed static application authenticates its virtual administrator while user-session endpoints reject it');
    await navigate('Marketplace','Marketplace integrations');
    await page.getByRole('button',{name:'Load marketplace',exact:true}).click();
    await page.getByRole('button', {name:'Preview Browser provider',exact:true}).click();
    await fill('Provider client ID', 'browser-oauth-client');
    await fill('Installation name', `market-provider-${suffix}`);
    await fill('Provider client secret', 'browser-oauth-secret', true);
    await fill('Link to application (optional)', `market-app-${suffix}`);
    await page.getByRole('button', {name:'Install integration',exact:true}).click();
    await page.getByText('Integration installed.',{exact:true}).waitFor();
    const linkedApp = await api('GET', `/api/get-application?id=built-in/market-app-${suffix}`, undefined, admin.token);
    assert.ok(linkedApp.data.providers.some(value => value.name === `market-provider-${suffix}`));
    await page.screenshot({path:path.join(artifacts, 'marketplace-installed.png'), fullPage:true});
    await page.getByRole('button', {name:`Uninstall built-in/market-provider-${suffix}`,exact:true}).click();
    await page.getByText('Integration uninstalled.',{exact:true}).waitFor();
    const unlinkedApp = await api('GET', `/api/get-application?id=built-in/market-app-${suffix}`, undefined, admin.token);
    assert.deepEqual(unlinkedApp.data.providers, []);
    const appDeletion = page.waitForResponse(response => response.url().endsWith('/api/delete-integration') && response.request().postDataJSON().name === `market-app-${suffix}`);
    await page.getByRole('button', {name:`Uninstall built-in/market-app-${suffix}`,exact:true}).click();
    assert.ok((await appDeletion).ok());
    await page.getByText('Integration uninstalled.',{exact:true}).waitFor();
    assert.equal((await api('GET', `/api/get-integrations?owner=built-in`, undefined, admin.token)).data.some(value=>value.name===`market-app-${suffix}`||value.name===`market-provider-${suffix}`),false);
    checks.push('Marketplace UI fetched checksummed local catalog, installed real application/provider, linked and uninstalled both transactionally');
    await page.getByRole('button', {name:'Sign out',exact:true}).click();
    await page.getByRole('heading', {name:'Sign in',exact:true}).waitFor();
    // Browser logout revokes the administrator's earlier API session too.
    admin = await api('POST', '/api/login', { owner:'built-in', name:'admin', password:'123' });
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

    const loginApplication=await api('POST','/api/applications',{
      owner:'admin',name:`browser-login-${suffix}`,display_name:'Browser primary login',organization:'built-in',
      enable_password:true,enable_code_signin:true,signin_methods:[{name:'Password',rule:'All'},{name:'LDAP',rule:'All'},{name:'Verification code',rule:'Email only'}],
      providers:[{name:`built-in/browser-mail-${suffix}`,rule:'All',canSignIn:true}],
    },admin.token);
    const directoryProvider=await api('POST','/api/providers',{
      owner:'built-in',name:`browser-directory-${suffix}`,display_name:'Browser LDAP fixture',category:'LDAP',type:'LDAP',
      host:directory.url,disable_ssl:true,client_id:'cn=service,dc=example,dc=test',client_secret:'search-password',
      metadata:JSON.stringify({base_dn:'dc=example,dc=test',filter:'(objectClass=person)',filter_fields:['uid']}),
    },admin.token);
    await api('POST','/api/update-user',{owner:'built-in',name:username,ldap:directoryProvider.id},admin.token);
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await page.getByRole('combobox',{name:'Sign-in method',exact:true}).selectOption('email');
    await fill('Username',username);await fill('Application',`admin/browser-login-${suffix}`);
    await page.getByRole('button',{name:'Send sign-in code',exact:true}).click();
    await page.getByText('Sign-in code sent to your enrolled contact.',{exact:true}).waitFor();
    const signInDelivery=mail.find(value=>value.to===email&&value.subject==='Sign-in verification');
    assert.ok(signInDelivery);
    const signInCode=signInDelivery.body.match(/\b\d{6}\b/)[0];
    await fill('Sign-in code','wrong');
    const rejectedCode=page.waitForResponse(response=>response.url().endsWith('/api/login')&&response.request().method()==='POST');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    assert.equal((await rejectedCode).status(),401);
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    await fill('Sign-in code',signInCode);
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    checks.push('Passwordless email first factor delivers to enrolled contact and rejects wrong proof before real browser login');
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await page.getByRole('combobox',{name:'Sign-in method',exact:true}).selectOption('ldap');
    await fill('Username',username);await fill('Application',`admin/browser-login-${suffix}`);
    await fill('Password','DirectoryPassword42!',true);
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    assert.ok(directory.metrics.searches>0&&directory.metrics.userBinds>0&&directory.metrics.errors===0);
    token=await page.evaluate(()=>JSON.parse(localStorage.getItem('casdog.auth.token')));
    assert.equal((await api('GET','/api/get-account',undefined,token)).name,username);
    checks.push('LDAP browser login uses real ldap3 service bind, directory search and distinct user password');
    await navigate('Account','Account settings');

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
    const confirmationResponse = page.waitForResponse(response => response.url().endsWith('/api/mfa/verify'));
    await fill('Authenticator code', totp(setup.secret));
    await page.getByRole('button', { name: 'Verify and enable MFA' }).click();
    const confirmation = await (await confirmationResponse).json();
    assert.ok(confirmation.recovery_codes.length >= 2);
    await page.getByText('MFA enabled. Save your one-use recovery codes.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor();
    await fill('Username', username);
    await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
    await page.getByRole('combobox', { name: 'Verification method' }).waitFor();
    assert.equal(await page.evaluate(() => localStorage.getItem('casdog.auth.token')), null);
    await page.getByRole('combobox', {name:'Verification method'}).selectOption('recovery');
    await fill('Verification code', confirmation.recovery_codes[0]);
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
    await page.getByRole('combobox', {name:'Verification method'}).selectOption('recovery');
    await fill('Verification code', confirmation.recovery_codes[1]);
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
    const delivery = mail.find(value => value.to === email && value.subject === 'Reset your password');
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
    for(const secret of secretsThatMustNotBeLogged)assert.ok(!serverOutput.join('').includes(secret),'Request tracing must omit query secrets');
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
    await directory.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
