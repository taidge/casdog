// Real navigation to a local WeChat protocol fixture; no API interception.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

async function freePort() {
  const socket = net.createServer();
  await new Promise((resolve, reject) => socket.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}
function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = [...secret.replace(/=+$/, '')].map(c => alphabet.indexOf(c).toString(2).padStart(5, '0')).join('');
  const key = Buffer.from(bits.match(/.{8}/g).map(v => parseInt(v, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = crypto.createHmac('sha1', key).update(counter).digest(), offset = digest.at(-1) & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
async function startWechat(origin, credentials) {
  const wire = [], tickets = new Map(), codes = new Map(), tokens = new Map();
  let subject = 'browser-shared-union';
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://fixture');
    const json = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); };
    if (req.method !== 'GET') return json(405, {});
    if (['/connect/qrconnect', '/connect/oauth2/authorize'].includes(url.pathname)) {
      const appid = url.searchParams.get('appid'), mobile = appid === credentials.mobile.id;
      const expected = mobile ? credentials.mobile : credentials.desktop;
      const redirect = new URL(url.searchParams.get('redirect_uri'));
      if (appid !== expected.id || redirect.origin !== origin || !redirect.pathname.startsWith('/api/auth/') || !redirect.pathname.endsWith('/callback') || url.searchParams.get('response_type') !== 'code' || url.searchParams.get('scope') !== (mobile ? 'snsapi_userinfo' : 'snsapi_login') || url.pathname !== (mobile ? '/connect/oauth2/authorize' : '/connect/qrconnect')) return json(400, {errcode: 40013});
      const ticket = crypto.randomBytes(24).toString('hex');
      tickets.set(ticket, { appid, redirect: redirect.href, state: url.searchParams.get('state'), subject, expires: Date.now() + 300000 });
      wire.push({stage: 'authorization', appid, mobile, path: url.pathname, scope: url.searchParams.get('scope'), browserUa: req.headers['user-agent']});
      res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store'});
      res.end(`<!doctype html><html><body><h1>Local WeChat authorization fixture</h1><p>This is a protocol fixture, not a real WeChat account.</p><form action="/authorize/finish" method="get"><input type="hidden" name="ticket" value="${ticket}"><button>Authorize fixture WeChat</button></form></body></html>`);
      return;
    }
    if (url.pathname === '/authorize/finish') {
      const key = url.searchParams.get('ticket'), flow = tickets.get(key); tickets.delete(key);
      if (!flow || flow.expires < Date.now()) return json(400, {});
      const code = crypto.randomBytes(24).toString('hex'); codes.set(code, flow);
      const callback = new URL(flow.redirect); callback.searchParams.set('state', flow.state); callback.searchParams.set('code', code);
      res.writeHead(302, {Location: callback.href, 'Cache-Control': 'no-store'}); res.end(); return;
    }
    if (url.pathname === '/sns/oauth2/access_token') {
      const code = url.searchParams.get('code'), flow = codes.get(code); codes.delete(code);
      const appid = url.searchParams.get('appid'), expected = appid === credentials.mobile.id ? credentials.mobile : credentials.desktop;
      const valid = !!flow && flow.expires > Date.now() && flow.appid === appid && expected.id === appid && expected.secret === url.searchParams.get('secret') && url.searchParams.get('grant_type') === 'authorization_code';
      wire.push({stage: 'token', appid, credentialMatched: valid});
      if (!valid) return json(200, {errcode: 40029, errmsg: 'Invalid fixture authorization'});
      const token = crypto.randomBytes(32).toString('hex'); tokens.set(token, flow);
      return json(200, {access_token: token, openid: 'browser-openid', unionid: flow.subject, expires_in: 7200, scope: appid === credentials.mobile.id ? 'snsapi_userinfo' : 'snsapi_login'});
    }
    if (url.pathname === '/sns/userinfo') {
      const flow = tokens.get(url.searchParams.get('access_token'));
      const valid = !!flow && flow.expires > Date.now() && url.searchParams.get('openid') === 'browser-openid';
      wire.push({stage: 'userinfo', appid: flow?.appid, identityMatched: valid});
      if (!valid) return json(200, {errcode: 40003});
      return json(200, {openid: 'browser-openid', unionid: flow.subject, nickname: 'WeChat browser user'});
    }
    return json(404, {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { origin: `http://127.0.0.1:${server.address().port}/`, wire, setSubject(value) {subject = value;}, close: () => new Promise(resolve => {server.closeAllConnections(); server.close(resolve);}) };
}

async function runWechatBrowser({browser, database, artifacts, fixtureExecutable}) {
  assert.ok(database, 'A migrated disposable browser database is required');
  const folder = path.join(artifacts, 'wechat'); await fs.mkdir(folder, {recursive: true});
  const executable = fixtureExecutable || path.resolve(artifacts, '../../debug/examples/wechat_browser_fixture.exe');
  await fs.access(executable);
  const executableHash = crypto.createHash('sha256').update(await fs.readFile(executable)).digest('hex').toUpperCase();
  await fs.writeFile(path.join(folder, 'runtime-image.json'), JSON.stringify({executable,sha256:executableHash,verified_at:new Date().toISOString()},null,2));
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'casdog-wechat-browser-'));
  const configPath = path.join(directory, 'fixture.json');
  const suffix = crypto.randomBytes(6).toString('hex'), origin = `http://127.0.0.1:${await freePort()}`;
  const credentials = {desktop: {id: `desktop-${suffix}`, secret: crypto.randomBytes(24).toString('hex')}, mobile: {id: `mobile-${suffix}`, secret: crypto.randomBytes(24).toString('hex')}};
  const adminPassword = `Fixture${crypto.randomBytes(20).toString('hex')}!`;
  const config = {database, origin, wechat_origin: '', jwt_secret: crypto.randomBytes(32).toString('hex'), admin_id: crypto.randomUUID(), admin_name: `wx-admin-${suffix}`, admin_password: adminPassword};
  const fixture = await startWechat(origin, credentials); config.wechat_origin = fixture.origin;
  const contexts = [], checks = [], runtimeErrors = [], output = [];
  let process, page;
  const scrub = text => [database, config.jwt_secret, adminPassword, credentials.desktop.secret, credentials.mobile.secret].reduce((text, secret) => text.split(secret).join('[redacted]'), String(text));
  try {
    await fs.writeFile(configPath, JSON.stringify(config), {mode: 0o600});
    process = spawn(executable, ['--config', configPath], {cwd: path.resolve(__dirname, '../crates/casdog'), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
    process.stdout.on('data', data => output.push(scrub(data))); process.stderr.on('data', data => output.push(scrub(data)));
    let processError; process.once('error', error => {processError = error;});
    let ready = false;
    for (let n = 0; n < 240; n++) {
      if (processError || process.exitCode !== null) break;
      try {if ((await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(1000)})).ok) {ready = true; break;}} catch {}
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    assert.ok(ready, `WeChat development example did not start: ${output.join('').slice(-1500)}`);
    await fs.rm(configPath);
    const adminContext = await browser.newContext(); contexts.push(adminContext);
    async function api(method, route, body, token) {
      const response = await adminContext.request.fetch(`${origin}${route}`, {method, data: body, headers: token ? {Authorization: `Bearer ${token}`} : {}});
      assert.ok(response.ok(), `${method} ${route} returned HTTP ${response.status()}`);
      return response.json();
    }
    const admin = await api('POST', '/api/login', {owner: 'built-in', name: config.admin_name, password: adminPassword}); assert.ok(admin.token);
    const owner = `wx-browser-${suffix}`, appName = `wx-app-${suffix}`, providerName = `wx-${suffix}`;
    await api('POST', '/api/organizations', {owner: 'admin', name: owner, display_name: 'WeChat browser tenant'}, admin.token);
    const provider = await api('POST', '/api/providers', {owner, name: providerName, display_name: 'Browser WeChat', category: 'OAuth', type: 'WeChat', client_id: credentials.desktop.id, client_secret: credentials.desktop.secret, client_id2: credentials.mobile.id, client_secret2: credentials.mobile.secret}, admin.token);
    assert.equal(provider.client_secret, '***'); assert.equal(provider.client_secret2, '***');
    await api('POST', '/api/applications', {owner, name: appName, display_name: 'WeChat browser app', organization: owner, enable_password: true, enable_idp_signup: true, providers: [{name: `${owner}/${providerName}`, canSignIn: true, canSignUp: true, canUnlink: true}]}, admin.token);
    const appReference = `${owner}/${appName}`;
    async function context(mobile) {
      const ctx = await browser.newContext({viewport: {width: mobile ? 420 : 1380, height: 980}, userAgent: mobile ? 'Mozilla/5.0 Mobile MicroMessenger/8.0' : 'Mozilla/5.0 CasdogDesktopBrowser'}); contexts.push(ctx);
      const pg = await ctx.newPage(); pg.on('pageerror', error => runtimeErrors.push(error.message));
      return {ctx, pg};
    }
    async function loginPage(pg) {
      await pg.goto(origin); await pg.getByRole('button', {name: 'Sign in', exact: true}).first().click();
      await pg.getByRole('heading', {name: 'Sign in', exact: true}).waitFor();
      await pg.getByRole('textbox', {name: 'Application', exact: true}).fill(appReference);
    }
    async function consent(ctx, pg, mobile) {
      await pg.getByRole('heading', {name: 'Local WeChat authorization fixture'}).waitFor();
      const url = new URL(pg.url()); assert.equal(url.searchParams.get('appid'), mobile ? credentials.mobile.id : credentials.desktop.id);
      const cdp = await ctx.newCDPSession(pg);
      await cdp.send('Network.setUserAgentOverride', {userAgent: mobile ? 'Mozilla/5.0 Desktop callback changed UA' : 'Mozilla/5.0 MicroMessenger/8 callback changed UA'});
      await pg.getByRole('button', {name: 'Authorize fixture WeChat'}).click();
    }
    const desktop = await context(false); page = desktop.pg;
    await loginPage(page); await page.getByRole('button', {name: 'Sign in with Browser WeChat', exact: true}).click();
    await consent(desktop.ctx, page, false);
    await page.getByRole('heading', {name: 'Identity and access management', exact: true}).waitFor();
    const firstToken = await page.evaluate(() => JSON.parse(localStorage.getItem('casdog.auth.token'))); assert.ok(firstToken);
    const firstUser = await api('GET', '/api/get-account', undefined, firstToken);
    const userId = firstUser.data?.id || firstUser.id;
    assert.ok(userId); assert.ok(fixture.wire.some(item => item.stage === 'token' && item.appid === credentials.desktop.id && item.credentialMatched));
    await page.screenshot({path: path.join(folder, 'desktop.png'), fullPage: true});
    checks.push('WeChat desktop browser completes real qrconnect/code/token/userinfo and session flow while callback UA changes to MicroMessenger');
    await page.getByRole('button', {name: 'Account', exact: true}).first().click();
    await page.getByRole('button', {name: 'MFA', exact: true}).click();
    const setupResponse = page.waitForResponse(r => new URL(r.url()).pathname === '/api/mfa/setup' && r.request().method() === 'POST');
    await page.getByRole('button', {name: 'Set up authenticator', exact: true}).click();
    const setup = await (await setupResponse).json();
    await page.getByLabel('Authenticator code', {exact: true}).fill(totp(setup.secret));
    await page.getByRole('button', {name: 'Verify and enable MFA'}).click();
    await page.getByText('MFA enabled. Save your one-use recovery codes.', {exact: true}).waitFor();
    const nextTotpWindow = (Math.floor(Date.now() / 30000) + 1) * 30000 + 1000;
    const mobile = await context(true); page = mobile.pg;
    await loginPage(page); await page.getByRole('button', {name: 'Sign in with Browser WeChat', exact: true}).click();
    await consent(mobile.ctx, page, true);
    await page.getByRole('combobox', {name: 'Verification method'}).waitFor();
    assert.equal(await page.evaluate(() => localStorage.getItem('casdog.auth.token')), null);
    await page.getByLabel('Verification code', {exact: true}).fill('invalid');
    await page.evaluate(() => new Promise(requestAnimationFrame));
    const invalidProof = page.waitForResponse(response => new URL(response.url()).pathname === '/api/auth/session' && response.request().method() === 'POST' && response.request().postData()?.includes('invalid'));
    await page.getByRole('button', {name: 'Sign in', exact: true}).last().click();
    assert.equal((await invalidProof).status(), 401);
    assert.equal(await page.evaluate(() => localStorage.getItem('casdog.auth.token')), null);
    await page.getByRole('combobox', {name: 'Verification method'}).waitFor();
    while (Date.now() < nextTotpWindow) await new Promise(resolve => setTimeout(resolve, Math.min(1000, nextTotpWindow - Date.now())));
    await page.getByLabel('Verification code', {exact: true}).fill(totp(setup.secret));
    await page.evaluate(() => new Promise(requestAnimationFrame));
    await page.getByRole('button', {name: 'Sign in', exact: true}).last().click();
    await page.getByRole('heading', {name: 'Identity and access management', exact: true}).waitFor();
    const mobileToken = await page.evaluate(() => JSON.parse(localStorage.getItem('casdog.auth.token')));
    const mobileUser = await api('GET', '/api/get-account', undefined, mobileToken); assert.equal(mobileUser.data?.id || mobileUser.id, userId);
    assert.ok(fixture.wire.some(item => item.stage === 'token' && item.appid === credentials.mobile.id && item.credentialMatched));
    await page.screenshot({path: path.join(folder, 'micromessenger-mfa.png'), fullPage: true});
    checks.push('MicroMessenger browser uses secondary credentials and persistent variant despite desktop callback UA, enforces TOTP and signs into the same UnionID account');
    const localPassword = `Link${crypto.randomBytes(16).toString('hex')}!`, localName = `wx-link-${suffix}`;
    const localUser = await api('POST', '/api/users', {owner, name: localName, display_name: 'WeChat link browser user', password: localPassword}, admin.token);
    fixture.setSubject('browser-linked-union');
    const link = await context(true); page = link.pg;
    await loginPage(page);
    await page.getByRole('textbox', {name: 'Organization', exact: true}).fill(owner);
    await page.getByRole('textbox', {name: 'Username', exact: true}).fill(localName);
    await page.getByLabel('Password', {exact: true}).fill(localPassword);
    await page.getByRole('button', {name: 'Sign in', exact: true}).last().click();
    await page.getByRole('heading', {name: 'Identity and access management', exact: true}).waitFor();
    await page.getByRole('button', {name: 'Account', exact: true}).first().click();
    await page.getByRole('button', {name: 'Linked accounts', exact: true}).click();
    await page.getByRole('textbox', {name: 'Application', exact: true}).fill(appReference);
    await page.getByRole('button', {name: 'Load sign-in providers', exact: true}).click();
    await page.getByRole('button', {name: 'Link Browser WeChat', exact: true}).click();
    await consent(link.ctx, page, true);
    await page.getByRole('heading', {name: 'Linked accounts', exact: true}).waitFor();
    const linked = await api('GET', `/api/users/${localUser.id}`, undefined, admin.token);
    assert.equal(linked.provider_ids[`oauth:${provider.id}`], 'browser-linked-union');
    await page.screenshot({path: path.join(folder, 'linked-account.png'), fullPage: true});
    checks.push('Authenticated account browser links WeChat through secondary credentials and real code exchange without replacing another UnionID account');
    assert.deepEqual(runtimeErrors, []);
    assert.equal(fixture.wire.filter(item => item.stage === 'token').length, 3);
    await fs.writeFile(path.join(folder, 'results.json'), JSON.stringify({passed: true, checks, apiInterception: false, realWechatAccountAcceptance: false, runtimeErrors, wire: fixture.wire}, null, 2));
    return checks;
  } catch (error) {
    if (page && !page.isClosed()) {await page.screenshot({path: path.join(folder, 'failure.png'), fullPage: true}).catch(() => {});}
    await fs.writeFile(path.join(folder, 'results.json'), JSON.stringify({passed: false, checks, error: scrub(error.message), runtimeErrors, apiInterception: false, realWechatAccountAcceptance: false}, null, 2));
    throw new Error(scrub(error.message));
  } finally {
    for (const context of contexts) await context.close().catch(() => {});
    if (process && process.exitCode === null) {process.kill(); await new Promise(resolve => {process.once('exit', resolve); setTimeout(resolve, 5000);});}
    await fixture.close();
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('casdog-wechat-browser-'));
    await fs.rm(directory, {recursive: true, force: true});
    await fs.writeFile(path.join(folder, 'server.log'), output.join(''));
  }
}
module.exports = {runWechatBrowser};
