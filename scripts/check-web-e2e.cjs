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
const artifacts = path.join(metadata.target_directory, 'phase11', 'browser-e2e');
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

function protoLength(tag,bytes){
  function variable(value){const result=[];for(value=BigInt(value);value>127n;value>>=7n)result.push(Number(value&127n)|128);result.push(Number(value));return Buffer.from(result);}
  return Buffer.concat([variable(BigInt(tag)*8n+2n),variable(bytes.length),bytes]);
}
function browserTrace(){
  const fixed=(tag,value)=>{const bytes=Buffer.alloc(9);bytes[0]=tag*8+1;bytes.writeBigUInt64LE(value,1);return bytes;};
  const now=BigInt(Date.now())*1000000n;
  const span=Buffer.concat([protoLength(1,Buffer.alloc(16,4)),protoLength(2,Buffer.alloc(8,5)),protoLength(5,Buffer.from('Browser telemetry span')),fixed(7,now),fixed(8,now+1000000n)]);
  return protoLength(1,protoLength(2,protoLength(2,span)));
}

async function main() {
  await fs.mkdir(artifacts, { recursive: true });
  const mail = [];
  const scimToken=crypto.randomBytes(24).toString('hex'),scimRequests=[];
  let scimUsers=[];
  const appBundle = Buffer.from(JSON.stringify({manifest:{id:'browser-portal',type:'app',version:'1.0',variables:[{name:'appUrl',label:{en:'Application URL'},type:'url',required:true}]},files:{'application.json':{redirectUris:['{{appUrl}}/callback']}}}));
  const providerBundle = Buffer.from(JSON.stringify({manifest:{id:'browser-provider',type:'provider',version:'1.0',variables:[]},files:{'provider.json':{category:'OAuth',type:'GitHub',scopes:'user:email'}}}));
  const themeBundle = Buffer.from(JSON.stringify({manifest:{id:'browser-theme',type:'theme',version:'1.0',variables:[]},files:{'theme.json':{themeData:{isEnabled:true,themeType:'light',colorPrimary:'#126f85',borderRadius:12,isCompact:true},formOffset:4,formCss:'body h2 { color:rgb(13,75,125); } .sidebar { display:none; }',formCssMobile:'body h2 { color:rgb(40,100,80); }',formSideHtml:'<strong>Browser theme side panel</strong>',footerHtml:'<p>Browser theme footer</p>',formBackgroundUrl:'',formBackgroundUrlMobile:''}}}));
  const registry = {integrations:[
    {id:'browser-portal',name:{en:'Browser portal'},type:'app',latest:'1.0',versions:[{version:'1.0',url:'app.json',sha256:crypto.createHash('sha256').update(appBundle).digest('hex')}]},
    {id:'browser-provider',name:{en:'Browser provider'},type:'provider',latest:'1.0',versions:[{version:'1.0',url:'provider.json',sha256:crypto.createHash('sha256').update(providerBundle).digest('hex')}]},
    {id:'browser-theme',name:{en:'Browser theme'},type:'theme',latest:'1.0',versions:[{version:'1.0',url:'theme.json',sha256:crypto.createHash('sha256').update(themeBundle).digest('hex')}]},
  ]};
  const mailServer = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if(request.method==='GET'&&pathname==='/scim/v2/Users'){
      scimRequests.push(request.headers.authorization);
      if(request.headers.authorization!==`Bearer ${scimToken}`){response.writeHead(401);response.end('{}');return;}
      const url=new URL(request.url,'http://localhost'),start=Number(url.searchParams.get('startIndex')||1),count=Number(url.searchParams.get('count')||100),rows=scimUsers.slice(start-1,start-1+count);
      response.writeHead(200,{'Content-Type':'application/scim+json'});
      response.end(JSON.stringify({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:scimUsers.length,startIndex:start,itemsPerPage:rows.length,Resources:rows}));return;
    }
    if (request.method === 'GET') {
      const body = {'/marketplace/index.json':JSON.stringify(registry),'/marketplace/app.json':appBundle,'/marketplace/provider.json':providerBundle,'/marketplace/theme.json':themeBundle}[pathname];
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
  let startupError;
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
      server.on('error', error => {startupError=error;serverOutput.push(error.message);});
    }
    let ready = false;
    const startupStarted=Date.now();let nextStartupReport=0;
    while (!ready) {
      try {
        ready = (await fetch(`${origin}/api/health`,{signal:AbortSignal.timeout(2000)})).ok;
      } catch {}
      if (ready) break;
      if(startupError)break;
      if (server?.exitCode !== null && server?.exitCode !== undefined) break;
      // A live owned process is still starting, even when an observation window
      // expires. Keep its PID and diagnostics available instead of restarting it.
      if(!server&&Date.now()-startupStarted>=50000)break;
      if(Date.now()>=nextStartupReport){
        await fs.writeFile(path.join(artifacts,'startup-state.json'),JSON.stringify({pid:server?.pid,exitCode:server?.exitCode,signal:server?.signalCode,elapsedMs:Date.now()-startupStarted,ready:false}));
        nextStartupReport=Date.now()+30000;
      }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    await fs.writeFile(path.join(artifacts,'startup-state.json'),JSON.stringify({pid:server?.pid,exitCode:server?.exitCode,signal:server?.signalCode,elapsedMs:Date.now()-startupStarted,ready}));
    assert.ok(ready, `Backend did not start (PID ${server?.pid}, exit ${server?.exitCode}, signal ${server?.signalCode}). ${serverOutput.join('').slice(-3000)}`);
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
    const disabledReload=page.waitForResponse(response=>response.url().includes('/api/get-key?')&&response.request().method()==='GET');
    await page.getByRole('combobox',{name:'Key state',exact:true}).selectOption('Inactive');
    await page.evaluate(()=>new Promise(requestAnimationFrame));
    await page.getByRole('button',{name:'Save API key',exact:true}).click();
    assert.ok((await disabled).ok());
    assert.equal((await (await disabledReload).json()).data.state,'Inactive');
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    await page.waitForFunction(()=>Array.from(document.querySelectorAll('button')).some(button=>button.textContent==='Save API key'&&button.getAttribute('aria-busy')==='false'));
    assert.equal((await context.request.get(`${origin}/api/users`,{headers:keyHeaders})).status(),401);
    const enabled=page.waitForResponse(response=>response.url().endsWith('/api/update-key'));
    const enabledReload=page.waitForResponse(response=>response.url().includes('/api/get-key?')&&response.request().method()==='GET');
    await page.getByRole('combobox',{name:'Key state',exact:true}).selectOption('Active');
    await page.evaluate(()=>new Promise(requestAnimationFrame));
    await page.getByRole('button',{name:'Save API key',exact:true}).click();
    assert.ok((await enabled).ok());
    assert.equal((await (await enabledReload).json()).data.state,'Active');
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    await page.waitForFunction(()=>Array.from(document.querySelectorAll('button')).some(button=>button.textContent==='Save API key'&&button.getAttribute('aria-busy')==='false'));
    assert.ok((await context.request.get(`${origin}/api/users`,{headers:keyHeaders})).ok());
    await page.getByRole('button',{name:'Delete API key',exact:true}).click();
    await page.getByText('API key deleted.',{exact:true}).waitFor();
    assert.equal((await context.request.get(`${origin}/api/users`,{headers:keyHeaders})).status(),401);
    checks.push('API key UI creates real credentials; Basic/query authenticate without JWT and disable/delete revoke immediately');
    await navigate('Site settings','Site settings');
    await page.getByRole('button',{name:'Load site settings',exact:true}).click();
    await page.getByText('Site settings loaded.',{exact:true}).waitFor();
    const previousPool=(await api('GET','/api/get-setting',undefined,admin.token)).data.runtime.generation;
    await fill('Audit retention days','30');
    await fill('Maximum open connections','8');await fill('Maximum idle connections','1');await fill('Connection lifetime (seconds)','60');
    await page.getByRole('button',{name:'Save site settings',exact:true}).click();
    await page.getByText('Audit retention and connection pool settings are active.',{exact:true}).waitFor();
    const poolSettings=(await api('GET','/api/get-setting',undefined,admin.token)).data;
    assert.equal(poolSettings.recordRetentionDays,30);assert.equal(poolSettings.runtime.poolSettingsApplied,true);
    assert.equal(poolSettings.runtime.effectiveMaxOpen,8);assert.equal(poolSettings.runtime.effectiveMaxIdle,1);assert.notEqual(poolSettings.runtime.generation,previousPool);
    await page.screenshot({path:path.join(artifacts,'site-settings.png'),fullPage:true});
    checks.push('Global settings UI applies real SQLx and Diesel pool limits to a new generation while retaining active audit retention');
    scimUsers=[{schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],id:`scim-id-${suffix}`,userName:`scim-ui-${suffix}`,displayName:'SCIM browser user',active:true,title:'SCIM engineer',locale:'en',preferredLanguage:'en',addresses:[{primary:true,formatted:'Browser work address',locality:'Shanghai',region:'SH'}]}];
    secretsThatMustNotBeLogged.push(scimToken);
    await navigate('Syncers','Syncers');
    await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:'SCIM'});
    await page.getByText('SCIM reads users from Host/Users.',{exact:false}).waitFor();
    await fill('Owner','built-in');await fill('Name',`browser-scim-${suffix}`);await fill('Organization','built-in');
    await fill('Host',`http://127.0.0.1:${mailServer.address().port}/scim/v2`);await fill('Password',scimToken,true);
    await page.getByRole('button',{name:'Save resource',exact:true}).click();await page.getByText('Resource saved.',{exact:true}).waitFor();
    await page.getByRole('button',{name:`browser-scim-${suffix}`,exact:true}).click();
    await page.getByRole('button',{name:'Run selected syncer',exact:true}).click();
    await page.getByText('Synchronization completed.',{exact:false}).waitFor();
    const scimAccount=(await api('GET',`/api/get-user?id=built-in/scim-ui-${suffix}`,undefined,admin.token)).data;
    const scimProfile=await api('GET',`/api/users/${scimAccount.id}`,undefined,admin.token);
    assert.equal(scimProfile.title,'SCIM engineer');assert.equal(scimProfile.location,'Shanghai');assert.equal(scimProfile.region,'SH');
    assert.deepEqual(scimProfile.address,['Browser work address']);assert.ok(scimRequests.includes(`Bearer ${scimToken}`));
    await page.screenshot({path:path.join(artifacts,'scim-syncer.png'),fullPage:true});
    checks.push('SCIM source configured and run through Glory imports a real authenticated HTTP directory user and standard profile fields');
    const logProvider=await api('POST','/api/providers',{owner:'built-in',name:`browser-log-${suffix}`,display_name:'Browser OpenClaw telemetry',category:'Log',type:'Agent',sub_type:'OpenClaw'},admin.token);
    const logApplication=await api('POST','/api/applications',{owner:'admin',name:`browser-telemetry-${suffix}`,display_name:'Browser telemetry',organization:'built-in'},admin.token);
    await navigate('Telemetry','Telemetry receivers');
    await fill('OpenClaw log provider ID or owner/name',logProvider.id);
    await fill('Receiver application ID or owner/name',logApplication.id);
    await page.getByRole('button',{name:'Save receiver',exact:true}).click();
    await page.getByText('Receiver saved.',{exact:true}).waitFor();
    let exporter=await page.getByLabel('Exporter token',{exact:true}).inputValue();
    secretsThatMustNotBeLogged.push(exporter);
    const exportTrace=async token=>context.request.post(`${origin}/api/v1/traces`,{headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/x-protobuf'},data:browserTrace()});
    assert.equal((await exportTrace(exporter)).status(),200);
    const ingested=await api('GET','/api/get-entries?owner=built-in',undefined,admin.token);
    assert.ok(JSON.stringify(ingested).includes('Browser telemetry span'));
    await page.getByRole('button',{name:'Rotate exporter token',exact:true}).click();
    await page.getByText('Exporter token rotated.',{exact:true}).waitFor();
    const currentExporter=await page.getByLabel('Exporter token',{exact:true}).inputValue();
    secretsThatMustNotBeLogged.push(currentExporter);assert.notEqual(exporter,currentExporter);
    assert.equal((await exportTrace(exporter)).status(),401);assert.equal((await exportTrace(currentExporter)).status(),200);
    assert.equal(await page.getByLabel('Exporter token',{exact:true}).getAttribute('type'),'password');
    await page.getByRole('button',{name:/^Revoke receiver /}).first().click();
    await page.getByText('Receiver revoked.',{exact:true}).waitFor();
    assert.equal((await exportTrace(currentExporter)).status(),401);
    assert.equal(await page.getByLabel('Exporter token',{exact:true}).count(),0);
    await page.getByText(/^Receiver .* · built-in · Disabled$/).waitFor();
    await page.screenshot({path:path.join(artifacts,'telemetry-revoked.png'),fullPage:true});
    checks.push('Telemetry UI approves a real receiver; OTLP protobuf persists an Entry and rotation/revocation immediately reject old exporter tokens');

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
    const themedRef=`built-in/market-app-${suffix}`;
    const originalBrand=(await api('GET',`/api/auth/branding?application=${encodeURIComponent(themedRef)}`)).data;
    await page.getByRole('button',{name:'Preview Browser theme',exact:true}).click();
    await page.getByRole('textbox',{name:'Theme application',exact:true}).waitFor();
    await fill('Installation name',`market-theme-${suffix}`);await fill('Theme application',themedRef);
    await page.getByRole('button',{name:'Install integration',exact:true}).click();
    await page.getByText('Integration installed.',{exact:true}).waitFor();
    await navigate('Sign in','Sign in');await fill('Application',themedRef);
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('.main h2')).color==='rgb(13, 75, 125)');
    assert.equal(await page.locator('.sidebar').isVisible(),true);
    assert.equal(await page.locator('iframe[title="Application side panel"]').getAttribute('sandbox'),'');
    await page.frameLocator('iframe[title="Application side panel"]').getByText('Browser theme side panel',{exact:true}).waitFor();
    await page.frameLocator('iframe[title="Application footer"]').getByText('Browser theme footer',{exact:true}).waitFor();
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    assert.equal(await page.locator('iframe[title="Application side panel"]').isVisible(),true);
    await page.screenshot({path:path.join(artifacts,'theme-desktop.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('.main h2')).color==='rgb(40, 100, 80)');
    await page.frameLocator('iframe[title="Application footer"]').getByText('Browser theme footer',{exact:true}).waitFor();
    assert.equal(await page.locator('iframe[title="Application side panel"]').isVisible(),false);
    await page.screenshot({path:path.join(artifacts,'theme-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
    await navigate('Sign up','Create account');await fill('Application',themedRef);
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('.main h2')).color==='rgb(13, 75, 125)');
    await navigate('Authorize','Authorize application');await fill('Client ID',installedApp.data.clientId);
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('.main h2')).color==='rgb(13, 75, 125)');
    await navigate('Marketplace','Marketplace integrations');
    assert.equal(await page.locator('.casdog-auth-root').count(),0);
    await page.getByRole('button',{name:`Uninstall built-in/market-theme-${suffix}`,exact:true}).click();
    await page.getByText('Integration uninstalled.',{exact:true}).waitFor();
    const restoredBrand=(await api('GET',`/api/auth/branding?application=${encodeURIComponent(themedRef)}`)).data;
    assert.deepEqual(restoredBrand,originalBrand);
    checks.push('Checksummed Marketplace theme installs, renders scoped desktop/mobile login/signup/authorization branding, isolates HTML and restores the complete original application styling on uninstall');
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

    const wallet=await api('POST','/api/providers',{owner:'built-in',name:`browser-wallet-${suffix}`,display_name:'Browser wallet',category:'Payment',type:'Balance'},admin.token);
    const billingRole=await api('POST','/api/roles',{owner:'built-in',name:`browser-paid-${suffix}`,display_name:'Browser paid member',is_enabled:true},admin.token);
    const billingPlan=await api('POST','/api/plans',{owner:'built-in',name:`browser-plan-${suffix}`,display_name:'Browser subscription',price_per_month:4.5,price_per_year:45,currency:'USD',role:billingRole.id,is_enabled:true},admin.token);
    const billingPricing=await api('POST','/api/pricings',{owner:'built-in',name:`browser-pricing-${suffix}`,display_name:'Browser pricing',plans:JSON.stringify([billingPlan.id]),is_enabled:true},admin.token);
    await api('POST','/api/products',{owner:'built-in',name:`browser-plan-product-${suffix}`,display_name:'Browser premium plan',plan_id:billingPlan.id,price:4.5,currency:'USD',quantity:-1,state:'Active'},admin.token);
    await api('POST','/api/update-user',{owner:'built-in',name:username,balance:20,balance_currency:'USD'},admin.token);
    await navigate('Store','Store and subscriptions');
    await page.getByRole('button',{name:'Select Browser premium plan',exact:true}).click();
    await page.getByRole('combobox',{name:'Payment provider',exact:true}).selectOption(wallet.id);
    await page.getByRole('combobox',{name:'Plan pricing',exact:true}).selectOption(billingPricing.id);
    await page.getByRole('combobox',{name:'Billing period',exact:true}).selectOption('yearly');
    await page.getByText('Plan price: 45.00 USD',{exact:true}).waitFor();
    await page.getByRole('combobox',{name:'Billing period',exact:true}).selectOption('monthly');
    await page.getByRole('button',{name:'Confirm purchase',exact:true}).click();
    await page.getByText('Purchase paid. Your balance and subscriptions have been refreshed.',{exact:true}).waitFor();
    await page.getByText('Wallet balance: 15.5 USD',{exact:true}).waitFor();
    let owned=await api('GET','/api/store/purchases',undefined,token);
    assert.equal(owned.data.length,1);assert.equal(owned.data[0].state,'Paid');assert.equal(owned.subscriptions.length,1);
    checks.push('Ordinary user purchases a real priced subscription through the store UI; wallet, paid history and subscription persist');
    const noConsent=page.getByRole('button',{name:'Enable renewal',exact:true});
    await noConsent.click();
    await page.getByText('Confirm renewal authorization before enabling.',{exact:true}).waitFor();
    await page.getByRole('checkbox',{name:'I authorize renewal at this price',exact:true}).check();
    await page.getByRole('button',{name:'Enable renewal',exact:true}).click();
    await page.getByText('Renewal authorization saved.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Disable renewal',exact:true}).waitFor();
    owned=await api('GET','/api/store/purchases',undefined,token);
    assert.equal(owned.subscriptions[0].renewal.enabled,true);assert.equal(owned.subscriptions[0].renewal.max_amount_cents,450);
    await page.screenshot({path:path.join(artifacts,'store-renewal.png'),fullPage:true});
    await page.getByRole('button',{name:'Disable renewal',exact:true}).click();
    await page.getByText('Future renewals disabled.',{exact:true}).waitFor();
    owned=await api('GET','/api/store/purchases',undefined,token);assert.equal(owned.subscriptions[0].renewal.enabled,false);
    checks.push('Store renewal requires explicit beneficiary consent at the displayed price cap and persists enable/disable without authorizing an administrator to spend for another user');

    const developmentGateway=await api('POST','/api/providers',{owner:'built-in',name:`browser-development-payment-${suffix}`,display_name:'Development gateway',category:'Payment',type:'Dummy'},admin.token);
    await api('POST','/api/products',{owner:'built-in',name:`browser-recharge-${suffix}`,display_name:'Browser wallet recharge',is_recharge:true,recharge_options:[5,10],disable_custom_recharge:true,price:0,currency:'USD',quantity:-1,state:'Active'},admin.token);
    await page.getByRole('button',{name:'Refresh store',exact:true}).click();
    await page.getByRole('button',{name:'Select Browser wallet recharge',exact:true}).click();
    assert.equal(await page.getByRole('combobox',{name:'Payment provider',exact:true}).locator('option').evaluateAll(options=>options.some(option=>option.textContent==='Browser wallet')),false);
    assert.equal(await page.getByRole('textbox',{name:'Recharge amount',exact:true}).count(),0);
    await page.getByRole('combobox',{name:'Payment provider',exact:true}).selectOption(developmentGateway.id);
    await page.getByRole('combobox',{name:'Recharge option',exact:true}).selectOption('10');
    await page.getByRole('button',{name:'Confirm purchase',exact:true}).click();
    await page.getByText('Purchase created. Continue payment or refresh its status in Your purchases.',{exact:true}).waitFor();
    owned=await api('GET','/api/store/purchases',undefined,token);
    const pending=owned.data.find(order=>order.kind==='recharge');assert.ok(pending);
    assert.ok(pending.payment_id);
    await api('POST','/api/notify-payment',{id:pending.payment_id,state:'Paid'},admin.token);
    await page.getByRole('button',{name:`Refresh payment ${pending.id}`,exact:true}).click();
    await page.getByText('Payment refreshed.',{exact:true}).waitFor();
    await page.getByText('Wallet balance: 25.5 USD',{exact:true}).waitFor();
    owned=await api('GET','/api/store/purchases',undefined,token);assert.equal(owned.data.find(order=>order.id===pending.id).state,'Paid');
    await page.screenshot({path:path.join(artifacts,'store-purchases.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await page.screenshot({path:path.join(artifacts,'store-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
    checks.push('Store recharge excludes self-funding wallet, restricts configured amounts and reflects an administrator-settled development payment exactly once');
    await navigate('Account','Account settings');

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
    await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await fill('Username','admin');await fill('Password','123',true);await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    const restoreAdmin=await page.evaluate(()=>JSON.parse(localStorage.getItem('casdog.auth.token')));
    const restoredName=`restored-${suffix}`,restoredId=crypto.randomUUID(),restoreSeed='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',restoreRecovery=crypto.randomUUID(),restorePassword='RestoredBrowser42!';
    secretsThatMustNotBeLogged.push(restoreSeed,restoreRecovery,restorePassword);
    await navigate('Restore users and MFA','Restore users and MFA');
    const restoreFile=path.join(artifacts,'restore-upload.json');
    await fs.writeFile(restoreFile,JSON.stringify({users:[{id:restoredId,owner:'built-in',name:restoredName,displayName:'Restored browser user',password:restorePassword,passwordType:'plain',preferredMfaType:'app',totpSecret:restoreSeed,recoveryCodes:[restoreRecovery]}]}));
    try {
      const [chooser]=await Promise.all([page.waitForEvent('filechooser'),page.getByRole('button',{name:'Casdoor JSON backup',exact:true}).click()]);
      await chooser.setFiles(restoreFile);await page.getByText('Ready to restore 1 accounts.',{exact:false}).waitFor();
    } finally {await fs.unlink(restoreFile).catch(()=>{});}
    const restoreText=await page.locator('body').innerText();assert.ok(!restoreText.includes(restoreSeed)&&!restoreText.includes(restoreRecovery));
    await page.getByRole('button',{name:'Restore users and MFA',exact:true}).last().click();
    await page.getByText('Confirm that this is a trusted, current MFA backup.',{exact:true}).waitFor();
    await page.getByRole('checkbox',{name:'I am restoring a current, unmasked backup with MFA credentials',exact:true}).check();
    await page.getByRole('button',{name:'Restore users and MFA',exact:true}).last().click();
    await page.getByText('Restored 1 accounts with their supported MFA credentials.',{exact:true}).waitFor();
    const restoredProfile=await api('GET',`/api/users/${restoredId}`,undefined,restoreAdmin);
    assert.equal(restoredProfile.mfa_enabled,true);assert.equal(restoredProfile.preferred_mfa_type,'app');
    assert.ok(!(await page.evaluate(()=>JSON.stringify({...localStorage,...sessionStorage}))).includes(restoreSeed));
    await page.screenshot({path:path.join(artifacts,'mfa-restored.png'),fullPage:true});
    await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    const signInRestored=async()=>{await fill('Username',restoredName);await fill('Password',restorePassword,true);await page.getByRole('button',{name:'Sign in',exact:true}).last().click();await page.getByRole('combobox',{name:'Verification method'}).waitFor();assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);await page.getByRole('combobox',{name:'Verification method'}).selectOption('recovery');await fill('Verification code',restoreRecovery);};
    await signInRestored();await page.getByRole('button',{name:'Sign in',exact:true}).last().click();await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    const restoredToken=await page.evaluate(()=>JSON.parse(localStorage.getItem('casdog.auth.token')));
    assert.equal((await api('GET','/api/get-account',undefined,restoredToken)).id,restoredId);
    await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await signInRestored();
    const reusedRecovery=page.waitForResponse(response=>response.url().endsWith('/api/auth/password/session')&&response.request().postData()?.includes(restoreRecovery));
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();assert.equal((await reusedRecovery).ok(),false);
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    checks.push('Trusted local JSON MFA backup restores through the admin UI, keeps secrets out of browser storage, enforces password MFA and consumes the original recovery code once');
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
