// Browser regression checks for the actual Trunk/Glory WASM application.
const { chromium } = require('../web/node_modules/playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const root = path.resolve(__dirname, '../web/dist');
const artifacts = path.resolve(__dirname, '../web/target/browser-check');
const types = { '.html':'text/html', '.js':'application/javascript', '.wasm':'application/wasm', '.css':'text/css', '.svg':'image/svg+xml' };
async function main() {
  await fs.mkdir(artifacts, { recursive:true });
  const server = http.createServer(async (req,res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      const file = path.resolve(root, '.' + decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname));
      if (!file.startsWith(root + path.sep)) throw Error('Invalid asset path');
      res.setHeader('Content-Type', types[path.extname(file)] || 'application/octet-stream');
      res.end(await fs.readFile(file));
    } catch { res.writeHead(404); res.end('Not found'); }
  });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let browser, page;
  try {
    browser = await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL || 'msedge', headless:true});
    const context = await browser.newContext({viewport:{width:1440,height:1000}});
    page = await context.newPage();
    const errors = [], calls = [];
    // Glory dispatches input through animation frames. Observe the committed
    // input before issuing the next interaction in these fast scripted flows.
    const fill = async (control, value) => {
      await control.fill(value);
      await page.evaluate(() => new Promise(requestAnimationFrame));
    };
    page.on('console',event=>{if(event.type()==='error'){errors.push(event.text());console.error('Browser console',event.text());}});
    page.on('pageerror',error=>{errors.push(error.message);console.error('Browser runtime error',error.message);});
    let users=[{id:'user-1',owner:'built-in',name:'alice',display_name:'Alice',is_admin:true,custom:{retained:'value'}}];
    const user={...users[0],email:'alice@example.test',phone:'+15555550123'};
    let socialPending=false;
    let links=[],consents=[],sessions=[{id:'session-1',name:'Browser session'}];
    let integrations=[];
    const reply=(route,value)=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
    await context.route('**/api/**',async route=>{
      const req=route.request(), url=new URL(req.url()), endpoint=url.pathname;
      let body;try{body=req.postDataJSON();}catch{}
      calls.push({endpoint,method:req.method(),body,raw:req.postData()});
      if(endpoint==='/api/login/oauth/device/verify')return reply(route,{device_code:'verified-device',application:'Portal'});
      if(endpoint==='/api/login/oauth/device/authorize')return reply(route,{status:'ok'});
      if(endpoint==='/api/health')return reply(route,{status:'ok'});
      if(endpoint==='/api/get-integrations')return reply(route,{status:'ok',data:integrations});
      if(endpoint==='/api/get-marketplace-index')return reply(route,{status:'ok',data:{integrations:[{id:'portal',name:{en:'Portal template'},latest:'1.0'},{id:'other',name:{en:'Other template'},latest:'1.0'}]}});
      if(endpoint==='/api/get-marketplace-bundle')return reply(route,{status:'ok',data:{manifest:{id:url.searchParams.get('integrationId'),version:'1.0',variables:[{name:'appUrl',label:{en:'Application URL'},type:'url',required:true},{name:'secret',label:{en:'Integration secret'},type:'password',required:true}]}}});
      if(endpoint==='/api/install-integration'){integrations=[{...body}];return reply(route,{status:'ok'});}
      if(endpoint==='/api/delete-integration'){integrations=integrations.filter(i=>i.owner!==body.owner||i.name!==body.name);return reply(route,{status:'ok'});}
      if(endpoint==='/api/login')return reply(route,{token:'',mfa_required:true,mfa_types:['email','sms','app','recovery']});
      if(endpoint==='/api/auth/password/session' || endpoint==='/api/auth/session') {
        if(body?.passcode==='123456')return reply(route,{token:'browser-test-token',user});
        if(body?.passcode)return reply(route,{status:'error',msg:'Invalid second-factor proof'});
        if(endpoint==='/api/auth/session'&&socialPending)return reply(route,{token:'',mfa_required:true,mfa_types:['app']});
        return reply(route,{pending:false});
      }
      if(endpoint.endsWith('/send-code')||endpoint.endsWith('/cancel'))return reply(route,{status:'ok'});
      if(endpoint==='/api/auth/providers')return reply(route,{status:'ok',data:[{name:'mock',display_name:'Mock provider'}]});
      if(endpoint==='/api/auth/links')return reply(route,{status:'ok',data:links});
      if(endpoint==='/api/auth/mock') {socialPending=true;return reply(route,{url:origin+'/?social=complete'});}
      if(endpoint==='/api/auth/mock/link'){links=[{provider_id:'provider-1',provider:'mock',display_name:'Mock provider'}];return reply(route,{url:origin+'/?social=linked'});}
      if(endpoint==='/api/auth/mock/unlink'){links=[];return reply(route,{status:'ok'});}
      if(endpoint==='/api/get-account'||endpoint==='/api/userinfo')return reply(route,user);
      if(endpoint==='/api/users'&&req.method()==='GET')return reply(route,users);
      if(endpoint==='/api/users'&&req.method()==='POST'){users.push({...body,id:'user-new'});return reply(route,body);}
      if(endpoint.startsWith('/api/users/')&&req.method()==='PUT'){users=users.map(v=>v.id==='user-1'?{...v,...body}:v);return reply(route,body);}
      if(endpoint.startsWith('/api/users/')&&req.method()==='DELETE'){users=users.filter(v=>v.id!==endpoint.split('/').pop());return reply(route,{status:'ok'});}
      if(endpoint==='/api/mfa/setup')return reply(route,{secret:'JBSWY3DPEHPK3PXP',qr_url:'otpauth://totp/Casdog:alice?secret=JBSWY3DPEHPK3PXP&issuer=Casdog'});
      if(endpoint==='/api/mfa/verify')return reply(route,body.code==='123456'?{success:true,recovery_codes:['one-use-code']}:{success:false});
      if(endpoint==='/api/mfa/delete')return reply(route,{status:'ok'});
      if(endpoint==='/api/request-password-reset')return reply(route,{status:'ok',requestId:'reset-id'});
      if(endpoint==='/api/reset-password'||endpoint==='/api/set-password'||endpoint==='/api/logout')return reply(route,{status:'ok'});
      if(endpoint==='/api/consents'&&req.method()==='POST'){consents=[{id:'consent-1',name:'Portal'}];return reply(route,{status:'ok'});}
      if(endpoint==='/api/consents')return reply(route,consents);
      if(endpoint.startsWith('/api/consents/')){consents=[];return reply(route,{status:'ok'});}
      if(endpoint==='/api/sessions')return reply(route,sessions);
      if(endpoint.startsWith('/api/sessions/')){sessions=[];return reply(route,{status:'ok'});}
      if(endpoint.startsWith('/api/webauthn/credentials'))return reply(route,[]);
      if(endpoint==='/api/send-verification-code'||endpoint==='/api/reset-email-or-phone')return reply(route,{status:'ok'});
      if(endpoint==='/api/signup')return reply(route,{status:'ok'});
      return reply(route,{status:'ok',data:[]});
    });
    await page.goto(origin);
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    await page.getByRole('button',{name:'Marketplace',exact:true}).click();
    await page.getByText('Sign in as a tenant administrator to manage integrations.',{exact:true}).waitFor();
    assert.equal(calls.filter(c=>c.endpoint==='/api/get-integrations').length,0);
    await page.getByRole('combobox',{name:'Language',exact:true}).selectOption('zh');
    await page.waitForFunction(()=>JSON.parse(localStorage.getItem('casdog.locale'))==='zh');
    await page.getByRole('combobox',{name:'Language',exact:true}).selectOption('en');
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Username',exact:true}),'alice');
    await fill(page.getByLabel('Password',{exact:true}),'Password42!');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('combobox',{name:'Verification method'}).waitFor();
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    await page.getByRole('button',{name:'Send verification code'}).click();
    await fill(page.getByRole('textbox',{name:'Verification code'}),'wrong');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByText('Invalid second-factor proof',{exact:true}).waitFor();
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    await fill(page.getByRole('textbox',{name:'Verification code'}),'123456');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    const loginCall=calls.find(c=>c.endpoint==='/api/login');
    assert.equal(loginCall.body.password,'Password42!');
    assert.equal(calls.find(c=>c.endpoint==='/api/auth/password/session/send-code').body.mfaType,'email');
    await page.getByRole('button',{name:'Marketplace',exact:true}).click();
    await page.getByRole('button',{name:'Load marketplace',exact:true}).click();
    await page.getByRole('button',{name:'Preview Portal template',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Application URL',exact:true}),'https://portal.example.test');
    await fill(page.getByLabel('Integration secret',{exact:true}),'discard-this-secret');
    await page.getByRole('button',{name:'Preview Other template',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('[aria-label="Application URL"]').value==='');
    assert.equal(await page.getByLabel('Integration secret',{exact:true}).inputValue(),'');
    await fill(page.getByRole('textbox',{name:'Application URL',exact:true}),'https://other.example.test');
    await fill(page.getByLabel('Integration secret',{exact:true}),'new-secret');
    await page.getByRole('button',{name:'Install integration',exact:true}).click();
    await page.getByText('Integration installed.',{exact:true}).waitFor();
    assert.deepEqual(calls.find(c=>c.endpoint==='/api/install-integration').body,{owner:'built-in',name:'other',integrationId:'other',version:'1.0',variables:{appUrl:'https://other.example.test',secret:'new-secret'}});
    await page.getByRole('button',{name:'Uninstall built-in/other',exact:true}).click();
    await page.getByText('Integration uninstalled.',{exact:true}).waitFor();
    assert.deepEqual(calls.find(c=>c.endpoint==='/api/delete-integration').body,{owner:'built-in',name:'other'});
    await page.getByRole('button',{name:'Users',exact:true}).click();
    await page.getByRole('button',{name:'Alice',exact:true}).click();
    const display=page.getByRole('textbox',{name:'Display name',exact:true});
    await display.fill('Alice');
    await display.pressSequentially(' changed');
    assert.equal(await display.inputValue(),'Alice changed');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    assert.equal(calls.filter(c=>c.endpoint==='/api/users/user-1'&&c.method==='PUT').at(-1).body.display_name,'Alice changed');
    assert.equal(calls.filter(c=>c.endpoint==='/api/users/user-1'&&c.method==='PUT').at(-1).body.custom.retained,'value');
    await page.getByRole('button',{name:'New resource',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('[aria-label="Owner"]').value==='admin');
    await fill(page.getByRole('textbox',{name:'Username',exact:true}),'bob');
    await fill(page.getByRole('textbox',{name:'Display name',exact:true}),'Bob');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByRole('button',{name:'Bob',exact:true}).click();
    await page.getByRole('button',{name:'Delete selected resource',exact:true}).click();
    await page.getByText('Resource deleted.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Sites',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Port',exact:true}),'8443');
    await page.getByRole('combobox',{name:'SSL mode',exact:true}).selectOption({label:'HTTP Only'});
    await page.evaluate(()=>new Promise(requestAnimationFrame));
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    assert.equal(calls.find(c=>c.endpoint==='/api/sites'&&c.method==='POST').body.ssl_mode,'HTTP Only');
    assert.match(calls.find(c=>c.endpoint==='/api/sites'&&c.method==='POST').raw,/"port":8443[,}]/);
    await page.getByRole('button',{name:'Providers',exact:true}).click();
    await page.getByRole('combobox',{name:'Category',exact:true}).selectOption({label:'Scan'});
    await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:'MCP Scan'});
    await fill(page.getByRole('textbox',{name:'Subtype',exact:true}),'Intranet Scan');
    await fill(page.getByRole('textbox',{name:'Endpoint URL / paths',exact:true}),'/mcp');
    await fill(page.getByRole('textbox',{name:'Scopes / discovery targets',exact:true}),'127.0.0.1/32');
    await fill(page.getByRole('textbox',{name:'Content / discovery ports',exact:true}),'8080');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    const providerWrite=calls.find(c=>c.endpoint==='/api/providers'&&c.method==='POST').body;
    assert.equal(providerWrite.type,'MCP Scan');
    assert.equal(providerWrite.scopes,'127.0.0.1/32');
    assert.equal(providerWrite.content,'8080');

    await page.getByRole('button',{name:'Account',exact:true}).click();
    await page.getByRole('button',{name:'Email and phone',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'New contact',exact:true}),'new@example.test');
    await page.getByRole('button',{name:'Send contact code'}).click();
    await fill(page.getByRole('textbox',{name:'Contact verification code'}),'123456');
    await page.getByRole('button',{name:'Verify and update contact'}).click();
    await page.getByText('Contact updated.',{exact:true}).waitFor();
    assert.equal(calls.find(c=>c.endpoint==='/api/send-verification-code').body.method,'contact');
    await page.getByRole('button',{name:'MFA',exact:true}).click();
    await page.getByRole('button',{name:'Set up authenticator',exact:true}).click();
    await page.getByRole('img',{name:'Authenticator setup QR code'}).waitFor();
    assert.match(await page.getByRole('img',{name:'Authenticator setup QR code'}).getAttribute('src'),/^data:image\/svg\+xml,/);
    await fill(page.getByRole('textbox',{name:'Authenticator code'}),'wrong');
    await page.getByRole('button',{name:'Verify and enable MFA'}).click();
    await page.getByText('The verification code is invalid or expired. Try the current code from your authenticator.',{exact:true}).waitFor();
    await fill(page.getByRole('textbox',{name:'Authenticator code'}),'123456');
    await page.getByRole('button',{name:'Verify and enable MFA'}).click();
    await page.getByText('one-use-code',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Linked accounts',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Application',exact:true}),'admin/portal');
    await page.getByRole('button',{name:'Load sign-in providers'}).click();
    await page.getByRole('button',{name:'Link Mock provider'}).waitFor();
    await page.getByRole('button',{name:'Consents',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Application',exact:true}),'admin/portal');
    await page.getByRole('button',{name:'Grant consent',exact:true}).click();
    await page.getByRole('button',{name:'Revoke Portal',exact:true}).click();
    await page.getByText('Consent revoked.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Device authorization',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'User code',exact:true}),'ab12-cd34');
    await page.getByRole('button',{name:'Verify user code',exact:true}).click();
    await page.getByText('Review the application before approving access.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Approve device',exact:true}).click();
    await page.getByText('Device approved.',{exact:true}).waitFor();
    assert.equal(calls.find(c=>c.endpoint==='/api/login/oauth/device/authorize').body.device_code,'verified-device');
    await page.getByRole('button',{name:'Recover password',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Email',exact:true}),'alice@example.test');
    await page.getByRole('button',{name:'Send reset code'}).click();
    await fill(page.getByRole('textbox',{name:'Reset code'}),'reset-secret');
    await fill(page.getByLabel('New password',{exact:true}),'NewPassword42!');
    await fill(page.getByLabel('Confirm new password',{exact:true}),'NewPassword42!');
    await page.getByRole('button',{name:'Reset password',exact:true}).click();
    await page.getByText('Password reset. Sign in with your new password.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    await page.getByRole('button',{name:'Create account',exact:true}).click();
    await page.getByRole('heading',{name:'Create account',exact:true}).waitFor();
    await fill(page.getByRole('textbox',{name:'Username',exact:true}),'new-user');
    await fill(page.getByRole('textbox',{name:'Display name',exact:true}),'New user');
    await fill(page.getByLabel('Password',{exact:true}),'Password42!');
    await fill(page.getByLabel('Confirm password',{exact:true}),'Password42!');
    await page.getByRole('button',{name:'Sign up',exact:true}).last().click();
    await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    assert.equal(calls.find(c=>c.endpoint==='/api/signup').body.name,'new-user');
    await page.getByRole('button',{name:'Sign in with Mock provider',exact:true}).click();
    await page.getByRole('combobox',{name:'Verification method'}).waitFor();
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    await fill(page.getByRole('textbox',{name:'Verification code'}),'123456');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    assert.ok(calls.some(c=>c.endpoint==='/api/auth/session'&&c.body?.passcode==='123456'));
    await page.getByRole('button',{name:'Account',exact:true}).click();
    await page.getByRole('button',{name:'Linked accounts',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Application',exact:true}),'admin/portal');
    await page.getByRole('button',{name:'Load sign-in providers'}).click();
    await page.getByRole('button',{name:'Link Mock provider',exact:true}).click();
    await page.waitForFunction(()=>!new URL(location.href).searchParams.has('social'));
    await page.getByRole('button',{name:'Unlink Mock provider',exact:true}).click();
    await page.getByText('Account unlinked.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    assert.deepEqual(errors,[]);
    await page.evaluate(()=>{window.scrollTo(0,0);document.querySelector('.sidebar').scrollTop=0;});
    await page.screenshot({path:path.join(artifacts,'desktop.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.evaluate(()=>{window.scrollTo(0,0);document.querySelector('.sidebar').scrollTop=0;});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await page.screenshot({path:path.join(artifacts,'mobile.png'),fullPage:true});
    await fs.writeFile(path.join(artifacts,'results.json'),JSON.stringify({passed:true,requests:calls.map(c=>({method:c.method,path:c.endpoint})),runtimeErrors:errors},null,2));
    console.log('Glory/Sapid browser flows passed');
  } catch (error) {
    if(page){await fs.writeFile(path.join(artifacts,'failure.html'),await page.content());await page.screenshot({path:path.join(artifacts,'failure.png'),fullPage:true});}
    throw error;
  } finally {
    if(browser)await browser.close();
    await new Promise(resolve=>server.close(resolve));
  }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
