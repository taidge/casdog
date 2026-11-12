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
    let expectedCartConflict=false;
    // Glory dispatches input through animation frames. Observe the committed
    // input before issuing the next interaction in these fast scripted flows.
    const fill = async (control, value) => {
      await control.fill(value);
      await page.evaluate(() => new Promise(requestAnimationFrame));
    };
    page.on('console',event=>{if(event.type()==='error'){if(expectedCartConflict&&event.text().includes('the server responded with a status of 409'))return;errors.push(event.text());console.error('Browser console',event.text());}});
    page.on('pageerror',error=>{errors.push(error.message);console.error('Browser runtime error',error.message);});
    let users=[{id:'user-1',owner:'built-in',name:'alice',display_name:'Alice',is_admin:true,custom:{retained:'value'}}];
    const user={...users[0],email:'alice@example.test',phone:'+15555550123'};
    let delayProfile=false,releaseProfile;
    const profileGate=new Promise(resolve=>{releaseProfile=resolve;});
    let socialPending=false;
    let links=[],consents=[],sessions=[{id:'session-1',name:'Browser session'}];
    let integrations=[];
    let themeInstalled=false;
    let keys=[];
    let siteSettings={dbMaxOpenConns:0,dbMaxIdleConns:0,dbConnMaxLifetime:0,recordRetentionDays:0};
    let receivers=[],receiverToken=0;
    let storeOrders=[],storeSubscriptions=[],walletBalance=100;
    let cartRevision=0,cartItems=[],rejectCartQuote=false;
    const cart=()=>({revision:cartRevision,items:cartItems,total_amount_cents:cartItems.reduce((sum,item)=>sum+item.total_amount_cents,0),currency:'USD',valid:true});
    const storeCatalog={status:'ok',total:2,data:[
      {id:'store-plan-product',name:'premium',display_name:'Fixture premium',plan_id:'store-plan',price:5,currency:'USD',quantity:-1},
      {id:'store-recharge',name:'recharge',display_name:'Fixture recharge',is_recharge:true,recharge_options:[5,10],disable_custom_recharge:true,price:0,currency:'USD',quantity:-1},
    ],plans:[{id:'store-plan',name:'premium',display_name:'Premium',price_per_month:5,price_per_year:50}],pricings:[{id:'store-pricing',name:'public',display_name:'Public',plans:'["store-plan"]'}],providers:[{id:'wallet',name:'wallet',display_name:'Wallet',type:'Balance'},{id:'gateway',name:'gateway',display_name:'Gateway',type:'Dummy'}]};
    const reply=(route,value)=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
    await context.route('**/api/**',async route=>{
      const req=route.request(), url=new URL(req.url()), endpoint=url.pathname;
      let body;try{body=req.postDataJSON();}catch{}
      calls.push({endpoint,method:req.method(),body,raw:req.postData(),query:Object.fromEntries(url.searchParams)});
      if(endpoint==='/api/login/oauth/device/verify')return reply(route,{device_code:'verified-device',application:'Portal'});
      if(endpoint==='/api/login/oauth/device/authorize')return reply(route,{status:'ok'});
      if(endpoint==='/api/health')return reply(route,{status:'ok'});
      if(endpoint==='/api/get-setting')return reply(route,{status:'ok',data:siteSettings});
      if(endpoint==='/api/update-setting'){siteSettings=body;return reply(route,{status:'ok',data:true,recordRetentionApplied:true,poolSettingsApplied:false,applied:false});}
      if(endpoint==='/api/upload-users-with-mfa'){
        const failed=body.some(row=>row.totpSecret==='***');
        return reply(route,{total:body.length,created:failed?0:body.length,failed:failed?body.length:0,errors:failed?['Invalid MFA enrollment; no accounts were created.']:[]});
      }
      if(endpoint==='/api/telemetry/receivers'&&req.method()==='GET')return reply(route,{status:'ok',data:receivers});
      if(endpoint==='/api/telemetry/receivers'&&req.method()==='POST'){
        let existing=receivers.find(receiver=>receiver.provider===body.provider);
        const issue=!existing||body.rotate||!existing.enabled;
        const receiver={id:existing?.id||'receiver-1',organization:'built-in',...body};
        receivers=[receiver];return reply(route,{status:'ok',data:{...receiver,...(issue?{token:`otlp_fixture_${++receiverToken}`}:{})}});
      }
      if(endpoint.startsWith('/api/telemetry/receivers/')&&req.method()==='DELETE'){receivers=receivers.map(receiver=>({...receiver,enabled:false}));return reply(route,{status:'ok'});}
      if(endpoint==='/api/set-subscription-auto-renew'){
        const enabled=url.searchParams.get('autoRenew')==='true';const subscription=storeSubscriptions.find(value=>value.id===url.searchParams.get('id'));
        subscription.renewal={enabled,mode:'balance',currency:'USD',max_amount_cents:500};subscription.auto_renew=enabled;return reply(route,{status:'ok',data:true,data2:subscription.renewal});
      }

      if(endpoint==='/api/store/catalog')return reply(route,storeCatalog);
      if(endpoint==='/api/store/cart'&&req.method()==='GET')return reply(route,{status:'ok',data:cart()});
      if(endpoint==='/api/store/cart'&&req.method()==='PUT'){
        assert.equal(body.revision,cartRevision);
        cartItems=body.items.map((item,index)=>{const product=storeCatalog.data.find(product=>product.id===item.productId),price=product.is_recharge?item.customPrice:5;return {id:`cart-${index}`,product_id:product.id,name:product.name,display_name:product.display_name,quantity:item.quantity,pricing_name:item.pricingName,plan_name:item.planName,period:item.period,custom_price:product.is_recharge?item.customPrice:null,unit_amount_cents:price*100,total_amount_cents:price*100*item.quantity,currency:'USD',valid:true};});
        cartRevision++;return reply(route,{status:'ok',data:cart()});
      }
      if(endpoint==='/api/store/cart/checkout'){
        assert.equal(body.revision,cartRevision);assert.equal(body.expectedTotalCents,cart().total_amount_cents);
        if(rejectCartQuote){rejectCartQuote=false;return route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({status:'error',msg:'Cart quote changed. Refresh and review current prices.'})});}
        const order={id:'cart-order',name:'cart-purchase',display_name:'Cart purchase',state:'Created',price:cart().total_amount_cents/100,currency:'USD'};
        storeOrders.unshift(order);cartItems=[];cartRevision++;return reply(route,{status:'ok',data:{order,cart_revision:cartRevision}});
      }
      if(endpoint==='/api/pay-order'){storeOrders.find(order=>order.id===url.searchParams.get('id')).state='Paid';return reply(route,{status:'ok',autoPaid:true});}
      if(endpoint==='/api/store/purchases')return reply(route,{status:'ok',data:storeOrders,subscriptions:storeSubscriptions,wallet:{balance:walletBalance,currency:'USD'},total:storeOrders.length});
      if(endpoint==='/api/buy-product'){
        const recharge=url.searchParams.get('id')==='store-recharge';
        const order={id:`store-order-${storeOrders.length}`,name:`purchase-${storeOrders.length}`,display_name:recharge?'Wallet recharge':'Premium plan',state:recharge?'Created':'Paid',price:recharge?Number(url.searchParams.get('customPrice')):5,currency:'USD',kind:recharge?'recharge':'plan',pay_url:'https://dummy-payment.example.com/checkout'};
        storeOrders.unshift(order);
        if(!recharge){walletBalance-=5;storeSubscriptions.push({id:'subscription-1',plan:'Premium',state:'active',start_date:'2026-11-12',end_date:'2026-12-12',auto_renew:true,renewal:{enabled:false},renewal_quote:{amount:5,currency:'USD'}});}
        return reply(route,{status:'ok',order,data:{id:'payment-1'},autoPaid:!recharge});
      }
      if(endpoint==='/api/reconcile-order'){const order=storeOrders.find(order=>order.id===url.searchParams.get('id'));if(order.state!=='Paid'){order.state='Paid';walletBalance+=order.price;}return reply(route,{status:'ok',order});}
      if(endpoint==='/api/cancel-order'){storeOrders.find(order=>order.id===url.searchParams.get('id')).state='Canceled';return reply(route,{status:'ok'});}

      if(endpoint==='/api/get-keys')return reply(route,{status:'ok',data:keys.map(key=>({...key,accessSecret:'***'}))});
      if(endpoint==='/api/get-key')return reply(route,{status:'ok',data:keys.find(key=>`${key.owner}/${key.name}`===url.searchParams.get('id'))||null});
      if(endpoint==='/api/add-key'){keys.push({...body,accessKey:'fixture-access',accessSecret:'fixture-secret'});return reply(route,{status:'ok',data:true});}
      if(endpoint==='/api/update-key'){keys=keys.map(key=>key.owner===body.owner&&key.name===body.name?{...key,...body}:key);return reply(route,{status:'ok',data:true});}
      if(endpoint==='/api/delete-key'){keys=keys.filter(key=>key.owner!==body.owner||key.name!==body.name);return reply(route,{status:'ok',data:true});}
      if(endpoint==='/api/trust-application-credentials')return reply(route,{status:'ok'});
      if(endpoint==='/api/auth/code/start')return reply(route,{pending:true,expires_in:300,method:body.method});
      if(endpoint==='/api/get-integrations')return reply(route,{status:'ok',data:integrations});
      if(endpoint==='/api/get-marketplace-index')return reply(route,{status:'ok',data:{integrations:[{id:'portal',name:{en:'Portal template'},latest:'1.0'},{id:'other',name:{en:'Other template'},latest:'1.0'},{id:'provider',name:{en:'OAuth provider'},latest:'1.0'},{id:'theme',name:{en:'Portal theme'},latest:'1.0'}]}});
      if(endpoint==='/api/get-marketplace-bundle'){
        const id=url.searchParams.get('integrationId'),type=id==='provider'?'provider':id==='theme'?'theme':'app';
        return reply(route,{status:'ok',data:{manifest:{id,type,version:'1.0',variables:type==='app'?[{name:'appUrl',label:{en:'Application URL'},type:'url',required:true},{name:'secret',label:{en:'Integration secret'},type:'password',required:true}]:[]}}});
      }
      if(endpoint==='/api/auth/branding')return reply(route,{status:'ok',data:themeInstalled&&['built-in/theme-app','theme-client'].includes(url.searchParams.get('application'))?{application:'built-in/theme-app',themeData:{isEnabled:true,colorPrimary:'#124678',borderRadius:12},formOffset:4,formCss:'body h2 { color: rgb(18, 70, 120); } .sidebar { display:none; }',formCssMobile:'h2 { color: rgb(40, 100, 80); }',formSideHtml:'<strong>Tenant portal</strong>',footerHtml:'<p>Tenant footer</p>'}:null});
      if(endpoint==='/api/install-integration'){integrations=[{...body}];if(body.integrationId==='theme')themeInstalled=true;return reply(route,{status:'ok'});}
      if(endpoint==='/api/delete-integration'){integrations=integrations.filter(i=>i.owner!==body.owner||i.name!==body.name);if(body.name==='theme')themeInstalled=false;return reply(route,{status:'ok'});}
      if(endpoint==='/api/login') {
        if(body.type==='code')return reply(route,body.code==='654321'?{token:'code-token',user}:{status:'error',msg:'Invalid sign-in proof'});
        if(body.type==='ldap')return reply(route,{token:'ldap-token',user});
        return reply(route,{token:'',mfa_required:true,mfa_types:['email','sms','app','recovery']});
      }
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
      if(endpoint==='/api/get-account'||endpoint==='/api/userinfo'){
        if(endpoint==='/api/get-account'&&delayProfile){delayProfile=false;await profileGate;}
        return reply(route,user);
      }
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
    assert.deepEqual(calls.find(c=>c.endpoint==='/api/install-integration').body,{owner:'built-in',name:'other',integrationId:'other',version:'1.0',variables:{appUrl:'https://other.example.test',secret:'new-secret'},clientId:'',clientSecret:'',application:''});
    await page.getByRole('button',{name:'Uninstall built-in/other',exact:true}).click();
    await page.getByText('Integration uninstalled.',{exact:true}).waitFor();
    assert.deepEqual(calls.find(c=>c.endpoint==='/api/delete-integration').body,{owner:'built-in',name:'other'});
    await page.getByRole('button',{name:'Preview OAuth provider',exact:true}).click();
    await page.getByRole('button',{name:'Install integration',exact:true}).click();
    await page.getByText('Enter the provider client ID and secret.',{exact:true}).waitFor();
    assert.equal(calls.filter(c=>c.endpoint==='/api/install-integration').length,1);
    await fill(page.getByRole('textbox',{name:'Provider client ID',exact:true}),'oauth-client');
    await fill(page.getByLabel('Provider client secret',{exact:true}),'oauth-secret');
    await fill(page.getByRole('textbox',{name:'Link to application (optional)',exact:true}),'portal');
    await page.getByRole('button',{name:'Install integration',exact:true}).click();
    await page.getByText('Integration installed.',{exact:true}).waitFor();
    const providerInstall=calls.filter(c=>c.endpoint==='/api/install-integration').at(-1).body;
    assert.equal(providerInstall.clientId,'oauth-client');
    assert.equal(providerInstall.clientSecret,'oauth-secret');
    assert.equal(providerInstall.application,'portal');
    await page.getByRole('button',{name:'Preview OAuth provider',exact:true}).click();
    assert.equal(await page.getByLabel('Provider client secret',{exact:true}).inputValue(),'');
    await page.getByRole('button',{name:'Preview Portal theme',exact:true}).click();
    await page.getByRole('button',{name:'Install integration',exact:true}).click();
    await page.getByText('Choose an application for the theme.',{exact:true}).waitFor();
    await fill(page.getByRole('textbox',{name:'Theme application',exact:true}),'built-in/theme-app');
    await page.getByRole('button',{name:'Install integration',exact:true}).click();
    await page.getByText('Integration installed.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Sign in',exact:true}).first().click();
    await fill(page.getByRole('textbox',{name:'Application',exact:true}),'built-in/theme-app');
    await page.waitForFunction(()=>document.querySelector('.main').dataset.brandingApplication==='built-in/theme-app'&&getComputedStyle(document.querySelector('.main h2')).color==='rgb(18, 70, 120)');
    assert.deepEqual(await page.locator('.main button').first().evaluate(node=>({color:getComputedStyle(node).backgroundColor,radius:getComputedStyle(node).borderRadius})),{color:'rgb(18, 70, 120)',radius:'12px'});
    assert.equal(await page.locator('iframe[title="Application side panel"]').getAttribute('sandbox'),'');
    assert.equal(await page.locator('iframe[title="Application footer"]').count(),1);
    await page.frameLocator('iframe[title="Application side panel"]').getByText('Tenant portal',{exact:true}).waitFor();
    await page.frameLocator('iframe[title="Application footer"]').getByText('Tenant footer',{exact:true}).waitFor();
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    assert.equal(await page.locator('iframe[title="Application side panel"]').isVisible(),true);
    assert.equal(await page.locator('.sidebar').isVisible(),true);
    await page.setViewportSize({width:390,height:844});
    await page.waitForFunction(()=>getComputedStyle(document.querySelector('.main h2')).color==='rgb(40, 100, 80)');
    await page.frameLocator('iframe[title="Application footer"]').getByText('Tenant footer',{exact:true}).waitFor();
    await page.setViewportSize({width:1440,height:1000});
    await fill(page.getByRole('textbox',{name:'Application',exact:true}),'built-in/other-app');
    await page.waitForFunction(()=>!document.querySelector('.casdog-auth-root')&&!document.querySelector('iframe[title="Application footer"]'));
    await page.getByRole('button',{name:'Sign up',exact:true}).first().click();
    await page.getByRole('heading',{name:'Create account',exact:true}).waitFor();
    await fill(page.getByRole('textbox',{name:'Application',exact:true}),'built-in/theme-app');
    await page.waitForFunction(()=>document.querySelector('.main').dataset.brandingApplication==='built-in/theme-app');
    await page.getByRole('button',{name:'Authorize',exact:true}).click();
    await page.getByRole('heading',{name:'Authorize application',exact:true}).waitFor();
    await fill(page.getByRole('textbox',{name:'Client ID',exact:true}),'theme-client');
    await page.waitForFunction(()=>document.querySelector('.main').dataset.brandingApplication==='built-in/theme-app');
    await page.getByRole('button',{name:'Marketplace',exact:true}).click();
    await page.waitForFunction(()=>!document.querySelector('.casdog-auth-root'));
    await page.getByRole('button',{name:'Uninstall built-in/theme',exact:true}).click();
    await page.getByText('Integration uninstalled.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Sign in',exact:true}).first().click();
    await fill(page.getByRole('textbox',{name:'Application',exact:true}),'built-in/theme-app');
    await page.waitForFunction(()=>!document.querySelector('.casdog-auth-root'));
    await page.getByRole('button',{name:'Marketplace',exact:true}).click();
    await page.setViewportSize({width:390,height:844});
    await page.evaluate(()=>new Promise(requestAnimationFrame));
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await page.screenshot({path:path.join(artifacts,'marketplace-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
    await page.getByRole('button',{name:'API keys',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Key name',exact:true}),'browser-key');
    await page.getByRole('button',{name:'Save API key',exact:true}).click();
    await page.getByText('API key saved.',{exact:true}).waitFor();
    assert.equal(await page.getByRole('textbox',{name:'Access key',exact:true}).inputValue(),'fixture-access');
    assert.equal(await page.getByLabel('Access secret',{exact:true}).getAttribute('type'),'password');
    await page.getByRole('button',{name:'Show access secret',exact:true}).click();
    assert.equal(await page.getByLabel('Access secret',{exact:true}).inputValue(),'fixture-secret');
    await page.getByRole('combobox',{name:'Key state',exact:true}).selectOption('Inactive');
    await page.getByRole('button',{name:'Save API key',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('[aria-label="Access secret"]').type==='password');
    assert.equal(calls.filter(c=>c.endpoint==='/api/update-key').at(-1).body.state,'Inactive');
    assert.equal(calls.filter(c=>c.endpoint==='/api/update-key').at(-1).body.accessSecret,undefined);
    await page.getByRole('button',{name:'Delete API key',exact:true}).click();
    await page.getByText('API key deleted.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'New API key',exact:true}).click();
    await page.getByRole('combobox',{name:'Key type',exact:true}).selectOption('Application');
    await page.waitForFunction(()=>document.querySelector('[aria-label="Bound user"]')?.value==='');
    await fill(page.getByRole('textbox',{name:'Reviewed application ID or owner/name',exact:true}),'built-in/reviewed');
    await page.getByRole('button',{name:'Trust static application',exact:true}).click();
    await page.getByText('Static application credentials trusted.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Store',exact:true}).click();
    await page.getByRole('button',{name:'Select Fixture premium',exact:true}).click();
    await page.getByRole('combobox',{name:'Payment provider',exact:true}).selectOption('wallet');
    await page.getByRole('combobox',{name:'Billing period',exact:true}).selectOption('yearly');
    await page.getByText('Plan price: 50.00 USD',{exact:true}).waitFor();
    await page.getByRole('combobox',{name:'Billing period',exact:true}).selectOption('monthly');
    await page.getByRole('button',{name:'Confirm purchase',exact:true}).click();
    await page.getByText('Purchase paid. Your balance and subscriptions have been refreshed.',{exact:true}).waitFor();
    await page.getByText('Wallet balance: 95 USD',{exact:true}).waitFor();
    assert.equal(calls.filter(call=>call.endpoint==='/api/buy-product').at(-1).query.planName,'store-plan');
    assert.equal(calls.filter(call=>call.endpoint==='/api/buy-product').at(-1).query.period,'monthly');
    assert.equal(await page.getByRole('button',{name:'Disable renewal',exact:true}).count(),0);
    const oldConsents=calls.filter(call=>call.endpoint==='/api/set-subscription-auto-renew').length;
    await page.getByRole('button',{name:'Enable renewal',exact:true}).click();
    await page.getByText('Confirm renewal authorization before enabling.',{exact:true}).waitFor();
    assert.equal(calls.filter(call=>call.endpoint==='/api/set-subscription-auto-renew').length,oldConsents);
    await page.getByRole('checkbox',{name:'I authorize renewal at this price',exact:true}).check();
    await page.getByRole('button',{name:'Enable renewal',exact:true}).click();
    await page.getByText('Renewal authorization saved.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Disable renewal',exact:true}).waitFor();
    assert.equal(calls.filter(call=>call.endpoint==='/api/set-subscription-auto-renew').at(-1).query.maxAmountCents,'500');
    await page.getByRole('button',{name:'Disable renewal',exact:true}).click();
    await page.getByText('Future renewals disabled.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Select Fixture recharge',exact:true}).click();
    assert.equal(await page.getByRole('textbox',{name:'Recharge amount',exact:true}).count(),0);
    assert.equal(await page.getByRole('combobox',{name:'Payment provider',exact:true}).locator('option[value="wallet"]').count(),0);
    await page.getByRole('combobox',{name:'Recharge option',exact:true}).selectOption('10');
    await page.getByRole('button',{name:'Confirm purchase',exact:true}).click();
    await page.getByText('Purchase created. Continue payment or refresh its status in Your purchases.',{exact:true}).waitFor();
    assert.equal(calls.filter(call=>call.endpoint==='/api/buy-product').at(-1).query.customPrice,'10');
    await page.getByRole('button',{name:'Refresh payment store-order-1',exact:true}).click();
    await page.getByText('Wallet balance: 105 USD',{exact:true}).waitFor();
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await page.screenshot({path:path.join(artifacts,'store-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
    await page.getByRole('button',{name:'Select Fixture premium',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Cart quantity',exact:true}),'2');
    await page.getByRole('button',{name:'Add to cart',exact:true}).click();
    await page.getByText('Added to your cart. Open Shopping cart to review and place one order.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Open shopping cart',exact:true}).click();
    await page.getByText('Cart total: 10.00 USD',{exact:true}).waitFor();
    await fill(page.getByRole('textbox',{name:'Quantity for Fixture premium',exact:true}),'3');
    await page.getByRole('button',{name:'Update quantity for Fixture premium',exact:true}).click();
    await page.getByText('Cart total: 15.00 USD',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Store',exact:true}).click();
    await page.getByRole('button',{name:'Select Fixture recharge',exact:true}).click();
    await page.getByRole('combobox',{name:'Recharge option',exact:true}).selectOption('10');
    await page.getByRole('button',{name:'Add to cart',exact:true}).click();
    await page.getByText('Added to your cart. Open Shopping cart to review and place one order.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Shopping cart',exact:true}).click();
    await page.getByText('Cart total: 25.00 USD',{exact:true}).waitFor();
    assert.equal(await page.getByRole('combobox',{name:'Cart payment provider',exact:true}).locator('option[value="wallet"]').count(),0);
    await page.getByRole('button',{name:'Remove Fixture recharge',exact:true}).click();
    await page.getByText('Cart total: 15.00 USD',{exact:true}).waitFor();
    rejectCartQuote=true;expectedCartConflict=true;
    await page.getByRole('button',{name:'Place cart order',exact:true}).click();
    await page.getByText('409: Cart quote changed. Refresh and review current prices.',{exact:true}).waitFor();
    expectedCartConflict=false;
    assert.equal(calls.filter(call=>call.endpoint==='/api/pay-order').length,0);
    await page.getByRole('button',{name:'Refresh cart',exact:true}).click();
    await page.getByText('Cart total: 15.00 USD',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Place cart order',exact:true}).click();
    await page.getByText('Cart order paid. Open Store to view your purchase and benefits.',{exact:true}).waitFor();
    await page.getByText('Your cart is empty.',{exact:true}).waitFor();
    assert.equal(calls.filter(call=>call.endpoint==='/api/pay-order').length,1);
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await page.screenshot({path:path.join(artifacts,'cart-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});
    await page.getByRole('button',{name:'Site settings',exact:true}).click();
    await page.getByRole('button',{name:'Save site settings',exact:true}).click();
    await page.getByText('Load current settings before editing.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Load site settings',exact:true}).click();
    await page.getByText('Site settings loaded.',{exact:true}).waitFor();
    await fill(page.getByRole('textbox',{name:'Audit retention days',exact:true}),'30');
    await page.getByRole('button',{name:'Save site settings',exact:true}).click();
    await page.getByText('Audit retention saved and active for the next cleanup. Pool settings remain pending.',{exact:true}).waitFor();
    assert.equal(calls.find(call=>call.endpoint==='/api/update-setting').body.recordRetentionDays,30);
    await page.getByRole('button',{name:'Telemetry',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'OpenClaw log provider ID or owner/name',exact:true}),'fixture-log');
    await fill(page.getByRole('textbox',{name:'Receiver application ID or owner/name',exact:true}),'fixture-app');
    await page.getByRole('button',{name:'Save receiver',exact:true}).click();
    await page.getByText('Receiver saved.',{exact:true}).waitFor();
    assert.equal(await page.getByLabel('Exporter token',{exact:true}).inputValue(),'otlp_fixture_1');
    assert.equal(await page.getByLabel('Exporter token',{exact:true}).getAttribute('type'),'password');
    await page.getByRole('button',{name:'Show exporter token',exact:true}).click();
    await page.getByRole('button',{name:'Rotate exporter token',exact:true}).click();
    await page.getByText('Exporter token rotated.',{exact:true}).waitFor();
    assert.equal(await page.getByLabel('Exporter token',{exact:true}).inputValue(),'otlp_fixture_2');
    assert.equal(await page.getByLabel('Exporter token',{exact:true}).getAttribute('type'),'password');
    assert.equal(receivers[0].token,undefined);
    await page.getByRole('button',{name:'Revoke receiver receiver-1',exact:true}).click();
    await page.getByText('Receiver revoked.',{exact:true}).waitFor();
    await page.getByText(/^Receiver .* · built-in · Disabled$/).waitFor();
    assert.equal(await page.getByLabel('Exporter token',{exact:true}).count(),0);
    await page.getByRole('button',{name:'Products',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Name',exact:true}),'recharge-check');
    await page.getByRole('checkbox',{name:'Recharge product',exact:true}).check();
    await fill(page.getByRole('textbox',{name:'Recharge amounts (JSON array)',exact:true}),'[10,25]');
    await page.getByRole('checkbox',{name:'Only preset recharge amounts',exact:true}).check();
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    const rechargeWrite=calls.find(c=>c.endpoint==='/api/products'&&c.method==='POST').body;
    assert.equal(rechargeWrite.is_recharge,true);assert.deepEqual(rechargeWrite.recharge_options,[10,25]);assert.equal(rechargeWrite.disable_custom_recharge,true);
    await page.getByRole('button',{name:'Plans',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Monthly price',exact:true}),'12.34');
    await fill(page.getByRole('textbox',{name:'Yearly price',exact:true}),'123.4');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    const planWrite=calls.find(c=>c.endpoint==='/api/plans'&&c.method==='POST').body;
    assert.equal(planWrite.price_per_month,12.34);assert.equal(planWrite.price_per_year,123.4);assert.equal(planWrite.product,undefined);
    await page.getByRole('button',{name:'Pricings',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Plan references (JSON array)',exact:true}),'["admin/premium"]');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    assert.equal(calls.find(c=>c.endpoint==='/api/pricings'&&c.method==='POST').body.plans,'["admin/premium"]');
    await page.getByRole('button',{name:'Syncers',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Username',exact:true}),'directory-reader');
    await fill(page.getByRole('textbox',{name:'Database',exact:true}),'external');
    await fill(page.getByRole('textbox',{name:'Table',exact:true}),'directory.users');
    await fill(page.getByRole('textbox',{name:'Field mappings (JSON array)',exact:true}),'[{"name":"uid","type":"varchar","casdoor_name":"id","is_key":true},{"name":"login","type":"varchar","casdoor_name":"name"}]');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    const syncerWrite=calls.find(call=>call.endpoint==='/api/syncers'&&call.method==='POST').body;
    assert.equal(syncerWrite.user,'directory-reader');assert.equal(syncerWrite.user_name,undefined);assert.equal(syncerWrite.table_columns[0].is_key,true);assert.equal(syncerWrite.is_read_only,true);
    await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:'SCIM'});
    await page.getByText('SCIM reads users from Host/Users.',{exact:false}).waitFor();
    assert.equal(await page.getByRole('textbox',{name:'Database',exact:true}).isVisible(),false);
    await fill(page.getByRole('textbox',{name:'Host',exact:true}),'https://directory.example/scim/v2');
    await fill(page.getByLabel('Password',{exact:true}),'fixture-scim-token');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    const scimWrite=calls.filter(call=>call.endpoint==='/api/syncers'&&call.method==='POST').at(-1).body;
    assert.equal(scimWrite.type,'SCIM');assert.equal(scimWrite.user,'');assert.equal(scimWrite.password,'fixture-scim-token');
    assert.deepEqual(scimWrite.table_columns,[]);assert.equal(scimWrite.is_read_only,true);
    await page.getByRole('button',{name:'Restore users and MFA',exact:true}).first().click();
    await page.getByRole('heading',{name:'Restore users and MFA',exact:true}).waitFor();
    const chooseBackup=async value=>{
      const file=path.join(artifacts,'restore-upload.json');
      await fs.writeFile(file,JSON.stringify(value));
      try {
        const [chooser]=await Promise.all([page.waitForEvent('filechooser'),page.getByRole('button',{name:'Casdoor JSON backup',exact:true}).click()]);
        // A real file path lets Chromium emit the trusted chooser event that
        // Glory requires; payload-based synthetic change events are rejected.
        await chooser.setFiles(file);
        await page.getByText('Ready to restore 1 accounts.',{exact:false}).waitFor();
      } finally {await fs.unlink(file).catch(()=>{});}
    };
    const rawSeed='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',rawRecovery='fixture-original-uuid-recovery';
    await chooseBackup({users:[{owner:'built-in',name:'restore-fixture',password:'RestorePassword42!',passwordType:'plain',preferredMfaType:'app',totpSecret:rawSeed,recoveryCodes:[rawRecovery]}],providers:[{clientSecret:'unrelated-provider-secret'}],padding:'x'.repeat(70000)});
    const visibleRestore=await page.locator('body').innerText();assert.ok(!visibleRestore.includes(rawSeed)&&!visibleRestore.includes(rawRecovery));
    assert.ok(!(await page.evaluate(()=>JSON.stringify({...localStorage,...sessionStorage}))).includes(rawSeed));
    await page.getByRole('button',{name:'Restore users and MFA',exact:true}).last().click();
    await page.getByText('Confirm that this is a trusted, current MFA backup.',{exact:true}).waitFor();
    assert.equal(calls.filter(call=>call.endpoint==='/api/upload-users-with-mfa').length,0);
    await page.getByRole('checkbox',{name:'I am restoring a current, unmasked backup with MFA credentials',exact:true}).check();
    await page.getByRole('button',{name:'Restore users and MFA',exact:true}).last().click();
    await page.getByText('Restored 1 accounts with their supported MFA credentials.',{exact:true}).waitFor();
    const restoredPayload=calls.find(call=>call.endpoint==='/api/upload-users-with-mfa');
    assert.equal(Array.isArray(restoredPayload.body),true);assert.equal(restoredPayload.body[0].totpSecret,rawSeed);
    assert.equal(restoredPayload.raw.includes('unrelated-provider-secret'),false);assert.equal(restoredPayload.query.owner,'built-in');
    await page.getByText('No backup ready.',{exact:true}).waitFor();
    await chooseBackup([{owner:'built-in',name:'masked-mfa',totpSecret:'***',preferredMfaType:'app'}]);
    await page.getByRole('checkbox',{name:'I am restoring a current, unmasked backup with MFA credentials',exact:true}).check();
    await page.getByRole('button',{name:'Restore users and MFA',exact:true}).last().click();
    await page.getByText('Restore rejected. No accounts were created; review the errors below.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Clear backup',exact:true}).click();await page.getByText('No backup ready.',{exact:true}).waitFor();
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

    await page.getByRole('button',{name:'New resource',exact:true}).click();
    await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:'Custom'});
    await fill(page.getByRole('textbox',{name:'OAuth authorization URL',exact:true}),'https://identity.example/authorize');
    await fill(page.getByRole('textbox',{name:'OAuth token URL',exact:true}),'https://identity.example/token');
    await fill(page.getByRole('textbox',{name:'OAuth user info URL',exact:true}),'https://identity.example/userinfo');
    await fill(page.getByRole('textbox',{name:'OAuth user mapping (JSON)',exact:true}),'{"id":"data.id","displayName":"data.name"}');
    await fill(page.getByLabel('Secondary client secret',{exact:true}),'secondary-private');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();await page.getByText('Resource saved.',{exact:true}).waitFor();
    const oauthWrite=calls.filter(c=>c.endpoint==='/api/providers'&&c.method==='POST').at(-1).body;
    assert.equal(oauthWrite.custom_auth_url,'https://identity.example/authorize');assert.deepEqual(oauthWrite.user_mapping,{id:'data.id',displayName:'data.name'});assert.equal(oauthWrite.client_secret2,'secondary-private');
    await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:'Okta'});
    await fill(page.getByRole('textbox',{name:'Okta issuer base',exact:true}),'https://example.okta.com/oauth2/default');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();await page.getByText('Resource saved.',{exact:true}).waitFor();
    assert.equal(calls.filter(c=>c.endpoint==='/api/providers'&&c.method==='POST').at(-1).body.domain,'https://example.okta.com/oauth2/default');
    await page.getByRole('combobox',{name:'Category',exact:true}).selectOption({label:'Email'});
    await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:'SMTP'});
    await fill(page.getByRole('textbox',{name:'From address',exact:true}),'sender@example.test');
    await fill(page.getByRole('textbox',{name:'From name',exact:true}),'Browser Sender');
    await page.getByRole('checkbox',{name:'Allow plaintext SMTP',exact:true}).check();
    assert.equal(await page.getByRole('textbox',{name:'OAuth authorization URL',exact:true}).isVisible(),false);
    await page.getByRole('button',{name:'Save resource',exact:true}).click();await page.getByText('Resource saved.',{exact:true}).waitFor();
    const emailWrite=calls.filter(c=>c.endpoint==='/api/providers'&&c.method==='POST').at(-1).body;
    assert.equal(emailWrite.client_id2,'sender@example.test');assert.equal(emailWrite.client_secret2,'Browser Sender');assert.equal(emailWrite.disable_ssl,true);

    await page.getByRole('button',{name:'Pricings',exact:true}).click();
    await fill(page.getByRole('textbox',{name:'Owner',exact:true}),'built-in');
    await fill(page.getByRole('textbox',{name:'Name',exact:true}),'invited-pricing');
    await page.getByRole('checkbox',{name:'Invite-only pricing',exact:true}).check();
    await fill(page.getByRole('textbox',{name:'Invited usernames (empty allows the whole tenant)',exact:true}),'alice, future-user');
    await page.getByRole('button',{name:'Save resource',exact:true}).click();
    await page.getByText('Resource saved.',{exact:true}).waitFor();
    const pricingWrite=calls.filter(call=>call.endpoint==='/api/pricings'&&call.method==='POST').at(-1).body;
    assert.equal(pricingWrite.is_invite_only,true);assert.deepEqual(pricingWrite.users,['alice','future-user']);

    delayProfile=true;
    const delayedProfile=page.waitForRequest(request=>new URL(request.url()).pathname==='/api/get-account');
    await page.getByRole('button',{name:'Account',exact:true}).click();
    await page.getByRole('heading',{name:'Profile',exact:true}).waitFor();
    await delayedProfile;
    assert.equal(await page.getByRole('textbox',{name:'Display name',exact:true}).count(),0);
    assert.equal(await page.getByRole('button',{name:'Save profile',exact:true}).count(),0);
    releaseProfile();
    await fill(page.getByRole('textbox',{name:'Display name',exact:true}),'Loaded profile edit');
    await page.getByRole('button',{name:'Save profile',exact:true}).click();
    await page.getByText('Profile saved.',{exact:true}).waitFor();
    assert.equal(calls.filter(call=>call.endpoint==='/api/users/user-1'&&call.method==='PUT').at(-1).body.display_name,'Loaded profile edit');
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
    await page.getByRole('combobox',{name:'Sign-in method',exact:true}).selectOption('email');
    await fill(page.getByRole('textbox',{name:'Username',exact:true}),'alice');
    await page.getByRole('button',{name:'Send sign-in code',exact:true}).click();
    await page.getByText('Sign-in code sent to your enrolled contact.',{exact:true}).waitFor();
    assert.equal(calls.find(c=>c.endpoint==='/api/auth/code/start').body.method,'email');
    await fill(page.getByRole('textbox',{name:'Sign-in code',exact:true}),'wrong');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByText('Invalid sign-in proof',{exact:true}).waitFor();
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    await fill(page.getByRole('textbox',{name:'Sign-in code',exact:true}),'654321');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    assert.equal(calls.filter(c=>c.endpoint==='/api/login'&&c.body.type==='code').at(-1).body.password,undefined);
    assert.equal(calls.filter(c=>c.endpoint==='/api/login'&&c.body.type==='code').at(-1).body.codeMethod,'email');
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await page.getByRole('combobox',{name:'Sign-in method',exact:true}).selectOption('ldap');
    await fill(page.getByRole('textbox',{name:'Username',exact:true}),'alice');
    await fill(page.getByLabel('Password',{exact:true}),'DirectoryPassword42!');
    await page.getByRole('button',{name:'Sign in',exact:true}).last().click();
    await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    assert.equal(calls.filter(c=>c.endpoint==='/api/login').at(-1).body.type,'ldap');
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
