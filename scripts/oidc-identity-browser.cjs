const assert=require('node:assert/strict');

// Configure through the actual Glory form and real global-admin approval.
async function configureOidcIdentity({page,fill,saveProvider,api,admin,suffix,fixture}){
  const name=`browser-signed-oidc-${suffix}`,label='Browser signed OIDC identity';
  await page.getByRole('button',{name:'New resource',exact:true}).click();
  await page.getByRole('combobox',{name:'Category',exact:true}).selectOption({label:'OAuth'});
  await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:'OIDC'});
  await fill('Owner','built-in');await fill('Name',name);await fill('Display name',label);
  await fill('Client ID / API key',fixture.clientId);await fill('Client secret',fixture.clientSecret,true);
  await fill('Scopes / discovery targets','openid profile email');await fill('Authentication method','client_secret_post');
  await fill('OIDC issuer base',fixture.origin+'/signed-issuer');
  await fill('OAuth user mapping (JSON)',JSON.stringify({id:'sub',username:'preferred_username',displayName:'name',email:'email',emailVerified:'email_verified'}));
  const provider=await saveProvider();await page.getByRole('button',{name:label,exact:true}).click();
  await page.getByRole('button',{name:'Approve private provider endpoints',exact:true}).click();await page.getByText('Private provider endpoints approved.',{exact:true}).waitFor();
  const saved=await api('GET',`/api/providers/${provider.id}`,undefined,admin.token);assert.equal(saved.method,'client_secret_post');assert.equal(saved.domain,fixture.origin+'/signed-issuer');assert.ok(!saved.custom_user_info_url);
  const application=await api('POST','/api/applications',{owner:'admin',name,display_name:label,organization:'built-in',enable_idp_signup:true,providers:[{name:`built-in/${name}`,canSignIn:true,canSignUp:true,canUnlink:true}]},admin.token);
  return{label,provider:provider.id,application:application.id};
}

async function checkOidcIdentity({page,fill,signIn,password,api,admin,checks,fixture,configured,suffix}){
  const signOut=async()=>{await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();};
  await signOut();fixture.setSignedMode('valid');const subject=`signed-sub-${suffix}`;
  fixture.setSignedIdentity({id:subject,username:`signed-${suffix}`,displayName:'Signed OIDC User',email:`signed-${suffix}@example.test`});
  await fill('Application',configured.application);await page.getByRole('button',{name:`Sign in with ${configured.label}`,exact:true}).click();await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
  const token=await page.evaluate(()=>JSON.parse(localStorage.getItem('casdog.auth.token')));assert.ok(token);
  const account=await api('GET','/api/get-account',undefined,token);assert.equal(account.provider_ids[`oauth:${configured.provider}`],subject);assert.equal(account.display_name,'Signed OIDC User');assert.equal(account.email_verified,true);assert.equal(account.email,`signed-${suffix}@example.test`);
  assert.ok(fixture.requests.some(value=>value.kind==='signed-discovery'));assert.ok(fixture.requests.some(value=>value.kind==='signed-jwks'));assert.ok(fixture.requests.some(value=>value.kind==='signed-token'&&value.subject===subject&&value.pkce&&value.idTokenOnly&&value.query===''));
  assert.ok(!fixture.requests.some(value=>['userinfo','template-userinfo'].includes(value.kind)&&value.subject===subject));
  checks.push('Issuer-only OIDC created in Glory performs real discovery, S256 code exchange and RSA-2048 JWKS signature verification with the durable nonce, then signs in from ID-token-only claims without a UserInfo endpoint');
  await signOut();const origin=new URL(page.url()).origin;
  for(const mode of ['wrong-nonce','bad-signature']){
    const before=await api('GET','/api/users?owner=built-in&page_size=100',undefined,admin.token);fixture.setSignedMode(mode);const rejected=`signed-${mode}-${suffix}`;
    fixture.setSignedIdentity({id:rejected,username:rejected,displayName:'Rejected OIDC User',email:`${rejected}@example.test`});await fill('Application',configured.application);
    const callback=page.waitForResponse(response=>new URL(response.url()).pathname.startsWith('/api/auth/')&&new URL(response.url()).pathname.endsWith('/callback'));
    await page.getByRole('button',{name:`Sign in with ${configured.label}`,exact:true}).click();const denied=await callback;assert.equal(denied.status(),401);assert.match(await denied.text(),/OIDC identity verification failed/);
    await page.waitForURL(url=>url.pathname.startsWith('/api/auth/')&&url.pathname.endsWith('/callback'));
    assert.equal(await page.evaluate(()=>localStorage.getItem('casdog.auth.token')),null);
    const unauthenticated=await page.request.get(origin+'/api/get-account');assert.equal(unauthenticated.status(),401);
    const after=await api('GET','/api/users?owner=built-in&page_size=100',undefined,admin.token);assert.equal(after.total,before.total);assert.ok(!after.data.some(user=>user.name===rejected));
    assert.ok(fixture.requests.some(value=>value.kind==='signed-token'&&value.subject===rejected&&value.mode===mode));
    checks.push(mode==='wrong-nonce'?'A real signed OIDC response with the wrong browser-flow nonce is rejected during browser callback with HTTP 401, creates no account and establishes no local session':'A real OIDC response with a corrupted RSA signature is rejected during browser callback with HTTP 401, creates no account and establishes no local session');
    await page.goto(origin+'/');await page.getByRole('button',{name:'Sign in',exact:true}).first().click();await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
  }
  fixture.setSignedMode('valid');await signIn(password);await page.getByRole('heading',{name:'Identity and access management'}).waitFor();return page.evaluate(()=>JSON.parse(localStorage.getItem('casdog.auth.token')));
}
module.exports={configureOidcIdentity,checkOidcIdentity};
