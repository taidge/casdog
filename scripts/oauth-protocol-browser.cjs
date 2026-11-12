const assert=require('node:assert/strict');
async function configureOAuthProtocols({page,fill,saveProvider,api,admin,suffix,fixture}) {
  const configured=[];
  for(const mode of ['oidc','template']) {
    const label=`Browser ${mode} protocol`,name=`browser-${mode}-${suffix}`;
    await page.getByRole('button',{name:'New resource',exact:true}).click();
    await page.getByRole('combobox',{name:'Category',exact:true}).selectOption({label:'OAuth'});
    await page.getByRole('combobox',{name:'Type',exact:true}).selectOption({label:mode==='oidc'?'OIDC':'Custom'});
    await fill('Owner','built-in');await fill('Name',name);await fill('Display name',label);
    await fill('Client ID / API key',fixture.clientId);await fill('Client secret',fixture.clientSecret,true);
    await fill('Scopes / discovery targets','openid browser.protocol');await fill('OAuth user mapping (JSON)',JSON.stringify(fixture.mapping));
    if(mode==='oidc')await fill('OIDC issuer base',fixture.origin+'/issuer');
    else {
      await fill('OAuth authorization URL',fixture.origin+'/authorize');
      await fill('OAuth token URL',fixture.origin+'/template/token?appid={clientId}&secret={clientSecret}&code={code}&redirect={redirectUri}&state={state}&verifier={codeVerifier}');
      await fill('OAuth user info URL',fixture.origin+'/template/userinfo?access_token={access_token}&openid={openid}&appid={clientId}&state={state}');
    }
    const provider=await saveProvider();await page.getByRole('button',{name:label,exact:true}).click();
    await page.getByRole('button',{name:'Approve private provider endpoints',exact:true}).click();await page.getByText('Private provider endpoints approved.',{exact:true}).waitFor();
    const application=await api('POST','/api/applications',{owner:'admin',name,display_name:label,organization:'built-in',enable_idp_signup:true,providers:[{name:`built-in/${name}`,canSignIn:true,canSignUp:true,canUnlink:true}]},admin.token);
    configured.push({mode,label,provider:provider.id,application:application.id});
  }
  return configured;
}
async function checkOAuthProtocols({page,fill,signIn,password,api,checks,fixture,configured,suffix}) {
  let localToken;
  for(const config of configured) {
    await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    const subject=`${config.mode}-subject-${suffix}`;
    fixture.setIdentity({id:subject,username:`${config.mode}-${suffix}`,displayName:`Mapped ${config.mode}`,email:`${config.mode}-${suffix}@example.test`,avatarUrl:'https://example.test/protocol.png'});
    await fill('Application',config.application);await page.getByRole('button',{name:`Sign in with ${config.label}`,exact:true}).click();await page.getByRole('heading',{name:'Identity and access management'}).waitFor();
    const token=await page.evaluate(()=>JSON.parse(localStorage.getItem('casdog.auth.token')));const user=await api('GET','/api/get-account',undefined,token);
    assert.equal(user.provider_ids[`oauth:${config.provider}`],subject);assert.equal(user.display_name,`Mapped ${config.mode}`);assert.equal(user.email_verified,true);
    if(config.mode==='oidc') {assert.ok(fixture.requests.some(value=>value.kind==='discovery'));assert.ok(fixture.requests.some(value=>value.kind==='token'&&value.subject===subject&&value.pkce));}
    else {assert.ok(fixture.requests.some(value=>value.kind==='template-token'&&value.subject===subject&&value.pkce&&value.query===''));assert.ok(fixture.requests.some(value=>value.kind==='template-userinfo'&&value.subject===subject));}
    checks.push(config.mode==='oidc'?'Issuer-only OIDC configured in Glory discovers real metadata, negotiates S256 PKCE and authenticates mapped user-info without accepting an unverified ID token':'OAuth URL templates configured in Glory send secrets only in the real token POST form, verify S256 PKCE and use request-local token-response fields and state in the real user-info request');
    await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();await signIn(password);await page.getByRole('heading',{name:'Identity and access management'}).waitFor();localToken=await page.evaluate(()=>JSON.parse(localStorage.getItem('casdog.auth.token')));
  }
  return localToken;
}
module.exports={configureOAuthProtocols,checkOAuthProtocols};
