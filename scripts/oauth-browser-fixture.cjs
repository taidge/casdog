// An actual OAuth authorization server used by the browser and Rust HTTP client.
// No browser route is intercepted or replaced.
const http = require('node:http');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

async function startOAuthDirectory() {
  const clientId = 'browser-custom-client', clientSecret = crypto.randomBytes(24).toString('hex');
  const codes = new Map(), tokens = new Map(), requests = [];
  const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
  const signedKid=crypto.randomUUID(),signedJwk={...publicKey.export({format:'jwk'}),kid:signedKid,use:'sig',alg:'RS256'};
  const signedCodes=new Map();
  let identity = {}, signedIdentity={}, signedMode='valid', origin;
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, origin);
      if(url.pathname==='/issuer/.well-known/openid-configuration'){requests.push({kind:'discovery'});res.setHeader('Content-Type','application/json');res.end(JSON.stringify({issuer:origin+'/issuer',authorization_endpoint:origin+'/authorize',token_endpoint:origin+'/token',userinfo_endpoint:origin+'/userinfo',code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['client_secret_post']}));return;}
      if(url.pathname==='/signed-issuer/.well-known/openid-configuration'&&req.method==='GET'){
        requests.push({kind:'signed-discovery'});res.setHeader('Content-Type','application/json');
        res.end(JSON.stringify({issuer:origin+'/signed-issuer',authorization_endpoint:origin+'/signed-issuer/authorize',token_endpoint:origin+'/signed-issuer/token',jwks_uri:origin+'/signed-issuer/jwks',id_token_signing_alg_values_supported:['RS256'],code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['client_secret_post']}));return;
      }
      if(url.pathname==='/signed-issuer/jwks'&&req.method==='GET'){
        requests.push({kind:'signed-jwks',mode:signedMode});res.setHeader('Content-Type','application/json');res.end(JSON.stringify({keys:[signedJwk]}));return;
      }
      if(url.pathname==='/signed-issuer/authorize'&&req.method==='GET'){
        assert.equal(url.searchParams.get('client_id'),clientId);assert.equal(url.searchParams.get('response_type'),'code');
        assert.ok(url.searchParams.get('scope').split(' ').includes('openid'));assert.equal(url.searchParams.get('code_challenge_method'),'S256');
        const nonce=url.searchParams.get('nonce');assert.ok(nonce&&nonce.length>=32);assert.ok(url.searchParams.get('code_challenge'));
        const redirect=new URL(url.searchParams.get('redirect_uri'));assert.equal(redirect.hostname,'localhost');assert.match(redirect.pathname,/^\/api\/auth\/[^/]+\/callback$/);
        const code=crypto.randomUUID();signedCodes.set(code,{redirect:redirect.toString(),nonce,challenge:url.searchParams.get('code_challenge'),identity:structuredClone(signedIdentity),mode:signedMode});
        requests.push({kind:'signed-authorize',mode:signedMode,scope:url.searchParams.get('scope'),nonce:true});
        redirect.searchParams.set('code',code);redirect.searchParams.set('state',url.searchParams.get('state'));res.writeHead(302,{Location:redirect.toString()});res.end();return;
      }
      if(url.pathname==='/signed-issuer/token'&&req.method==='POST'){
        assert.equal(url.search,'');assert.equal(req.headers.authorization,undefined);const chunks=[];for await(const chunk of req)chunks.push(chunk);const data=new URLSearchParams(Buffer.concat(chunks).toString());
        assert.equal(data.get('client_id'),clientId);assert.equal(data.get('client_secret'),clientSecret);assert.equal(data.get('grant_type'),'authorization_code');
        const record=signedCodes.get(data.get('code'));assert.ok(record);signedCodes.delete(data.get('code'));assert.equal(data.get('redirect_uri'),record.redirect);
        const verifier=data.get('code_verifier');assert.ok(verifier);assert.equal(crypto.createHash('sha256').update(verifier).digest('base64url'),record.challenge);
        const now=Math.floor(Date.now()/1000);const claims={iss:origin+'/signed-issuer',aud:clientId,sub:record.identity.id,preferred_username:record.identity.username,name:record.identity.displayName,email:record.identity.email,email_verified:true,iat:now,exp:now+300,nonce:record.mode==='wrong-nonce'?record.nonce+'-wrong':record.nonce};
        const header=Buffer.from(JSON.stringify({alg:'RS256',kid:signedKid,typ:'JWT'})).toString('base64url'),payload=Buffer.from(JSON.stringify(claims)).toString('base64url'),input=header+'.'+payload;
        const signature=crypto.sign('RSA-SHA256',Buffer.from(input),privateKey);if(record.mode==='bad-signature')signature[0]^=1;
        requests.push({kind:'signed-token',subject:record.identity.id,mode:record.mode,pkce:true,idTokenOnly:true,query:url.search});
        res.setHeader('Content-Type','application/json');res.end(JSON.stringify({id_token:input+'.'+signature.toString('base64url'),token_type:'Bearer'}));return;
      }
      if (url.pathname === '/authorize' && req.method === 'GET') {
        assert.equal(url.searchParams.get('client_id'), clientId);
        assert.equal(url.searchParams.get('response_type'), 'code');
        const redirect = new URL(url.searchParams.get('redirect_uri'));
        assert.equal(redirect.hostname, 'localhost');
        assert.match(redirect.pathname, /^\/api\/auth\/[^/]+\/callback$/);
        const code = crypto.randomUUID();
        codes.set(code, { redirect: redirect.toString(), identity: structuredClone(identity),state:url.searchParams.get('state'),challenge:url.searchParams.get('code_challenge') });
        requests.push({ kind: 'authorize', scope: url.searchParams.get('scope') });
        redirect.searchParams.set('code', code);
        redirect.searchParams.set('state', url.searchParams.get('state'));
        res.writeHead(302, { Location: redirect.toString() }); res.end(); return;
      }
      if (['/token','/template/token'].includes(url.pathname) && req.method === 'POST') {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        const data = new URLSearchParams(Buffer.concat(chunks).toString());
        const template=url.pathname==='/template/token';assert.equal(url.search,'');
        assert.equal(data.get(template?'appid':'client_id'),clientId);assert.equal(data.get(template?'secret':'client_secret'),clientSecret);
        if(!template)assert.equal(data.get('grant_type'),'authorization_code');
        const record = codes.get(data.get('code')); assert.ok(record);
        codes.delete(data.get('code')); assert.equal(data.get(template?'redirect':'redirect_uri'),record.redirect);
        const verifier=data.get(template?'verifier':'code_verifier');if(record.challenge){assert.ok(verifier);assert.equal(crypto.createHash('sha256').update(verifier).digest('base64url'),record.challenge);}if(template){assert.ok(record.challenge);assert.equal(data.get('state'),record.state);}
        const token = crypto.randomBytes(24).toString('hex'); tokens.set(token,{identity:record.identity,state:record.state});
        requests.push({kind:template?'template-token':'token',subject:record.identity.id,pkce:!!record.challenge,query:url.search});
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ access_token: token, token_type: 'Bearer',openid:record.identity.id })); return;
      }
      if (['/userinfo','/template/userinfo'].includes(url.pathname) && req.method === 'GET') {
        const template=url.pathname==='/template/userinfo';const token=template?url.searchParams.get('access_token'):(req.headers.authorization||'').replace(/^Bearer /,'');
        const record=tokens.get(token);assert.ok(record);const profile=record.identity;
        if(template){assert.equal(req.headers.authorization,undefined);assert.equal(url.searchParams.get('openid'),profile.id);assert.equal(url.searchParams.get('appid'),clientId);assert.equal(url.searchParams.get('state'),record.state);}
        requests.push({kind:template?'template-userinfo':'userinfo',subject:profile.id});
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ data: { employeeId: profile.id, login: profile.username,
          profile: { fullName: profile.displayName, picture: profile.avatarUrl },
          contacts: { email: profile.email, emailVerified: true, phone: '+14155552671', phoneVerified: true } } })); return;
      }
      res.writeHead(404); res.end();
    } catch (error) { res.writeHead(400); res.end(JSON.stringify({ error: error.message })); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, clientId, clientSecret, requests, setIdentity(value) { identity = value; },
    setSignedIdentity(value){signedIdentity=structuredClone(value);},
    setSignedMode(value){assert.ok(['valid','wrong-nonce','bad-signature'].includes(value));signedMode=value;},
    mapping: { id: 'data.employeeId', username: 'data.login', displayName: 'data.profile.fullName',
      email: 'data.contacts.email', emailVerified: 'data.contacts.emailVerified', phone: 'data.contacts.phone',
      phoneVerified: 'data.contacts.phoneVerified', avatarUrl: 'data.profile.picture' },
    close: () => new Promise(resolve => server.close(resolve)) };
}
module.exports = { startOAuthDirectory };
