// Wire-only storage fixture. Browser APIs still reach the real Rust backend.
const http=require('node:http');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
async function startCloudStorage(){
 const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 const objects=new Map(),requests=[];const key=crypto.randomBytes(32).toString('base64');
 let origin;
 const server=http.createServer(async(req,res)=>{try{
  const url=new URL(req.url,origin),chunks=[];for await(const chunk of req)chunks.push(chunk);const bytes=Buffer.concat(chunks);
  requests.push({method:req.method,path:url.pathname,query:Object.fromEntries(url.searchParams),authorization:req.headers.authorization});
  if(url.pathname==='/oauth/token'){
   const assertion=new URLSearchParams(bytes.toString()).get('assertion');assert.ok(assertion);const [header,payload,signature]=assertion.split('.');
   assert.equal(JSON.parse(Buffer.from(header,'base64url')).alg,'RS256');assert.equal(JSON.parse(Buffer.from(payload,'base64url')).aud,origin+'/oauth/token');
   assert.ok(crypto.verify('RSA-SHA256',Buffer.from(header+'.'+payload),publicKey,Buffer.from(signature,'base64url')));
   res.setHeader('Content-Type','application/json');res.end(JSON.stringify({access_token:'browser-storage-token',token_type:'Bearer',expires_in:3600}));return;
  }
  let objectKey=url.pathname;
  if(url.pathname.startsWith('/upload/storage/')){assert.equal(req.headers.authorization,'Bearer browser-storage-token');objectKey='gcs:'+url.searchParams.get('name');}
  else if(url.pathname.startsWith('/storage/')){assert.equal(req.headers.authorization,'Bearer browser-storage-token');objectKey='gcs:'+decodeURIComponent(url.pathname.split('/o/')[1]);}
  else assert.match(req.headers.authorization||'',/^(SharedKey |AWS4-HMAC-SHA256 )/);
  if(req.method==='PUT'||req.method==='POST'){objects.set(objectKey,bytes);res.setHeader('Content-Type','application/json');res.end('{}');}
  else if(req.method==='DELETE'){objects.delete(objectKey);res.statusCode=204;res.end();}
  else if(objects.has(objectKey)){res.setHeader('Content-Type','text/plain');res.end(objects.get(objectKey));}
  else {res.statusCode=404;res.end();}
 }catch(error){res.statusCode=500;res.end(error.message);}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin=`http://127.0.0.1:${server.address().port}`;
 return {origin,key,requests,objects,serviceAccount:{type:'service_account',project_id:'browser-fixture',private_key_id:'browser-key',private_key:privateKey.export({type:'pkcs8',format:'pem'}).toString(),client_email:'browser@fixture.iam.gserviceaccount.com',token_uri:origin+'/oauth/token'},close:()=>new Promise(resolve=>server.close(resolve))};
}
module.exports={startCloudStorage};
