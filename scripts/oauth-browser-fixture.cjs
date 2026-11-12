// An actual OAuth authorization server used by the browser and Rust HTTP client.
// No browser route is intercepted or replaced.
const http = require('node:http');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

async function startOAuthDirectory() {
  const clientId = 'browser-custom-client', clientSecret = crypto.randomBytes(24).toString('hex');
  const codes = new Map(), tokens = new Map(), requests = [];
  let identity = {}, origin;
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, origin);
      if (url.pathname === '/authorize' && req.method === 'GET') {
        assert.equal(url.searchParams.get('client_id'), clientId);
        assert.equal(url.searchParams.get('response_type'), 'code');
        const redirect = new URL(url.searchParams.get('redirect_uri'));
        assert.equal(redirect.hostname, 'localhost');
        assert.match(redirect.pathname, /^\/api\/auth\/[^/]+\/callback$/);
        const code = crypto.randomUUID();
        codes.set(code, { redirect: redirect.toString(), identity: structuredClone(identity) });
        requests.push({ kind: 'authorize', scope: url.searchParams.get('scope') });
        redirect.searchParams.set('code', code);
        redirect.searchParams.set('state', url.searchParams.get('state'));
        res.writeHead(302, { Location: redirect.toString() }); res.end(); return;
      }
      if (url.pathname === '/token' && req.method === 'POST') {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        const data = new URLSearchParams(Buffer.concat(chunks).toString());
        assert.equal(data.get('client_id'), clientId); assert.equal(data.get('client_secret'), clientSecret);
        assert.equal(data.get('grant_type'), 'authorization_code');
        const record = codes.get(data.get('code')); assert.ok(record);
        codes.delete(data.get('code')); assert.equal(data.get('redirect_uri'), record.redirect);
        const token = crypto.randomBytes(24).toString('hex'); tokens.set(token, record.identity);
        requests.push({ kind: 'token', subject: record.identity.id });
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ access_token: token, token_type: 'Bearer' })); return;
      }
      if (url.pathname === '/userinfo' && req.method === 'GET') {
        const token = (req.headers.authorization || '').replace(/^Bearer /, '');
        const profile = tokens.get(token); assert.ok(profile);
        requests.push({ kind: 'userinfo', subject: profile.id });
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
    mapping: { id: 'data.employeeId', username: 'data.login', displayName: 'data.profile.fullName',
      email: 'data.contacts.email', emailVerified: 'data.contacts.emailVerified', phone: 'data.contacts.phone',
      phoneVerified: 'data.contacts.phoneVerified', avatarUrl: 'data.profile.picture' },
    close: () => new Promise(resolve => server.close(resolve)) };
}
module.exports = { startOAuthDirectory };
