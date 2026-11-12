const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');

async function startCloudDirectoryFixture() {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const state = { azureChanged: false, googleChanged: false, suffix: crypto.randomBytes(6).toString('hex') };
  const azureSecret = crypto.randomBytes(24).toString('hex');
  const azureToken = crypto.randomBytes(24).toString('hex'), googleToken = crypto.randomBytes(24).toString('hex');
  const requests = [];
  let origin;
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, origin);
      const send = value => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
      if (req.method === 'POST') {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        const form = new URLSearchParams(Buffer.concat(chunks).toString());
        if (url.pathname === '/azure/token') {
          assert.equal(form.get('grant_type'), 'client_credentials');
          assert.equal(form.get('client_id'), 'browser-cloud-client'); assert.equal(form.get('client_secret'), azureSecret);
          assert.equal(form.get('scope'), 'https://graph.microsoft.com/.default');
          requests.push({ kind: 'azure-token' }); send({ access_token: azureToken, token_type: 'Bearer', expires_in: 3600 }); return;
        }
        if (url.pathname === '/google/token') {
          assert.equal(form.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
          const parts = form.get('assertion').split('.'); assert.equal(parts.length, 3);
          const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
          assert.equal(header.alg, 'RS256'); assert.ok(crypto.verify('RSA-SHA256', Buffer.from(parts.slice(0, 2).join('.')), pair.publicKey, Buffer.from(parts[2], 'base64url')));
          const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
          assert.equal(claims.iss, 'browser-service@directory.test'); assert.equal(claims.sub, 'directory-admin@browser.test');
          assert.equal(claims.aud, `${origin}/google/token`);
          assert.equal(claims.scope, 'https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly');
          assert.ok(claims.exp > claims.iat && claims.exp - claims.iat <= 3600);
          requests.push({ kind: 'google-token' }); send({ access_token: googleToken, token_type: 'Bearer', expires_in: 3600 }); return;
        }
      }
      if (url.pathname === '/graph/v1.0/users') {
        assert.equal(req.headers.authorization, `Bearer ${azureToken}`);
        const second = url.searchParams.get('page') === 'two'; requests.push({ kind: 'azure-users', second });
        const item = second ? { id: `azure-B-${state.suffix}`, userPrincipalName: `aad-b-${state.suffix}@browser.test`, displayName: 'Cloud Azure B', mail: `aad-b-${state.suffix}@browser.test`, accountEnabled: true }
          : { id: `azure-A-${state.suffix}`, userPrincipalName: `aad-${state.azureChanged ? 'renamed' : 'a'}-${state.suffix}@browser.test`, displayName: state.azureChanged ? 'Cloud Azure renamed' : 'Cloud Azure A', mail: `aad-a-${state.suffix}@browser.test`, givenName: 'Azure', surname: 'Browser', accountEnabled: !state.azureChanged, preferredLanguage: 'en', mobilePhone: '+14155552671' };
        send({ value: [item], ...(!second ? { '@odata.nextLink': `${origin}/graph/v1.0/users?page=two` } : {}) }); return;
      }
      if (url.pathname.startsWith('/admin/directory/v1/')) {
        assert.equal(req.headers.authorization, `Bearer ${googleToken}`);
        const second = url.searchParams.get('pageToken') === 'two';
        if (url.pathname.endsWith('/users')) {
          requests.push({ kind: 'google-users', second });
          const user = second ? { id: `google-B-${state.suffix}`, primaryEmail: `gw-b-${state.suffix}@browser.test`, name: { fullName: 'Cloud Workspace B' }, suspended: false }
            : { id: `google-A-${state.suffix}`, primaryEmail: `gw-${state.googleChanged ? 'renamed' : 'a'}-${state.suffix}@browser.test`, name: { fullName: state.googleChanged ? 'Cloud Workspace renamed' : 'Cloud Workspace A', givenName: 'Workspace', familyName: 'Browser' }, suspended: state.googleChanged, isAdmin: true, creationTime: '2025-01-01T00:00:00Z' };
          send({ kind: 'admin#directory#users', users: [user], ...(!second ? { nextPageToken: 'two' } : {}) }); return;
        }
        if (url.pathname.endsWith('/groups')) {
          requests.push({ kind: 'google-groups', second });
          const group = second ? { id: `group-B-${state.suffix}`, email: `team-b-${state.suffix}@browser.test`, name: 'Cloud Workspace second group' }
            : { id: `group-A-${state.suffix}`, email: `team-${state.googleChanged ? 'renamed' : 'a'}-${state.suffix}@browser.test`, name: state.googleChanged ? 'Cloud Workspace renamed group' : 'Cloud Workspace first group' };
          send({ kind: 'admin#directory#groups', groups: [group], ...(!second ? { nextPageToken: 'two' } : {}) }); return;
        }
        if (url.pathname.endsWith('/members')) {
          const groupA = url.pathname.includes(`group-A-${state.suffix}`); requests.push({ kind: 'google-members', groupA, second });
          const members = groupA && state.googleChanged ? [] : [{ id: `google-${groupA && !second ? 'A' : 'B'}-${state.suffix}`, type: 'USER', role: 'MEMBER' }];
          send({ kind: 'admin#directory#members', members, ...(groupA && !second && !state.googleChanged ? { nextPageToken: 'two' } : {}) }); return;
        }
      }
      res.writeHead(404); res.end('{}');
    } catch { res.writeHead(400); res.end('{"error":"fixture protocol validation failed"}'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, state, requests, azureSecret, key,
    account: JSON.stringify({ type: 'service_account', client_email: 'browser-service@directory.test', private_key: key, private_key_id: 'browser-key', token_uri: `${origin}/google/token` }),
    close: () => new Promise(resolve => server.close(resolve)) };
}

async function checkCloudDirectories({ page, navigate, fill, api, admin, checks, fixture, suffix, secrets }) {
  secrets.push(fixture.azureSecret, fixture.key);
  const token = admin.token;
  const owner = 'built-in';
  const saved = async () => {
    const response = page.waitForResponse(value => new URL(value.url()).pathname.startsWith('/api/syncers') && ['POST', 'PUT'].includes(value.request().method()) && !value.url().endsWith('/network-approval'));
    await page.getByRole('button', { name: 'Save resource', exact: true }).click();
    const result = await response; assert.ok(result.ok(), await result.text());
    await page.getByText('Resource saved.', { exact: true }).waitFor(); return result.json();
  };
  const select = async name => { await page.getByRole('button', { name, exact: true }).click(); };
  const approve = async () => {
    await page.getByRole('button', { name: 'Load directory network approval', exact: true }).click();
    await page.getByText(`Targets: ${fixture.origin}`, { exact: false }).waitFor();
    await page.getByRole('button', { name: 'Approve private directory endpoints', exact: true }).click();
    await page.getByText('Private directory endpoints approved.', { exact: true }).waitFor();
  };
  const run = async () => {
    const finished = page.waitForResponse(value => /\/api\/syncers\/[^/]+\/run$/.test(new URL(value.url()).pathname) && value.request().method() === 'POST');
    await page.getByRole('button', { name: 'Run selected syncer', exact: true }).click();
    const result = await finished; assert.ok(result.ok(), await result.text());
    await page.getByText('Synchronization completed.', { exact: false }).waitFor();
  };
  const user = async sourceId => {
    const users = await api('GET', `/api/users?owner=${owner}&page_size=1000`, undefined, token);
    const matches = users.data.filter(value => value.external_id === sourceId);
    assert.equal(matches.length, 1, `Expected one tenant-owned immutable directory identity ${sourceId}`);
    return matches[0];
  };
  await navigate('Syncers', 'Syncers');
  await page.getByRole('button', { name: 'New resource', exact: true }).click();
  await page.getByRole('combobox', { name: 'Type', exact: true }).selectOption({ label: 'Azure AD' });
  const azureName = `browser-azure-dir-${suffix}`;
  await fill('Owner', owner); await fill('Name', azureName); await fill('Organization', owner);
  await fill('Azure tenant ID / domain', 'browser-tenant.example.test'); await fill('Azure client ID', 'browser-cloud-client'); await fill('Azure client secret', fixture.azureSecret, true);
  await fill('Cloud transport options (JSON)', JSON.stringify({ token_endpoint: `${fixture.origin}/azure/token`, api_base: `${fixture.origin}/graph/v1.0` }));
  const azure = await saved(); await select(azureName); await approve(); await run();
  const firstAzure = await user(`azure-A-${fixture.state.suffix}`);
  assert.equal(firstAzure.displayName || firstAzure.display_name, 'Cloud Azure A');
  const maskedAzure = await api('GET', `/api/syncers/${azure.id}`, undefined, token); assert.equal(maskedAzure.password, '***');
  fixture.state.azureChanged = true; await run();
  const renamedAzure = await user(`azure-A-${fixture.state.suffix}`);
  assert.equal(renamedAzure.id, firstAzure.id); assert.equal(renamedAzure.isForbidden ?? renamedAzure.is_forbidden, true);
  assert.notEqual(renamedAzure.name, firstAzure.name);
  assert.equal(renamedAzure.properties.cloud_directory.principal, `aad-renamed-${fixture.state.suffix}@browser.test`);
  assert.ok(fixture.requests.filter(value => value.kind === 'azure-users' && value.second).length >= 2);
  checks.push('Azure AD configured in Glory authenticates client credentials, imports every real Graph page and preserves the local UUID across UPN rename while applying account-disabled state');

  await page.getByRole('button', { name: 'New resource', exact: true }).click();
  await page.getByRole('combobox', { name: 'Type', exact: true }).selectOption({ label: 'Google Workspace' });
  const googleName = `browser-google-dir-${suffix}`;
  await fill('Owner', owner); await fill('Name', googleName); await fill('Organization', owner);
  await fill('Delegated administrator email', 'directory-admin@browser.test'); await fill('Service account email', 'browser-service@directory.test'); await fill('Service account JSON', fixture.account, true);
  await fill('Cloud transport options (JSON)', JSON.stringify({ api_base: `${fixture.origin}/admin/directory/v1`, customer: 'my_customer' }));
  const google = await saved(); await select(googleName); await approve(); await run();
  const firstGoogle = await user(`google-A-${fixture.state.suffix}`), otherGoogle = await user(`google-B-${fixture.state.suffix}`);
  assert.equal(firstGoogle.isAdmin ?? firstGoogle.is_admin, false);
  const groupsResult = await api('GET', `/api/groups?owner=${owner}&page_size=1000`, undefined, token);
  const groups = groupsResult.data || groupsResult.items || groupsResult;
  const groupA = groups.find(value => value.contact_email === `team-a-${fixture.state.suffix}@browser.test`);
  assert.ok(groupA); assert.deepEqual(new Set(await api('GET', `/api/groups/${groupA.id}/users`, undefined, token)), new Set([firstGoogle.id, otherGoogle.id]));
  await api('POST', '/api/groups/add-user', { user_id: firstGoogle.id, group_id: groupA.id }, token);
  fixture.state.googleChanged = true; await run();
  const renamedGoogle = await user(`google-A-${fixture.state.suffix}`);
  assert.equal(renamedGoogle.id, firstGoogle.id); assert.equal(renamedGoogle.isForbidden ?? renamedGoogle.is_forbidden, true);
  assert.notEqual(renamedGoogle.name, firstGoogle.name);
  assert.equal(renamedGoogle.properties.cloud_directory.principal, `gw-renamed-${fixture.state.suffix}@browser.test`);
  assert.deepEqual(await api('GET', `/api/groups/${groupA.id}/users`, undefined, token), [firstGoogle.id]);
  const changedGroup = await api('GET', `/api/groups/${groupA.id}`, undefined, token);
  assert.equal(changedGroup.contact_email, `team-renamed-${fixture.state.suffix}@browser.test`);
  assert.equal((await api('GET', `/api/syncers/${google.id}`, undefined, token)).password, '***');
  assert.ok(fixture.requests.some(value => value.kind === 'google-groups' && value.second)); assert.ok(fixture.requests.some(value => value.kind === 'google-members' && value.second));
  checks.push('Google Workspace configured in Glory exchanges a verified delegated service-account assertion, imports complete user/group/member pages and reconciles stable managed groups while retaining an explicit manual membership');
}
module.exports = { startCloudDirectoryFixture, checkCloudDirectories };
