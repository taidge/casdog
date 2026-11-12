const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');

async function startTransportFixture() {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const url = new URL(request.url, 'http://fixture.local');
    const text = Buffer.concat(chunks).toString();
    requests.push({ method: request.method, path: url.pathname, query: Object.fromEntries(url.searchParams),
      headers: request.headers, text, body: text && request.headers['content-type']?.startsWith('application/json') ? JSON.parse(text) : Object.fromEntries(new URLSearchParams(text)) });
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { origin: `http://127.0.0.1:${server.address().port}`, requests,
    close: () => new Promise(resolve => server.close(resolve)) };
}

async function checkTransportForms({ page, api, admin, fill, saveProvider, suffix, checks, fixture, secrets }) {
  const secret = crypto.randomBytes(24).toString('hex'); secrets.push(secret);
  const create = async (category, name) => {
    await page.getByRole('button', { name: 'New resource', exact: true }).click();
    await page.getByRole('combobox', { name: 'Category', exact: true }).selectOption({ label: category });
    await page.getByRole('combobox', { name: 'Type', exact: true }).selectOption({ label: 'Custom HTTP' });
    await fill('Owner', 'built-in'); await fill('Name', `${name}-${suffix}`); await fill('Display name', name);
  };
  const approve = async () => {
    await page.getByRole('button', { name: 'Approve private provider endpoints', exact: true }).click();
    await page.getByText('Private provider endpoints approved.', { exact: true }).waitFor();
  };
  await create('Email', 'Browser mapped HTTP mail');
  await fill('Endpoint URL / paths', `${fixture.origin}/mail?retained=yes`);
  await fill('From address', 'sender@browser.test'); await fill('From name', 'HTTP Browser Sender');
  await fill('HTTP request method', 'PUT'); await fill('HTTP content type', 'application/json');
  await fill('HTTP body mapping (JSON)', JSON.stringify({ toAddress: 'destination', subject: 'heading', content: 'message' }));
  await fill('HTTP headers (JSON)', JSON.stringify({ 'X-Delivery-Secret': secret }));
  const email = await saveProvider();
  await page.getByRole('button', { name: 'Browser mapped HTTP mail', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('[aria-label="HTTP request method"]')?.value === 'PUT');
  assert.equal((await api('GET', `/api/providers/${email.id}`, undefined, admin.token)).http_headers['X-Delivery-Secret'], '***');
  await approve();
  const content = 'Wire message: + & = 中文';
  await api('POST', '/api/send-email', { provider: email.id, to: 'recipient@browser.test', title: 'Mapped heading', content }, admin.token);
  const wire = fixture.requests.at(-1); assert.equal(wire.method, 'PUT'); assert.equal(wire.query.retained, 'yes');
  assert.equal(wire.headers['x-delivery-secret'], secret); assert.equal(wire.body.destination, 'recipient@browser.test');
  assert.equal(wire.body.heading, 'Mapped heading'); assert.equal(wire.body.message, content);
  assert.equal(wire.body.fromAddress, 'sender@browser.test'); assert.equal(wire.body.fromName, 'HTTP Browser Sender');
  checks.push('Custom HTTP Email configured in Glory sends real PUT JSON with mapped fields, From name/address and masked shared HTTP headers after explicit private endpoint review');

  await fill('HTTP request method', 'GET'); await saveProvider(email.id);
  await page.getByRole('button', { name: 'Load private provider approval', exact: true }).click();
  await page.getByText('The saved provider configuration changed. Review its endpoints before approving again.', { exact: true }).waitFor();
  const count = fixture.requests.length;
  const denied = await page.request.post(`${process.env.CASDOG_E2E_BASE_URL || 'http://localhost:18085'}/api/send-email`, {
    headers: { Authorization: `Bearer ${admin.token}` }, data: { provider: email.id, to: 'recipient@browser.test', content } });
  assert.equal(denied.status(), 403); assert.equal(fixture.requests.length, count);
  await approve(); await api('POST', '/api/send-email', { provider: email.id, to: 'recipient@browser.test', title: 'Query heading', content }, admin.token);
  const query = fixture.requests.at(-1); assert.equal(query.method, 'GET'); assert.equal(query.text, '');
  assert.equal(query.query.retained, 'yes'); assert.equal(query.query.message, content); assert.equal(query.query.destination, 'recipient@browser.test');
  checks.push('Changing HTTP Email method invalidates its durable private approval and blocks delivery until renewed; real GET query encoding preserves existing parameters and Unicode content');

  await create('Notification', 'Browser GET notification');
  await fill('Endpoint URL / paths', `${fixture.origin}/notify?retained=yes&key=${secret}`); await fill('HTTP request method', 'GET');
  await fill('Notification parameter name', 'messageText'); await fill('Default receiver', 'browser-recipient');
  await fill('HTTP headers (JSON)', JSON.stringify({ 'X-Delivery-Secret': secret }));
  const notify = await saveProvider(); await page.getByRole('button', { name: 'Browser GET notification', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('[aria-label="HTTP request method"]')?.value === 'GET');
  assert.equal((await api('GET', `/api/providers/${notify.id}`, undefined, admin.token)).endpoint, '***');
  await approve(); await api('POST', '/api/send-notification', { provider: notify.id, title: 'Ignored subject', content }, admin.token);
  const notification = fixture.requests.at(-1); assert.equal(notification.method, 'GET'); assert.equal(notification.query.retained, 'yes'); assert.equal(notification.query.key, secret);
  assert.equal(notification.query.messageText, content); assert.equal(notification.query.recipient, 'browser-recipient');
  assert.equal(notification.headers['x-delivery-secret'], secret);
  checks.push('Custom HTTP Notification configured in Glory sends a real GET with the configured content parameter, default recipient and masked shared request header');
}
module.exports = { startTransportFixture, checkTransportForms };
