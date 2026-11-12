// Real, independent Kerby KDC and JDK GSS client for browser integration tests.
// Tickets are supplied through normal HTTP headers; no API responses are mocked.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');

async function startKerberos(project, targetDirectory) {
  const directory = path.join(targetDirectory, 'phase13', `browser-kdc-${crypto.randomUUID()}`);
  await fs.mkdir(directory, { recursive: true });
  const realm = `R${crypto.randomBytes(12).toString('hex').toUpperCase()}.CASDOG.TEST`;
  const reservation = net.createServer();
  await new Promise((resolve, reject) => reservation.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
  const process = spawn('java', [
    '--class-path', path.join(targetDirectory, 'phase13', 'kerby', '*'),
    path.join(project, 'scripts', 'KerberosFixture.java'), directory, realm, String(port),
  ], { cwd: project, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = [];
  const readers = [];
  let failure;
  let diagnostics = '';
  const closed = new Promise(resolve => process.once('close', (code, signal) => resolve({ code, signal })));
  function rejectReaders(error) {
    failure = error;
    for (const reader of readers.splice(0)) reader.reject(error);
  }
  process.on('error', error => rejectReaders(error));
  process.stdin.on('error', error => rejectReaders(error));
  process.on('close', (code, signal) => rejectReaders(new Error(`Test KDC exited (${code}, ${signal}): ${diagnostics}`)));
  process.stderr.setEncoding('utf8');
  process.stderr.on('data', chunk => { diagnostics = (diagnostics + chunk).slice(-65536); });
  const output = readline.createInterface({ input: process.stdout });
  output.on('line', line => {
    const reader = readers.shift();
    if (reader) reader.resolve(line);
    else lines.push(line);
  });
  function readLine() {
    if (lines.length) return Promise.resolve(lines.shift());
    if (failure) return Promise.reject(failure);
    return new Promise((resolve, reject) => {
      const reader = { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } };
      const timer = setTimeout(() => {
        const index = readers.indexOf(reader);
        if (index >= 0) readers.splice(index, 1);
        reject(new Error(`Test KDC timed out: ${diagnostics}`));
      }, 40000);
      readers.push(reader);
    });
  }
  let commands = Promise.resolve();
  function command(value) {
    const result = commands.then(async () => {
      if (failure) throw failure;
      process.stdin.write(`${value}\n`);
      return readLine();
    });
    commands = result.catch(() => {});
    return result;
  }
  async function close() {
    if (process.exitCode !== null || process.signalCode !== null) return closed;
    process.stdin.end('QUIT\n');
    let timeout;
    const outcome = await Promise.race([
      closed,
      new Promise(resolve => { timeout = setTimeout(() => resolve(null), 10000); }),
    ]);
    clearTimeout(timeout);
    if (!outcome) { process.kill(); return closed; }
    assert.equal(outcome.code, 0, `Test KDC failed on shutdown: ${diagnostics}`);
    return outcome;
  }
  try {
    assert.equal(await readLine(), 'READY', 'Independent KDC did not start');
    const keytab = (await fs.readFile(path.join(directory, 'casdog.localhost.keytab'))).toString('base64');
    return {
      realm, port, keytab, serviceName: 'HTTP/casdog.localhost',
      async issue(user = 'alice', mechanism = 'spnego') {
        assert.ok(['alice', 'bob', 'alice/admin'].includes(user));
        assert.ok(['spnego', 'spnego128', 'krb5', 'krb5128'].includes(mechanism));
        const result = await command(`TOKEN ${user} ${mechanism} casdog.localhost`);
        const match = /^TOKEN (\d+) ([A-Za-z0-9+/]+=*)$/.exec(result);
        assert.ok(match, `JDK failed to issue a service ticket: ${result}`);
        return { id: match[1], token: match[2] };
      },
      async verify(id, authenticateHeader) {
        const reply = authenticateHeader?.replace(/^Negotiate /, '');
        assert.match(String(id), /^\d+$/);
        assert.match(reply || '', /^[A-Za-z0-9+/]+=*$/);
        assert.equal(await command(`CHECK ${id} ${reply}`), 'VERIFIED', 'JDK rejected server mutual authentication');
      },
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}

module.exports = { startKerberos };
