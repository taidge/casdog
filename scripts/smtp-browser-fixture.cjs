const net = require('node:net');
const crypto = require('node:crypto');
async function startSmtpRelay() {
  const username = 'browser-smtp-user', password = crypto.randomBytes(24).toString('hex');
  const messages = [], authentications = [], sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    socket.write('220 browser.test ESMTP\r\n');
    let pending = '', data = false, message = [], login = 0, loginName = '';
    const authenticate = (name, secret) => {
      const accepted = name === username && secret === password;
      authentications.push({ username: name, accepted }); socket.write(accepted ? '235 2.7.0 authenticated\r\n' : '535 5.7.8 denied\r\n');
    };
    socket.on('data', bytes => {
      pending += bytes.toString();
      while (pending.includes('\r\n')) {
        const index = pending.indexOf('\r\n'), line = pending.slice(0, index); pending = pending.slice(index + 2);
        if (data) { if (line === '.') { messages.push(message.join('\r\n')); message = []; data = false; socket.write('250 2.0.0 queued\r\n'); } else message.push(line.startsWith('..') ? line.slice(1) : line); continue; }
        if (login === 1) { loginName = Buffer.from(line, 'base64').toString(); login = 2; socket.write('334 UGFzc3dvcmQ6\r\n'); continue; }
        if (login === 2) { authenticate(loginName, Buffer.from(line, 'base64').toString()); login = 0; continue; }
        if (/^(EHLO|HELO) /i.test(line)) socket.write('250-browser.test\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1048576\r\n');
        else if (/^AUTH PLAIN /i.test(line)) { const parts = Buffer.from(line.slice(11), 'base64').toString().split('\0'); authenticate(parts.at(-2), parts.at(-1)); }
        else if (/^AUTH LOGIN$/i.test(line)) { login = 1; socket.write('334 VXNlcm5hbWU6\r\n'); }
        else if (/^(MAIL FROM:|RCPT TO:|RSET|NOOP)/i.test(line)) socket.write('250 2.1.0 ok\r\n');
        else if (/^DATA$/i.test(line)) { data = true; socket.write('354 End with dot\r\n'); }
        else if (/^QUIT$/i.test(line)) { socket.end('221 2.0.0 bye\r\n'); }
        else socket.write('502 5.5.1 unsupported\r\n');
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { host: '127.0.0.1', port: server.address().port, username, password, messages, authentications,
    close: async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); } };
}
module.exports = { startSmtpRelay };
