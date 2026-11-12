// Local LDAP wire fixture for the real ldap3 client used in browser E2E.
const net = require('node:net');
function tlv(tag, value) {
  value = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const size = value.length < 128 ? Buffer.from([value.length]) : Buffer.from([0x82, value.length >> 8, value.length & 255]);
  return Buffer.concat([Buffer.from([tag]), size, value]);
}
function header(bytes) {
  if (bytes.length < 2) return null;
  const count = bytes[1] & 128 ? bytes[1] & 127 : 0;
  if (count > 4) throw Error('Oversized LDAP fixture length');
  if (bytes.length < 2 + count) return null;
  const length = count ? bytes.readUIntBE(2, count) : bytes[1];
  if (length > 100000) throw Error('Oversized LDAP fixture packet');
  return { offset: 2 + count, length };
}
function item(bytes) {
  const part = header(bytes);
  if (!part || bytes.length < part.offset + part.length) throw Error('Incomplete LDAP fixture item');
  return { tag:bytes[0], value:bytes.subarray(part.offset,part.offset+part.length), rest:bytes.subarray(part.offset+part.length) };
}
async function startDirectory(username, adState) {
  const sockets = new Set();
  const metrics = { searches:0, userBinds:0, errors:0 };
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('close',()=>sockets.delete(socket));
    socket.on('error',()=>{});
    let pending = Buffer.alloc(0);
    const reply = (id, tag, value) => socket.write(tlv(0x30,Buffer.concat([tlv(2,id),tlv(tag,value)])));
    const result = code => Buffer.concat([tlv(0x0a,Buffer.from([code])),tlv(4,''),tlv(4,'')]);
    socket.on('data', bytes => {
      pending=Buffer.concat([pending,bytes]);
      try {
        for (;;) {
          const frame=header(pending);
          if (!frame || pending.length<frame.offset+frame.length) break;
          const body=pending.subarray(frame.offset,frame.offset+frame.length);
          pending=pending.subarray(frame.offset+frame.length);
          const id=item(body), operation=item(id.rest);
          if (operation.tag===0x60) {
            const version=item(operation.value), dn=item(version.rest), password=item(dn.rest);
            const directoryDn=`uid=${username()},dc=example,dc=test`;
            const service=dn.value.toString()==='cn=service,dc=example,dc=test' && password.value.toString()==='search-password';
            const user=dn.value.toString()===directoryDn && password.value.toString()==='DirectoryPassword42!';
            if (user) metrics.userBinds++;
            reply(id.value,0x61,result(service||user?0:49));
          } else if (operation.tag===0x63) {
            metrics.searches++;
            if(adState){
              const state=adState();
              const values={objectGUID:Buffer.from('33221100554477668899'+(state.guidTail||'aabbccddeeff'),'hex'),sAMAccountName:state.name,givenName:'Browser',sn:'Directory',displayName:'AD browser user',userPrincipalName:`${state.name}@example.test`,userAccountControl:state.disabled?'514':'512',title:'Directory engineer',department:'Browser department'};
              const attributes=Object.entries(values).map(([name,value])=>tlv(0x30,Buffer.concat([tlv(4,name),tlv(0x31,tlv(4,value))])));
              reply(id.value,0x64,Buffer.concat([tlv(4,state.dn),tlv(0x30,Buffer.concat(attributes))]));
            } else if (operation.value.includes(Buffer.from(username()))) {
              const attr=tlv(0x30,Buffer.concat([tlv(4,'uid'),tlv(0x31,tlv(4,username()))]));
              reply(id.value,0x64,Buffer.concat([tlv(4,`uid=${username()},dc=example,dc=test`),tlv(0x30,attr)]));
            }
            reply(id.value,0x65,result(0));
          } else if (operation.tag===0x42) socket.end();
          else throw Error('Unexpected LDAP fixture operation');
        }
      } catch { metrics.errors++;socket.destroy(); }
    });
  });
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
  return {
    url:`ldap://127.0.0.1:${server.address().port}`, metrics,
    close:async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));},
  };
}
module.exports = { startDirectory };
