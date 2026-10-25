import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import type { AddressInfo } from 'node:net';
import { BlockedError, FetchError, checkUrl, isPublicAddress, safeFetch } from './fetch.ts';

test('isPublicAddress rejects every private, reserved and mapped range', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.5', '::1', '::', 'fc00::1', 'fd12::1', 'fe80::1', '::ffff:127.0.0.1',
    '::ffff:10.0.0.1', '64:ff9b::a00:1', '64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '2002:7f00:1::', 'not-an-ip']) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
  for (const ip of ['8.8.8.8', '64:ff9b::808:808', '64:ff9b::40ef:6d81', '1.1.1.1', '76.76.21.21', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(isPublicAddress(ip), true, ip);
  }
});

test('checkUrl refuses odd schemes, credentials and ports', () => {
  assert.throws(() => checkUrl('file:///etc/passwd'), BlockedError);
  assert.throws(() => checkUrl('gopher://x'), BlockedError);
  assert.throws(() => checkUrl('https://user:pw@example.com'), BlockedError);
  assert.throws(() => checkUrl('http://example.com:6379/'), /Port 6379/);
  assert.throws(() => checkUrl('nope'), BlockedError);
  assert.equal(checkUrl('https://example.com:8443/x').port, '8443');
});

let server: http.Server;
let port = 0;
before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/gzip') {
      res.writeHead(200, { 'content-encoding': 'gzip', 'content-type': 'text/html' });
      return res.end(zlib.gzipSync('<html>squeezed</html>'));
    }
    if (req.url === '/big') return res.end('x'.repeat(50_000));
    if (req.url === '/bomb') {
      res.writeHead(200, { 'content-encoding': 'gzip' });
      return res.end(zlib.gzipSync(Buffer.alloc(5_000_000)));
    }
    if (req.url === '/hop') return res.writeHead(302, { location: '/gzip' }).end();
    if (req.url === '/loop') return res.writeHead(302, { location: '/loop' }).end();
    if (req.url === '/to-loopback-v6') return res.writeHead(302, { location: `http://[::1]:${port}/gzip` }).end();
    if (req.url === '/to-metadata') return res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' }).end();
    if (req.url === '/cookies') return res.writeHead(200, { 'set-cookie': ['a=1; Secure', 'b=2'] }).end('ok');
    res.end('hello');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as AddressInfo).port;
});
after(() => server.close());

// The local test server lives on 127.0.0.1, so tests explicitly allow that one address and any port.
const local = { isAllowed: (ip: string) => ip === '127.0.0.1', ports: null, maxBytes: 10_000, timeoutMs: 3000 };

test('loopback is refused by default, both by IP literal and by hostname', async () => {
  await assert.rejects(safeFetch(`http://127.0.0.1:${port}/`, { ports: null, maxBytes: 1000, timeoutMs: 2000 }), BlockedError);
  await assert.rejects(safeFetch(`http://localhost:${port}/`, { ports: null, maxBytes: 1000, timeoutMs: 2000 }), BlockedError);
});

test('a public-looking name that resolves to a private address is refused (DNS rebinding)', async () => {
  const lookup = ((_h: string, _o: unknown, cb: (e: null, a: { address: string; family: number }[]) => void) =>
    cb(null, [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.7', family: 4 }])) as never;
  await assert.rejects(safeFetch('http://innocent.example/', { maxBytes: 1000, timeoutMs: 2000, lookup }), /private or reserved/);
});

test('redirects are followed, and every hop is re-checked', async () => {
  const ok = await safeFetch(`http://127.0.0.1:${port}/hop`, local);
  assert.equal(ok.body, '<html>squeezed</html>');
  assert.deepEqual(ok.redirects.map((r) => r.status), [302]);
  await assert.rejects(safeFetch(`http://127.0.0.1:${port}/to-loopback-v6`, local), BlockedError);
  await assert.rejects(safeFetch(`http://127.0.0.1:${port}/to-metadata`, local), BlockedError);
  await assert.rejects(safeFetch(`http://127.0.0.1:${port}/loop`, local), FetchError);
});

test('bodies are capped after decompression; cookies are kept raw', async () => {
  const big = await safeFetch(`http://127.0.0.1:${port}/big`, local);
  assert.equal(big.truncated, true);
  assert.equal(big.body.length, 10_000);
  const bomb = await safeFetch(`http://127.0.0.1:${port}/bomb`, local);
  assert.equal(bomb.truncated, true);
  assert.equal(bomb.bytes, 10_000);
  const c = await safeFetch(`http://127.0.0.1:${port}/cookies`, local);
  assert.deepEqual(c.setCookies, ['a=1; Secure', 'b=2']);
});
