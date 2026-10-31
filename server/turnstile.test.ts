import { test } from 'node:test';
import assert from 'node:assert/strict';
import { turnstileFromEnv, verify } from './turnstile.ts';

const t = turnstileFromEnv({ TURNSTILE_SITE_KEY: '0x4AAAAAAA', TURNSTILE_SECRET: 's3cret', TURNSTILE_HOSTNAMES: 'autopsy.example, www.autopsy.example' })!;
const answer = (body: unknown, status = 200) => (async () => new Response(JSON.stringify(body), { status })) as typeof fetch;
const ok = { success: true, action: 'examine', hostname: 'autopsy.example' };

test('turnstileFromEnv is off without both keys and loud when half configured', () => {
  assert.equal(turnstileFromEnv({}), null);
  assert.equal(turnstileFromEnv({ TURNSTILE_SITE_KEY: 'abc' }), null);
  assert.throws(() => turnstileFromEnv({ TURNSTILE_SITE_KEY: 'abc', TURNSTILE_SECRET: 's' }), /TURNSTILE_HOSTNAMES/);
  assert.throws(() => turnstileFromEnv({ TURNSTILE_SITE_KEY: '"><script>', TURNSTILE_SECRET: 's', TURNSTILE_HOSTNAMES: 'a' }), /site key/);
  assert.deepEqual([...t.hostnames], ['autopsy.example', 'www.autopsy.example']);
});

test('verify passes only a successful token for this action and an approved hostname', async () => {
  assert.equal(await verify(t, 'tok', '203.0.113.9', answer(ok)), true);
  assert.equal(await verify(t, 'tok', '203.0.113.9', answer({ ...ok, success: false })), false);
  assert.equal(await verify(t, 'tok', '203.0.113.9', answer({ ...ok, action: 'signup' })), false);
  assert.equal(await verify(t, 'tok', '203.0.113.9', answer({ success: true, hostname: 'autopsy.example' })), false);
  assert.equal(await verify(t, 'tok', '203.0.113.9', answer({ ...ok, hostname: 'localhost' })), false);
});

test('verify fails closed on missing tokens, siteverify errors and odd bodies', async () => {
  for (const token of [undefined, '', 42, 'x'.repeat(2049)]) assert.equal(await verify(t, token, '', answer(ok)), false);
  assert.equal(await verify(t, 'tok', '', answer(ok, 500)), false);
  assert.equal(await verify(t, 'tok', '', (async () => new Response('<html>')) as typeof fetch), false);
  assert.equal(await verify(t, 'tok', '', (async () => { throw new TypeError('network'); }) as typeof fetch), false);
});

test('verify sends the secret and token, and the client address only when it is an IP', async () => {
  const sent: URLSearchParams[] = [];
  const spy = (async (_url: string, init: RequestInit) => {
    sent.push(init.body as URLSearchParams);
    return new Response(JSON.stringify(ok));
  }) as typeof fetch;
  await verify(t, 'tok', '203.0.113.9', spy);
  await verify(t, 'tok', 'unknown', spy);
  assert.equal(sent[0].get('secret'), 's3cret');
  assert.equal(sent[0].get('response'), 'tok');
  assert.equal(sent[0].get('remoteip'), '203.0.113.9');
  assert.equal(sent[1].has('remoteip'), false);
});
