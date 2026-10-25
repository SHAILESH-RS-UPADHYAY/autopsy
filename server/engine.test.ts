import { test } from 'node:test';
import assert from 'node:assert/strict';
import { match, type Evidence } from './engine.ts';
import { renderingVerdict, securityReport } from './verdict.ts';
import { protocol } from './protocol.ts';
import { scanHtml } from './html.ts';
import { caseNumber, normalizeInput } from './examine.ts';
import { RULES } from './signatures.ts';

const evidence = (over: Partial<Evidence>): Evidence => ({
  finalUrl: 'https://shop.example.com/', host: 'shop.example.com', headers: {}, setCookies: [], html: '', meta: {},
  scripts: [], stylesheets: [], bundles: [], styles: [], dns: null, tls: null, ...over,
});

const NEXT_HTML = `<!doctype html><html lang="en"><head><title>Acme</title>
<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123" async></script>
<link rel="stylesheet" href="/_next/static/css/app.css"></head><body><div id="__next"><main><h1>Acme ships faster</h1>
<p>${'Real words about the product that a crawler can read. '.repeat(20)}</p></main></div>
<script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/","gsp":true}</script>
<script src="/_next/static/chunks/main-abc.js"></script></body></html>`;

const nextOnVercel = () => evidence({
  headers: { server: 'Vercel', 'x-vercel-id': 'bom1::abcd', 'x-vercel-cache': 'HIT', 'strict-transport-security': 'max-age=63072000' },
  setCookies: ['_ga=GA1.1.secretvalue; Path=/'],
  html: NEXT_HTML,
  scripts: scanHtml(NEXT_HTML, 'https://shop.example.com/').scripts,
  styles: [{ url: 'https://shop.example.com/_next/static/css/app.css', body: '/*! tailwindcss v3.4.1 | MIT License */ .a{--tw-ring-offset:0}' }],
  dns: { a: ['76.76.21.21'], aaaa: [], cname: ['cname.vercel-dns.com'], ns: ['ns1.vercel-dns.com'], mx: ['aspmx.l.google.com'], txt: ['v=spf1 include:_spf.google.com ~all'], zone: 'example.com' },
  tls: { subject: 'shop.example.com', issuer: "Let's Encrypt · R11", validFrom: '', validTo: '', daysLeft: 70, san: [], protocol: 'TLSv1.3', alpn: 'h2', authorized: true, error: '' },
});

test('Next.js on Vercel: confirmed findings, versions, implied parent, shared exhibits, redacted cookies', () => {
  const { findings, exhibits } = match(nextOnVercel());
  const f = Object.fromEntries(findings.map((x) => [x.id, x]));
  for (const id of ['nextjs', 'vercel', 'tailwind', 'ga4', 'google-workspace', 'letsencrypt', 'http2']) assert.equal(f[id]?.confidence, 'confirmed', id);
  assert.equal(f.tailwind.version, '3.4.1');
  assert.equal(f.react.confidence, 'implied');
  assert.deepEqual(f.react.impliedBy, ['Next.js']);
  assert.ok(!f.wordpress && !f.netlify, 'no false positives');
  const cookieEx = exhibits.find((e) => e.source === 'cookie');
  assert.equal(cookieEx?.excerpt, 'Set-Cookie: _ga=[redacted]');
  assert.ok(!JSON.stringify(exhibits).includes('secretvalue'));
  assert.equal(new Set(exhibits.map((e) => e.n)).size, exhibits.length);
  assert.ok(f.vercel.exhibits.length >= 3);
});

test('verdict reads __NEXT_DATA__ and the protocol cites the evidence', () => {
  const ev = nextOnVercel();
  const { findings } = match(ev);
  const v = renderingVerdict(ev, findings);
  assert.equal(v.mode, 'SSG');
  assert.match(v.reasons.join(' '), /"gsp": true/);
  const steps = protocol(findings, v, securityReport(ev, false));
  assert.match(steps[0].command, /create-next-app/);
  assert.match(steps[0].why, /Next\.js, exhibits? \d/);
  assert.ok(steps.some((s) => s.phase === 'Styling' && /tailwindcss/.test(s.command)));
  assert.ok(steps.some((s) => s.phase === 'Hosting' && s.command === 'npx vercel'));
  assert.ok(steps.some((s) => s.phase === 'Harden' && /Content-Security-Policy/.test(s.command)));
});

test('WordPress behind Cloudflare: generator version, PHP implied via rule and header', () => {
  const html = '<html><head><meta name="generator" content="WordPress 6.4.2"><link rel="stylesheet" href="/wp-content/themes/x/style.css"></head><body><p>Hi</p></body></html>';
  const ev = evidence({
    headers: { server: 'cloudflare', 'cf-ray': '8a1b-BOM', 'x-powered-by': 'PHP/8.2.12', link: '<https://x.com/wp-json/>; rel="https://api.w.org/"' },
    html, meta: scanHtml(html, 'https://x.com').meta,
  });
  const { findings } = match(ev);
  const f = Object.fromEntries(findings.map((x) => [x.id, x]));
  assert.equal(f.wordpress.version, '6.4.2');
  assert.equal(f.cloudflare.confidence, 'confirmed');
  assert.equal(f.php.version, '8.2.12');
  assert.deepEqual(f.php.impliedBy, ['WordPress']);
  assert.equal(renderingVerdict(ev, findings).mode, 'Server-rendered');
});

test('Vite + React SPA: empty mount node means client-side rendering', () => {
  const html = '<!doctype html><html><head><script type="module" crossorigin src="/assets/index-DkF3a9Qx.js"></script></head><body><div id="root"></div></body></html>';
  const ev = evidence({ html, bundles: [{ url: 'https://app.example.com/assets/index-DkF3a9Qx.js', body: 'var e=Symbol.for("react.transitional.element");relList.supports("modulepreload")' }] });
  const { findings } = match(ev);
  const ids = findings.filter((x) => x.confidence !== 'trace').map((x) => x.id);
  assert.ok(ids.includes('vite') && ids.includes('react'), ids.join());
  const v = renderingVerdict(ev, findings);
  assert.equal(v.mode, 'CSR');
  assert.match(protocol(findings, v, securityReport(ev, false))[0].command, /template react-ts/);
});

test('security grade: a hardened site gets A, a bare one F', () => {
  const strong = evidence({
    headers: {
      'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()',
    },
    setCookies: ['s=1; Secure; HttpOnly; SameSite=Lax'],
    tls: { subject: '', issuer: 'X', validFrom: '', validTo: '', daysLeft: 80, san: [], protocol: 'TLSv1.3', alpn: 'h2', authorized: true, error: '' },
  });
  assert.equal(securityReport(strong, true).grade, 'A');
  const weak = evidence({ finalUrl: 'http://old.example.com/', headers: { 'content-security-policy': "script-src 'self' 'unsafe-inline'" }, setCookies: ['sid=1'] });
  const r = securityReport(weak, true);
  assert.equal(r.grade, 'F');
  assert.equal(r.rows.find((x) => x.id === 'csp')!.pass, false);
});

test('scanHtml resolves URLs, reads meta, counts only visible words', () => {
  const s = scanHtml(`<html lang="fr"><head><title> Bonjour \n monde </title><meta property="og:title" content="X">
    <script src="//cdn.example.com/a.js"></script><script>var hidden = "words words words";</script>
    <link rel="preload stylesheet" href="b.css"></head><body><p>un deux trois</p><style>.x{}</style></body></html>`, 'https://site.fr/dir/');
  assert.equal(s.title, 'Bonjour monde');
  assert.equal(s.lang, 'fr');
  assert.equal(s.meta['og:title'], 'X');
  assert.deepEqual(s.scripts, ['https://cdn.example.com/a.js']);
  assert.deepEqual(s.stylesheets, ['https://site.fr/dir/b.css']);
  assert.equal(s.words, 5);
});

test('titles decode HTML entities', () => {
  assert.equal(scanHtml('<title>Blog &#8211; Tom &amp; Co &#x2014; ok</title>', 'https://x.io').title, 'Blog – Tom & Co — ok');
});

test('inputs normalise and case numbers are stable per host and day', () => {
  assert.equal(normalizeInput('  example.com/path '), 'https://example.com/path');
  assert.equal(normalizeInput('http://x.io'), 'http://x.io');
  const d = new Date('2026-10-25T10:00:00Z');
  assert.equal(caseNumber('example.com', d), caseNumber('example.com', d));
  assert.match(caseNumber('example.com', d), /^AX-20261025-[0-9A-Z]{4}$/);
  assert.notEqual(caseNumber('example.com', d), caseNumber('example.org', d));
});

test('rule table is well-formed', () => {
  const ids = new Set<string>();
  for (const r of RULES) {
    assert.ok(!ids.has(r.id), `duplicate ${r.id}`);
    ids.add(r.id);
    assert.ok(r.checks.length > 0, r.id);
  }
  for (const r of RULES) for (const p of r.implies ?? []) assert.ok(ids.has(p), `${r.id} implies unknown ${p}`);
  assert.ok(RULES.length >= 150, `${RULES.length} rules`);
});
