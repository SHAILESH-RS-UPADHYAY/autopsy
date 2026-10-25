import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { BlockedError, FetchError } from './fetch.ts';
import { examine, normalizeInput, type CaseFile } from './examine.ts';

const PORT = Number(process.env.PORT || 3000);
const PUBLIC = join(import.meta.dirname, '..', 'public');
const BRAND = join(import.meta.dirname, '..', 'brand');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json', '.ico': 'image/x-icon',
};

// Autopsy grades other sites' headers, so it sends a full set itself.
const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};

// ponytail: in-memory bucket and cache, per process. Move both to Redis if this runs on more than one instance.
const buckets = new Map<string, { tokens: number; at: number }>();
function allow(ip: string): boolean {
  const now = Date.now();
  const b = buckets.get(ip) ?? { tokens: 6, at: now };
  b.tokens = Math.min(6, b.tokens + (now - b.at) / 10_000);
  b.at = now;
  buckets.set(ip, b);
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}

const cache = new Map<string, { at: number; report: CaseFile }>();
const CACHE_MS = 10 * 60 * 1000;

function clientIp(req: http.IncomingMessage) {
  const fwd = TRUST_PROXY ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() : '';
  return fwd || req.socket.remoteAddress || 'unknown';
}

function failure(err: unknown): { kind: string; message: string } {
  if (err instanceof BlockedError) return { kind: 'refused', message: err.message };
  if (err instanceof FetchError) return { kind: 'unreachable', message: err.message };
  if ((err as Error)?.name === 'AbortError') return { kind: 'cancelled', message: 'Examination cancelled.' };
  console.error(err);
  return { kind: 'internal', message: 'The examination failed unexpectedly.' };
}

async function handleExamine(req: http.IncomingMessage, res: http.ServerResponse, target: string) {
  res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no' });
  const send = (event: string, data: unknown) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

  let key: string;
  try {
    key = normalizeInput(target).toLowerCase();
  } catch (err) {
    send('failure', failure(err));
    return res.end();
  }
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) {
    for (const s of hit.report.stages) send('stage', s);
    send('report', { ...hit.report, cached: true });
    return res.end();
  }
  if (!allow(clientIp(req))) {
    send('failure', { kind: 'rate-limited', message: 'Too many examinations from this address. Wait a minute and try again.' });
    return res.end();
  }

  const abort = new AbortController();
  res.on('close', () => abort.abort());
  const deadline = setTimeout(() => abort.abort(), 25_000);
  try {
    const report = await examine(target, (e) => send('stage', e), { signal: abort.signal });
    cache.set(key, { at: Date.now(), report });
    send('report', report);
  } catch (err) {
    send('failure', failure(err));
  } finally {
    clearTimeout(deadline);
    res.end();
  }
}

async function serveStatic(pathname: string, res: http.ServerResponse) {
  // The brand kit lives beside public/ so there is one copy of each logo.
  const brand = pathname.startsWith('/brand/');
  const root = brand ? BRAND : PUBLIC;
  const rel = normalize(decodeURIComponent(pathname === '/' ? '/index.html' : brand ? pathname.slice(6) : pathname)).replace(/^[/\\]+/, '');
  const file = join(root, rel);
  if (!file.startsWith(root + sep)) {
    res.writeHead(403, SECURITY_HEADERS).end();
    return;
  }
  try {
    const body = await readFile(file);
    const long = /\/fonts\//.test(pathname);
    res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': TYPES[extname(file)] ?? 'application/octet-stream', 'cache-control': long ? 'public, max-age=31536000, immutable' : 'no-cache' });
    res.end(body);
  } catch {
    res.writeHead(404, { ...SECURITY_HEADERS, 'content-type': 'text/plain' }).end('Not found');
  }
}

export const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  if (req.method !== 'GET' && req.method !== 'HEAD') return res.writeHead(405, SECURITY_HEADERS).end();
  if (url.pathname === '/api/examine') return void handleExamine(req, res, url.searchParams.get('url') ?? '');
  if (url.pathname === '/api/health') return res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'application/json' }).end('{"ok":true}');
  return void serveStatic(url.pathname, res);
});

if (process.argv[1] && import.meta.filename === normalize(process.argv[1])) {
  server.listen(PORT, () => console.log(`Autopsy on http://localhost:${PORT}`));
}
