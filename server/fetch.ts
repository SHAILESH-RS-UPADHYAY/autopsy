// The only way Autopsy touches the network. Strangers choose the URL, so every
// connection is pinned to an address that was checked first (no DNS rebinding),
// every redirect hop is re-checked, and every byte is counted.
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import zlib from 'node:zlib';
import type { Readable } from 'node:stream';

export class BlockedError extends Error {}
export class FetchError extends Error {}

const blocked = new net.BlockList();
for (const [range, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) blocked.addSubnet(range, bits, 'ipv4');
for (const [range, bits] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2001:db8::', 32],
  ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
] as const) blocked.addSubnet(range, bits, 'ipv6');

const nat64 = new net.BlockList();
nat64.addSubnet('64:ff9b::', 96, 'ipv6');

// DNS64 networks answer 64:ff9b::a.b.c.d for IPv4-only hosts; the last 32 bits are the real target.
function embeddedIpv4(ip: string): string {
  const [head, tail = ''] = ip.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const words = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right].map((w) => parseInt(w || '0', 16));
  return [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join('.');
}

/** True for addresses on the public internet. IPv4-mapped and NAT64 IPv6 are judged by their IPv4. */
export function isPublicAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (!family) return false;
  if (family === 6 && !ip.includes('.') && nat64.check(ip, 'ipv6')) return isPublicAddress(embeddedIpv4(ip));
  return !blocked.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

export interface FetchOptions {
  maxBytes: number;
  timeoutMs: number;
  accept?: string;
  signal?: AbortSignal;
  maxRedirects?: number;
  /** Test seams. Production uses the defaults. */
  isAllowed?: (ip: string) => boolean;
  ports?: number[] | null;
  lookup?: typeof dns.lookup;
}

export interface FetchResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  bytes: number;
  truncated: boolean;
  redirects: { url: string; status: number }[];
  address: string;
  ms: number;
}

export const USER_AGENT = 'AutopsyBot/1.0 (tech-stack examination; one visit per request)';
const DEFAULT_PORTS = [80, 443, 8080, 8443];

export function checkUrl(raw: string, ports: number[] | null = DEFAULT_PORTS): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new BlockedError('That is not a valid web address.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new BlockedError('Only http and https addresses can be examined.');
  if (url.username || url.password) throw new BlockedError('Addresses with embedded credentials are refused.');
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
  if (ports && !ports.includes(port)) throw new BlockedError(`Port ${port} is not examined. Allowed: ${ports.join(', ')}.`);
  return url;
}

// Resolve, refuse if *any* answer is private, then hand net.connect the checked address.
function guardedLookup(isAllowed: (ip: string) => boolean, lookup: typeof dns.lookup) {
  return (hostname: string, options: dns.LookupOptions, callback: (...args: unknown[]) => void) => {
    lookup(hostname, { all: true, family: options.family ?? 0 }, (err, addresses) => {
      if (err) return callback(err);
      const list = addresses as dns.LookupAddress[];
      const bad = list.find((a) => !isAllowed(a.address));
      if (!list.length || bad) return callback(new BlockedError(`${hostname} resolves to a private or reserved address (${bad?.address ?? 'none'}).`));
      if (options.all) callback(null, list);
      else callback(null, list[0].address, list[0].family);
    });
  };
}

function decoder(encoding: string | undefined): NodeJS.ReadWriteStream | null {
  switch ((encoding || '').trim().toLowerCase()) {
    case 'gzip': case 'x-gzip': return zlib.createGunzip();
    case 'deflate': return zlib.createInflate();
    case 'br': return zlib.createBrotliDecompress();
    case 'zstd': return 'createZstdDecompress' in zlib ? (zlib as unknown as { createZstdDecompress(): NodeJS.ReadWriteStream }).createZstdDecompress() : null;
    default: return null;
  }
}

function once(url: URL, opts: Required<Pick<FetchOptions, 'maxBytes' | 'timeoutMs'>> & FetchOptions, isAllowed: (ip: string) => boolean) {
  return new Promise<Omit<FetchResult, 'redirects' | 'url' | 'ms'> & { location?: string }>((resolve, reject) => {
    if (net.isIP(url.hostname.replace(/^\[|\]$/g, '')) && !isAllowed(url.hostname.replace(/^\[|\]$/g, ''))) {
      return reject(new BlockedError(`${url.hostname} is a private or reserved address.`));
    }
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, {
      method: 'GET',
      headers: {
        'user-agent': USER_AGENT,
        accept: opts.accept ?? 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en',
      },
      lookup: guardedLookup(isAllowed, opts.lookup ?? dns.lookup) as never,
      timeout: opts.timeoutMs,
      signal: opts.signal,
      // Certificates are evidence, not a gate: an expired cert is a finding.
      rejectUnauthorized: false,
    });
    req.on('timeout', () => req.destroy(new FetchError(`No answer within ${Math.round(opts.timeoutMs / 1000)} s.`)));
    req.on('error', (err) => reject(err instanceof BlockedError || err instanceof FetchError ? err : new FetchError(friendly(err))));
    req.on('response', (res) => {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) if (k !== 'set-cookie' && v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : v;
      const setCookies = res.headers['set-cookie'] ?? [];
      const address = res.socket?.remoteAddress ?? '';
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        return resolve({ status, headers, setCookies, body: '', bytes: 0, truncated: false, address, location: res.headers.location });
      }
      const unzip = decoder(res.headers['content-encoding']);
      const stream: Readable = unzip ? (res.pipe(unzip) as unknown as Readable) : res;
      const chunks: Buffer[] = [];
      let bytes = 0;
      let truncated = false;
      const finish = () => resolve({ status, headers, setCookies, body: Buffer.concat(chunks).toString('utf8'), bytes, truncated, address });
      stream.on('data', (chunk: Buffer) => {
        // Counted after decompression, so a zip bomb stops at the cap too.
        if (bytes + chunk.length > opts.maxBytes) {
          chunks.push(chunk.subarray(0, opts.maxBytes - bytes));
          bytes = opts.maxBytes;
          truncated = true;
          res.destroy();
          stream.removeAllListeners('data');
          finish();
          return;
        }
        chunks.push(chunk);
        bytes += chunk.length;
      });
      stream.on('end', () => !truncated && finish());
      stream.on('error', (err) => !truncated && reject(new FetchError(`The response could not be decoded (${err.message}).`)));
    });
    req.end();
  });
}

function friendly(err: Error & { code?: string }): string {
  switch (err.code) {
    case 'ENOTFOUND': return 'That domain does not exist (no DNS answer).';
    case 'ECONNREFUSED': return 'The server refused the connection.';
    case 'ECONNRESET': return 'The server dropped the connection.';
    case 'ETIMEDOUT': return 'The connection timed out.';
    case 'EAI_AGAIN': return 'DNS lookup failed. Try again.';
    case 'CERT_HAS_EXPIRED': return 'The certificate has expired.';
    default: return err.message || 'The request failed.';
  }
}

export async function safeFetch(raw: string, options: FetchOptions): Promise<FetchResult> {
  const started = Date.now();
  const isAllowed = options.isAllowed ?? isPublicAddress;
  const maxRedirects = options.maxRedirects ?? 5;
  const redirects: FetchResult['redirects'] = [];
  let url = checkUrl(raw, options.ports === undefined ? DEFAULT_PORTS : options.ports);
  for (;;) {
    const res = await once(url, options, isAllowed);
    if (res.location === undefined) {
      const { location: _, ...rest } = res;
      return { ...rest, url: url.href, redirects, ms: Date.now() - started };
    }
    redirects.push({ url: url.href, status: res.status });
    if (redirects.length > maxRedirects) throw new FetchError(`More than ${maxRedirects} redirects.`);
    url = checkUrl(new URL(res.location, url).href, options.ports === undefined ? DEFAULT_PORTS : options.ports);
  }
}
