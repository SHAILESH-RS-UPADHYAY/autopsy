import dns from 'node:dns';
import tls from 'node:tls';
import { BlockedError, isPublicAddress } from './fetch.ts';

export interface DnsRecords {
  a: string[];
  aaaa: string[];
  cname: string[];
  ns: string[];
  mx: string[];
  txt: string[];
  zone: string;
}

export interface TlsInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysLeft: number;
  san: string[];
  protocol: string;
  alpn: string;
  authorized: boolean;
  error: string;
}

const resolver = new dns.promises.Resolver({ timeout: 3000, tries: 2 });
// Loopback stubs (systemd-resolved, local DNS proxies) don't answer c-ares queries; public resolvers back them up.
resolver.setServers([...resolver.getServers().filter((s) => !/^(?:127\.|::1$|\[::1\])/.test(s)), '1.1.1.1', '8.8.8.8']);
const quiet = <T>(p: Promise<T>, fallback: T) => p.catch(() => fallback);

export async function probeDns(host: string): Promise<DnsRecords> {
  const [a, aaaa, cname, txtHost] = await Promise.all([
    quiet(resolver.resolve4(host), []),
    quiet(resolver.resolve6(host), []),
    quiet(resolver.resolveCname(host), []),
    quiet(resolver.resolveTxt(host), []),
  ]);
  // NS and MX live on the zone apex. Walk up until a label answers
  // (handles www.bbc.co.uk without a public-suffix list).
  let zone = host;
  let ns: string[] = [];
  const labels = host.split('.');
  for (let i = 0; i < labels.length - 1 && !ns.length; i++) {
    zone = labels.slice(i).join('.');
    ns = await quiet(resolver.resolveNs(zone), []);
  }
  const [mx, txtZone] = await Promise.all([
    quiet(resolver.resolveMx(zone), []),
    zone === host ? Promise.resolve([] as string[][]) : quiet(resolver.resolveTxt(zone), []),
  ]);
  return {
    a, aaaa, cname, ns: ns.map((n) => n.toLowerCase()),
    mx: mx.sort((x, y) => x.priority - y.priority).map((m) => m.exchange.toLowerCase()),
    txt: [...txtHost, ...txtZone].map((parts) => parts.join('')),
    zone,
  };
}

const name = (o: Record<string, string | string[]> | undefined) => {
  if (!o) return '';
  const pick = (k: string) => (Array.isArray(o[k]) ? (o[k] as string[])[0] : (o[k] as string)) || '';
  return [pick('O'), pick('CN')].filter(Boolean).join(' · ');
};

/** Reads the certificate. Connects only to an address that passed the public-address check. */
export function probeTls(host: string, address: string, timeoutMs = 5000): Promise<TlsInfo | null> {
  if (!isPublicAddress(address)) return Promise.reject(new BlockedError('TLS probe refused a private address.'));
  return new Promise((resolve) => {
    const socket = tls.connect({ host: address, port: 443, servername: host, ALPNProtocols: ['h2', 'http/1.1'], rejectUnauthorized: false, timeout: timeoutMs });
    const done = (v: TlsInfo | null) => {
      socket.destroy();
      resolve(v);
    };
    socket.once('secureConnect', () => {
      const c = socket.getPeerCertificate();
      if (!c || !c.valid_to) return done(null);
      done({
        subject: name(c.subject as never),
        issuer: name(c.issuer as never),
        validFrom: new Date(c.valid_from).toISOString(),
        validTo: new Date(c.valid_to).toISOString(),
        daysLeft: Math.floor((new Date(c.valid_to).getTime() - Date.now()) / 86_400_000),
        san: (c.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean).slice(0, 20),
        protocol: socket.getProtocol() || '',
        alpn: socket.alpnProtocol || '',
        authorized: socket.authorized,
        error: socket.authorizationError ? String(socket.authorizationError) : '',
      });
    });
    socket.once('timeout', () => done(null));
    socket.once('error', () => done(null));
  });
}
