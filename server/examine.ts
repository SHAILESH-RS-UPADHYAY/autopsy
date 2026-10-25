import dns from 'node:dns';
import { BlockedError, checkUrl, isPublicAddress, safeFetch, type FetchOptions } from './fetch.ts';
import { probeDns, probeTls, type DnsRecords, type TlsInfo } from './probes.ts';
import { scanHtml } from './html.ts';
import { match, type Evidence, type Exhibit, type Finding } from './engine.ts';
import { renderingVerdict, securityReport, type Security, type Verdict } from './verdict.ts';
import { protocol, type Step } from './protocol.ts';
import { CATEGORIES } from './signatures.ts';

export type StageId = 'intake' | 'dns' | 'tls' | 'document' | 'scripts' | 'signatures' | 'verdict';
export interface StageEvent { stage: StageId; status: 'start' | 'done' | 'skipped'; detail: string; ms: number }

export interface CaseFile {
  caseNo: string;
  examinedAt: string;
  durationMs: number;
  subject: { input: string; finalUrl: string; host: string; address: string; status: number; title: string; lang: string; bytes: number; redirects: { url: string; status: number }[] };
  stages: StageEvent[];
  exhibits: Exhibit[];
  findings: Finding[];
  categories: Record<string, string>;
  verdict: Verdict;
  security: Security;
  protocol: Step[];
  dns: DnsRecords | null;
  tls: TlsInfo | null;
  notes: string[];
}

export function normalizeInput(raw: string): string {
  const s = raw.trim();
  if (!s || s.length > 2048) throw new BlockedError('Enter a web address up to 2,048 characters.');
  return /^[a-z][\w+.-]*:\/\//i.test(s) ? s : `https://${s}`;
}

// Short, stable docket number: same host on the same day, same case.
export function caseNumber(host: string, date: Date) {
  let h = 0x811c9dc5;
  for (const ch of host) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return `AX-${date.toISOString().slice(0, 10).replace(/-/g, '')}-${h.toString(36).toUpperCase().padStart(7, '0').slice(-4)}`;
}

const sameSite = (a: string, b: string) => {
  const tail = (h: string) => h.split('.').slice(-2).join('.');
  return tail(a) === tail(b);
};

// App bundles first: they carry the framework fingerprints.
const bundleRank = (u: string) => (/(?:main|app|index|framework|vendor|bundle|runtime|entry|_app|chunk)/i.test(u) ? 0 : 1);

export interface ExamineOptions { signal?: AbortSignal; net?: Pick<FetchOptions, 'isAllowed' | 'ports' | 'lookup'> }

export async function examine(raw: string, emit: (e: StageEvent) => void, opts: ExamineOptions = {}): Promise<CaseFile> {
  const started = Date.now();
  const stages: StageEvent[] = [];
  const notes: string[] = [];
  const log = (stage: StageId, status: StageEvent['status'], detail: string, t0: number) => {
    const e = { stage, status, detail, ms: Date.now() - t0 };
    if (status !== 'start') stages.push(e);
    emit(e);
  };
  const base: Omit<FetchOptions, 'maxBytes' | 'timeoutMs'> = { signal: opts.signal, ...opts.net };
  const isAllowed = opts.net?.isAllowed ?? isPublicAddress;

  let t = Date.now();
  log('intake', 'start', 'Reading the address', t);
  const input = normalizeInput(raw);
  const url = checkUrl(input, opts.net?.ports === undefined ? undefined : opts.net.ports);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  log('intake', 'done', `Subject: ${host}`, t);

  t = Date.now();
  log('dns', 'start', 'Resolving DNS records', t);
  const records = await probeDns(host).catch(() => null);
  const ips = [...(records?.a ?? []), ...(records?.aaaa ?? [])];
  log('dns', 'done', records ? `${ips.length} address(es), ${records.ns.length} nameserver(s), ${records.mx.length} mail exchanger(s)` : 'No DNS answer', t);

  t = Date.now();
  log('document', 'start', `Fetching ${url.href}`, t);
  const doc = await safeFetch(url.href, { ...base, maxBytes: 3_000_000, timeoutMs: 9000 });
  if (doc.truncated) notes.push('The document was larger than 3 MB; only the first 3 MB was examined.');
  log('document', 'done', `HTTP ${doc.status} · ${(doc.bytes / 1024).toFixed(0)} KB · ${doc.redirects.length} redirect(s) · ${doc.ms} ms`, t);

  const finalUrl = new URL(doc.url);
  t = Date.now();
  let tlsInfo: TlsInfo | null = null;
  if (finalUrl.protocol === 'https:') {
    log('tls', 'start', 'Reading the TLS certificate', t);
    const address = doc.address || (await dns.promises.lookup(finalUrl.hostname).then((r) => r.address).catch(() => ''));
    tlsInfo = address && isAllowed(address) ? await probeTls(finalUrl.hostname, address).catch(() => null) : null;
    log('tls', 'done', tlsInfo ? `${tlsInfo.protocol} · ${tlsInfo.issuer} · ${tlsInfo.daysLeft} days left · ALPN ${tlsInfo.alpn || 'none'}` : 'No certificate read', t);
  } else {
    log('tls', 'skipped', 'Plain http: no certificate', t);
  }

  const contentType = doc.headers['content-type'] ?? '';
  const isHtml = /html|xml/.test(contentType) || /<html|<!doctype html/i.test(doc.body.slice(0, 2000));
  if (!isHtml) notes.push(`The address returned ${contentType || 'an unknown type'}, not HTML; only headers and DNS were examined.`);
  const scan = scanHtml(isHtml ? doc.body : '', doc.url);

  t = Date.now();
  const firstParty = (u: string) => {
    try {
      return sameSite(new URL(u).hostname, finalUrl.hostname);
    } catch {
      return false;
    }
  };
  const pick = (list: string[], n: number) => list.filter(firstParty).sort((a, b) => bundleRank(a) - bundleRank(b)).slice(0, n);
  const jsTargets = pick(scan.scripts, 6);
  const cssTargets = pick(scan.stylesheets, 3);
  log('scripts', 'start', `Sampling ${jsTargets.length} script(s) and ${cssTargets.length} stylesheet(s)`, t);
  const grab = async (u: string, maxBytes: number) => {
    try {
      const r = await safeFetch(u, { ...base, maxBytes, timeoutMs: 6000, accept: '*/*' });
      return r.status < 400 ? { url: r.url, body: r.body } : null;
    } catch {
      return null;
    }
  };
  const [bundles, styles] = await Promise.all([
    Promise.all(jsTargets.map((u) => grab(u, 1_500_000))),
    Promise.all(cssTargets.map((u) => grab(u, 800_000))),
  ]);
  const okBundles = bundles.filter((b): b is NonNullable<typeof b> => !!b);
  const okStyles = styles.filter((b): b is NonNullable<typeof b> => !!b);
  const kb = Math.round([...okBundles, ...okStyles].reduce((n, f) => n + f.body.length, 0) / 1024);
  log('scripts', 'done', `${okBundles.length} script(s), ${okStyles.length} stylesheet(s), ${kb.toLocaleString('en-US')} KB read`, t);

  t = Date.now();
  log('signatures', 'start', 'Matching signatures', t);
  const evidence: Evidence = {
    finalUrl: doc.url, host: finalUrl.hostname, headers: doc.headers, setCookies: doc.setCookies,
    html: isHtml ? doc.body : '', meta: scan.meta, scripts: scan.scripts, stylesheets: scan.stylesheets,
    bundles: [...okBundles, ...scan.inline.map((body, i) => ({ url: `${doc.url}#inline-${i + 1}`, body }))],
    styles: okStyles, dns: records, tls: tlsInfo,
  };
  const { findings, exhibits } = match(evidence);
  log('signatures', 'done', `${findings.length} technologies, ${exhibits.length} exhibits`, t);

  t = Date.now();
  log('verdict', 'start', 'Writing the verdict', t);
  const verdict = renderingVerdict(evidence, findings);
  const security = securityReport(evidence, url.protocol === 'http:');
  const steps = protocol(findings, verdict, security);
  log('verdict', 'done', `${verdict.mode} · security grade ${security.grade}`, t);

  const now = new Date();
  return {
    caseNo: caseNumber(finalUrl.hostname, now),
    examinedAt: now.toISOString(),
    durationMs: Date.now() - started,
    subject: { input: raw.trim(), finalUrl: doc.url, host: finalUrl.hostname, address: doc.address, status: doc.status, title: scan.title, lang: scan.lang, bytes: doc.bytes, redirects: doc.redirects },
    stages, exhibits, findings, categories: CATEGORIES, verdict, security, protocol: steps, dns: records, tls: tlsInfo, notes,
  };
}
