import { RULES, type Category, type Check, type Rule, type Source } from './signatures.ts';
import type { DnsRecords, TlsInfo } from './probes.ts';

/** Everything collected about one site. Pure data, so matching runs offline in tests. */
export interface Evidence {
  finalUrl: string;
  host: string;
  headers: Record<string, string>;
  setCookies: string[];
  html: string;
  meta: Record<string, string>;
  scripts: string[];
  stylesheets: string[];
  bundles: { url: string; body: string }[];
  styles: { url: string; body: string }[];
  dns: DnsRecords | null;
  tls: TlsInfo | null;
}

export type Confidence = 'confirmed' | 'probable' | 'trace' | 'implied';

export interface Exhibit {
  n: number;
  source: Source;
  label: string;
  excerpt: string;
}

export interface Finding {
  id: string;
  name: string;
  category: Category;
  url: string;
  confidence: Confidence;
  score: number;
  version: string;
  exhibits: number[];
  impliedBy: string[];
}

const short = (s: string, n = 160) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const fileOf = (u: string) => {
  try {
    const p = new URL(u);
    return p.host + p.pathname;
  } catch {
    return u;
  }
};

// Show the matched text with a little context, whitespace flattened.
function context(text: string, m: RegExpExecArray, pad = 48) {
  const start = Math.max(0, m.index - pad);
  const end = Math.min(text.length, m.index + m[0].length + pad);
  return `${start ? '…' : ''}${text.slice(start, end).replace(/\s+/g, ' ').trim()}${end < text.length ? '…' : ''}`;
}

const keyMatches = (key: Check['key'], name: string) =>
  key === undefined || (typeof key === 'string' ? key === name : key.test(name));

interface Hit { source: Source; label: string; excerpt: string; version: string }

function run(check: Check, ev: Evidence): Hit | null {
  const test = (value: string) => (check.pattern ? check.pattern.exec(value) : value ? ([value] as unknown as RegExpExecArray) : null);
  const ver = (m: RegExpExecArray | null) => (m && check.pattern && m[1]) || '';
  switch (check.source) {
    case 'header':
      for (const [name, value] of Object.entries(ev.headers)) {
        if (!keyMatches(check.key, name)) continue;
        const m = test(value);
        if (m) return { source: 'header', label: name, excerpt: short(`${name}: ${value}`), version: ver(m) };
      }
      return null;
    case 'cookie':
      for (const raw of ev.setCookies) {
        const name = raw.split('=')[0].trim();
        // Values can be session secrets: exhibits show the name only.
        if (keyMatches(check.key, name)) return { source: 'cookie', label: name, excerpt: `Set-Cookie: ${name}=[redacted]`, version: '' };
      }
      return null;
    case 'meta':
      for (const [name, value] of Object.entries(ev.meta)) {
        if (!keyMatches(check.key, name)) continue;
        const m = test(value);
        if (m) return { source: 'meta', label: name, excerpt: short(`<meta name="${name}" content="${value}">`), version: ver(m) };
      }
      return null;
    case 'html': {
      const m = check.pattern!.exec(ev.html);
      return m ? { source: 'html', label: 'document', excerpt: short(context(ev.html, m), 200), version: ver(m) } : null;
    }
    case 'script': case 'stylesheet':
      for (const u of check.source === 'script' ? ev.scripts : ev.stylesheets) {
        const m = check.pattern!.exec(u);
        if (m) return { source: check.source, label: check.source === 'script' ? '<script src>' : '<link rel=stylesheet>', excerpt: short(fileOf(u)), version: ver(m) };
      }
      return null;
    case 'js': case 'css':
      for (const f of check.source === 'js' ? ev.bundles : ev.styles) {
        const m = check.pattern!.exec(f.body);
        if (m) return { source: check.source, label: short(fileOf(f.url), 80), excerpt: short(context(f.body, m, 36), 180), version: ver(m) };
      }
      return null;
    case 'dns': {
      const records = (ev.dns?.[check.key as keyof DnsRecords] ?? []) as string[];
      for (const r of records) {
        const m = check.pattern!.exec(r);
        if (m) return { source: 'dns', label: String(check.key).toUpperCase(), excerpt: short(`${String(check.key).toUpperCase()} → ${r}`), version: ver(m) };
      }
      return null;
    }
    case 'tls': {
      const value = ev.tls ? String(ev.tls[check.key as 'issuer' | 'alpn'] ?? '') : '';
      const m = value ? check.pattern!.exec(value) : null;
      return m ? { source: 'tls', label: String(check.key), excerpt: `${check.key === 'alpn' ? 'ALPN negotiated' : 'Issuer'}: ${value}`, version: '' } : null;
    }
    case 'url': {
      const m = check.pattern!.exec(ev.host);
      return m ? { source: 'url', label: 'hostname', excerpt: ev.host, version: '' } : null;
    }
  }
}

const level = (score: number): Confidence => (score >= 1 ? 'confirmed' : score >= 0.6 ? 'probable' : 'trace');
const RANK: Record<Confidence, number> = { implied: 0, trace: 1, probable: 2, confirmed: 3 };

export function match(ev: Evidence, rules: Rule[] = RULES): { findings: Finding[]; exhibits: Exhibit[] } {
  const exhibits: Exhibit[] = [];
  const exhibitKey = new Map<string, number>();
  const findings = new Map<string, Finding>();

  for (const r of rules) {
    let score = 0;
    const versions: string[] = [];
    const refs = new Set<number>();
    for (const check of r.checks) {
      const hit = run(check, ev);
      if (!hit) continue;
      score += check.weight;
      if (hit.version) versions.push(hit.version);
      const k = `${hit.source}\u0000${hit.label}\u0000${hit.excerpt}`;
      let n = exhibitKey.get(k);
      if (n === undefined) {
        n = exhibits.length + 1;
        exhibits.push({ n, source: hit.source, label: hit.label, excerpt: hit.excerpt });
        exhibitKey.set(k, n);
      }
      refs.add(n);
    }
    if (score > 0) {
      findings.set(r.id, {
        id: r.id, name: r.name, category: r.category, url: r.url, confidence: level(score),
        score: Math.round(score * 100) / 100, version: versions[0] ?? '', exhibits: [...refs].sort((a, b) => a - b), impliedBy: [],
      });
    }
  }

  // Parents of solid findings (Next.js → React) are added or upgraded, never invented as evidence.
  const byId = new Map(rules.map((r) => [r.id, r]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const f of [...findings.values()]) {
      if (RANK[f.confidence] < RANK.probable && f.confidence !== 'implied') continue;
      for (const pid of byId.get(f.id)?.implies ?? []) {
        const parent = byId.get(pid);
        if (!parent) continue;
        const existing = findings.get(pid);
        if (!existing) {
          findings.set(pid, { id: pid, name: parent.name, category: parent.category, url: parent.url, confidence: 'implied', score: 0, version: '', exhibits: [], impliedBy: [f.name] });
          changed = true;
        } else if (!existing.impliedBy.includes(f.name)) {
          existing.impliedBy.push(f.name);
          if (existing.confidence === 'trace') existing.confidence = 'probable';
        }
      }
    }
  }

  const ordered = [...findings.values()].sort((a, b) => RANK[b.confidence] - RANK[a.confidence] || b.score - a.score || a.name.localeCompare(b.name));
  return { findings: ordered, exhibits };
}
