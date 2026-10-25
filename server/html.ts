// Attribute-level HTML scanning. No DOM: Autopsy needs tag attributes and
// visible text, not a render tree.

export interface Scan {
  title: string;
  lang: string;
  meta: Record<string, string>;
  scripts: string[];
  inline: string[];
  stylesheets: string[];
  links: { rel: string; href: string }[];
  words: number;
}

const ATTR = /([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;

export function attrs(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of tag.matchAll(ATTR)) out[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  return out;
}

const absolute = (href: string, base: string) => {
  try {
    return new URL(href.trim(), base).href;
  } catch {
    return '';
  }
};

const NAMED: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', mdash: '—', ndash: '–', hellip: '…', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“' };
export const decodeEntities = (s: string) =>
  s.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (m, e: string) =>
    e[0] === '#' ? String.fromCodePoint(parseInt(e.slice(e[1].toLowerCase() === 'x' ? 2 : 1), e[1].toLowerCase() === 'x' ? 16 : 10)) : NAMED[e.toLowerCase()] ?? m);

export function visibleWords(html: string): number {
  const text = html
    .replace(/<(script|style|noscript|template|svg)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[#\w]+;/g, ' ');
  return (text.match(/[\p{L}\p{N}]{2,}/gu) || []).length;
}

export function scanHtml(html: string, base: string): Scan {
  const meta: Record<string, string> = {};
  for (const m of html.matchAll(/<meta\b([^>]*)>/gi)) {
    const a = attrs(m[1]);
    const key = (a.name || a.property || a['http-equiv'] || '').toLowerCase();
    if (key && a.content !== undefined && !(key in meta)) meta[key] = a.content;
  }
  const scripts: string[] = [];
  const inline: string[] = [];
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const a = attrs(m[1]);
    if (a.src) {
      const url = absolute(a.src, base);
      if (url) scripts.push(url);
    } else if (m[2].trim()) inline.push(m[2].slice(0, 200_000));
  }
  const links: Scan['links'] = [];
  for (const m of html.matchAll(/<link\b([^>]*)>/gi)) {
    const a = attrs(m[1]);
    if (a.rel && a.href) links.push({ rel: a.rel.toLowerCase(), href: absolute(a.href, base) });
  }
  return {
    title: decodeEntities((/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1] ?? '').replace(/\s+/g, ' ').trim()).slice(0, 200),
    lang: attrs(/<html\b([^>]*)>/i.exec(html)?.[1] ?? '').lang ?? '',
    meta,
    scripts: [...new Set(scripts)],
    inline,
    stylesheets: links.filter((l) => l.rel.split(/\s+/).includes('stylesheet')).map((l) => l.href),
    links,
    words: visibleWords(html),
  };
}
