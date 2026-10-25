const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const ARCHIVE_KEY = 'ax-archive';
const STAGES = { intake: 'Intake', dns: 'DNS', tls: 'Certificate', document: 'Document', scripts: 'Scripts', signatures: 'Signatures', verdict: 'Verdict' };
const STAMP = { confirmed: ['Confirmed', ''], probable: ['Probable', 'faint'], trace: ['Trace', 'faint'], implied: ['Implied', 'blue'] };
let source = null;
let current = null;

/* ── Views ── */
function show(view) {
  for (const id of ['intake', 'exam', 'refusal', 'report']) $(id).hidden = id !== view;
  scrollTo({ top: 0 });
}

/* ── Archive: a per-browser list of past cases ── */
function readArchive() {
  try {
    return JSON.parse(localStorage.getItem(ARCHIVE_KEY) || '[]');
  } catch {
    return [];
  }
}
function remember(report) {
  const entry = { caseNo: report.caseNo, host: report.subject.host, input: report.subject.input, at: report.examinedAt };
  const list = [entry, ...readArchive().filter((e) => e.host !== entry.host)].slice(0, 8);
  try {
    localStorage.setItem(ARCHIVE_KEY, JSON.stringify(list));
  } catch { /* storage blocked */ }
}
function renderArchive() {
  const list = readArchive();
  $('archive').hidden = !list.length;
  $('archive-list').innerHTML = list.map((e) => `<li><button type="button" data-url="${esc(e.input)}">
    <span class="no">${esc(e.caseNo)}</span><span class="host">${esc(e.host)}</span>
    <span class="when">${esc(new Date(e.at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }))}</span></button></li>`).join('');
}

/* ── Examination ── */
function examine(raw) {
  const input = raw.trim();
  if (!input) {
    $('hint').textContent = 'Type a web address first, for example linear.app.';
    $('hint').classList.add('bad');
    $('url').focus();
    return;
  }
  source?.close();
  current = null;
  history.replaceState(null, '', `?url=${encodeURIComponent(input)}`);
  $('exam-subject').textContent = input;
  $('exam-case').textContent = 'Case pending';
  $('log').replaceChildren();
  show('exam');
  const started = performance.now();
  const rows = new Map();

  source = new EventSource(`/api/examine?url=${encodeURIComponent(input)}`);
  source.addEventListener('stage', (e) => {
    const s = JSON.parse(e.data);
    let li = rows.get(s.stage);
    if (!li) {
      li = document.createElement('li');
      li.innerHTML = '<span class="t"></span><span class="stage"></span><span class="detail"></span>';
      rows.set(s.stage, li);
      $('log').append(li);
    }
    li.className = s.status === 'start' ? 'pending' : s.status;
    li.querySelector('.t').textContent = `T+${((performance.now() - started) / 1000).toFixed(2)}s`;
    li.querySelector('.stage').textContent = STAGES[s.stage] ?? s.stage;
    li.querySelector('.detail').textContent = s.detail;
  });
  source.addEventListener('report', (e) => {
    source.close();
    current = JSON.parse(e.data);
    remember(current);
    renderReport(current);
  });
  source.addEventListener('failure', (e) => {
    source.close();
    refuse(JSON.parse(e.data), input);
  });
  source.onerror = () => {
    if (current || source.readyState !== EventSource.CLOSED) return;
    refuse({ kind: 'unreachable', message: 'The connection to the examiner dropped. Check that the server is running and try again.' }, input);
  };
}

function refuse(f, input) {
  const titles = {
    refused: ['Examination refused', 'Refused'],
    unreachable: ['The subject could not be reached', 'No answer'],
    'rate-limited': ['Too many cases at once', 'Hold'],
    cancelled: ['Examination cancelled', 'Void'],
    internal: ['The examination failed', 'Error'],
  };
  const [title, stamp] = titles[f.kind] ?? titles.internal;
  $('refusal').innerHTML = `<span class="stamp big land">${esc(stamp)}</span>
    <p class="eyebrow">Case note · ${esc(input)}</p><h2>${esc(title)}</h2><p>${esc(f.message)}</p>
    <button type="button" id="again">Back to intake</button>`;
  show('refusal');
  $('again').addEventListener('click', () => {
    history.replaceState(null, '', '/');
    show('intake');
    $('url').value = input;
    $('url').focus();
  });
}

/* ── Case file ── */
function renderReport(r) {
  const s = r.subject;
  const when = new Date(r.examinedAt);
  const solid = r.findings.filter((f) => f.confidence !== 'trace');
  const traces = r.findings.filter((f) => f.confidence === 'trace');
  const order = Object.keys(r.categories);
  const byCat = order.map((c) => [c, solid.filter((f) => f.category === c)]).filter(([, l]) => l.length);
  const frameworks = solid.filter((f) => ['framework', 'cms'].includes(f.category)).map((f) => f.name);
  const hosting = solid.filter((f) => f.category === 'hosting' && !/HTTP/.test(f.name)).map((f) => f.name);

  const exrefs = (f) => f.exhibits.length
    ? `<span class="exrefs">${f.exhibits.map((n) => `<button type="button" class="exref" data-ex="${n}" aria-label="Exhibit ${n}">${n}</button>`).join('')}</span>`
    : '<span class="exrefs"></span>';
  const finding = (f) => {
    const [label, tone] = STAMP[f.confidence];
    return `<div class="finding" data-id="${esc(f.id)}">
      <span class="name"><a href="${esc(f.url)}" target="_blank" rel="noopener noreferrer">${esc(f.name)}</a>${f.version ? `<span class="ver">v${esc(f.version)}</span>` : ''}
        ${f.impliedBy.length ? `<span class="implied">${f.confidence === 'implied' ? 'Implied by' : 'Also implied by'} ${esc(f.impliedBy.join(', '))}</span>` : ''}</span>
      ${exrefs(f)}<span class="stamp ${tone}">${label}</span></div>`;
  };

  const lead = [
    frameworks.length ? `Built with <em>${esc(frameworks.slice(0, 3).join(', '))}</em>` : 'No front-end framework identified',
    hosting.length ? `served by <em>${esc(hosting.slice(0, 2).join(' and '))}</em>` : '',
  ].filter(Boolean).join(', ');

  $('report').innerHTML = `
    <header class="case-head">
      <div>
        <ul class="docket">
          <li class="no"><span>Case no.</span><b>${esc(r.caseNo)}</b></li>
          <li><span>Examined</span><b>${esc(when.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }))}</b></li>
          <li><span>Duration</span><b>${(r.durationMs / 1000).toFixed(1)} s</b></li>
          <li><span>Status</span><b>HTTP ${esc(s.status)}</b></li>
          <li><span>Exhibits</span><b>${r.exhibits.length}</b></li>
        </ul>
        <h1>${esc(s.title || s.host)}</h1>
        <p class="final-url">${esc(s.finalUrl)}${s.redirects.length ? ` · reached after ${s.redirects.length} redirect${s.redirects.length > 1 ? 's' : ''}` : ''}${r.cached ? ' · from the last 10 minutes' : ''}</p>
        <p class="summary">${lead}. ${esc(r.verdict.summary)}</p>
        <div class="actions">
          <button type="button" class="primary" data-act="new">New case</button>
          <button type="button" data-act="print">Print / PDF</button>
          <button type="button" data-act="md">Copy as Markdown</button>
          <button type="button" data-act="json">Download JSON</button>
        </div>
      </div>
      <div class="verdicts">
        <div><span class="label">Rendering</span><span class="stamp big land">${esc(r.verdict.mode)}</span></div>
        <div><span class="label">Security grade</span><span class="stamp big land grade">${esc(r.security.grade)}</span></div>
      </div>
    </header>

    <section class="sec" aria-labelledby="s1">
      <div class="sec-head"><span class="num">I</span><h2 id="s1">Findings</h2><p>Grouped by system. Numbers point to the exhibits that prove each one.</p></div>
      <div>${byCat.length ? byCat.map(([c, list]) => `<div class="system"><h3>${esc(r.categories[c])}</h3>${list.map(finding).join('')}</div>`).join('') : '<p class="none">Nothing identifiable. The site may be hand-built or hide its tooling well.</p>'}
        ${traces.length ? `<div class="system"><h3>Traces, weak evidence</h3>${traces.map(finding).join('')}</div>` : ''}</div>
    </section>

    <section class="sec" aria-labelledby="s2">
      <div class="sec-head"><span class="num">II</span><h2 id="s2">How pages render</h2><p>Read from the first HTML response, before any JavaScript ran.</p></div>
      <div><p class="mode-line"><b>${esc(r.verdict.mode)}</b>${esc(r.verdict.summary)}</p>
        <ul class="reasons">${r.verdict.reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>
    </section>

    <section class="sec" aria-labelledby="s3">
      <div class="sec-head"><span class="num">III</span><h2 id="s3">Security posture</h2><p>Response headers and the certificate. Grade ${esc(r.security.grade)}: ${r.security.rows.filter((x) => x.pass).length} of ${r.security.rows.length} checks pass.</p></div>
      <div><table class="security"><tbody>${r.security.rows.map((x) => `<tr><th scope="row">${esc(x.label)}</th>
        <td class="mark ${x.pass ? 'pass' : 'fail'}">${x.pass ? 'PASS' : 'FAIL'}</td><td class="val">${esc(x.value)}</td></tr>`).join('')}</tbody></table></div>
    </section>

    <section class="sec" aria-labelledby="s4">
      <div class="sec-head"><span class="num">IV</span><h2 id="s4">Build your own</h2><p>The same architecture, step by step. Each step says which evidence it follows from.</p></div>
      <ol class="steps">${r.protocol.map((p) => `<li><span class="phase">${esc(p.phase)}</span><h3>${esc(p.title)}</h3>
        <div class="cmd"><pre>${esc(p.command)}</pre><button type="button" data-copy>Copy</button></div><p class="why">${esc(p.why)}</p></li>`).join('')}</ol>
    </section>

    <section class="sec" aria-labelledby="s5">
      <div class="sec-head"><span class="num">V</span><h2 id="s5">Exhibits</h2><p>Raw evidence, quoted as received. Cookie values are never shown.</p></div>
      <ol class="exhibits">${r.exhibits.map((x) => `<li class="exhibit" id="ex-${x.n}"><span class="tag">EX. ${String(x.n).padStart(2, '0')}</span>
        <div><span class="src">${esc(x.source)} · ${esc(x.label)}</span><code>${esc(x.excerpt)}</code></div></li>`).join('') || '<li><p class="none">No exhibits were collected.</p></li>'}</ol>
    </section>

    <section class="sec" aria-labelledby="s6">
      <div class="sec-head"><span class="num">VI</span><h2 id="s6">Appendix</h2><p>Records gathered along the way.</p></div>
      <div class="appendix">
        <div><h3>DNS</h3><dl>${r.dns ? [['A', r.dns.a], ['AAAA', r.dns.aaaa], ['CNAME', r.dns.cname], ['NS', r.dns.ns], ['MX', r.dns.mx]].filter(([, v]) => v.length).map(([k, v]) => `<dt>${k}</dt><dd>${esc(v.slice(0, 6).join(', '))}</dd>`).join('') || '<dd>No records answered.</dd>' : '<dd>DNS did not answer.</dd>'}</dl></div>
        <div><h3>Certificate</h3><dl>${r.tls ? `<dt>Issuer</dt><dd>${esc(r.tls.issuer)}</dd><dt>Valid until</dt><dd>${esc(r.tls.validTo.slice(0, 10))} (${r.tls.daysLeft} days)</dd><dt>Protocol</dt><dd>${esc(r.tls.protocol)} · ALPN ${esc(r.tls.alpn || 'none')}</dd>` : '<dd>Not examined.</dd>'}</dl></div>
        <div><h3>Route</h3><dl>${s.redirects.map((x) => `<dt>${x.status}</dt><dd>${esc(x.url)}</dd>`).join('')}<dt>${esc(s.status)}</dt><dd>${esc(s.finalUrl)}</dd><dt>Size</dt><dd>${(s.bytes / 1024).toFixed(0)} KB${s.lang ? ` · lang ${esc(s.lang)}` : ''}</dd></dl></div>
        ${r.notes.length ? `<div><h3>Notes</h3><ul class="notes">${r.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul></div>` : ''}
      </div>
    </section>`;

  const stamps = $('report').querySelectorAll('.stamp.land');
  stamps.forEach((st, i) => st.style.setProperty('--delay', `${0.15 + i * 0.22}s`));
  stamps[1]?.style.setProperty('--tilt', '5deg');
  show('report');
  document.title = `${r.caseNo} · ${s.host} — Autopsy`;
}

/* ── Exports ── */
function markdown(r) {
  const lines = [`# Autopsy case ${r.caseNo}: ${r.subject.host}`, '', `Examined ${r.examinedAt} · ${r.subject.finalUrl}`, '', `**Rendering:** ${r.verdict.mode}. ${r.verdict.summary}`, `**Security grade:** ${r.security.grade}`, '', '## Findings'];
  for (const f of r.findings.filter((x) => x.confidence !== 'trace')) {
    lines.push(`- **${f.name}**${f.version ? ` ${f.version}` : ''} (${f.confidence}${f.impliedBy.length ? `, implied by ${f.impliedBy.join(', ')}` : ''})${f.exhibits.length ? ` [${f.exhibits.map((n) => `ex. ${n}`).join(', ')}]` : ''}`);
  }
  lines.push('', '## Build your own');
  r.protocol.forEach((p, i) => lines.push(`${i + 1}. **${p.title}** (${p.phase})`, '', '   ```', ...p.command.split('\n').map((c) => `   ${c}`), '   ```', `   ${p.why}`, ''));
  lines.push('## Exhibits');
  for (const x of r.exhibits) lines.push(`${x.n}. ${x.source} · ${x.label}: \`${x.excerpt.replace(/`/g, "'")}\``);
  return lines.join('\n');
}

function download(name, text, type) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => (btn.textContent = old), 1400);
  } catch {
    btn.textContent = 'Copy blocked';
  }
}

/* ── Wiring ── */
$('form').addEventListener('submit', (e) => {
  e.preventDefault();
  examine($('url').value);
});
$('url').addEventListener('input', () => {
  $('hint').classList.remove('bad');
  $('hint').textContent = 'One visit to the page and a handful of its scripts. Nothing about the subject is stored.';
});

document.addEventListener('click', (e) => {
  const t = e.target;
  const pick = t.closest('[data-url]');
  if (pick) {
    $('url').value = pick.dataset.url;
    return examine(pick.dataset.url);
  }
  const ex = t.closest('[data-ex]');
  if (ex) {
    const target = $(`ex-${ex.dataset.ex}`);
    target?.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
    target?.classList.add('lit');
    setTimeout(() => target?.classList.remove('lit'), 1600);
    return;
  }
  const btn = t.closest('[data-copy]');
  if (btn) return copy(btn.previousElementSibling.textContent, btn);
  const act = t.closest('[data-act]')?.dataset.act;
  if (!act || !current) return;
  if (act === 'new') {
    history.replaceState(null, '', '/');
    renderArchive();
    show('intake');
    $('url').value = '';
    $('url').focus();
  }
  if (act === 'print') print();
  if (act === 'md') copy(markdown(current), t.closest('button'));
  if (act === 'json') download(`${current.caseNo}-${current.subject.host}.json`, JSON.stringify(current, null, 2), 'application/json');
});

// Hovering an exhibit tag lights every finding that cites it.
document.addEventListener('mouseover', (e) => {
  const ex = e.target.closest?.('.exref');
  document.querySelectorAll('.exref.lit').forEach((b) => b.classList.remove('lit'));
  if (ex) document.querySelectorAll(`.exref[data-ex="${ex.dataset.ex}"]`).forEach((b) => b.classList.add('lit'));
});

$('theme').addEventListener('click', () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
  try {
    localStorage.setItem('ax-theme', root.dataset.theme);
  } catch { /* storage blocked */ }
});

renderArchive();
const initial = new URLSearchParams(location.search).get('url');
if (initial) {
  $('url').value = initial;
  examine(initial);
}
