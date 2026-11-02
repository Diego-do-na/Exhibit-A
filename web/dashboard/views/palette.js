/* XAPalette: global command palette (Cmd/Ctrl+K) for the Exhibit A dashboard.
 *
 * Jumps to pull requests/runs, proven or discarded findings, and code modules,
 * all from live API data. Plain DOM only (textContent, no innerHTML), so the
 * strict CSP holds. Loaded on every page; it injects its own trigger hint and
 * dialog, so pages only need the script tag.
 */
(function () {
  'use strict';

  const PAGES = [
    { t: 'Overview', d: 'Headline proof numbers', href: 'index.html' },
    { t: 'Pull requests', d: 'Runs across the repository', href: 'prs.html' },
    { t: 'Findings', d: 'Every suspicion and its verdict', href: 'findings.html' },
    { t: 'Code graph', d: 'Packages, heatmap and attack paths', href: 'graph.html' },
    { t: 'Benchmark', d: 'Loop against the naive baseline', href: 'benchmark.html' },
  ];

  function params() {
    try { return new URLSearchParams(window.location.search); } catch (e) { return new URLSearchParams(); }
  }
  const RUN_ID = params().get('run') || '';

  async function getJSON(path) {
    const res = await fetch(path, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error('http ' + res.status);
    return res.json();
  }

  async function loadItems() {
    const items = PAGES.map((p) => ({ group: 'Go to', title: p.t, detail: p.d, href: p.href }));
    try {
      const runs = await getJSON('/api/runs?per_page=100');
      for (const r of (runs && runs.runs) || []) {
        const name = r.pr ? 'PR ' + r.pr : r.run_id;
        items.push({
          group: 'Pull requests',
          title: name + ' · ' + (r.title || r.run_id),
          detail: (r.repo || '') + ' · ' + (r.headline || ''),
          href: 'pr.html?run=' + encodeURIComponent(r.run_id),
          keys: (r.run_id + ' ' + (r.pr || '') + ' ' + (r.title || '') + ' ' + (r.repo || '')).toLowerCase(),
        });
      }
    } catch (e) { /* offline or unauthenticated: pages stay available */ }
    if (RUN_ID) {
      try {
        const detail = await getJSON('/api/runs/' + encodeURIComponent(RUN_ID));
        for (const f of (detail && detail.proven) || []) {
          items.push({
            group: 'Findings in this run', kind: 'proven',
            title: (f.id || 'finding') + ' · ' + (f.class || ''),
            detail: (f.cwe || '') + ' · ' + (f.file || '') + ':' + (f.line || 0),
            href: 'finding.html?run=' + encodeURIComponent(RUN_ID) + '&finding=' + encodeURIComponent(f.id || ''),
            keys: ((f.id || '') + ' ' + (f.class || '') + ' ' + (f.cwe || '') + ' ' + (f.file || '')).toLowerCase(),
          });
        }
        for (const f of (detail && detail.discarded) || []) {
          items.push({
            group: 'Discarded in this run',
            title: (f.id || 'suspicion') + ' · ' + (f.verdict || 'discarded'),
            detail: (f.class || '') + ' · ' + (f.reason || ''),
            href: 'pr.html?run=' + encodeURIComponent(RUN_ID) + '#why-safe',
            keys: ((f.id || '') + ' ' + (f.class || '') + ' ' + (f.reason || '')).toLowerCase(),
          });
        }
      } catch (e) { /* keep runs and pages */ }
      try {
        const graph = await getJSON('/api/runs/' + encodeURIComponent(RUN_ID) + '/codegraph');
        if (graph && graph.available) {
          for (const n of graph.nodes || []) {
            if (n.kind !== 'file' && !/function|method/.test(n.kind || '')) continue;
            const label = n.kind === 'file' ? (n.name || n.id) : ((n.file || '') + ' :: ' + (n.label || n.name || ''));
            items.push({
              group: 'Modules in this run',
              title: label,
              detail: (n.findings && n.findings.length ? n.findings.length + ' finding(s) · ' : '') + (n.kind || ''),
              href: 'graph.html?run=' + encodeURIComponent(RUN_ID) + '&focus=' + encodeURIComponent(n.id),
              keys: ((n.name || '') + ' ' + (n.file || '') + ' ' + (n.id || '')).toLowerCase(),
            });
          }
        }
      } catch (e) { /* keep the rest */ }
    }
    return items;
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  let root = null, input = null, list = null, items = null, shown = [], active = 0;

  function close() {
    if (root) root.style.display = 'none';
  }
  function open() {
    if (!root) build();
    root.style.display = 'flex';
    input.value = '';
    active = 0;
    if (!items) {
      const wait = el('div', 'pal-empty', 'Loading runs…');
      list.replaceChildren(wait);
      loadItems().then((loaded) => { items = loaded; render(''); });
    } else {
      render('');
    }
    setTimeout(() => input.focus(), 0);
  }

  function render(q) {
    q = q.trim().toLowerCase();
    shown = !q
      ? (items || []).slice(0, 60)
      : (items || []).filter((it) => ((it.title + ' ' + (it.detail || '')).toLowerCase().includes(q) || (it.keys || '').includes(q))).slice(0, 60);
    list.replaceChildren();
    if (!shown.length) {
      list.appendChild(el('div', 'pal-empty', q ? 'No match. Try a PR number, finding id or module.' : 'Type to search runs, findings and modules.'));
      return;
    }
    let lastGroup = '';
    shown.forEach((it, i) => {
      if (it.group !== lastGroup) {
        lastGroup = it.group;
        list.appendChild(el('div', 'pal-group', lastGroup));
      }
      const b = el('button', 'pal-item' + (i === active ? ' pal-on' : ''));
      b.type = 'button';
      b.setAttribute('role', 'option');
      const tt = el('span', 'pal-t', it.title);
      const dd = el('span', 'pal-d', it.detail || '');
      b.append(tt, dd);
      b.addEventListener('click', () => { window.location.href = it.href; });
      b.addEventListener('mousemove', () => { active = i; paint(); });
      list.appendChild(b);
    });
  }
  function paint() {
    Array.from(list.querySelectorAll('.pal-item')).forEach((n, i) => {
      n.classList.toggle('pal-on', i === active);
      if (i === active) n.scrollIntoView({ block: 'nearest' });
    });
  }
  function go() {
    const it = shown[active];
    if (it) window.location.href = it.href;
  }

  function build() {
    root = el('div', 'ovl pal-ovl');
    root.style.display = 'none';
    root.setAttribute('role', 'dialog');
    root.setAttribute('aria-modal', 'true');
    root.setAttribute('aria-label', 'Command palette');
    const box = el('div', 'modal pal-box');
    const bar = el('div', 'pal-bar');
    input = document.createElement('input');
    input.className = 'pal-input';
    input.type = 'search';
    input.placeholder = 'Jump to a PR, finding or module…  (Esc to close)';
    input.setAttribute('aria-label', 'Jump to a PR, finding or module');
    input.addEventListener('input', () => { active = 0; render(input.value); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(shown.length - 1, active + 1); paint(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(0, active - 1); paint(); }
      else if (e.key === 'Enter') go();
      else if (e.key === 'Escape') close();
    });
    bar.appendChild(input);
    list = el('div', 'pal-list');
    list.setAttribute('role', 'listbox');
    const hint = el('div', 'pal-hint', RUN_ID ? 'Searching this run plus every page and PR.' : 'Tip: open a PR page first to also search its findings and modules.');
    box.append(bar, list, hint);
    root.appendChild(box);
    root.addEventListener('click', (e) => { if (e.target === root) close(); });
    document.body.appendChild(root);

    const trigger = el('button', 'ib pal-trigger', '⌘K');
    trigger.type = 'button';
    trigger.title = 'Command palette (⌘K)';
    trigger.setAttribute('aria-label', 'Open command palette');
    trigger.addEventListener('click', open);
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); root.style.display === 'none' ? open() : close(); }
      else if (e.key === 'Escape' && root && root.style.display !== 'none') close();
    });
    const side = document.querySelector('nav.side');
    if (side) {
      const wrap = el('div', 'pal-side');
      wrap.appendChild(trigger);
      const lbl = el('span', 'pal-side-lbl', 'Command palette');
      wrap.appendChild(lbl);
      side.appendChild(wrap);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', build);
  else build();
})();
