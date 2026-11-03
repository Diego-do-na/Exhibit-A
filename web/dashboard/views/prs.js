/* View logic for prs.html, rendered by ../dc-lite.js. */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    let pre = ''; try { pre = new URLSearchParams(window.location.search).get('pr') || ''; } catch (e) { /* no query */ }
    this.state = { q: '', agent: 'all', kind: 'all', sort: 'new', sel: pre || 'T131', y: 'lines' };
  }
  renderVals() {
    const COL = window.XA_AUTHOR_COLORS || { claude: '#0f2557', Muse: '#2c4fc4', Copilot: '#6a8fd8', assistant: '#9aa3e0', unlogged: '#c3cbd8', gemini: '#4b3fa0', grok: '#b7834f', agy: '#d9b98f', 'cursor-agent': '#7f97b8', 'claude-cloud': '#4a5873' };
    const D = window.XA_PRS || [];
    const DI = { '10-27': 0, '10-28': 1, '10-29': 2, '10-30': 3, '10-31': 4, '11-01': 5 };
    const MON = { '10': 'Oct', '11': 'Nov' };
    const fmt = (n) => n.toLocaleString('en-US');
    const short = (n) => n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n);
    const cyc = (m) => m < 60 ? m + 'm' : Math.floor(m / 60) + 'h' + String(m % 60).padStart(2, '0');
    const all = D.map(([id, t, when, a, cm, f, add, del, ts, area, cy]) => ({ id, t, a, cm, f, add, del, ts, area, cy, ch: add + del,
      min: DI[when.slice(0, 5)] * 1440 + parseInt(when.slice(6, 8), 10) * 60 + parseInt(when.slice(9, 11), 10),
      whenL: MON[when.slice(0, 2)] + ' ' + parseInt(when.slice(3, 5), 10) + ', ' + when.slice(6) }));
    const st = this.state;
    const q = st.q.trim().toLowerCase();
    const kindOf = (a) => window.XA_authorType ? window.XA_authorType(a) : 'unattributed';
    const byKind = all.filter((r) => st.kind === 'all' || kindOf(r.a) === st.kind || (st.kind === 'unattributed' && kindOf(r.a) === 'unattributed'));
    const byAgent = byKind.filter((r) => st.agent === 'all' || r.a === st.agent);
    const cmp = { new: (a, b) => b.min - a.min, old: (a, b) => a.min - b.min, big: (a, b) => b.ch - a.ch, slow: (a, b) => b.cy - a.cy };
    const list = byAgent.filter((r) => !q || (r.id + ' ' + r.t + ' ' + r.a + ' ' + r.area).toLowerCase().includes(q)).sort(cmp[st.sort]);

    const B = byAgent;
    const sum = (k) => B.reduce((s, r) => s + r[k], 0);
    const cs = B.map((r) => r.cy).sort((a, b) => a - b);
    const n = Math.max(B.length, 1);
    const tot = [
      { i: 'M6 3v12M18 9a3 3 0 0 0-3-3h-4M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z', l: 'Pull requests', v: String(B.length), u: 'merged into main' },
      { i: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 8a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z', l: 'Commits', v: String(sum('cm')), u: (sum('cm') / n).toFixed(1) + ' per pull request' },
      { i: 'M4 6h16M4 12h10M4 18h13', l: 'Lines changed', v: short(sum('add') + sum('del')), u: '+' + short(sum('add')) + ' added · −' + short(sum('del')) + ' removed' },
      { i: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 7v5l3 2', l: 'Median cycle', v: B.length ? cyc(cs[Math.floor(cs.length / 2)]) : '—', u: '90th percentile ' + (B.length ? cyc(cs[Math.floor(cs.length * 0.9)]) : '—') }
    ];
    const withT = B.filter((r) => r.ts > 0).length;
    const days = {}; B.forEach((r) => { const d = Math.floor(r.min / 1440); days[d] = (days[d] || 0) + 1; });
    const minor = [
      { v: Math.round(withT / n * 100) + '%', l: 'touch at least one test file' },
      { v: (sum('f') / n).toFixed(1), l: 'files changed per pull request' },
      { v: fmt(Math.round((sum('add') + sum('del')) / n)), l: 'lines per pull request on average' },
      { v: String(Object.keys(days).length), l: 'active days in the window' },
      { v: String(new Set(B.map((r) => r.a)).size), l: 'contributing authors' }
    ];
    const lead1 = st.agent === 'all'
      ? 'Ten authors, most of them coding agents, merged 134 pull requests in six days. Work arrived in small, verifiable steps: a typical change took under ten minutes from first commit to merge.'
      : st.agent + ' merged ' + B.length + ' of the 134 pull requests, with ' + sum('cm') + ' commits and ' + fmt(sum('add')) + ' lines added.';

    const counts = {}; all.forEach((r) => { counts[r.a] = (counts[r.a] || 0) + 1; });
    const agOpts = [{ k: 'all', l: 'All authors' }].concat(Object.keys(COL).map((k) => ({ k, l: k + ' (' + counts[k] + ')' })));
    const sortOpts = [['new', 'Newest'], ['old', 'Oldest'], ['big', 'Largest'], ['slow', 'Slowest']].map(([k, l]) => ({ k, l }));
    const yOpts = [['lines', 'Lines'], ['files', 'Files'], ['cycle', 'Cycle']].map(([k, l]) => ({ l, cls: 'sb' + (st.y === k ? ' sb-on' : ''), pick: () => this.setState({ y: k }) }));

    const inL = {}; list.forEach((r) => { inL[r.id] = 1; });
    const X0 = 48, X1 = 996, Y0 = 260, Y1 = 30;
    const xs = (m) => X0 + (m / 8640) * (X1 - X0);
    const YM = { lines: [(r) => r.ch, 4.5, [[1, '1'], [10, '10'], [100, '100'], [1000, '1k'], [10000, '10k']], 'Lines changed'],
      files: [(r) => r.f, 2.5, [[1, '1'], [10, '10'], [100, '100']], 'Files touched'],
      cycle: [(r) => r.cy + 1, 2.2, [[1, '0m'], [10, '10m'], [60, '1h']], 'Minutes to merge'] };
    const [yv, ymax, yt, ytitle] = YM[st.y];
    const ys = (v) => Y0 - (Math.log10(Math.max(v, 1)) / ymax) * (Y0 - Y1);
    const dw = (X1 - X0) / 6;
    const s0 = all.find((r) => r.id === st.sel) || all[all.length - 1];
    const tl = { yt: ytitle,
      days: ['Oct 27', 'Oct 28', 'Oct 29', 'Oct 30', 'Oct 31', 'Nov 1'].map((l, i) => ({ l, x: X0 + i * dw, w: dw, tx: X0 + i * dw + dw / 2, f: i % 2 ? 'rgba(13,27,62,.03)' : 'rgba(13,27,62,0)' })),
      grid: yt.map(([v, l]) => ({ y: ys(v), ty: ys(v) + 4, l })),
      dots: all.slice().sort((a, b) => (inL[a.id] || 0) - (inL[b.id] || 0)).map((r) => {
        const s = r.id === st.sel;
        return { x: xs(r.min).toFixed(1), y: ys(yv(r)).toFixed(1), r: s ? 8.5 : 6, c: COL[r.a], op: inL[r.id] ? 0.9 : 0.1,
          s: s ? '#0d1b3e' : 'rgba(255,255,255,.9)', sw: s ? 2 : 1, t: r.id + ' · ' + r.t, pick: () => this.setState({ sel: r.id }) };
      }),
      sx: xs(s0.min).toFixed(1), sy: (ys(yv(s0)) - 15).toFixed(1), sl: s0.id };

    const BK = [['<50', 0, 50], ['50–200', 50, 200], ['200–500', 200, 500], ['500–1.5k', 500, 1500], ['1.5k+', 1500, 1e9]];
    const hc = BK.map(([l, a, b]) => ({ l, n: B.filter((r) => r.ch >= a && r.ch < b).length }));
    const hm = Math.max(1, ...hc.map((h) => h.n));
    const hist = hc.map((h, i) => ({ ...h, pct: (h.n / hm * 78).toFixed(1), c: ['#c3cbd8', '#9aa3e0', '#6a8fd8', '#2c4fc4', '#0f2557'][i] }));
    const CK = [['<5m', 0, 5], ['5–15m', 5, 15], ['15–30m', 15, 30], ['30–60m', 30, 60], ['1h+', 60, 1e9]];
    const cc = CK.map(([l, a, b]) => ({ l, n: B.filter((r) => r.cy >= a && r.cy < b).length }));
    const cm = Math.max(1, ...cc.map((h) => h.n));
    const cyh = cc.map((h, i) => ({ ...h, pct: (h.n / cm * 78).toFixed(1), c: ['#0f2557', '#2c4fc4', '#6a8fd8', '#9aa3e0', '#b7834f'][i] }));

    const rows = list.map((r) => ({ id: r.id, t: r.t, a: r.a, ty: kindOf(r.a), isAgent: kindOf(r.a) === 'agent', c: COL[r.a], when: r.whenL, ch: fmt(r.ch), cyc: cyc(r.cy), aria: r.id + ' ' + r.t,
      cls: 'prow' + (st.sel === r.id ? ' prow-on' : ''), pick: () => this.setState({ sel: r.id }) }));
    const t0 = Math.max(1, s0.ch);
    const sizeOf = (x) => x < 50 ? 'XS' : x < 200 ? 'S' : x < 500 ? 'M' : x < 1500 ? 'L' : 'XL';
    const rankSize = all.slice().sort((a, b) => b.ch - a.ch).findIndex((r) => r.id === s0.id) + 1;
    const sel = { id: s0.id, t: s0.t, a: s0.a, c: COL[s0.a], when: s0.whenL, cm: s0.cm, f: s0.f, cyc: cyc(s0.cy), add: fmt(s0.add), del: fmt(s0.del),
      addPct: (s0.add / t0 * 100).toFixed(1), delPct: (s0.del / t0 * 100).toFixed(1), size: 'Size ' + sizeOf(s0.ch),
      href: 'pr.html?pr=' + encodeURIComponent(s0.id), story: 'Merged by ' + s0.a + ' after ' + s0.cm + (s0.cm === 1 ? ' commit' : ' commits') + ' across ' + s0.f + ' files, mostly in ' + s0.area + '. It is the #' + rankSize + ' largest change of the 134' + (s0.ts ? ', and touched ' + s0.ts + (s0.ts === 1 ? ' test file.' : ' test files.') : '.') };

    // Author to package map: where each author merged most, from the same rows.
    const byAuthor = {};
    all.forEach((r) => {
      const cell = byAuthor[r.a] || (byAuthor[r.a] = { a: r.a, c: COL[r.a], n: 0, areas: {} });
      cell.n += 1; cell.areas[r.area] = (cell.areas[r.area] || 0) + 1;
    });
    const pkgmap = Object.values(byAuthor).sort((a, b) => b.n - a.n).map((cell) => {
      const top = Object.entries(cell.areas).sort((a, b) => b[1] - a[1])[0];
      return { a: cell.a, c: cell.c, n: cell.n, area: top[0], an: top[1] };
    });

    this.__d = { all, COL, BK, CK, yv, ymax, yt, ytitle, ykey: st.y, cyc, fmt };
    const kindOpts = [{ k: 'all', l: 'All types' }, { k: 'agent', l: 'Agents' }, { k: 'human', l: 'Humans' }, { k: 'unattributed', l: 'Unattributed' }];
    const byA = {}; byAgent.forEach((r) => { const k = r.a; (byA[k] = byA[k] || []).push(r); });
    const maxN = Math.max(1, ...Object.values(byA).map((v) => v.length));
    const authorRows = Object.entries(byA).sort((a, b) => b[1].length - a[1].length).map(([a, v]) => {
      const cys = v.map((r) => r.cy).sort((x, y) => x - y);
      return { a, ty: kindOf(a), isAgent: kindOf(a) === 'agent', isHuman: kindOf(a) === 'human', c: COL[a] || '#4a5873', n: v.length,
        pct: (v.length / maxN * 100).toFixed(1), lines: fmt(v.reduce((s, r) => s + r.ch, 0)), med: cyc(cys[Math.floor(cys.length / 2)]),
        testsPct: Math.round(v.filter((r) => r.ts > 0).length / v.length * 100) + '%' };
    });
    return { tot, minor, lead1, shown: list.length + ' of 134 shown', agent: st.agent, agOpts, onAgent: (e) => this.setState({ agent: e.target.value }),
      kind: st.kind, kindOpts, onKind: (e) => this.setState({ kind: e.target.value }), authorRows,
      sort: st.sort, sortOpts, onSort: (e) => this.setState({ sort: e.target.value }), yOpts, tl, hist, cyh, rows, sel, pkgmap,
      q: st.q, onQ: (e) => this.setState({ q: e.target.value }) };
  }

  // The expanded version of each chart: same data, drawn in full (see fullchart.js).
  fullSpec(id) {
    const d = this.__d;
    if (!d) return null;
    const { all, COL } = d;
    const authors = Object.keys(COL);
    if (id === 'tl') {
      const dayNames = ['Oct 27', 'Oct 28', 'Oct 29', 'Oct 30', 'Oct 31', 'Nov 1'];
      const perDay = dayNames.map((_, i) => all.filter((r) => Math.floor(r.min / 1440) === i).length);
      const label = d.ykey === 'lines' ? ' lines' : d.ykey === 'files' ? ' files' : ' min to merge';
      const val = (r) => d.yv(r) - (d.ykey === 'cycle' ? 1 : 0);
      const sorted = all.slice().sort((a, b) => val(b) - val(a));
      const counts = {}; all.forEach((r) => { counts[r.a] = (counts[r.a] || 0) + 1; });
      return { type: 'scatter', title: 'Merge timeline', aria: 'Every pull request at the moment it merged', xMax: 8640, yMaxLog: d.ymax, yTitle: d.ytitle + ' (log scale)',
        days: dayNames.map((l, i) => ({ l, sub: perDay[i] + ' PRs' })), yTicks: d.yt,
        points: all.map((r) => ({ key: r.id, x: r.min, y: d.yv(r), color: COL[r.a], r: 4 + Math.min(5, Math.log10(Math.max(2, r.ch)) * 1.1),
          tip: r.id + ' \u00b7 ' + r.t + ' \u00b7 ' + r.a + ' \u00b7 ' + r.whenL + ' \u00b7 ' + d.fmt(val(r)) + label })),
        labelled: sorted.slice(0, 6).map((r) => ({ key: r.id, x: r.min, y: d.yv(r) })),
        legend: authors.filter((a) => counts[a]).map((a) => ({ name: a, color: COL[a], n: counts[a] })),
        rows: sorted.map((r) => ({ key: r.id, label: r.id + ' \u00b7 ' + r.t, value: d.fmt(val(r)) + label, n: val(r) })) };
    }
    if (id === 'hist' || id === 'cyh') {
      const isH = id === 'hist';
      const BK = isH ? d.BK : d.CK, get = isH ? (r) => r.ch : (r) => r.cy;
      const values = {}; const rows = [];
      BK.forEach(([l, a, b]) => {
        values[l] = {};
        const inB = all.filter((r) => get(r) >= a && get(r) < b);
        inB.forEach((r) => { values[l][r.a] = (values[l][r.a] || 0) + 1; });
        const top = inB.slice().sort((x, y) => get(y) - get(x)).slice(0, 3).map((r) => r.id).join(', ');
        rows.push({ key: l, label: l + (isH ? ' lines' : ''), value: inB.length + ' PRs' + (top ? ' \u00b7 ' + top : ''), n: inB.length });
      });
      return { type: 'bars', title: isH ? 'Lines changed per PR' : 'Time from first commit to merge', aria: isH ? 'Pull requests by size' : 'Pull requests by time to merge',
        yTitle: 'Pull requests', cats: BK.map(([l]) => ({ k: l, l: isH ? l + ' lines' : l })), series: authors.map((a) => ({ k: a, name: a, color: COL[a] })), values, rows,
        totalNote: (k) => (rows.find((x) => x.key === k) || {}).value || '' };
    }
    return null;
  }
};

