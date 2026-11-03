/* View logic for prs.html, rendered by ../dc-lite.js.
 *
 * PRs and authors come from the dashboard API for the current --source
 * (/api/repos, then /api/repos/<id>): recorded runs, their spend and their
 * recorded models. The ledger records no author names and no agent/human
 * mapping, so every author row reads "not recorded" for its type, never a
 * guess. The merged-PR metadata section (views/prdata.js) is shown only for
 * the Exhibit-A source, labeled as such.
 */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    let repo = '';
    try { repo = new URLSearchParams(window.location.search).get('repo') || ''; } catch (e) { /* no query */ }
    this.state = { q: '', agent: 'all', kind: 'all', sort: 'new', sel: null, y: 'cost', repos: [], repoId: repo, detail: null, err: '', info: null };
  }
  componentDidMount() {
    fetch('/api/info', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((info) => { if (info) this.setState({ info }); })
      .catch(() => {});
    fetch('/api/repos', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((body) => {
        const repos = (body && body.repos) || [];
        if (!repos.length) { this.setState({ repos: [] }); return; }
        this.setState({ repos });
        const want = this.state.repoId;
        const pick = repos.some((x) => x.id === want) ? want : repos[0].id;
        this.loadRepo(pick);
      })
      .catch(() => this.setState({ err: 'Could not load repositories.' }));
  }
  loadRepo(id) {
    this.setState({ repoId: id, detail: null, err: '', sel: null });
    fetch('/api/repos/' + encodeURIComponent(id), { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((detail) => {
        if (!detail) { this.setState({ err: 'Could not load this repository.' }); return; }
        this.setState({ detail });
      })
      .catch(() => this.setState({ err: 'Could not load this repository.' }));
  }
  money(v) {
    if (v == null) return 'not recorded';
    return '$' + Number(v).toFixed(4).replace(/0+$/, '').replace(/\.$/, '');
  }
  isExhibitA() {
    const s = this.state;
    const names = [((s.info || {}).source || ''), s.repoId, ((s.detail && s.detail.repo) || {}).name || '']
      .map((x) => String(x).toLowerCase());
    return names.some((n) => n.indexOf('exhibit-a') >= 0);
  }
  renderVals() {
    const MC = ['#0f2557', '#2c4fc4', '#6a8fd8', '#9aa3e0', '#4b3fa0', '#b7834f', '#d9b98f', '#7f97b8'];
    const st = this.state;
    const detail = st.detail;
    const m = (detail && detail.metrics) || {};
    const prs = ((detail && detail.pull_requests) || []).map((p) => ({
      run: p.run_id, id: p.pr ? 'PR ' + String(p.pr).replace(/^#/, '') : (p.run_id || '').slice(0, 12),
      t: p.title || p.headline || p.run_id, branch: p.branch || '', status: p.status || '',
      models: p.models || [], model: (p.models && p.models[0]) || 'model not recorded',
      cost: p.cost_usd || 0, dur: typeof p.duration_s === 'number' ? p.duration_s : null,
      proven: p.proven || 0, dropped: p.dropped || 0, files: (p.files_touched || []).length,
      started: p.started_at || '', filesTouched: p.files_touched || [],
      href: 'pr.html?run=' + encodeURIComponent(p.run_id),
    }));
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));
    const emptySource = !st.err && st.repos.length === 0;
    const ready = !!detail && !emptySource;

    const byModel = {};
    prs.forEach((p) => {
      const cell = byModel[p.model] || (byModel[p.model] = { a: p.model, n: 0, cost: 0, proven: 0, durs: [], runs: [] });
      cell.n += 1; cell.cost += p.cost || 0; cell.proven += p.proven; if (p.dur != null) cell.durs.push(p.dur); cell.runs.push(p);
    });
    const models = Object.keys(byModel);
    const mcol = {};
    models.forEach((a, i) => { mcol[a] = MC[i % MC.length]; });
    const q = st.q.trim().toLowerCase();
    const byAgent = prs.filter((p) => st.agent === 'all' || p.model === st.agent);
    const byKind = byAgent.filter((p) => st.kind === 'all' || st.kind === 'not recorded');
    const cmp = { new: (a, b) => (b.started < a.started ? -1 : b.started > a.started ? 1 : 0),
      old: (a, b) => (a.started < b.started ? -1 : a.started > b.started ? 1 : 0),
      big: (a, b) => b.cost - a.cost, slow: (a, b) => (b.dur || 0) - (a.dur || 0) };
    const list = byKind.filter((p) => !q || (p.run + ' ' + p.t + ' ' + p.model + ' ' + p.branch).toLowerCase().includes(q))
      .sort(cmp[st.sort] || cmp.new);

    const sum = (k) => byAgent.reduce((s, p) => s + (p[k] || 0), 0);
    const n = Math.max(byAgent.length, 1);
    const tot = [
      { i: 'M6 3v12M18 9a3 3 0 0 0-3-3h-4M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z', l: 'Recorded runs', v: ready ? String(byAgent.length) : '…', u: (detail && detail.repo && detail.repo.name) || 'this source' },
      { i: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 8a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z', l: 'Proven findings', v: ready ? String(m.proven || 0) : '…', u: (m.discarded || 0) + ' discarded suspicions' },
      { i: 'M4 6h16M4 12h10M4 18h13', l: 'Recorded spend', v: ready ? this.money(sum('cost')) : '…', u: (models.length || 0) + ' recorded models' },
      { i: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 7v5l3 2', l: 'Median run', v: ready && byAgent.length ? (() => { const d = byAgent.map((p) => p.dur).filter((v) => v != null).sort((a, b) => a - b); return d.length ? d[Math.floor(d.length / 2)] + 's' : 'not recorded'; })() : '…', u: 'across recorded runs' },
    ];
    const withProven = byAgent.filter((p) => p.proven > 0).length;
    const minor = [
      { v: ready ? Math.round(withProven / n * 100) + '%' : '…', l: 'of runs prove a finding' },
      { v: ready ? (sum('files') / n).toFixed(1) : '…', l: 'touched files per run' },
      { v: ready ? this.money(byAgent.length ? sum('cost') / byAgent.length : null) : '…', l: 'spend per run on average' },
      { v: String(models.length), l: 'recorded models' },
    ];
    const lead1 = ready ? (byAgent.length + ' recorded runs, ' + (m.proven || 0) + ' proven findings, ' + this.money(sum('cost')) + ' recorded spend.') : 'Loading the recorded runs for this source.';

    // Timeline: one point per recorded run at its start time.
    const starts = byAgent.map((p) => p.started).filter(Boolean).sort();
    const t0 = starts.length ? Date.parse(starts[0]) : 0;
    const t1 = starts.length ? Date.parse(starts[starts.length - 1]) : 1;
    const span = Math.max(1, t1 - t0);
    const X0 = 48, X1 = 996, Y0 = 260, Y1 = 30;
    const xs = (p) => X0 + ((Date.parse(p.started || starts[0] || 0) - t0) / span) * (X1 - X0);
    const YM = { cost: [(p) => p.cost, Math.max(1e-9, ...byAgent.map((p) => p.cost)), 'Recorded spend'],
      dur: [(p) => (p.dur == null ? 0 : p.dur), Math.max(1, ...byAgent.map((p) => (p.dur == null ? 0 : p.dur))), 'Run duration (s)'],
      proven: [(p) => p.proven, Math.max(1, ...byAgent.map((p) => p.proven)), 'Proven findings'] };
    const [yv, ymax, ytitle] = YM[st.y] || YM.cost;
    const ys = (v) => Y0 - (Math.log10(Math.max(v, 1)) / Math.log10(Math.max(ymax, 10))) * (Y0 - Y1);
    const inL = {};
    list.forEach((p) => { inL[p.run] = 1; });
    const s0 = list.find((p) => p.run === st.sel) || list[0];
    const dots = byAgent.slice().sort((a, b) => (inL[a.run] || 0) - (inL[b.run] || 0)).map((p) => {
      const s = s0 && p.run === s0.run;
      return { x: xs(p).toFixed(1), y: ys(Math.max(yv(p), st.y === 'cost' ? 0.0001 : 1)).toFixed(1), r: s ? 8.5 : 6, c: mcol[p.model] || '#4a5873', op: inL[p.run] ? 0.9 : 0.1,
        s: s ? '#0d1b3e' : 'rgba(255,255,255,.9)', sw: s ? 2 : 1, t: p.id + ' · ' + p.t + ' · ' + this.money(p.cost), pick: () => this.setState({ sel: p.run }) };
    });
    const daySet = [...new Set(starts.map((s) => s.slice(0, 10)))].sort();
    const tl = { yt: ytitle,
      days: daySet.map((l) => { const x = X0 + ((Date.parse(l) - t0) / span) * (X1 - X0); return { l: l.slice(5), x: x.toFixed(1), w: 0, tx: x.toFixed(1), f: 'rgba(13,27,62,0)' }; }),
      grid: [1, 10, 100].filter((v) => v <= Math.max(ymax, 10)).map((v) => ({ y: ys(v), ty: ys(v) + 4, l: String(v) })),
      dots, sx: s0 ? xs(s0).toFixed(1) : 0, sy: s0 ? (ys(Math.max(yv(s0), 1)) - 15).toFixed(1) : 0, sl: s0 ? s0.id : '' };

    const BK = [['<1¢', 0, 0.01], ['1–10¢', 0.01, 0.1], ['10–50¢', 0.1, 0.5], ['50¢+', 0.5, 1e18]];
    const hc = BK.map(([l, a, b]) => ({ l, n: byAgent.filter((p) => p.cost >= a && p.cost < b).length }));
    const hm = Math.max(1, ...hc.map((h) => h.n));
    const hist = hc.map((h, i) => ({ ...h, pct: (h.n / hm * 78).toFixed(1), c: ['#c3cbd8', '#9aa3e0', '#6a8fd8', '#2c4fc4'][i] }));
    const DK = [['<10s', 0, 10], ['10–60s', 10, 60], ['1–10m', 60, 600], ['10m+', 600, 1e18]];
    const dc = DK.map(([l, a, b]) => ({ l, n: byAgent.filter((p) => (p.dur == null ? -1 : p.dur) >= a && (p.dur || 0) < b).length }));
    const dm = Math.max(1, ...dc.map((h) => h.n));
    const cyh = dc.map((h, i) => ({ ...h, pct: (h.n / dm * 78).toFixed(1), c: ['#0f2557', '#2c4fc4', '#6a8fd8', '#9aa3e0'][i] }));

    const rows = list.map((p) => ({ id: p.id, t: p.t, a: p.model, ty: 'not recorded', isAgent: false, c: mcol[p.model] || '#4a5873',
      when: (p.started || '').slice(0, 16).replace('T', ' '), ch: String(p.files), cyc: p.dur == null ? '—' : p.dur + 's',
      aria: p.id + ' ' + p.t, cls: 'prow' + (s0 && st.sel === p.run ? ' prow-on' : ''), pick: () => this.setState({ sel: p.run }) }));
    const sel = s0 ? { id: s0.id, t: s0.t, a: s0.model, c: mcol[s0.model] || '#4a5873', when: (s0.started || '').slice(0, 16).replace('T', ' '),
      cm: String(s0.proven + s0.dropped), f: String(s0.files), cyc: s0.dur == null ? 'not recorded' : s0.dur + 's',
      add: this.money(s0.cost), del: '—', addPct: '100', delPct: '0', size: s0.proven ? s0.proven + ' proven' : 'nothing proven',
      story: (s0.branch ? 'Branch ' + s0.branch + '. ' : '') + 'Status ' + (s0.status || 'not recorded') + '. ' + s0.proven + ' proven, ' + s0.dropped + ' discarded. Touched files: ' + (s0.filesTouched.slice(0, 4).join(', ') || 'not recorded') + '.',
      href: s0.href } : null;

    const authorRows = models.sort((a, b) => byModel[b].n - byModel[a].n).map((a) => {
      const cell = byModel[a];
      const ds = cell.durs.sort((x, y) => x - y);
      return { a, ty: 'not recorded', isAgent: false, isHuman: false, c: mcol[a], n: cell.n,
        pct: (cell.n / Math.max(1, ...models.map((k) => byModel[k].n)) * 100).toFixed(1),
        lines: this.money(cell.cost), med: ds.length ? ds[Math.floor(ds.length / 2)] + 's' : '—',
        testsPct: Math.round(cell.proven / Math.max(1, cell.n) * 100) + '% proven' };
    });
    // Merged-PR metadata lives at pr.html?pr=<T-id>; runs link to pr.html?run=<id>.
    const hasMerged = this.isExhibitA();
    const XA = window.XA_PRS || [];
    const metaHits = (hasMerged && q) ? XA.filter((r) => (r[0] + ' ' + r[1]).toLowerCase().includes(q)).slice(0, 5)
      .map((r) => ({ id: r[0], t: r[1], href: 'pr.html?pr=' + encodeURIComponent(r[0]) })) : [];
    const pkgmap = hasMerged ? (() => {
      const byAuthor = {};
      XA.forEach((r) => {
        const cell = byAuthor[r[3]] || (byAuthor[r[3]] = { a: r[3], c: (window.XA_AUTHOR_COLORS || {})[r[3]] || '#4a5873', n: 0, areas: {} });
        cell.n += 1; cell.areas[r[9]] = (cell.areas[r[9]] || 0) + 1;
      });
      return Object.values(byAuthor).sort((a, b) => b.n - a.n).map((cell) => {
        const top = Object.entries(cell.areas).sort((a, b) => b[1] - a[1])[0];
        return { a: cell.a, c: cell.c, n: cell.n, area: top[0], an: top[1] };
      });
    })() : [];

    this.__d = { starts, t0, span, yv, ymax, ytitle, ykey: st.y, BK, DK, mcol, prs: byAgent, xs, ys, models, byModel };
    const kindOpts = [{ k: 'all', l: 'All types' }, { k: 'agent', l: 'Agents' }, { k: 'human', l: 'Humans' }, { k: 'not recorded', l: 'Not recorded' }];
    const agOpts = [{ k: 'all', l: 'All models' }].concat(models.map((k) => ({ k, l: k + ' (' + byModel[k].n + ')' })));
    const sortOpts = [['new', 'Newest'], ['old', 'Oldest'], ['big', 'Costliest'], ['slow', 'Slowest']].map(([k, l]) => ({ k, l }));
    const repoName = (detail && detail.repo && (detail.repo.name || detail.repo.id)) || (st.info && st.info.source) || 'loading';
    return { tot, minor, lead1, shown: list.length + ' of ' + prs.length + ' shown', agent: st.agent, agOpts, onAgent: (e) => this.setState({ agent: e.target.value }),
      kind: st.kind, kindOpts, onKind: (e) => this.setState({ kind: e.target.value }), authorRows,
      sort: st.sort, sortOpts, onSort: (e) => this.setState({ sort: e.target.value }),
      yOpts: opt([['cost', 'Spend'], ['dur', 'Duration'], ['proven', 'Proven']], 'y'), tl, hist, cyh, rows, sel,
      metaHits, hasMeta: metaHits.length > 0, hasMerged, noMerged: ready && !hasMerged,
      pkgmap, q: st.q, onQ: (e) => this.setState({ q: e.target.value }),
      repoName, ready, emptySource, err: st.err };
  }

  fullSpec(id) {
    const d = this.__d;
    if (!d || !d.starts) return null;
    if (id === 'tl') {
      const { yv, ymax } = d;
      const val = (p) => Math.max(yv(p), 1e-9);
      const sorted = d.prs.slice().sort((a, b) => val(b) - val(a));
      const days = [...new Set(d.starts.map((s) => s.slice(0, 10)))].sort();
      return { type: 'scatter', title: 'Recorded runs timeline', aria: 'Every recorded run at its start time', xMax: 1, yMaxLog: Math.log10(Math.max(ymax, 10)), yTitle: d.ytitle + ' (log scale)',
        days: days.map((l) => ({ l: l.slice(5), sub: d.prs.filter((p) => (p.started || '').slice(0, 10) === l).length + ' runs' })),
        yTicks: [1, 10, 100].filter((v) => v <= Math.max(ymax, 10)).map((v) => v),
        points: d.prs.map((p) => ({ key: p.run, x: d.xs(p), y: val(p), color: d.mcol[p.model] || '#4a5873', r: 5,
          tip: p.id + ' · ' + p.t + ' · ' + p.model })),
        labelled: sorted.slice(0, 6).map((p) => ({ key: p.run, x: d.xs(p), y: val(p) })),
        legend: d.models.map((a) => ({ name: a, color: d.mcol[a], n: d.byModel[a].n })),
        rows: sorted.map((p) => ({ key: p.run, label: p.id + ' · ' + p.t, value: String(Math.round(val(p) * 10000) / 10000), n: val(p) })) };
    }
    if (id === 'hist' || id === 'cyh') {
      const isH = id === 'hist';
      const BK = isH ? d.BK : d.DK;
      const get = isH ? ((p) => p.cost) : ((p) => (p.dur == null ? -1 : p.dur));
      const values = {};
      const rows = BK.map(([l, a, b]) => {
        const inB = d.prs.filter((p) => get(p) >= a && get(p) < b);
        values[l] = { runs: inB.length };
        return { key: l, label: l, value: inB.length + ' runs', n: inB.length };
      });
      return { type: 'bars', title: isH ? 'Recorded spend per run' : 'Run duration', aria: isH ? 'Recorded runs by spend' : 'Recorded runs by duration', yTitle: 'Recorded runs',
        cats: BK.map(([l]) => ({ k: l, l })), series: [{ k: 'runs', name: 'runs', color: '#2c4fc4' }], values, rows,
        totalNote: (k) => (rows.find((x) => x.key === k) || {}).value || '' };
    }
    return null;
  }
};
