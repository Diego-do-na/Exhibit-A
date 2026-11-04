/* View logic for findings.html, rendered by ../dc-lite.js.
 *
 * Every row comes from the dashboard API for the current --source
 * (/api/repos, then /api/repos/<id>): proven findings plus the recorded
 * non-proven verdicts (discarded_findings), never invented cases. The
 * verdict filter offers only verdicts the source actually recorded.
 */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    let repo = '';
    try { repo = new URLSearchParams(window.location.search).get('repo') || ''; } catch (e) { /* no query */ }
    this.state = { by: 'effect', sc: 'abs', v: 'all', e: 'all', sel: null, repos: [], repoId: repo, detail: null, err: '', info: null };
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
    if (v == null) return '';
    return '$' + Number(v).toFixed(4).replace(/0+$/, '').replace(/\.$/, '');
  }
  renderVals() {
    const VC = { proven: '#0f2557', discarded_unproven: '#c3cbd8', invalid_test: '#9aa3e0', flaky: '#d9b98f', env_failure: '#b7834f' };
    const VN = { proven: 'Proven', discarded_unproven: 'Discarded', invalid_test: 'Invalid test', flaky: 'Flaky', env_failure: 'Environment failure' };
    const EN = { read: 'File read', write: 'File write', exec: 'Command exec', sql: 'SQL read', unspecified: 'Unspecified effect', unknown: 'Unspecified effect', '': 'Unspecified effect' };
    const st = this.state;
    const detail = st.detail;
    const m = (detail && detail.metrics) || {};
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));
    const emptySource = !st.err && st.repos.length === 0;
    const ready = !!detail && !emptySource;

    const runById = {};
    ((detail && detail.pull_requests) || []).forEach((p) => { runById[p.run_id] = p; });
    const items = [];
    ((detail && detail.all_findings) || []).forEach((f) => {
      items.push({ id: f.finding_id || f.run_id, run: f.run_id, cls: f.class || 'recorded suspicion', file: f.file || '', line: f.line || 0,
        entry: f.entry_point || '', verdict: 'proven', effect: f.effect || 'unspecified', cwe: f.cwe || '', severity: f.severity || '',
        fix: f.fix_status || '', reason: f.reason || f.hypothesis || 'Recorded as proven in the ledger.',
        cost: (runById[f.run_id] || {}).cost_usd, href: 'pr.html?run=' + encodeURIComponent(f.run_id) });
    });
    ((detail && detail.discarded_findings) || []).forEach((x) => {
      items.push({ id: x.suspicion_id || x.run_id, run: x.run_id, cls: x.class || 'recorded suspicion', file: x.file || '', line: x.line || 0,
        entry: x.entry_point || '', verdict: x.verdict || 'discarded_unproven', effect: x.effect || 'unspecified', cwe: '', severity: '',
        fix: '', reason: x.reason || (x.reason_code ? 'Reason code: ' + x.reason_code : 'No reason was recorded.'),
        cost: (runById[x.run_id] || {}).cost_usd, href: 'pr.html?run=' + encodeURIComponent(x.run_id) });
    });

    const vt = (detail && detail.verdict_totals) || {};
    const raised = m.suspicions_raised || 0;
    const tot = [
      { i: 'M11 5a6 6 0 1 0 0 12 6 6 0 0 0 0-12ZM21 21l-4.3-4.3', l: 'Suspicions', v: ready ? String(raised) : '…', d: 'Raised by the adversary role across the recorded runs.' },
      { i: 'M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3ZM8.8 12l2.2 2.2 4.3-4.4', l: 'Proven', v: ready ? String(m.proven || 0) : '…', d: 'Each with an exploit test and a fix verified in the sandbox.' },
      { i: 'M18.4 5.6 5.6 18.4M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z', l: 'Refused', v: ready ? String(m.discarded || 0) : '…', d: 'Stopped by the oracle, each with a recorded reason.' },
      { i: 'M14.7 6.3a4 4 0 0 0-5.4 5L3 17.6V21h3.4l6.3-6.3a4 4 0 0 0 5-5.4l-2.6 2.6-2.1-2.1 2.7-2.5Z', l: 'Fix incomplete', v: ready ? String(m.fixes_bypassed || 0) : '…', d: 'Proven and fixed, but a defender variant still got through.' },
    ];
    const susTotal = Object.keys(VN).reduce((t, k) => t + (vt[k] || 0), 0) || items.length;
    const susBars = Object.keys(VN).map((k) => ({ w: susTotal ? ((vt[k] || 0) / susTotal * 100).toFixed(1) : 0, c: VC[k], v: String(vt[k] || 0), l: VN[k] })).filter((s) => s.v !== '0' || s.l === 'Proven');

    // Outcome by effect or by CWE, stacking recorded verdicts.
    const grp = {};
    const keyOf = (it) => st.by === 'effect' ? (EN[it.effect] || it.effect || 'Unspecified effect') : (it.cwe || 'Unspecified CWE');
    items.forEach((it) => {
      const k = keyOf(it);
      const cell = grp[k] || (grp[k] = {});
      cell[it.verdict] = (cell[it.verdict] || 0) + 1;
    });
    const ents = Object.entries(grp).map(([n, o]) => [n, o, Object.values(o).reduce((a, b) => a + b, 0)]).sort((a, b) => b[2] - a[2]);
    const mx = Math.max(1, ...(ents.map((e) => e[2])));
    const out = ents.map(([n, o, t]) => ({ n, t, parts: Object.keys(VN).filter((k) => o[k]).map((k) => ({
      w: (st.sc === 'abs' ? o[k] / mx : o[k] / t) * 100, c: VC[k], fg: k === 'proven' ? '#ffffff' : '#0d1b3e',
      l: st.sc === 'abs' ? String(o[k]) : Math.round(o[k] / t * 100) + '%', t: VN[k] + ': ' + o[k] })) }));
    const effRate = {};
    items.forEach((it) => {
      const k = EN[it.effect] || it.effect || 'Unspecified effect';
      const cell = effRate[k] || (effRate[k] = { p: 0, t: 0 });
      cell.t += 1;
      if (it.verdict === 'proven') cell.p += 1;
    });
    const ranked = Object.entries(effRate).map(([k, v]) => [k, v]).sort((a, b) => (b[1].p / b[1].t) - (a[1].p / a[1].t));
    const insights = ranked.slice(0, 3).map(([k, v]) => ({ v: v.p + ' / ' + v.t, l: k,
      d: v.p + ' of ' + v.t + ' recorded ' + k.toLowerCase() + ' suspicions were proven.' }));
    // Do not pad with placeholder insight cards when fewer than three effects exist.

    // Why the oracle said no: recorded discard reasons, grouped by reason code.
    const whyGroups = {};
    items.filter((it) => it.verdict !== 'proven').forEach((it) => {
      const k = it.reason && it.reason !== 'No reason was recorded.' ? it.reason : 'No reason was recorded';
      const cell = whyGroups[k] || (whyGroups[k] = { n: 0, ids: [] });
      cell.n += 1;
      if (cell.ids.length < 3) cell.ids.push(it.id);
    });
    const whyTotal = Math.max(1, items.filter((it) => it.verdict !== 'proven').length);
    const WC = ['#4b3fa0', '#2c4fc4', '#6a8fd8', '#b7834f', '#4a5873'];
    const why = Object.entries(whyGroups).sort((a, b) => b[1].n - a[1].n).slice(0, 4).map(([n, cell], i) => ({
      n: n.length > 60 ? n.slice(0, 60) + '…' : n, v: String(cell.n), c: WC[i % WC.length],
      w: (cell.n / Math.max(1, ...Object.values(whyGroups).map((c) => c.n)) * 100).toFixed(0),
      pc: Math.round(cell.n / whyTotal * 100) + '% of refusals',
      d: cell.ids.join(', ') + (cell.n > cell.ids.length ? ' and ' + (cell.n - cell.ids.length) + ' more' : '') + '.',
    }));
    while (why.length < 1) why.push({ n: 'Nothing refused', v: '0', c: '#4a5873', w: 0, pc: '0% of refusals', d: 'Every recorded suspicion was proven.' });

    // Fix status of the proven findings (recorded).
    const fixGroups = { verified: 0, bypassed: 0, not_verified: 0 };
    items.filter((it) => it.verdict === 'proven').forEach((it) => {
      const k = it.fix === 'verified' ? 'verified' : (it.fix === 'bypassed' ? 'bypassed' : 'not_verified');
      fixGroups[k] += 1;
    });
    const fixTotal = Math.max(1, items.filter((it) => it.verdict === 'proven').length);
    const fixRows = [['Fix verified', fixGroups.verified, '#0f2557'], ['Bypassed by a defender variant', fixGroups.bypassed, '#a5703f'], ['Fix not verified', fixGroups.not_verified, '#9aa3e0']]
      .map(([n, v, c]) => ({ n, c, pc: Math.round(v / fixTotal * 100) + '%', of: v + ' of ' + fixTotal }));
    const gen = [{ t: 'Fix status of proven findings', rows: fixRows }];

    // Spend per recorded run.
    const runs = ((detail && detail.run_series) || []).slice().sort((a, b) => (b.cost_usd || 0) - (a.cost_usd || 0));
    const cmax = Math.max(1e-9, ...runs.map((p) => p.cost_usd || 0));
    const cy = (v) => 210 - (v / Math.max(cmax, 1e-9)) * 180;
    const bw = runs.length ? (676 - 48) / runs.length : 0;
    const cost = { grid: [0, 0.5, 1].map((f) => ({ y: cy(cmax * f), ty: cy(cmax * f) + 4, l: '$' + (cmax * f).toFixed(3) })),
      bars: runs.map((p, i) => ({ x: 48 + i * bw + 2, w: Math.max(2, bw - 4), y: cy(p.cost_usd || 0), h: Math.max(2, 210 - cy(p.cost_usd || 0)),
        c: (p.proven || 0) > 0 ? '#0f2557' : '#9aa3e0', t: (p.run_id || '') + ' · ' + this.money(p.cost_usd),
        pick: () => { window.location.href = 'pr.html?run=' + encodeURIComponent(p.run_id); } })) };
    const spends = runs.map((p) => p.cost_usd || 0).sort((a, b) => a - b);
    const cstats = runs.length ? [
      { v: this.money(spends.reduce((a, b) => a + b, 0) / spends.length), l: 'average per run' },
      { v: this.money(spends[Math.floor(spends.length / 2)]), l: 'median per run' },
      { v: this.money(spends[spends.length - 1]), l: 'highest run' },
      { v: this.money(spends.reduce((a, b) => a + b, 0)), l: 'total recorded' },
    ] : [];

    // Run explorer with a real verdict filter: only recorded verdicts offered.
    const verdictsPresent = Object.keys(VN).filter((k) => (vt[k] || 0) > 0);
    const effectsPresent = [...new Set(items.map((it) => it.effect || 'unspecified'))];
    const vOpts = [{ k: 'all', l: 'All verdicts' }].concat(verdictsPresent.map((k) => ({ k, l: VN[k] })));
    const eOpts = [{ k: 'all', l: 'All effects' }].concat(effectsPresent.map((k) => ({ k, l: EN[k] || k })));
    const list = items.filter((it) => (st.v === 'all' || it.verdict === st.v) && (st.e === 'all' || (it.effect || 'unspecified') === st.e));
    const rows = list.slice(0, 200).map((it) => ({ case: it.id, cwe: it.cwe || '—', eff: EN[it.effect] || it.effect || '—',
      vs: [{ c: VC[it.verdict] || '#4a5873', t: VN[it.verdict] || it.verdict }],
      cls: 'frow' + (st.sel === it.id + '|' + it.run ? ' frow-on' : ''), pick: () => this.setState({ sel: it.id + '|' + it.run }) }));
    const s0 = items.find((it) => st.sel === it.id + '|' + it.run) || items[0];
    const sel = s0 ? { verdict: VN[s0.verdict] || s0.verdict, effect: EN[s0.effect] || s0.effect || '—', cwe: s0.cwe || '—',
      cls: s0.cls, file: (s0.file || '—') + (s0.line ? ':' + s0.line : ''), entry: s0.entry || '—',
      n: '1', calls: this.money(s0.cost), cost: s0.fix ? s0.fix.replace(/_/g, ' ') : (s0.verdict === 'proven' ? 'recorded' : 'no fix proposed'),
      vs: [{ c: VC[s0.verdict] || '#4a5873', v: VN[s0.verdict] || s0.verdict, r: s0.reason }],
      href: s0.href, runLabel: 'Open run ' + (s0.run || '').slice(0, 20) } : null;

    const repoName = (detail && detail.repo && (detail.repo.name || detail.repo.id)) || (st.info && st.info.source) || 'loading';
    const secLead1 = ready ? ('Of ' + raised + ' suspicions: ' + (m.proven || 0) + ' proven, ' + (m.discarded || 0) + ' refused. Refusing is a feature.') : 'Loading the recorded verdicts for this source.';
    this.__d = { items, VC, VN, EN, verdictsPresent, effectsPresent, vt, runs };
    return { tot, susBars, susTotal, outT: st.by === 'effect' ? 'effect' : 'CWE', byOpts: opt([['effect', 'Effect'], ['cwe', 'CWE']], 'by'), scOpts: opt([['abs', 'Count'], ['pct', '%']], 'sc'),
      out, insights, why, gen, cost, cstats, v: st.v, e: st.e, vOpts, eOpts, onV: (ev) => this.setState({ v: ev.target.value }), onE: (ev) => this.setState({ e: ev.target.value }),
      rows, empty: rows.length === 0 && ready, sel, repoName, secLead1, ready, emptySource, err: st.err };
  }

  fullSpec(id) {
    const d = this.__d;
    if (!d) return null;
    const { items, VC, VN, EN } = d;
    const legend = Object.keys(VN).filter((k) => d.verdictsPresent.includes(k)).map((k) => ({ name: VN[k], color: VC[k] }));
    const verdicts = (it) => VN[it.verdict] || it.verdict;
    if (id === 'sus') {
      const sorted = items.slice().sort((a, b) => (a.id < b.id ? -1 : 1));
      const rows = sorted.map((it) => ({ key: it.id + '|' + it.run, label: it.id, sub: (it.cwe || '—') + ' · ' + (EN[it.effect] || '—'),
        parts: [{ v: 1, color: VC[it.verdict] || '#4a5873', name: verdicts(it), text: EN[it.effect] || '', label: it.verdict }], value: verdicts(it) }));
      return { type: 'hbars', title: 'Recorded suspicions', aria: 'Every recorded suspicion by verdict', rowH: 40, labelW: 290, legend, groups: [{ rows, max: 1 }],
        rows: sorted.map((it) => ({ key: it.id + '|' + it.run, label: it.id, value: verdicts(it), n: 1 })) };
    }
    if (id === 'out') {
      const group = (keyOf) => {
        const grp = {};
        items.forEach((it) => { const k = keyOf(it); grp[k] = grp[k] || {}; grp[k][it.verdict] = (grp[k][it.verdict] || 0) + 1; });
        return Object.entries(grp).map(([n, o]) => [n, o, Object.values(o).reduce((a, b) => a + b, 0)]).sort((a, b) => b[2] - a[2]);
      };
      const mk = (title, ents, pre) => ({ title, rows: ents.map(([n, o, t]) => ({ key: pre + n, label: n, sub: (o.proven || 0) + ' of ' + t + ' proven',
        parts: Object.keys(o).map((k) => ({ v: o[k], color: VC[k] || '#4a5873', name: VN[k] || k, label: String(o[k]) })), value: String(t) })) });
      const g1 = mk('By effect', group((it) => EN[it.effect] || 'Unspecified effect'), 'e:');
      const g2 = mk('By verdict detail', group((it) => VN[it.verdict] || it.verdict), 'v:');
      const rows = [];
      [g1, g2].forEach((g) => g.rows.forEach((r) => rows.push({ key: r.key, label: g.title + ' · ' + r.label, value: r.sub, n: Number(r.value) })));
      g1.max = g2.max = Math.max(1, ...g1.rows.concat(g2.rows).map((r) => Number(r.value)));
      return { type: 'hbars', title: 'Outcome by effect and verdict', aria: 'Recorded verdicts by effect and by verdict', rowH: 36, labelW: 200, legend, groups: [g1, g2], rows };
    }
    if (id === 'cost') {
      const sorted = d.runs.slice().sort((a, b) => (b.cost_usd || 0) - (a.cost_usd || 0));
      const rows = sorted.map((p) => ({ key: p.run_id, label: p.run_id, sub: (p.proven || 0) + ' proven', v: p.cost_usd || 0, color: (p.proven || 0) > 0 ? '#0f2557' : '#9aa3e0', value: '$' + Number(p.cost_usd || 0).toFixed(4) }));
      return { type: 'hbars', title: 'Spend per run', aria: 'Recorded model spend for each run, highest first', rowH: 40, labelW: 290, legend, groups: [{ rows, max: Math.max(1e-9, ...rows.map((r) => r.v)) }],
        rows: rows.map((r) => ({ key: r.key, label: r.label, value: r.value, n: r.v })) };
    }
    return null;
  }
};
