/* View logic for index.html, rendered by ../dc-lite.js.
 *
 * Every figure comes from the dashboard API for the current --source
 * (/api/repos, then /api/repos/<id>): the ledger is the single source of
 * truth. Missing fields are hidden, never estimated. When the source holds
 * no runs, the page shows the onboarding steps instead of charts.
 */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    let repo = '';
    try { repo = new URLSearchParams(window.location.search).get('repo') || ''; } catch (e) { /* no query */ }
    this.state = { vel: 'runs', don: 'effect', fun: 'abs', repos: [], repoId: repo, detail: null, err: '', info: null, limit: 20, hasMore: false };
  }
  componentDidMount() {
    fetch('/api/info', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((info) => { if (info) this.setState({ info }); })
      .catch(() => {});
    fetch('/api/repos?limit=' + this.state.limit, { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((body) => {
        const repos = (body && body.repos) || [];
        if (!repos.length) { this.setState({ repos: [], hasMore: false }); return; }
        this.setState({ repos, hasMore: !!body.has_more });
        const want = this.state.repoId;
        const pick = repos.some((x) => x.id === want) ? want : repos[0].id;
        this.loadRepo(pick);
      })
      .catch(() => this.setState({ err: 'Could not load repositories.' }));
  }
  loadRepo(id) {
    this.setState({ repoId: id, detail: null, err: '' });
    fetch('/api/repos/' + encodeURIComponent(id) + '?limit=' + this.state.limit, { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((detail) => {
        if (!detail) { this.setState({ err: 'Could not load this repository.' }); return; }
        this.setState({ detail, hasMore: !!detail.has_more });
      })
      .catch(() => this.setState({ err: 'Could not load this repository.' }));
  }
  loadMore() {
    this.setState({ limit: this.state.limit + 20 });
    this.loadRepo(this.state.repoId);
  }
  money(v) {
    if (v == null) return '';
    return '$' + Number(v).toFixed(4).replace(/0+$/, '').replace(/\.$/, '');
  }
  num(v) {
    if (v == null) return '';
    return Number(v).toLocaleString('en-US');
  }
  dayOf(ts) {
    const d = String(ts || '').slice(0, 10);
    return /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : '';
  }
  renderVals() {
    const st = this.state;
    const detail = st.detail;
    const m = (detail && detail.metrics) || {};
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));
    const empty = !st.err && st.repos.length === 0;
    const ready = !!detail && !empty;
    const loading = !st.err && !empty && !detail;

    const raised = m.suspicions_raised || 0;
    const kpis = [
      { i: 'M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3ZM8.8 12l2.2 2.2 4.3-4.4', l: 'Proven findings', v: ready ? String(m.proven || 0) : '…', u: ready ? 'of ' + raised + ' suspicions' : 'loading recorded runs', p: raised ? Math.round((m.proven || 0) / raised * 100) : 0, c: '#2c4fc4', d: 'Each one ships an exploit test and a verified fix. A run with nothing proven reads "nothing could be proven", never safe.' },
      { i: 'M18.4 5.6 5.6 18.4M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z', l: 'Discarded suspicions', v: ready ? String(m.discarded || 0) : '…', u: 'refused for lack of proof', p: raised ? Math.round((m.discarded || 0) / Math.max(1, raised) * 100) : 0, c: '#4a5873', d: 'Suspicions the oracle refused, each with a recorded reason. Silence is counted, not hidden.' },
      { i: 'M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3ZM8.8 12l2.2 2.2 4.3-4.4', l: 'Fixes verified', v: ready ? String(m.fixes_verified || 0) : '…', u: ready ? (m.fixes_bypassed || 0) + ' bypassed' : 'loading recorded runs', p: (m.proven || 0) ? Math.round((m.fixes_verified || 0) / m.proven * 100) : 0, c: '#0f2557', d: 'Proven findings whose exploit passes on the fixed code while the baseline still passes.' },
      { i: 'M12 2v20M16.5 6.5C15.8 5.4 14 4.5 12 4.5c-2.5 0-4.5 1.6-4.5 3.7 0 5 9 2.6 9 7.1 0 2.1-2 3.7-4.5 3.7-2 0-3.8-.9-4.5-2', l: 'Model spend', v: ready ? this.money(m.cost_usd) : '…', u: ready ? this.num((m.tokens_in || 0) + (m.tokens_out || 0)) + ' tokens' : 'loading recorded runs', p: 100, c: '#b7834f', d: 'Recorded model spend across every run of this source.' },
    ];
    const minor = ready ? [
      { v: this.num(m.suspicions_raised), l: 'suspicions raised' },
      { v: this.num(m.exploits_written), l: 'exploit tests written' },
      { v: this.num(m.runs), l: 'recorded runs' },
      { v: (detail.cost_by_model ? Object.keys(detail.cost_by_model).length : 0) + ' model' + (Object.keys(detail.cost_by_model || {}).length === 1 ? '' : 's'), l: 'recorded models' },
      ...(m.median_duration_s != null ? [{ v: m.median_duration_s + 's', l: 'median run duration' }] : []),
      { v: this.num((m.tokens_in || 0) + (m.tokens_out || 0)), l: 'tokens in and out' },
    ] : [{ v: '…', l: 'loading recorded runs' }];

    // Runs per day, stacked by outcome (proven vs everything else).
    const series = (detail && detail.run_series) || [];
    const days = {};
    series.forEach((p) => {
      const d = this.dayOf(p.started_at);
      if (!d) return;
      const cell = days[d] || (days[d] = { proven: 0, other: 0, cost: 0, n: 0 });
      cell.n += 1;
      cell.cost += p.cost_usd || 0;
      if ((p.proven || 0) > 0) cell.proven += 1; else cell.other += 1;
    });
    const dayList = Object.keys(days).sort();
    const OUT = [['proven', '#0f2557'], ['other', '#9aa3e0']];
    const isCost = st.vel === 'cost';
    const top = Math.max(1, ...dayList.map((d) => isCost ? days[d].cost : days[d].n));
    const B = 250, T = 30;
    const ys = (v) => B - (v / (top === 0 ? 1 : Math.max(top, isCost ? top : Math.ceil(top))) * (B - T));
    const band = dayList.length ? (676 - 44) / dayList.length : 0, bw = Math.max(8, Math.min(58, band - 8));
    const vdays = dayList.map((label, i) => {
      const cell = days[label];
      const v = isCost ? cell.cost : cell.n;
      const x = 44 + band * i + (band - bw) / 2;
      const segs = []; let acc = 0;
      OUT.forEach(([k, c]) => {
        const part = isCost ? 0 : cell[k];
        if (!part) return;
        segs.push({ x, y: ys(acc + part), w: bw, h: Math.max(0, ys(acc) - ys(acc + part) - 1), c, t: label + ' · ' + k + ': ' + part });
        acc += part;
      });
      if (isCost) segs.push({ x, y: ys(v), w: bw, h: B - ys(v), c: '#2c4fc4', t: label + ' · ' + this.money(v) });
      return { label: label.slice(5), segs, cx: x + bw / 2, ty: ys(isCost ? v : acc) - 9, v: isCost ? this.money(v) : String(v) };
    });
    const ticks = isCost ? [0, top / 2, top] : [0, Math.ceil(top / 2), top];
    const vel = { days: vdays, legend: !isCost, yt: isCost ? 'Recorded spend' : 'Recorded runs',
      aria: isCost ? 'Recorded model spend per day' : 'Recorded runs per day, stacked by outcome',
      grid: ticks.map((v) => ({ y: ys(v), ty: ys(v) + 4, l: isCost ? this.money(v) : String(Math.round(v)) })) };

    // Busiest day / median run / largest spend; omit a card when the source has no value.
    const flow = [];
    if (series.length) {
      const byDay = {};
      series.forEach((p) => { const d = this.dayOf(p.started_at); if (d) byDay[d] = (byDay[d] || 0) + 1; });
      const top3 = Object.entries(byDay).sort((a, b) => b[1] - a[1])[0];
      const durs = series.map((p) => p.duration_s).filter((v) => typeof v === 'number').sort((a, b) => a - b);
      const big = series.slice().sort((a, b) => (b.cost_usd || 0) - (a.cost_usd || 0))[0];
      if (top3) flow.push({ l: 'Busiest day', v: top3[0].slice(5) + ' · ' + top3[1] + ' runs', d: 'The day with the most recorded runs.' });
      if (durs.length) flow.push({ l: 'Median run', v: durs[Math.floor(durs.length / 2)] + 's', d: 'Median recorded run duration.' });
      if (big && this.money(big.cost_usd)) flow.push({ l: 'Largest spend', v: this.money(big.cost_usd), d: 'Run ' + (big.run_id || '') + ' cost the most.' });
    }

    // Donut: by oracle effect (proven findings) or by verdict (all suspicions).
    const proven = (detail && detail.all_findings) || [];
    const vt = (detail && detail.verdict_totals) || {};
    const EFFC = { read: '#0f2557', write: '#2c4fc4', exec: '#6a8fd8', sql: '#9aa3e0', unspecified: '#c3cbd8' };
    const EFFN = { read: 'File read', write: 'File write', exec: 'Command exec', sql: 'SQL read', unspecified: 'Unspecified effect' };
    const VERC = { proven: '#0f2557', discarded_unproven: '#9aa3e0', invalid_test: '#c3cbd8', flaky: '#d9b98f', env_failure: '#b7834f' };
    const VERN = { proven: 'Proven', discarded_unproven: 'Discarded', invalid_test: 'Invalid test', flaky: 'Flaky', env_failure: 'Environment failure' };
    let src = [], total = 0, cap = 'RECORDED';
    if (st.don === 'effect') {
      const counts = {};
      proven.forEach((f) => { const k = (f.effect || 'unspecified'); counts[k] = (counts[k] || 0) + 1; });
      src = Object.entries(counts).map(([k, v]) => [EFFN[k] || k, v, EFFC[k] || '#4a5873']);
      total = proven.length; cap = 'PROVEN';
    } else {
      src = Object.keys(VERN).map((k) => [VERN[k], vt[k] || 0, VERC[k]]).filter((x) => x[1] > 0);
      total = src.reduce((t, x) => t + x[1], 0); cap = 'SUSPICIONS';
    }
    let a = -Math.PI / 2;
    const P = (r, t) => (100 + r * Math.cos(t)).toFixed(2) + ' ' + (100 + r * Math.sin(t)).toFixed(2);
    const segs = total ? src.map(([n, v, c]) => {
      const s = a, e = a + (v / total) * Math.PI * 2; a = e;
      const lg = e - s > Math.PI ? 1 : 0;
      return { n, v, c, pc: Math.round(v / total * 100) + '%', t: n + ': ' + v,
        d: 'M' + P(96, s) + ' A96 96 0 ' + lg + ' 1 ' + P(96, e) + ' L' + P(70, e) + ' A70 70 0 ' + lg + ' 0 ' + P(70, s) + ' Z' };
    }) : [];
    const don = { segs, total, cap };

    const FUN = [['Suspicions', m.suspicions_raised || 0, '#c3cbd8'], ['Exploits written', m.exploits_written || 0, '#9aa3e0'], ['Proven', m.proven || 0, '#2c4fc4'], ['Fix verified', m.fixes_verified || 0, '#16307a'], ['Bypass-resistant', m.fixes_verified || 0, '#0a1840']];
    const fmax = Math.max(1, ...FUN.map((x) => x[1]));
    const fun = FUN.map(([l, v, c]) => ({ l, c, w: (v / fmax * 100).toFixed(1), v: st.fun === 'abs' ? String(v) : (fmax ? Math.round(v / (FUN[0][1] || 1) * 100) + '%' : '0%') }));

    const prs = ((detail && detail.pull_requests) || []).slice(0, 5).map((p) => ({
      id: p.pr ? 'PR ' + String(p.pr).replace(/^#/, '') : (p.run_id || '').slice(0, 12),
      t: p.title || p.headline || p.run_id, a: (p.models && p.models[0]) || '',
      aria: 'Open run ' + (p.run_id || ''), go: () => { window.location.href = 'pr.html?run=' + encodeURIComponent(p.run_id); },
    }));
    const files = (detail && detail.hot_files && detail.hot_files.files) || [];
    const code = [
      { v: String(files.length), l: 'files touched', i: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5ZM14 3v5h5M9 13h6M9 17h4' },
      { v: String(m.runs || 0), l: 'runs recorded', i: 'M21 8 12 3 3 8v8l9 5 9-5V8ZM3 8l9 5 9-5M12 13v8' },
      { v: String(detail && detail.cost_by_model ? Object.keys(detail.cost_by_model).length : 0), l: 'models recorded', i: 'M8 4C5 4 5 6 5 8v2c0 1.5-1 2-2 2 1 0 2 .5 2 2v2c0 2 0 4 3 4M16 4c3 0 3 2 3 4v2c0 1.5 1 2 2 2-1 0-2 .5-2 2v2c0 2 0 4-3 4' },
      { v: m.median_duration_s != null ? String(m.median_duration_s) + 's' : '—', l: 'median run', i: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 7v5l3 2' },
    ];

    const secLead1 = ready ? (m.runs + ' recorded runs, ' + (m.proven || 0) + ' proven findings, ' + this.money(m.cost_usd) + ' recorded spend.') : 'Loading the recorded runs for this source.';
    const secLead2 = ready ? 'Recorded runs for this source, oldest to newest.' : 'Loading the recorded runs for this source.';
    const secLead3 = ready ? 'What the oracle observed across the recorded runs.' : 'Loading the recorded findings for this source.';
    const secLead4 = ready ? 'The recorded runs and what they touched.' : 'Loading the recorded runs for this source.';
    const funnelNote = ready ? ((m.discarded || 0) + ' stopped without proof; ' + (m.fixes_bypassed || 0) + ' proven fixes were bypassed.') : 'Loading the recorded funnel for this source.';

    this.__d = { days: dayList, cells: days, OUT, EFFC, EFFN, VERC, VERN, FUN, isCost };
    const repoName = (detail && detail.repo && (detail.repo.name || detail.repo.id)) || (st.info && st.info.source) || 'loading';
    return { kpis, minor, flow, secLead1, secLead2, secLead3, secLead4, funnelNote, repoName,
      vel, velOpts: opt([['runs', 'Runs'], ['cost', 'Cost']], 'vel'), agents: OUT.map(([n, c]) => ({ n, c })),
      don, donT: st.don === 'effect' ? 'effect' : 'verdict', donOpts: opt([['effect', 'Effect'], ['verdict', 'Verdict']], 'don'),
      fun, funOpts: opt([['abs', 'Count'], ['pct', '%']], 'fun'), latest: prs, code,
      empty, ready, loading, hasMore: !!st.hasMore, loadMore: () => this.loadMore(),
      err: st.err, repoId: st.repoId,
      repoOpts: st.repos.map((r) => ({ k: r.id, l: (r.name || r.id) + ' (' + r.runs + ')' })),
      hasRepos: st.repos.length > 1, onRepo: (e) => this.loadRepo(e.target.value) };
  }

  fullSpec(id) {
    const d = this.__d;
    if (!d) return null;
    if (id === 'vel') {
      const cats = d.days.map((l) => ({ k: l, l: l.slice(5), sub: d.cells[l].n + ' runs' }));
      const values = {}; d.days.forEach((l) => { values[l] = { proven: d.cells[l].proven, other: d.cells[l].other }; });
      const rows = d.days.map((l) => ({ key: l, label: l, value: d.cells[l].n + ' runs · ' + d.cells[l].proven + ' proven', n: d.cells[l].n }));
      return { type: 'bars', title: 'Recorded runs per day', aria: 'Recorded runs per day, stacked by outcome', yTitle: 'Recorded runs',
        cats, series: d.OUT.map(([n, c]) => ({ k: n, name: n, color: c })), values, rows,
        totalNote: (k) => { const c = d.cells[k]; return c ? c.n + ' runs · ' + c.proven + ' proven' : ''; } };
    }
    if (id === 'don') {
      const mk = (idv, title, entries, center) => ({ id: idv, title, center, slices: entries.map(([n, v, c]) => ({ key: n, label: n, v, color: c })) });
      const eff = {}, ver = {};
      ((this.state.detail && this.state.detail.all_findings) || []).forEach((f) => { const k = f.effect || 'unspecified'; eff[k] = (eff[k] || 0) + 1; });
      Object.entries((this.state.detail && this.state.detail.verdict_totals) || {}).forEach(([k, v]) => { if (v > 0) ver[k] = v; });
      const items = [mk('effect', 'By effect (proven findings)', Object.entries(eff).map(([k, v]) => [(d.EFFN[k] || k), v, d.EFFC[k] || '#4a5873']), 'proven'),
        mk('verdict', 'By verdict (all suspicions)', Object.entries(ver).map(([k, v]) => [(d.VERN[k] || k), v, d.VERC[k] || '#4a5873']), 'suspicions')];
      const rows = [];
      items.forEach((it) => { const t = it.slices.reduce((x, s) => x + s.v, 0); it.slices.forEach((s) => rows.push({ key: it.id + ':' + s.key, label: s.label, value: s.v + ' of ' + t, n: s.v })); });
      return { type: 'donuts', title: 'Findings breakdown', items, rows };
    }
    if (id === 'fun') {
      const rows = d.FUN.map(([l, v, c], i) => {
        const prev = i ? d.FUN[i - 1][1] : v;
        return { key: l, label: l, sub: i ? (prev ? 'drops ' + (prev - v) + ' from the stage above' : 'no drop from the stage above') : 'starting point', v, color: c, value: v + '' };
      });
      return { type: 'hbars', title: 'Verification funnel', rowH: 44, labelW: 230, groups: [{ rows, max: Math.max(1, ...d.FUN.map((x) => x[1])) }],
        rows: rows.map((r) => ({ key: r.key, label: r.label, value: r.value, n: r.v })) };
    }
    return null;
  }
};
