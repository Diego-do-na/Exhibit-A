/* View logic for benchmark.html, rendered by ../dc-lite.js.
 *
 * The systems table and the per-target matrix come from GET /api/benchmark,
 * which aggregates bench/results/*.json for the Exhibit-A repo only. Any
 * other source gets "no benchmark data for this source" and nothing is
 * estimated. The safeguard, role and author panels describe the same
 * Exhibit-A evaluation and are shown only when the benchmark is available.
 */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { sm: 'prec', ab: 'fp', m: 'prs', agent: 'claude', bench: null, err: '' };
  }
  componentDidMount() {
    fetch('/api/benchmark', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((bench) => { if (bench) this.setState({ bench }); })
      .catch(() => this.setState({ err: 'Could not load the benchmark.' }));
  }
  money(v) {
    if (v == null) return '—';
    return '$' + Number(v).toFixed(4).replace(/0+$/, '').replace(/\.$/, '');
  }
  renderVals() {
    const st = this.state;
    const bench = st.bench;
    const hasBench = !!(bench && bench.available);
    const systems = (bench && bench.systems) || [];
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));
    const fmt = (n) => n == null ? '—' : Number(n).toLocaleString('en-US');

    const top = systems.slice().sort((a, b) => (b.reported || 0) - (a.reported || 0));
    const A = top[0] || null, B = top[1] || null;
    const ek = [
      { i: 'M18.4 5.6 5.6 18.4M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z', l: 'False positives', a: A ? String(A.false_positives) : '—', an: A ? A.system : '—', b: B ? String(B.false_positives) : '—', bn: B ? B.system : '—', d: 'Reports that pointed at no real vulnerability, per bench/results.' },
      { i: 'M12 12 19 5M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', l: 'Precision', a: A && A.precision != null ? A.precision.toFixed(2) : '—', an: A ? A.system : '—', b: B && B.precision != null ? B.precision.toFixed(2) : '—', bn: B ? B.system : '—', d: 'Share of reports that pointed at a real vulnerability.' },
      { i: 'M12 2v20M16.5 6.5C15.8 5.4 14 4.5 12 4.5c-2.5 0-4.5 1.6-4.5 3.7 0 5 9 2.6 9 7.1 0 2.1-2 3.7-4.5 3.7-2 0-3.8-.9-4.5-2', l: 'Cost per report', a: A && A.reported ? this.money(A.cost_usd / A.reported) : '—', an: A ? A.system : '—', b: B && B.reported ? this.money(B.cost_usd / B.reported) : '—', bn: B ? B.system : '—', d: 'Each Exhibit A report includes an exploit test and a verified fix.' },
    ];
    const SM = { prec: ['precision', 'Precision is the share of reports that were real.', (v) => v == null ? '—' : v.toFixed(2)],
      rec: ['recall', 'Recall is the share of known vulnerabilities found.', (v) => v == null ? '—' : v.toFixed(2)],
      rep: ['reported', 'Number of findings reported.', (v) => String(v)],
      cost: ['cost_usd', 'Total recorded model spend for the system.', (v) => this.money(v)] };
    const [skey, note, f] = SM[st.sm];
    const smax = Math.max(1e-9, ...systems.map((s) => skey === 'cost_usd' ? s.cost_usd : (s[skey] || 0)));
    const sm = systems.map((s) => {
      const raw = skey === 'cost_usd' ? s.cost_usd : s[skey];
      const num = skey === 'cost_usd' ? raw : (raw || 0);
      return { n: s.system, c: '#0f2557', v: f(raw), w: (num / smax * 100).toFixed(1) };
    });
    const buy = [
      { l: 'Targets measured', a: A ? String(A.targets) : '—', b: B ? String(B.targets) : '—' },
      { l: 'Findings reported', a: A ? String(A.reported) : '—', b: B ? String(B.reported) : '—' },
      { l: 'True positives', a: A ? String(A.true_positives) : '—', b: B ? String(B.true_positives) : '—' },
      { l: 'Discarded suspicions', a: A ? String(A.discarded) : '—', b: B ? String(B.discarded) : '—' },
      { i: 'M12 2v20M16.5 6.5C15.8 5.4 14 4.5 12 4.5c-2.5 0-4.5 1.6-4.5 3.7 0 5 9 2.6 9 7.1 0 2.1-2 3.7-4.5 3.7-2 0-3.8-.9-4.5-2', l: 'Cost per report', a: A && A.reported ? this.money(A.cost_usd / A.reported) : '—', b: B && B.reported ? this.money(B.cost_usd / B.reported) : '—' },
      { l: 'Model calls', a: A ? fmt(A.calls) : '—', b: B ? fmt(B.calls) : '—' },
    ];

    // Ablations, role split and author scorecard are omitted unless the
    // current source recorded them. Nothing here is a bundled Exhibit-A snapshot.
    const AB = [];
    const ab = [];
    const abIns = [];
    const roles = [];
    const sysCost = systems.reduce((t, s) => t + (s.cost_usd || 0), 0);
    const sysRep = systems.reduce((t, s) => t + (s.reported || 0), 0);
    const econ = [{ v: fmt(systems.reduce((t, s) => t + (s.calls || 0), 0)), l: 'model calls recorded' }, { v: this.money(sysCost), l: 'total recorded spend' },
      { v: sysRep ? this.money(sysCost / sysRep) : '—', l: 'per reported finding' },
      { v: String(systems.length), l: 'systems compared' }];

    const AG = [];
    const MM = { prs: [2, 'Pull requests', ''], cm: [3, 'Commits', ''], add: [4, 'Lines added', ''] };
    const [mi, mlabel, unit] = MM[st.m] || MM.prs;
    const ag = { yt: mlabel, grid: [], bars: [] };
    const mOpts = Object.keys(MM).map((k) => ({ k, l: MM[k][1] }));
    const score = [];
    const pf = { n: '', c: '#4a5873', d: 'Authors for this source come from gh pr list --state all on the Pull requests page.', share: [] };

    const repAll = top.reduce((t, s) => t + (s.reported || 0), 0);
    const tgtAll = top.reduce((t, s) => t + (s.targets || 0), 0);
    const fpAll = top.reduce((t, s) => t + (s.false_positives || 0), 0);
    const pstats = [
      { v: hasBench && tgtAll ? Math.round(repAll / tgtAll * 100) + '%' : '—', l: 'proof rate: ' + (hasBench ? repAll + ' of ' + tgtAll + ' targets reported' : 'no benchmark data for this source') },
      { v: '—', l: 'fix rate: bench/results carry no fix data' },
      { v: hasBench && repAll ? this.money(sysCost / repAll) : '—', l: 'cost per reported finding' },
      { v: hasBench ? String(fpAll) : '—', l: 'false positives across systems' },
    ];
    const cover = hasBench ? top.slice(0, 4).map((s) => ({
      v: String(s.discarded || 0), n: 'Discarded · ' + s.system,
      d: (s.discarded || 0) + ' suspicions discarded without proof in ' + (bench.file || 'bench/results') + '. Reasons live in the run ledgers, not in bench/results.' })) : [];
    const redteam = 'red-team cheats live in docs/bench/ablations.md, not in bench/results.';
    const benchFile = bench ? (bench.available ? 'bench/results/' + bench.file : 'no benchmark data for this source') : 'loading…';
    const secLead1 = hasBench ? ('Same corpus across ' + systems.length + ' systems, from ' + benchFile + '. Only the file above was read.') : 'The corpus evaluation describes the Exhibit-A benchmark, not this source.';
    this.__d = { systems, top, AB, roles, AG, smax };
    return { ek, smOpts: opt([['prec', 'Precision'], ['rec', 'Recall'], ['rep', 'Reports'], ['cost', 'Cost']], 'sm'), sm, smNote: note, buy,
      buyA: A ? A.system : '—', buyB: B ? B.system : '—',
      abOpts: opt([['fp', 'False proofs'], ['tp', 'True proofs']], 'ab'), ab, abIns, roles, econ,
      cover, pstats, redteam, benchFile, secLead1, hasBench: hasBench, noBench: !hasBench && !!bench,
      hasAblations: false, hasRoles: false, hasAuthors: false,
      m: st.m, mOpts, onM: (e) => this.setState({ m: e.target.value }), ag, score, pf, err: st.err };
  }

  fullSpec(id) {
    const d = this.__d;
    if (!d) return null;
    const fmt = (n) => n == null ? '—' : Number(n).toLocaleString('en-US');
    if (id === 'sys') {
      const M = [['Precision', (s) => s.precision, (v) => v == null ? '—' : v.toFixed(2), 1], ['Recall', (s) => s.recall, (v) => v == null ? '—' : v.toFixed(2), 1], ['Reports', (s) => s.reported, (v) => String(v), 100], ['Cost', (s) => s.cost_usd, (v) => '$' + Number(v).toFixed(2), 10]];
      const groups = M.map(([title, get, f, max]) => ({ title, max, rows: d.systems.map((s) => ({ key: s.system, label: s.system, v: get(s) || 0, color: '#0f2557', value: f(get(s)) })) }));
      const rows = d.systems.map((s) => ({ key: s.system, label: s.system, value: 'precision ' + (s.precision == null ? '—' : s.precision.toFixed(2)) + ' · recall ' + (s.recall == null ? '—' : s.recall.toFixed(2)) + ' · ' + s.reported + ' reports', n: s.reported }));
      return { type: 'hbars', title: 'Systems compared', aria: 'Recorded systems across four measures', rowH: 38, labelW: 210, groups, rows };
    }
    if (id === 'abl') {
      const mk = (title, ix, max) => ({ title, max, note: ix === 1 ? 'lower is better' : 'higher is better', rows: d.AB.map((r, i) => ({ key: r[0], label: r[0], v: r[ix], color: i === 0 ? '#0f2557' : r[0] === 'Bare baseline' || r[0] === 'Failing test only' ? '#b7834f' : '#9aa3e0', value: String(r[ix]) })) });
      const rows = d.AB.map((r) => ({ key: r[0], label: r[0], value: r[1] + ' false proofs · ' + r[2] + ' true proofs', n: r[1] }));
      return { type: 'hbars', title: 'Ablations', aria: 'Cheating tests accepted and real exploits kept, per safeguard removed', rowH: 32, labelW: 220, groups: [mk('False proofs accepted (of 215 cheats)', 1, 162), mk('True proofs kept (of 53 real exploits)', 2, 53)], rows };
    }
    if (id === 'roles') {
      const total = d.roles.reduce((t, r) => t + r.v, 0);
      const rows = d.roles.map((r) => ({ key: r.n, label: r.n, sub: r.d, v: r.v, color: r.c, value: r.v + ' calls · ' + Math.round(r.v / total * 100) + '%' }));
      return { type: 'hbars', title: 'Calls by role', aria: 'Model calls for each of the four roles', rowH: 48, labelW: 220, groups: [{ rows, max: d.roles[0].v }],
        rows: rows.map((r) => ({ key: r.key, label: r.label, value: r.value + ' · ' + r.sub, n: r.v })) };
    }
    if (id === 'auth') {
      const M = [['Pull requests', 2, ''], ['Commits', 3, ''], ['Lines added', 4, ''], ['Test files touched', 5, ''], ['Median cycle', 6, ' min']];
      const groups = M.map(([title, ix, u]) => { const list = d.AG.slice().sort((a, b) => b[ix] - a[ix]); return { title, max: list[0][ix], rows: list.map((a) => ({ key: a[0], label: a[0], v: a[ix], color: a[1], value: fmt(a[ix]) + u })) }; });
      const rows = d.AG.map((a) => ({ key: a[0], label: a[0], value: a[2] + ' PRs · ' + a[3] + ' commits · +' + fmt(a[4]) + ' lines', n: a[2] }));
      return { type: 'hbars', title: 'Author performance', aria: 'Every author across five measures', rowH: 28, labelW: 150, groups, rows };
    }
    return null;
  }
};
