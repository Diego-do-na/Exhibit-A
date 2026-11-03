/* View logic for benchmark.html, rendered by ../dc-lite.js. */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { sm: 'prec', ab: 'fp', m: 'prs', agent: 'claude' };
  }
  renderVals() {
    const st = this.state;
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));
    const fmt = (n) => n.toLocaleString('en-US');

    const ek = [
      { i: 'M18.4 5.6 5.6 18.4M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z', l: 'False accusations', a: '0', b: '1', d: 'Only the naive model reported the already-patched Starlette release.' },
      { i: 'M12 12 19 5M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', l: 'Precision', a: '0.86', b: '0.67', d: 'Share of reports that pointed at a real vulnerability.' },
      { i: 'M12 2v20M16.5 6.5C15.8 5.4 14 4.5 12 4.5c-2.5 0-4.5 1.6-4.5 3.7 0 5 9 2.6 9 7.1 0 2.1-2 3.7-4.5 3.7-2 0-3.8-.9-4.5-2', l: 'Cost per report', a: '$0.15', b: '$0.02', d: 'Each Exhibit A report includes an exploit test and a verified fix.' }
    ];
    const SYS = [['Naive LLM', '#c3cbd8', 0.67, 1.0, 3, 0.0708], ['Exhibit A · compact', '#0f2557', 0.86, 0.68, 29, 2.2727], ['Exhibit A · standard', '#6a8fd8', 0, 0, 0, 4.7824]];
    const SM = { prec: [2, 1, (v) => v.toFixed(2), 'Precision is the share of reports that were real. The compact profile kept it high across 29 reports.'],
      rec: [3, 1, (v) => v.toFixed(2), 'Recall is the share of known vulnerabilities found. The naive model was only scored on three targets, which makes its 1.00 easy to reach.'],
      rep: [4, 29, (v) => String(v), 'Number of findings reported. The standard profile proved nothing live, so it reported nothing.'],
      cost: [5, 4.7824, (v) => '$' + v.toFixed(2), 'Total model spend for the run. Proof costs more than a guess; the standard profile spent the most and proved nothing.'] };
    const [ix, mx, f, note] = SM[st.sm];
    const sm = SYS.map((s) => ({ n: s[0], c: s[1], v: s[0].endsWith('standard') && st.sm === 'prec' ? 'not run' : f(s[ix]), w: (s[ix] / mx * 100).toFixed(1) }));
    const buy = [{ l: 'Reports still to triage', a: '0', b: '3' }, { l: 'Exploit tests written', a: '2', b: '0' }, { l: 'Fixes verified', a: '2', b: '0' },
      { i: 'M12 2v20M16.5 6.5C15.8 5.4 14 4.5 12 4.5c-2.5 0-4.5 1.6-4.5 3.7 0 5 9 2.6 9 7.1 0 2.1-2 3.7-4.5 3.7-2 0-3.8-.9-4.5-2', l: 'Cost per report', a: '$0.15', b: '$0.02' }, { l: 'Extra spend per target', a: '$0.08', b: '—' }];

    const AB = [['Full loop', 21, 49], ['No witness (L14)', 19, 49], ['No manifest (L1)', 20, 49], ['No admission (L2)', 18, 49], ['No app-tree check (L3)', 21, 49],
      ['No guard (L4)', 18, 49], ['No dir-fd check (L5)', 19, 48], ['No route access (L6)', 16, 49], ['No canary links (L7)', 22, 49], ['Failing test only', 104, 52], ['Bare baseline', 162, 53]];
    const ai = st.ab === 'fp' ? 1 : 2, am = st.ab === 'fp' ? 162 : 53;
    const ab = AB.map((r, i) => ({ n: r[0], v: r[ai], w: (r[ai] / am * 100).toFixed(1),
      c: i === 0 ? '#0f2557' : r[0] === 'Bare baseline' || r[0] === 'Failing test only' ? '#b7834f' : '#9aa3e0', lc: i === 0 ? '#0d1b3e' : '#3d4b68', fw: i === 0 ? 600 : 400 }));
    const abIns = [
      { v: '−87%', d: 'False proofs drop from 162 to 21 when the full loop and oracle are on.' },
      { v: '104', d: 'Cheats that still pass if you only require a failing test. A red test is not a proof.' },
      { v: '49 / 53', d: 'Real exploits kept by the full loop. Safety costs only four true proofs.' }
    ];

    const roles = [['Test writer', 44, '#0f2557', 'writes exploits'], ['Fixer', 33, '#2c4fc4', 'proposes patches'], ['Defender', 33, '#6a8fd8', 'tries to bypass fixes'], ['Adversary', 32, '#9aa3e0', 'raises suspicions']]
      .map(([n, v, c, d]) => ({ n, v, c, d, pct: (v / 44 * 100).toFixed(1) }));
    const econ = [{ v: '142', l: 'model calls' }, { v: '223k', l: 'tokens in and out' }, { v: '$0.081', l: 'per proven finding' }, { v: '4.4', l: 'calls per case' }];

    const AG = [
      ['claude', '#0f2557', 32, 100, 22522, 72, 10, 'The workhorse. Oracle provenance across threads and async tasks, the command-execution and SQL effects, findings dedupe and proven dependency vulnerabilities.'],
      ['Muse', '#2c4fc4', 26, 71, 32159, 65, 9, 'Model plumbing and new capability: the SSRF, redirect and access-control effects, proof bundles, and the JavaScript and TypeScript loop.'],
      ['Copilot', '#6a8fd8', 22, 27, 6167, 22, 9, 'Fast, focused merges: CLI subcommands, the pull-request diff mode, coverage matrix and dashboard views.'],
      ['assistant', '#9aa3e0', 17, 33, 4050, 18, 5, 'Hardening and glue: retries, sandbox limit tests, the report generator, audit mode and the repeatability harness.'],
      ['unlogged', '#c3cbd8', 15, 37, 8382, 20, 3, 'The first sprint, merged before the shared task log existed: scaffold, ledger, oracle, sandbox and the first CVE end to end.'],
      ['gemini', '#4b3fa0', 8, 26, 5484, 8, 30, 'Sandbox hardening with gVisor and seccomp, SARIF export, the Node sandbox image and the JS/TS oracle design.'],
      ['grok', '#b7834f', 7, 31, 44092, 49, 27, 'Few but heavy merges: the held-out corpus, the denial-of-service effect, the OS-level witness, the Node oracle core and the ablation table.'],
      ['agy', '#d9b98f', 4, 5, 4157, 2, 1, 'Bootstrapped the shared log and merge driver, wrote the architecture document and implemented the frontend.'],
      ['cursor-agent', '#7f97b8', 2, 2, 177, 1, 1, 'Wrote the README and the false-positive and recall metrics.'],
      ['claude-cloud', '#4a5873', 1, 7, 3856, 21, 40, 'Built SLICE: the call graph, sink catalog and reachability, merged as GitHub pull request #1.']];
    const MM = { prs: [2, 'Pull requests', ''], cm: [3, 'Commits', ''], add: [4, 'Lines added', ''], ts: [5, 'Test files touched', ''], cyc: [6, 'Median cycle (minutes)', 'm'] };
    const [mi, mlabel, unit] = MM[st.m];
    const sorted = AG.slice().sort((a, b) => b[mi] - a[mi]);
    const vmax = sorted[0][mi];
    const p = Math.pow(10, Math.floor(Math.log10(vmax))); const top = Math.ceil(vmax / p) * p;
    const G0 = 284, G1 = 30, gy = (v) => G0 - (v / top) * (G0 - G1);
    const bw = 940 / sorted.length;
    const short = (v) => v >= 10000 ? (v / 1000).toFixed(1) + 'k' : fmt(v);
    const ag = { yt: mlabel,
      grid: [0, 0.25, 0.5, 0.75, 1].map((t) => ({ y: gy(top * t), ty: gy(top * t) + 4, l: short(Math.round(top * t)) })),
      bars: sorted.map((a, i) => ({ x: 56 + i * bw + bw * 0.2, w: bw * 0.6, y: gy(a[mi]), h: Math.max(2, G0 - gy(a[mi])), c: a[1], cx: 56 + i * bw + bw / 2,
        ly: gy(a[mi]) - 9, v: short(a[mi]) + unit, n: a[0], t: a[0] + ': ' + fmt(a[mi]), pick: () => this.setState({ agent: a[0] }) })) };
    const mOpts = Object.keys(MM).map((k) => ({ k, l: MM[k][1] }));
    const score = AG.map((a) => ({ n: a[0], c: a[1], prs: a[2], cm: a[3], add: fmt(a[4]), ts: a[5], cyc: a[6] + ' min',
      bg: st.agent === a[0] ? 'rgba(44,79,196,.1)' : 'transparent', pick: () => this.setState({ agent: a[0] }) }));
    const p0 = AG.find((a) => a[0] === st.agent) || AG[0];
    const pf = { n: p0[0], c: p0[1], d: p0[7], share: [
      { l: 'Pull requests', v: p0[2] + ' of 134', pct: (p0[2] / 134 * 100).toFixed(1) },
      { l: 'Commits', v: p0[3] + ' of 339', pct: (p0[3] / 339 * 100).toFixed(1) },
      { l: 'Lines added', v: (p0[4] / 131046 * 100).toFixed(1) + '%', pct: (p0[4] / 131046 * 100).toFixed(1) },
      { l: 'Test files touched', v: p0[5] + ' of 278', pct: (p0[5] / 278 * 100).toFixed(1) }] };

    this.__d = { SYS, AB, roles, AG };
    return { ek, smOpts: opt([['prec', 'Precision'], ['rec', 'Recall'], ['rep', 'Reports'], ['cost', 'Cost']], 'sm'), sm, smNote: note, buy,
      abOpts: opt([['fp', 'False proofs'], ['tp', 'True proofs']], 'ab'), ab, abIns, roles, econ,
      cover: [
        { n: 'Effect never observed', v: '6', d: 'The exploit ran, but the oracle never saw the canary move. Without the observed effect there is no proof.' },
        { n: 'Invalid provenance', v: '4', d: 'The effect happened outside application code, so the run was refused with a named reason.' },
        { n: 'No verified fix', v: '3', d: 'The exploit worked, but no patch passed verification, so no finding was reported.' },
        { n: 'Guard tripwire', v: '1', d: 'The test tried to choose where the application lives; the guard stopped it first.' },
      ],
      pstats: [
        { v: '68%', l: 'proof rate: 30 of 44 suspicions proven' },
        { v: '87%', l: 'fix rate: 26 of 30 proven fixes resist bypass' },
        { v: '$0.081', l: 'cost per proven finding' },
        { v: '194 / 215', l: 'red-team cheats stopped; 21 remain as documented limits' },
      ],
      m: st.m, mOpts, onM: (e) => this.setState({ m: e.target.value }), ag, score, pf };
  }

  // The expanded version of each chart: same data, drawn in full (see fullchart.js).
  fullSpec(id) {
    const d = this.__d;
    if (!d) return null;
    const fmt = (n) => n.toLocaleString('en-US');
    if (id === 'sys') {
      const M = [['Precision', 2, (v) => v.toFixed(2), 1], ['Recall', 3, (v) => v.toFixed(2), 1], ['Reports', 4, (v) => String(v), 29], ['Cost', 5, (v) => '$' + v.toFixed(2), 4.7824]];
      const groups = M.map(([title, ix, f, max]) => ({ title, max, rows: d.SYS.map((s) => ({ key: s[0], label: s[0], v: s[ix], color: s[1], value: s[0].endsWith('standard') && ix === 2 ? 'not run' : f(s[ix]) })) }));
      const rows = d.SYS.map((s) => ({ key: s[0], label: s[0], value: 'precision ' + (s[0].endsWith('standard') ? 'not run' : s[2].toFixed(2)) + ' \u00b7 recall ' + s[3].toFixed(2) + ' \u00b7 ' + s[4] + ' reports \u00b7 $' + s[5].toFixed(2), n: s[2] }));
      return { type: 'hbars', title: 'Systems compared', aria: 'Naive baseline against Exhibit A, four measures', rowH: 38, labelW: 210, groups, rows };
    }
    if (id === 'abl') {
      const mk = (title, ix, max) => ({ title, max, note: ix === 1 ? 'lower is better' : 'higher is better', rows: d.AB.map((r, i) => ({ key: r[0], label: r[0], v: r[ix], color: i === 0 ? '#0f2557' : r[0] === 'Bare baseline' || r[0] === 'Failing test only' ? '#b7834f' : '#9aa3e0', value: String(r[ix]) })) });
      const rows = d.AB.map((r) => ({ key: r[0], label: r[0], value: r[1] + ' false proofs \u00b7 ' + r[2] + ' true proofs', n: r[1] }));
      return { type: 'hbars', title: 'Ablations', aria: 'Cheating tests accepted and real exploits kept, per safeguard removed', rowH: 32, labelW: 220, groups: [mk('False proofs accepted (of 215 cheats)', 1, 162), mk('True proofs kept (of 53 real exploits)', 2, 53)], rows };
    }
    if (id === 'roles') {
      const total = d.roles.reduce((t, r) => t + r.v, 0);
      const rows = d.roles.map((r) => ({ key: r.n, label: r.n, sub: r.d, v: r.v, color: r.c, value: r.v + ' calls \u00b7 ' + Math.round(r.v / total * 100) + '%' }));
      return { type: 'hbars', title: 'Calls by role', aria: 'Model calls for each of the four roles', rowH: 48, labelW: 220, groups: [{ rows, max: d.roles[0].v }],
        rows: rows.map((r) => ({ key: r.key, label: r.label, value: r.value + ' \u00b7 ' + r.sub, n: r.v })) };
    }
    if (id === 'auth') {
      const M = [['Pull requests', 2, ''], ['Commits', 3, ''], ['Lines added', 4, ''], ['Test files touched', 5, ''], ['Median cycle', 6, ' min']];
      const groups = M.map(([title, ix, u]) => { const list = d.AG.slice().sort((a, b) => b[ix] - a[ix]); return { title, max: list[0][ix], rows: list.map((a) => ({ key: a[0], label: a[0], v: a[ix], color: a[1], value: fmt(a[ix]) + u })) }; });
      const rows = d.AG.map((a) => ({ key: a[0], label: a[0], value: a[2] + ' PRs \u00b7 ' + a[3] + ' commits \u00b7 +' + fmt(a[4]) + ' lines', n: a[2] }));
      return { type: 'hbars', title: 'Author performance', aria: 'Every author across five measures', rowH: 28, labelW: 150, groups, rows };
    }
    return null;
  }
};

