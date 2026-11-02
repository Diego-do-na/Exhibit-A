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
      { l: 'False accusations', a: '0', b: '1', d: 'Only the naive model reported the already-patched Starlette release.' },
      { l: 'Precision', a: '0.86', b: '0.67', d: 'Share of reports that pointed at a real vulnerability.' },
      { l: 'Cost per report', a: '$0.15', b: '$0.02', d: 'Each Exhibit A report includes an exploit test and a verified fix.' }
    ];
    const SYS = [['Naive LLM', '#c3cbd8', 0.67, 1.0, 3, 0.0708], ['Exhibit A · compact', '#0f2557', 0.86, 0.68, 29, 2.2727], ['Exhibit A · standard', '#6a8fd8', 0, 0, 0, 4.7824]];
    const SM = { prec: [2, 1, (v) => v.toFixed(2), 'Precision is the share of reports that were real. The compact profile kept it high across 29 reports.'],
      rec: [3, 1, (v) => v.toFixed(2), 'Recall is the share of known vulnerabilities found. The naive model was only scored on three targets, which makes its 1.00 easy to reach.'],
      rep: [4, 29, (v) => String(v), 'Number of findings reported. The standard profile proved nothing live, so it reported nothing.'],
      cost: [5, 4.7824, (v) => '$' + v.toFixed(2), 'Total model spend for the run. Proof costs more than a guess; the standard profile spent the most and proved nothing.'] };
    const [ix, mx, f, note] = SM[st.sm];
    const sm = SYS.map((s) => ({ n: s[0], c: s[1], v: s[0].endsWith('standard') && st.sm === 'prec' ? 'n/a' : f(s[ix]), w: (s[ix] / mx * 100).toFixed(1) }));
    const buy = [{ l: 'Reports still to triage', a: '0', b: '3' }, { l: 'Exploit tests written', a: '2', b: '0' }, { l: 'Fixes verified', a: '2', b: '0' },
      { l: 'Cost per report', a: '$0.15', b: '$0.02' }, { l: 'Extra spend per target', a: '$0.08', b: '—' }];

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

    return { ek, smOpts: opt([['prec', 'Precision'], ['rec', 'Recall'], ['rep', 'Reports'], ['cost', 'Cost']], 'sm'), sm, smNote: note, buy,
      abOpts: opt([['fp', 'False proofs'], ['tp', 'True proofs']], 'ab'), ab, abIns, roles, econ,
      m: st.m, mOpts, onM: (e) => this.setState({ m: e.target.value }), ag, score, pf };
  }
};
