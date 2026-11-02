/* View logic for findings.html, rendered by ../dc-lite.js. */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { by: 'effect', sc: 'abs', v: 'all', e: 'all', sel: 'sql-injection-search' };
  }
  renderVals() {
    const VC = { P: '#0f2557', I: '#9aa3e0', D: '#c3cbd8' };
    const VN = { P: 'Proven', I: 'Invalid test', D: 'Discarded' };
    const EN = { exec: 'Command exec', read: 'File read', sql: 'SQL read', write: 'File write', access: 'Access bypass', connect: 'SSRF', redirect: 'Open redirect', dos: 'Denial of service' };
    const RS = { pr: 'The canary file was read by application code reached through a real entry point.', pw: 'The canary file was written by application code reached through a real entry point.',
      px: 'The canary was executed by a process that application code started.', ps: 'The canary row was read from the database through a real entry point.',
      pa: "The application handed the victim's token to the attacker.", pc: 'Application code requested the canary URL from inside the sandbox.',
      nf: 'The exploit worked, but no fix could be verified, so nothing was reported.', ne: 'The test passed and the canary was never touched.',
      nr: 'The application redirected, but the test did not fail.', pv: 'The canary was reached through a symlink the test created: invalid provenance.',
      pn: 'The canary was written with no application code on the stack.', wr: 'The test failed, but for the wrong reason: the canary row was never read.',
      d1: 'The slowdown was 40.6×, short of the 50× threshold.', d2: 'The test timed out before the entry point could be timed.', tw: 'The test tried to choose where the application is rooted.' };
    const C = [
      ['archive-extraction-pathtraversal', 'py', 0, 'CWE-22', 'write', 0.0597, 4, [['P', 'pw']]],
      ['command-injection-ping', 'py', 1, 'CWE-78', 'exec', 0.0641, 4, [['D', 'nf']]],
      ['command-injection-shell', 'py', 0, 'CWE-78', 'exec', 0.0605, 4, [['P', 'px']]],
      ['docsuite-large-command-injection', 'py', 1, 'CWE-78', 'exec', 0.1052, 7, [['P', 'px'], ['P', 'px']]],
      ['express-command-injection-ts', 'js', 1, 'CWE-78', 'exec', 0.0770, 4, [['P', 'px']]],
      ['express-command-injection', 'js', 0, 'CWE-78', 'exec', 0.0829, 4, [['P', 'px']]],
      ['express-download-traversal-ts', 'js', 1, 'CWE-22', 'read', 0.0753, 4, [['P', 'pr']]],
      ['express-download-traversal', 'js', 0, 'CWE-22', 'read', 0.0649, 4, [['P', 'pr']]],
      ['idor-document-fetch', 'py', 1, 'CWE-639', 'access', 0.0768, 4, [['P', 'pa']]],
      ['idor-export-download', 'py', 1, 'CWE-639', 'access', 0.0674, 4, [['P', 'pa']]],
      ['log-viewer-traversal', 'py', 1, 'CWE-22', 'read', 0.0487, 4, [['P', 'pr']]],
      ['open-redirect-continue', 'py', 1, 'CWE-601', 'redirect', 0.0662, 5, [['D', 'nf'], ['D', 'nr']]],
      ['open-redirect-next', 'py', 1, 'CWE-601', 'redirect', 0.0515, 4, [['D', 'nf']]],
      ['redos-search-query', 'py', 1, 'CWE-407', 'dos', 0.0230, 2, [['I', 'd1']]],
      ['redos-username-check', 'py', 1, 'CWE-1333', 'dos', 0.0190, 2, [['I', 'd2']]],
      ['report-export-write', 'py', 1, 'CWE-73', 'write', 0.0522, 4, [['P', 'pw']]],
      ['sql-injection-filter', 'py', 1, 'CWE-89', 'sql', 0.0442, 4, [['P', 'ps']]],
      ['sql-injection-login', 'py', 0, 'CWE-89', 'sql', 0.0944, 7, [['P', 'ps'], ['P', 'ps']]],
      ['sql-injection-search', 'py', 0, 'CWE-89', 'sql', 0.1698, 10, [['P', 'ps'], ['P', 'ps'], ['P', 'ps']]],
      ['sql-trunc-kind-injection', 'py', 1, 'CWE-89', 'sql', 0.0616, 3, [['I', 'wr'], ['I', 'wr']]],
      ['ssrf-webhook-fetch', 'py', 1, 'CWE-918', 'connect', 0.0696, 4, [['P', 'pc']]],
      ['ssti-email-template', 'py', 1, 'CWE-1336', 'exec', 0.0684, 4, [['P', 'px']]],
      ['ssti-jinja-preview', 'py', 0, 'CWE-1336', 'exec', 0.0598, 4, [['P', 'px']]],
      ['starlette-cve-2023-29159-fixed', 'py', 0, 'CWE-22', 'read', 0.2834, 6, [['D', 'ne'], ['I', 'pv'], ['P', 'pr']]],
      ['starlette-cve-2023-29159', 'py', 0, 'CWE-22', 'read', 0.1106, 4, [['P', 'pr']]],
      ['static-route-traversal', 'py', 1, 'CWE-22', 'read', 0.1161, 6, [['I', 'pv'], ['P', 'pr'], ['I', 'pv']]],
      ['tar-slip-restore', 'py', 0, 'CWE-22', 'write', 0.1356, 8, [['P', 'pw'], ['I', 'tw'], ['P', 'pw']]],
      ['unsafe-deserialization-pickle', 'py', 0, 'CWE-502', 'exec', 0.0463, 4, [['P', 'px']]],
      ['upload-avatar', 'py', 0, 'CWE-434', 'write', 0.0479, 4, [['P', 'pw']]],
      ['upload-filename-traversal', 'py', 1, 'CWE-73', 'write', 0.0279, 2, [['I', 'pn']]],
      ['xxe-catalog', 'py', 0, 'CWE-611', 'read', 0.0527, 4, [['P', 'pr']]],
      ['yaml-job-load', 'py', 0, 'CWE-502', 'exec', 0.0373, 4, [['P', 'px']]]
    ].map(([cs, lang, held, cwe, eff, cost, calls, vs]) => ({ cs, lang, held, cwe, eff, cost, calls, vs }));
    const st = this.state;
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));

    const tot = [
      { l: 'Suspicions', v: '44', d: 'Raised by the adversary role across 32 applications.' },
      { l: 'Proven', v: '30', d: 'Each with an exploit test and a fix verified in the sandbox.' },
      { l: 'Refused', v: '14', d: 'Stopped by the oracle with a named reason.' },
      { l: 'Fix incomplete', v: '4', d: 'Proven and fixed, but a defender variant still got through.' }
    ];

    const grp = {};
    C.forEach((c) => { const k = st.by === 'effect' ? EN[c.eff] : c.cwe; grp[k] = grp[k] || { P: 0, I: 0, D: 0 }; c.vs.forEach((v) => { grp[k][v[0]]++; }); });
    const ents = Object.entries(grp).map(([n, o]) => [n, o, o.P + o.I + o.D]).sort((a, b) => b[2] - a[2]);
    const mx = ents[0][2];
    const out = ents.map(([n, o, t]) => ({ n, t, parts: ['P', 'I', 'D'].filter((k) => o[k]).map((k) => ({
      w: (st.sc === 'abs' ? o[k] / mx : o[k] / t) * 100, c: VC[k], fg: k === 'P' ? '#ffffff' : '#0d1b3e',
      l: st.sc === 'abs' ? String(o[k]) : Math.round(o[k] / t * 100) + '%', t: VN[k] + ': ' + o[k] })) }));
    const insights = [
      { v: '9 / 10', l: 'Command exec', d: 'Nine of ten command-execution suspicions were proven, across Python, JavaScript and TypeScript. The tenth worked, but its fix could not be verified.' },
      { v: '0 / 3', l: 'Open redirect', d: 'The redirect happened, but no fix could be verified, so none of these reached a verdict of proven.' },
      { v: '0 / 2', l: 'Denial of service', d: 'The slowdowns were real but stayed below the 50× threshold the oracle requires.' }
    ];

    const why = [['Effect never observed', 6, '#4b3fa0', 'The test failed or passed, but the oracle never saw the canary being touched. Without the effect, there is no proof.'],
      ['Invalid provenance', 4, '#2c4fc4', 'The effect happened, but not through application code. Symlink tricks and test-side writes are rejected.'],
      ['No verified fix', 3, '#6a8fd8', 'The exploit worked, but no patch passed verification. A finding without a working fix is held back.'],
      ['Guard tripwire', 1, '#b7834f', 'The test tried to choose where the application lives. The guard flagged it before it could cheat.']]
      .map(([n, v, c, d]) => ({ n, v, c, d, w: (v / 6 * 100).toFixed(0), pc: Math.round(v / 14 * 100) + '% of refusals' }));

    const rate = (f) => { let p = 0, t = 0; C.filter(f).forEach((c) => c.vs.forEach((x) => { t++; if (x[0] === 'P') p++; })); return [p, t]; };
    const row = (n, f, c) => { const [p, t] = rate(f); return { n, c, pc: Math.round(p / t * 100) + '%', of: p + ' of ' + t }; };
    const gen = [
      { t: 'Held-out versus tuning set', rows: [row('Held-out cases', (c) => c.held, '#2c4fc4'), row('Tuning set', (c) => !c.held, '#0f2557')] },
      { t: 'Python versus JavaScript and TypeScript', rows: [row('Python', (c) => c.lang === 'py', '#6a8fd8'), row('JavaScript / TypeScript', (c) => c.lang === 'js', '#4b3fa0')] }
    ];

    const sorted = C.slice().sort((a, b) => b.cost - a.cost);
    const cy = (v) => 210 - (v / 0.3) * 180;
    const bw = (676 - 48) / sorted.length;
    const outc = (c) => c.vs.some((x) => x[0] === 'P') ? 'P' : c.vs.some((x) => x[0] === 'I') ? 'I' : 'D';
    const cost = { grid: [0, 0.1, 0.2, 0.3].map((v) => ({ y: cy(v), ty: cy(v) + 4, l: '$' + v.toFixed(2) })),
      bars: sorted.map((c, i) => ({ x: 48 + i * bw + 2, w: bw - 4, y: cy(c.cost), h: 210 - cy(c.cost), c: st.sel === c.cs ? '#b7834f' : VC[outc(c)],
        t: c.cs + ' · $' + c.cost.toFixed(3), pick: () => this.setState({ sel: c.cs }) })) };
    const costs = C.map((c) => c.cost).sort((a, b) => a - b);
    const cstats = [{ v: '$0.076', l: 'average per case' }, { v: '$' + costs[16].toFixed(3), l: 'median per case' },
      { v: '$0.283', l: 'highest, the patched Starlette release' }, { v: '$0.019', l: 'lowest, a ReDoS case' }];

    const list = C.filter((c) => (st.v === 'all' || c.vs.some((x) => x[0] === st.v)) && (st.e === 'all' || c.eff === st.e));
    const vOpts = [['all', 'All verdicts'], ['P', 'Proven'], ['I', 'Invalid test'], ['D', 'Discarded']].map(([k, l]) => ({ k, l }));
    const eOpts = [{ k: 'all', l: 'All effects' }].concat(Object.keys(EN).map((k) => ({ k, l: EN[k] })));
    const rows = list.map((c) => ({ case: c.cs, cwe: c.cwe, eff: EN[c.eff], vs: c.vs.map((x) => ({ c: VC[x[0]], t: VN[x[0]] })),
      cls: 'frow' + (st.sel === c.cs ? ' frow-on' : ''), pick: () => this.setState({ sel: c.cs }) }));
    const s0 = C.find((c) => c.cs === st.sel) || C[0];
    const sel = { case: s0.cs, cwe: s0.cwe, eff: EN[s0.eff], held: s0.held ? 'Held-out' : 'Tuning set', n: s0.vs.length, calls: s0.calls, cost: '$' + s0.cost.toFixed(2),
      vs: s0.vs.map((x) => ({ c: VC[x[0]], v: VN[x[0]], r: RS[x[1]] })) };

    return { tot, outT: st.by === 'effect' ? 'effect' : 'CWE', byOpts: opt([['effect', 'Effect'], ['cwe', 'CWE']], 'by'), scOpts: opt([['abs', 'Count'], ['pct', '%']], 'sc'),
      out, insights, why, gen, cost, cstats, v: st.v, e: st.e, vOpts, eOpts, onV: (ev) => this.setState({ v: ev.target.value }), onE: (ev) => this.setState({ e: ev.target.value }),
      rows, empty: rows.length === 0, sel };
  }
};
