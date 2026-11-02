/* View logic for index.html, rendered by ../dc-lite.js. */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { vel: 'prs', don: 'effect', fun: 'abs' };
  }
  renderVals() {
    const st = this.state;
    const AG = [['claude', '#0f2557'], ['Muse', '#2c4fc4'], ['Copilot', '#6a8fd8'], ['assistant', '#9aa3e0'], ['unlogged', '#c3cbd8'],
      ['gemini', '#4b3fa0'], ['grok', '#b7834f'], ['agy', '#d9b98f'], ['cursor-agent', '#7f97b8'], ['claude-cloud', '#4a5873']];
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));

    const DAYS = [
      ['Oct 27', { agy: 3, claude: 8, Muse: 6, unlogged: 12, assistant: 4, Copilot: 5, 'cursor-agent': 1 }, 12720],
      ['Oct 28', { assistant: 2, 'cursor-agent': 1, Copilot: 3, unlogged: 3, Muse: 3, claude: 3 }, 2418],
      ['Oct 29', { claude: 12, assistant: 7, Copilot: 2, Muse: 4 }, 8148],
      ['Oct 30', { claude: 4, Muse: 1, assistant: 1, 'claude-cloud': 1 }, 9753],
      ['Oct 31', { grok: 3, claude: 5, Muse: 6, gemini: 4, Copilot: 5, assistant: 2 }, 43569],
      ['Nov 1', { agy: 1, Muse: 6, Copilot: 7, grok: 4, gemini: 4, assistant: 1 }, 54438]
    ];
    const isP = st.vel === 'prs';
    const top = isP ? 40 : 60000, B = 250, T = 30;
    const ys = (v) => B - (v / top) * (B - T);
    const band = (676 - 44) / 6, bw = 58;
    const days = DAYS.map(([label, m, lines], i) => {
      const x = 44 + band * i + (band - bw) / 2;
      const segs = []; let acc = 0;
      if (isP) { AG.forEach(([n, c]) => { const v = m[n] || 0; if (!v) return; segs.push({ x, y: ys(acc + v), w: bw, h: Math.max(0, ys(acc) - ys(acc + v) - 1), c, t: n + ': ' + v }); acc += v; }); }
      else { acc = lines; segs.push({ x, y: ys(lines), w: bw, h: B - ys(lines), c: '#2c4fc4', t: lines.toLocaleString('en-US') + ' lines' }); }
      return { label, segs, cx: x + bw / 2, ty: ys(acc) - 9, v: isP ? String(acc) : (acc / 1000).toFixed(1) + 'k' };
    });
    const ticks = isP ? [0, 10, 20, 30, 40] : [0, 20000, 40000, 60000];
    const vel = { days, legend: isP, yt: isP ? 'Pull requests' : 'Lines added', aria: isP ? 'Pull requests merged per day by agent' : 'Lines added per day',
      grid: ticks.map((v) => ({ y: ys(v), ty: ys(v) + 4, l: isP ? String(v) : (v / 1000) + 'k' })) };

    const kpis = [
      { l: 'Proven findings', v: '30', u: 'of 44', p: 68, c: '#2c4fc4', d: 'Every one ships an exploit test and a verified fix.' },
      { l: 'False accusations', v: '0', u: 'naive LLM: 1', p: 0, c: '#0f2557', d: 'The patched Starlette release was never reported.' },
      { l: 'Precision', v: '0.86', u: 'recall 0.68', p: 86, c: '#6a8fd8', d: '25 of 29 reports matched the expected class.' },
      { l: 'Model spend', v: '$2.42', u: 'of $4.00', p: 60.5, c: '#b7834f', d: 'About eight cents for each proven finding.' }
    ];
    const minor = [
      { v: '18', l: 'held-out cases never used for tuning' }, { v: '3', l: 'languages: Python, JavaScript, TypeScript' },
      { v: '8', l: 'oracle effects the engine can observe' }, { v: '13', l: 'CWE classes in the corpus' },
      { v: '142', l: 'model calls across four roles' }, { v: '223k', l: 'tokens in and out' }
    ];
    const flow = [
      { l: 'Peak day', v: '39 PRs', d: 'Oct 27 — scaffold, ledger, oracle and sandbox.' },
      { l: 'Median cycle', v: '8 min', d: 'From first commit to merge. 90% close within 50 minutes.' },
      { l: 'Largest merge', v: '23.7k lines', d: 'T112, the ablation table with its generated results.' }
    ];

    const EFF = [['Command exec', 9, '#0f2557'], ['File read', 7, '#2c4fc4'], ['SQL read', 6, '#6a8fd8'], ['File write', 5, '#9aa3e0'], ['Access bypass', 2, '#b7834f'], ['SSRF', 1, '#d9b98f']];
    const VER = [['Proven', 30, '#0f2557'], ['Invalid test', 9, '#9aa3e0'], ['Discarded', 5, '#c3cbd8']];
    const src = st.don === 'effect' ? EFF : VER;
    const total = src.reduce((t, s) => t + s[1], 0);
    let a = -Math.PI / 2;
    const P = (r, t) => (100 + r * Math.cos(t)).toFixed(2) + ' ' + (100 + r * Math.sin(t)).toFixed(2);
    const segs = src.map(([n, v, c]) => {
      const s = a, e = a + (v / total) * Math.PI * 2; a = e;
      const lg = e - s > Math.PI ? 1 : 0;
      return { n, v, c, pc: Math.round(v / total * 100) + '%', t: n + ': ' + v,
        d: 'M' + P(96, s) + ' A96 96 0 ' + lg + ' 1 ' + P(96, e) + ' L' + P(70, e) + ' A70 70 0 ' + lg + ' 0 ' + P(70, s) + ' Z' };
    });
    const don = { segs, total, cap: st.don === 'effect' ? 'PROVEN' : 'SUSPICIONS' };

    const FUN = [['Suspicions', 44, '#c3cbd8'], ['Exploits written', 44, '#9aa3e0'], ['Proven', 30, '#2c4fc4'], ['Fix verified', 30, '#16307a'], ['Bypass-resistant', 26, '#0a1840']];
    const fun = FUN.map(([l, v, c]) => ({ l, c, w: (v / 44 * 100).toFixed(1), v: st.fun === 'abs' ? String(v) : Math.round(v / 44 * 100) + '%' }));

    const latest = [['T131', 'Frontend implementation', 'agy'], ['T128', 'Loop integration for JS/TS', 'Muse'], ['T138', 'Node HTTP attribution red team', 'Copilot'],
      ['T136', 'Judge the JS/TS corpus', 'grok'], ['T126', 'Node red team: 20+ attacks', 'Muse']].map(([id, t, a]) => ({ id, t, a }));
    const code = [{ v: '19', l: 'packages' }, { v: '120', l: 'modules' }, { v: '1,052', l: 'functions' }, { v: '1,932', l: 'test functions' }];

    return { kpis, minor, flow, vel, velOpts: opt([['prs', 'PRs'], ['lines', 'Lines']], 'vel'), agents: AG.map(([n, c]) => ({ n, c })),
      don, donT: st.don === 'effect' ? 'effect' : 'verdict', donOpts: opt([['effect', 'Effect'], ['verdict', 'Verdict']], 'don'),
      fun, funOpts: opt([['abs', 'Count'], ['pct', '%']], 'fun'), latest, code };
  }
};
