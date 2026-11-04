/* View logic for graph.html, rendered by ../dc-lite.js.
 *
 * The architecture graph comes from GET /api/graph for the current --source
 * (built from the checkout by exhibit-a scan --graph). There is no bundled
 * snapshot: another repository never sees Exhibit-A's packages.
 */
const LC = { core: '#0f2557', analysis: '#6a8fd8', surface: '#b7834f' };

window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = {
      lv: 'net', ly: 'all', sel: '', mod: null, q: '', full: false, fn: true,
      runId: '', heat: [], heatNote: '', paths: [], pathSel: -1,
      graph: null, graphNote: '',
    };
  }
  runParams() {
    try {
      const q = new URLSearchParams(window.location.search);
      return { run: q.get('run') || '', focus: q.get('focus') || '' };
    } catch (e) { return { run: '', focus: '' }; }
  }
  emptyGraph() {
    return {
      available: false, packages: [], modules: [], module_edges: [],
      package_edges: [], functions: {}, uses: [], layers: [], hotspots: {},
      stats: {}, command: 'exhibit-a scan --graph',
      reason: 'code graph is built from the repository checkout',
    };
  }
  g() { return this.state.graph || this.emptyGraph(); }
  PK() { return this.g().packages || []; }
  MODS() { return this.g().modules || []; }
  ME() { return this.g().module_edges || []; }
  PE() { return this.g().package_edges || []; }
  FN() { return this.g().functions || {}; }
  USES() { return this.g().uses || []; }
  LAYER() {
    const out = {};
    this.PK().forEach((p) => { out[p[0]] = p[2] || 'core'; });
    return out;
  }
  layerColor(id) {
    const row = (this.g().layers || []).find((l) => l.id === id);
    return (row && row.color) || LC[id] || LC.core;
  }
  async loadGraph() {
    try {
      const res = await fetch('/api/graph', { headers: { Accept: 'application/json' } });
      if (res.ok) {
        const graph = await res.json();
        const first = ((graph && graph.packages) || [])[0];
        this.setState({
          graph: graph || this.emptyGraph(),
          sel: this.state.sel || (first ? first[0] : ''),
          graphNote: (graph && graph.available) ? '' : ((graph && (graph.reason || graph.command)) || 'exhibit-a scan --graph'),
        });
        return;
      }
    } catch (e) { /* empty state stays */ }
    this.setState({ graph: this.emptyGraph(), graphNote: 'exhibit-a scan --graph' });
  }
  async loadRun() {
    const { run, focus } = this.runParams();
    if (focus) this.setState({ mod: focus });
    if (!run) return;
    this.setState({ runId: run });
    let graph = null;
    try {
      const res = await fetch('/api/runs/' + encodeURIComponent(run) + '/codegraph', { headers: { Accept: 'application/json' } });
      if (res.ok) graph = await res.json();
    } catch (e) { /* heatmap stays empty */ }
    if (!graph || !graph.available) {
      const why = graph && graph.reason ? graph.reason + '. ' : '';
      this.setState({ heatNote: 'No code graph was recorded for this run. ' + why + 'Compute one with exhibit-a scan --graph.' });
      return;
    }
    const SEVC = { low: '#6a8fd8', medium: '#b7834f', high: '#a5703f', critical: '#8f2f2f' };
    const rank = (s) => ({ '': 0, low: 1, medium: 2, high: 3, critical: 4 }[s] || 0);
    const byFile = {};
    for (const n of graph.nodes || []) {
      if (n.kind === 'file') byFile[n.id] = byFile[n.id] || { id: n.id, name: n.name || n.id, funcs: 0, proven: 0, sev: '' };
    }
    for (const n of graph.nodes || []) {
      if (!/function|method/.test(n.kind || '') || !n.file) continue;
      const fid = 'file:' + n.file;
      const cell = byFile[fid] || (byFile[fid] = { id: fid, name: n.file, funcs: 0, proven: 0, sev: '' });
      cell.funcs += 1;
    }
    for (const f of graph.findings || []) {
      const fid = 'file:' + (f.file || '');
      const cell = byFile[fid];
      if (!cell) continue;
      cell.proven += 1;
      if (rank(f.severity) > rank(cell.sev)) cell.sev = f.severity;
    }
    const files = Object.values(byFile);
    const total = Math.max(1, files.reduce((t, f) => t + Math.max(1, f.funcs), 0));
    const heat = files
      .sort((a, b) => b.proven - a.proven || b.funcs - a.funcs)
      .slice(0, 60)
      .map((f) => ({
        n: f.name, v: f.funcs + ' fn · ' + f.proven + ' proven',
        w: Math.max(3, (Math.max(1, f.funcs) / total) * 100).toFixed(1),
        c: f.proven ? (SEVC[f.sev] || '#a5703f') : '#7a86a1',
        pick: () => this.setState({ mod: f.id, pathSel: -1 }),
      }));
    const paths = (graph.proven_paths || []).slice(0, 12).map((p, i) => ({
      i, label: (p.entry || '?') + ' → ' + (p.sink || '?'),
      effect: p.effect || '', nodes: p.nodes || [],
      cls: 'sb' + (this.state.pathSel === i ? ' sb-on' : ''),
      pick: () => this.setState({ pathSel: i, mod: null }),
    }));
    this.setState({
      heat, paths,
      heatNote: heat.length ? 'Tiles sized by functions, colored by proven findings (run ' + run + ').' : 'No files in this run.',
    });
  }
  componentDidMount() {
    this.loadGraph();
    this.loadRun();
    const host = document.getElementById('gcanvas');
    if (!host || !window.DCViz) return;
    this.viz = window.DCViz.graph(host, {
      labelMin: 7.5,
      onSelect: (id) => {
        if (this.state.lv === 'pkg') this.setState({ sel: id });
        else if (id === null) this.setState({ mod: null });
        else this.setState({ mod: id, sel: this.pkgOf(id) });
      }
    });
  }
  mountNet() {
    const host = document.getElementById('ncanvas');
    if (!host || !window.DCNet || this.net) return;
    const tip = document.createElement('div');
    tip.className = 'net-tip';
    host.appendChild(tip);
    this.tip = tip;
    this.net = window.DCNet.create(host, {
      onSelect: (id) => {
        if (!id) { this.setState({ mod: null }); return; }
        if (this.state.lv === 'pkg') { this.setState({ sel: id, mod: null, fnSel: null }); return; }
        const n = this.net.node(id);
        const file = n && n.kind === 'func' ? n.parent : id;
        this.setState({ mod: file, sel: this.pkgOf(file), fnSel: n && n.kind === 'func' ? id : null });
      },
      onHover: (n, x, y) => {
        if (!n) { tip.classList.remove('net-tip-on'); return; }
        tip.textContent = n.title;
        tip.style.left = Math.round(x + 14) + 'px'; tip.style.top = Math.round(y + 14) + 'px';
        tip.classList.add('net-tip-on');
      }
    });
    this.netKey = null;
  }
  pkgNetData() {
    const PK = this.PK(), PE = this.PE();
    const max = Math.max(1, ...PK.map((p) => p[1] || 0));
    const nodes = PK.map(([n, loc, l]) => ({
      id: n, label: n, kind: 'file', layer: l || 'core', pkg: n, loc,
      r: 7 + Math.sqrt((loc || 0) / max) * 17,
      title: n + ' · ' + Number(loc || 0).toLocaleString('en-US') + ' lines',
    }));
    const edges = PE.map((e) => ({ a: e[0], b: e[1], t: 'imp', w: e[2] || 1 }));
    return { nodes, edges };
  }
  netData(withFn) {
    const MODS = this.MODS(), ME = this.ME(), LAYER = this.LAYER();
    const FN = this.FN(), USES = this.USES();
    const max = Math.max(1, ...MODS.map((m) => m[1] || 0));
    const nodes = [], edges = [];
    MODS.forEach(([n, loc, p]) => {
      const l = LAYER[p] || 'core';
      nodes.push({
        id: n, label: n.split('.').pop(), kind: 'file', layer: l, pkg: p, loc,
        r: 4.5 + Math.sqrt((loc || 0) / max) * 11,
        title: n + ' · ' + Number(loc || 0).toLocaleString('en-US') + ' lines',
      });
    });
    ME.forEach((e) => {
      if (typeof e[0] === 'number') {
        const a = MODS[e[0]], b = MODS[e[1]];
        if (a && b) edges.push({ a: a[0], b: b[0], t: 'imp' });
      } else {
        edges.push({ a: e[0], b: e[1], t: 'imp' });
      }
    });
    if (withFn) {
      const have = new Set();
      MODS.forEach(([n, , p]) => {
        const l = LAYER[p] || 'core';
        (FN[n] || []).forEach(([fname, kind, lines]) => {
          const id = n + '::' + fname;
          have.add(id);
          nodes.push({
            id, label: fname, kind: 'func', cls: kind === 'c', parent: n, layer: l, pkg: p, loc: lines,
            r: 2.2 + Math.min(3.2, Math.sqrt(lines || 0) * 0.28),
            title: (kind === 'c' ? 'class ' : 'def ') + fname + ' · ' + n + ' · ' + lines + ' lines',
          });
          edges.push({ a: n, b: id, t: 'own' });
        });
      });
      USES.forEach(([from, mod, fname]) => {
        const id = mod + '::' + fname;
        if (have.has(id) && from !== mod) edges.push({ a: from, b: id, t: 'use' });
      });
    }
    return { nodes, edges };
  }
  cur() { return this.net || { zoomBy() {}, fit() {} }; }
  pkgOf(id) {
    const m = this.MODS().find((x) => x[0] === id);
    return m ? m[2] : null;
  }
  componentDidRender() {
    const st = this.state, nv = this.net;
    this.mountNet();
    if (this.net) {
      const k = st.lv + (st.lv === 'net' && st.fn) + ':' + (this.g().available ? '1' : '0');
      if (this.netKey !== k) {
        this.netKey = k;
        this.net.set(st.lv === 'pkg' ? this.pkgNetData() : this.netData(st.lv === 'net' && st.fn));
      }
      this.net.filter(st.ly === 'all' ? null : (d) => d.layer === st.ly);
      this.net.find(st.q);
      const attack = st.pathSel >= 0 && st.paths[st.pathSel] ? st.paths[st.pathSel].nodes : null;
      const pkgFiles = st.sel ? this.MODS().filter((m) => m[2] === st.sel).map((m) => m[0]) : null;
      this.net.focus(attack && attack.length && st.lv !== 'pkg' ? attack : st.lv === 'pkg' ? (st.sel ? [st.sel] : null) : st.fnSel ? [st.fnSel] : st.mod ? [st.mod] : (st.lv === 'mod' ? pkgFiles : null));
      if (this.fullSeen !== st.full) { this.fullSeen = st.full; setTimeout(() => this.net.fit(), 60); }
      return;
    }
    const v = this.viz;
    if (!v) return;
    if (this.key !== st.lv) { this.key = st.lv; v.set(this.graphData(st.lv)); }
    v.filter(st.ly === 'all' ? null : (d) => d.layer === st.ly);
    v.find(st.q);
    if (st.lv === 'pkg') v.focus(st.sel ? [st.sel] : null);
    else if (st.mod) v.focus([st.mod]);
    else v.focus(st.sel ? this.MODS().filter((m) => m[2] === st.sel).map((m) => m[0]) : null);
    if (this.fullSeen !== st.full) { this.fullSeen = st.full; setTimeout(() => v.fit(), 60); }
  }
  graphData(lv) {
    const PK = this.PK(), PE = this.PE(), MODS = this.MODS(), ME = this.ME(), LAYER = this.LAYER();
    const maxP = Math.max(1, ...PK.map((p) => p[1] || 0));
    const maxM = Math.max(1, ...MODS.map((m) => m[1] || 0));
    if (lv === 'pkg') {
      return {
        key: 'pkg', arrows: true,
        nodes: PK.map(([n, loc, l]) => ({
          id: n, label: n, layer: l, loc,
          r: 12 + Math.sqrt((loc || 0) / maxP) * 26, color: LC[l] || LC.core,
          title: n + ' · ' + Number(loc || 0).toLocaleString('en-US') + ' lines',
        })),
        edges: PE.map((e) => ({ a: e[0], b: e[1], w: e[2] || 1 })),
      };
    }
    return {
      key: 'mod',
      nodes: MODS.map(([n, loc, p]) => {
        const l = LAYER[p] || 'core';
        return {
          id: n, label: n.split('.').pop(), layer: l, loc,
          r: 4.5 + Math.sqrt((loc || 0) / maxM) * 10, color: LC[l] || LC.core,
          title: n + ' · ' + Number(loc || 0).toLocaleString('en-US') + ' lines',
        };
      }),
      edges: ME.map((e) => {
        if (typeof e[0] === 'number') {
          const a = MODS[e[0]], b = MODS[e[1]];
          return a && b ? { a: a[0], b: b[0], w: 1 } : null;
        }
        return { a: e[0], b: e[1], w: 1 };
      }).filter(Boolean),
    };
  }
  renderVals() {
    const st = this.state;
    const PK = this.PK(), PE = this.PE(), MODS = this.MODS(), ME = this.ME(), LAYER = this.LAYER();
    const built = !!this.g().available;
    const available = !!(built && PK.length);
    const hasSummary = !!(built && !available);
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));
    const maxP = Math.max(1, ...PK.map((p) => p[1] || 0));
    const pk = PK.map(([n, loc, l]) => ({
      n, c: this.layerColor(l), w: ((loc || 0) / maxP * 100).toFixed(1),
      v: Number(loc || 0).toLocaleString('en-US'),
      op: st.ly === 'all' || st.ly === l ? 1 : 0.3,
      cls: 'pk' + (st.sel === n ? ' pk-on' : ''),
      pick: () => this.setState({ sel: n, mod: null }),
    }));
    const layerRows = this.g().layers || [];
    const layerTotal = layerRows.reduce((t, l) => t + (l.lines || 0), 0) || 1;
    const layers = layerRows.map((l) => ({
      name: l.name || l.id, c: l.color || this.layerColor(l.id),
      fg: l.fg || '#ffffff', d: l.detail || '',
      loc: Number(l.lines || 0).toLocaleString('en-US') + ' lines',
      pct: ((l.lines || 0) / layerTotal * 100).toFixed(1),
      pctL: Math.round((l.lines || 0) / layerTotal * 100) + '%',
    }));
    const rank = (arr) => {
      const m = (arr[0] && arr[0][1]) || 1;
      return (arr || []).map(([mm, v]) => ({
        m: mm, v: v > 999 ? (v / 1000).toFixed(1) + 'k' : String(v),
        pct: (v / m * 100).toFixed(0),
      }));
    };
    const hs = this.g().hotspots || {};
    const hot = [
      { t: 'Most depended on', d: 'Modules imported by the most other modules.', c: '#0f2557', rows: rank(hs.depended || []) },
      { t: 'Orchestrators', d: 'Modules that pull in the most others to do their job.', c: '#2c4fc4', rows: rank(hs.orchestrators || []) },
      { t: 'Heaviest modules', d: 'Lines of code in a single file.', c: '#b7834f', rows: rank(hs.heaviest || []) },
    ].filter((h) => h.rows.length);
    const lvl = st.lv, nm = lvl === 'pkg' ? st.sel : (st.mod || st.sel);
    let det = { on: false };
    if (nm && available) {
      let deps = [], users = [], meta = '';
      if (lvl === 'pkg' || !st.mod) {
        const w = (list, from, to) => list.filter((e) => e[from] === nm).map((e) => [e[to], e[2] || 1]).sort((a, b) => b[1] - a[1]);
        deps = w(PE, 0, 1); users = w(PE, 1, 0);
        const p = PK.find((x) => x[0] === nm);
        meta = p ? (p[2] || '').replace('surface', 'surfaces') + ' layer · ' + Number(p[1] || 0).toLocaleString('en-US') + ' lines · ' + MODS.filter((m) => m[2] === nm).length + ' modules' : '';
        det = {
          on: !!p, n: nm, c: p ? (LC[p[2]] || LC.core) : LC.core, meta,
          deps: deps.map(([n, c]) => ({ n: n + ' ×' + c, pick: () => this.setState({ sel: n, mod: null }) })),
          users: users.map(([n, c]) => ({ n: n + ' ×' + c, pick: () => this.setState({ sel: n, mod: null }) })),
        };
      } else {
        const i = MODS.findIndex((m) => m[0] === nm);
        deps = ME.filter((e) => (typeof e[0] === 'number' ? e[0] === i : e[0] === nm))
          .map((e) => (typeof e[1] === 'number' ? (MODS[e[1]] || [''])[0] : e[1]));
        users = ME.filter((e) => (typeof e[1] === 'number' ? e[1] === i : e[1] === nm))
          .map((e) => (typeof e[0] === 'number' ? (MODS[e[0]] || [''])[0] : e[0]));
        const m = MODS[i];
        det = {
          on: i >= 0, n: nm, c: LC[LAYER[m && m[2]] || 'core'],
          meta: m ? m[2] + ' package · ' + Number(m[1] || 0).toLocaleString('en-US') + ' lines' : '',
          deps: deps.map((n) => ({ n, pick: () => this.setState({ mod: n, sel: this.pkgOf(n) }) })),
          users: users.map((n) => ({ n, pick: () => this.setState({ mod: n, sel: this.pkgOf(n) }) })),
        };
      }
      det.hasDeps = deps.length > 0; det.hasUsers = users.length > 0;
      det.nDeps = deps.length; det.nUsers = users.length;
    }
    const heat = st.heat.length ? st.heat : [];
    const hasRun = !!st.runId || !!this.runParams().run;
    const stats = this.g().stats || {};
    const fmt = (n) => n == null ? '—' : (n >= 10000 ? (n / 1000).toFixed(1) + 'k' : Number(n).toLocaleString('en-US'));
    const tot = built ? [
      { i: 'M21 8 12 3 3 8v8l9 5 9-5V8ZM3 8l9 5 9-5M12 13v8', l: 'Packages', v: String(stats.packages || PK.length), u: 'top-level folders' },
      { i: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5ZM14 3v5h5M9 13h6M9 17h4', l: 'Modules', v: String(stats.modules || MODS.length), u: 'source files' },
      { i: 'M5 12h14M13 6l6 6-6 6M5 5v14', l: 'Imports', v: String(stats.imports || ME.length), u: 'internal dependencies' },
      { i: 'M4 6h16M4 12h16M4 18h10', l: 'Lines', v: fmt(stats.lines), u: (stats.functions ? fmt(stats.functions) + ' functions' : 'counted from the checkout') },
    ] : [];
    const heatNote = st.heatNote || (hasRun
      ? 'The recorded code graph carries no file heat for this run.'
      : (available ? 'Open a run report to see its recorded files and proven attack paths.'
        : 'No code graph for this source yet. Compute one with exhibit-a scan --graph.'));
    const heatEmpty = heat.length === 0;
    this.__d = { P: PK, LC, layers: layerRows };
    const lyKeys = [['all', 'All']].concat([...new Set(PK.map((p) => p[2] || 'core'))].map((k) => [k, k === 'core' ? 'Core' : k === 'analysis' ? 'Analysis' : k === 'surface' ? 'Surfaces' : k]));
    return {
      det, q: st.q, onQ: (e) => this.setState({ q: e.target.value }),
      heat, heatNote, heatEmpty, hasRun, noRun: !hasRun, paths: st.paths, hasPaths: st.paths.length > 0, runId: st.runId,
      zin: () => this.cur().zoomBy(1.35), zout: () => this.cur().zoomBy(1 / 1.35), zfit: () => this.cur().fit(),
      nDisp: 'block', gDisp: 'none', fnDisp: st.lv === 'net' ? 'inline-flex' : 'none',
      fnOpts: [[true, 'Functions on'], [false, 'Files only']].map(([k, l]) => ({ l, cls: 'sb' + (st.fn === k ? ' sb-on' : ''), pick: () => this.setState({ fn: k }) })),
      gfull: st.full ? 'gfull' : '', full: String(st.full), fullL: st.full ? 'Close expanded view' : 'Expand', toggleFull: () => this.setState({ full: !st.full }),
      tot, layers, hot, pk, hasGraph: available, noGraph: !built, hasSummary,
      graphCmd: this.g().command || 'exhibit-a scan --graph',
      graphNote: st.graphNote || this.g().reason || '',
      lvOpts: [['net', 'Network'], ['pkg', 'Packages'], ['mod', 'Modules']].map(([k, l]) => ({ l, cls: 'sb' + (st.lv === k ? ' sb-on' : ''), pick: () => this.setState({ lv: k, mod: null }) })),
      lyOpts: opt(lyKeys, 'ly'),
    };
  }

  fullSpec(id) {
    const d = this.__d;
    if (!d || id !== 'layers') return null;
    const names = { core: 'Proof core', analysis: 'Analysis', surface: 'Surfaces' };
    const total = (d.P || []).reduce((t, p) => t + p[1], 0) || 1;
    const max = Math.max(1, ...(d.P || []).map((p) => p[1] || 0));
    const ids = [...new Set((d.P || []).map((p) => p[2] || 'core'))];
    const groups = ids.map((l) => {
      const list = d.P.filter((p) => p[2] === l).sort((a, b) => b[1] - a[1]);
      const sum = list.reduce((t, p) => t + p[1], 0);
      return {
        title: names[l] || l, note: sum.toLocaleString('en-US') + ' lines · ' + Math.round(sum / total * 100) + '%', max,
        rows: list.map((p) => ({
          key: p[0], label: p[0], sub: Math.round(p[1] / total * 1000) / 10 + '% of the code',
          v: p[1], color: d.LC[l] || '#0f2557', value: p[1].toLocaleString('en-US'),
        })),
      };
    });
    const rows = d.P.slice().sort((a, b) => b[1] - a[1]).map((p) => ({
      key: p[0], label: p[0] + ' · ' + (names[p[2]] || p[2]),
      value: p[1].toLocaleString('en-US') + ' lines', n: p[1],
    }));
    return { type: 'hbars', title: 'Lines of code by layer', aria: 'Every package by layer', rowH: 30, labelW: 170, groups, rows };
  }
};
