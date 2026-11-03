/* View logic for graph.html, rendered by ../dc-lite.js. */
const LC = { core: '#0f2557', analysis: '#6a8fd8', surface: '#b7834f' };
// Packages: [name, lines, layer]. Lines per package as reported on this page.
const PK = [['oracle', 5971, 'core'], ['graph', 3063, 'analysis'], ['dashboard', 3017, 'surface'], ['advisory', 2918, 'analysis'], ['cli', 2800, 'surface'],
  ['sandbox', 2182, 'core'], ['loop', 1958, 'core'], ['report', 1576, 'surface'], ['models', 1206, 'core'], ['live', 828, 'surface'], ['ci', 809, 'surface'],
  ['findings', 675, 'analysis'], ['ledger', 612, 'core'], ['schemas', 594, 'core'], ['triage', 455, 'analysis'], ['audit', 453, 'analysis'],
  ['attest', 413, 'analysis'], ['scan', 283, 'analysis'], ['install', 80, 'core']];
const LAYER = Object.fromEntries(PK.map(([n, , l]) => [n, l]));
// Snapshot taken on 2026-11-02 from an ast walk of src/exhibit_a: modules as [name, lines, package],
// imports between modules as [from, to] indexes into MODS, imports between packages as [from, to, count].
const GRAPH = {"mod":[["exhibit_a",3,"-"],["__main__",7,"__main__"],["advisory",70,"advisory"],["advisory.deps",224,"advisory"],["advisory.deps_report",400,"advisory"],["advisory.enrich",274,"advisory"],["advisory.graph_reach",274,"advisory"],["advisory.osv",421,"advisory"],["advisory.proof",537,"advisory"],["advisory.reachability",131,"advisory"],["advisory.report",157,"advisory"],["advisory.symbols",238,"advisory"],["advisory.version",192,"advisory"],["attest",60,"attest"],["attest.keys",81,"attest"],["attest.manifest",272,"attest"],["audit",20,"audit"],["audit.audit",279,"audit"],["audit.rank",154,"audit"],["ci",11,"ci"],["ci.fixpr",179,"ci"],["ci.gate",200,"ci"],["ci.summary",419,"ci"],["cli",35,"cli"],["cli.__main__",7,"cli"],["cli.advisories",88,"cli"],["cli.dashboard",30,"cli"],["cli.ext",36,"cli"],["cli.ext.audit",161,"cli"],["cli.ext.deps",105,"cli"],["cli.ext.doctor",269,"cli"],["cli.ext.reproduce",246,"cli"],["cli.ext.sarif",60,"cli"],["cli.ext.sbom",111,"cli"],["cli.ext.variants",379,"cli"],["cli.ext.verify",77,"cli"],["cli.ledger",21,"cli"],["cli.parser",225,"cli"],["cli.report",27,"cli"],["cli.run",674,"cli"],["cli.runs",57,"cli"],["cli.scan",169,"cli"],["cli.trace",23,"cli"],["dashboard",55,"dashboard"],["dashboard.__main__",6,"dashboard"],["dashboard.export",185,"dashboard"],["dashboard.model",1491,"dashboard"],["dashboard.server",603,"dashboard"],["dashboard.sources",688,"dashboard"],["findings",30,"findings"],["findings.dedupe",433,"findings"],["findings.explain",212,"findings"],["graph",25,"graph"],["graph.build",934,"graph"],["graph.catalog",610,"graph"],["graph.js",11,"graph"],["graph.js_catalog",115,"graph"],["graph.js_graph",155,"graph"],["graph.reach",301,"graph"],["graph.slicer",211,"graph"],["graph.variants",701,"graph"],["install",80,"install"],["ledger",10,"ledger"],["ledger.index",63,"ledger"],["ledger.ledger",115,"ledger"],["ledger.trace",424,"ledger"],["live",36,"live"],["live.replay",158,"live"],["live.server",350,"live"],["live.summary",284,"live"],["loop",23,"loop"],["loop.pipeline",971,"loop"],["loop.prompts",562,"loop"],["loop.runner",402,"loop"],["models",50,"models"],["models.base",106,"models"],["models.baseten",138,"models"],["models.config",185,"models"],["models.cost",53,"models"],["models.errors",25,"models"],["models.http",83,"models"],["models.jsonschema",225,"models"],["models.meta",80,"models"],["models.ollama",52,"models"],["models.openai_compat",115,"models"],["models.record",30,"models"],["models.replay",64,"models"],["oracle",17,"oracle"],["oracle.canary_server",142,"oracle"],["oracle.guard",1064,"oracle"],["oracle.guard_node",127,"oracle"],["oracle.js",54,"oracle"],["oracle.layers",85,"oracle"],["oracle.oracle",2293,"oracle"],["oracle.plugin",1966,"oracle"],["oracle.provenance",223,"oracle"],["report",29,"report"],["report.cwe",342,"report"],["report.report",458,"report"],["report.sarif",446,"report"],["report.sbom",301,"report"],["sandbox",19,"sandbox"],["sandbox.image",92,"sandbox"],["sandbox.image_node",122,"sandbox"],["sandbox.runner",1542,"sandbox"],["sandbox.witness",53,"sandbox"],["sandbox.witness.supervisor",354,"sandbox"],["scan",283,"scan"],["schemas",30,"schemas"],["schemas.advisory",219,"schemas"],["schemas.base",9,"schemas"],["schemas.events",36,"schemas"],["schemas.graph",136,"schemas"],["schemas.repo_profile",28,"schemas"],["schemas.run_index",55,"schemas"],["schemas.suspicion",25,"schemas"],["schemas.verdict",56,"schemas"],["triage",10,"triage"],["triage.assess",244,"triage"],["triage.diffparse",201,"triage"]],"me":[[1,23],[2,3],[2,5],[2,7],[2,9],[2,10],[2,12],[3,12],[4,3],[4,6],[4,7],[4,8],[4,9],[4,10],[4,11],[4,52],[4,62],[4,71],[4,74],[4,78],[4,109],[4,112],[6,11],[6,54],[6,58],[6,109],[6,112],[7,3],[7,12],[8,59],[8,61],[8,62],[8,71],[8,73],[8,74],[8,108],[8,109],[8,112],[9,109],[10,3],[10,7],[10,9],[10,12],[10,109],[11,7],[13,14],[13,15],[15,0],[16,17],[16,18],[17,18],[17,52],[17,59],[17,62],[17,71],[17,74],[17,78],[17,112],[18,112],[20,119],[22,49],[22,62],[22,108],[23,25],[23,26],[23,36],[23,37],[23,38],[23,39],[23,40],[23,41],[24,23],[25,2],[28,17],[28,39],[28,52],[28,70],[28,93],[29,2],[29,4],[29,39],[30,104],[31,13],[31,71],[31,73],[32,99],[33,5],[33,100],[33,109],[34,39],[34,50],[34,52],[34,59],[34,60],[34,62],[34,71],[34,74],[34,78],[35,13],[36,62],[37,25],[37,26],[37,27],[37,36],[37,38],[37,39],[37,40],[37,41],[37,42],[37,77],[37,93],[38,96],[39,22],[39,41],[39,52],[39,57],[39,59],[39,61],[39,62],[39,70],[39,74],[39,77],[39,91],[39,107],[39,108],[39,112],[40,63],[41,39],[41,52],[41,56],[41,57],[41,107],[41,108],[41,112],[42,65],[43,45],[43,46],[43,47],[43,48],[44,47],[45,46],[45,48],[46,21],[46,22],[46,48],[46,52],[46,65],[46,93],[46,97],[46,108],[46,112],[47,45],[47,46],[47,48],[47,67],[48,108],[49,50],[49,51],[50,54],[50,93],[50,112],[51,93],[52,53],[52,54],[52,57],[52,58],[53,112],[54,53],[54,112],[56,112],[57,56],[57,58],[57,59],[57,103],[57,112],[58,54],[58,112],[58,119],[59,58],[59,112],[60,50],[60,54],[60,58],[60,59],[60,112],[62,63],[62,64],[63,114],[64,108],[65,64],[65,108],[66,67],[66,68],[66,69],[67,108],[68,62],[68,67],[68,69],[68,108],[69,93],[69,97],[69,108],[70,71],[70,73],[71,0],[71,49],[71,52],[71,58],[71,59],[71,62],[71,70],[71,73],[71,74],[71,87],[71,93],[71,108],[72,91],[72,93],[72,108],[73,87],[73,89],[73,91],[73,93],[73,94],[73,95],[73,101],[74,75],[74,76],[74,77],[74,78],[74,79],[74,83],[74,84],[74,86],[75,74],[75,78],[75,79],[76,75],[76,78],[76,79],[76,84],[77,74],[77,75],[77,76],[77,78],[77,82],[77,83],[77,84],[77,86],[78,79],[80,79],[81,79],[82,78],[82,84],[83,75],[83,78],[83,79],[83,80],[84,75],[84,78],[84,79],[84,80],[85,75],[85,86],[86,75],[86,78],[86,79],[87,92],[87,93],[92,94],[93,89],[93,90],[93,91],[93,92],[93,94],[93,95],[93,110],[95,92],[95,94],[96,97],[96,98],[96,99],[96,100],[98,49],[99,97],[100,4],[100,5],[100,109],[101,102],[101,103],[101,104],[103,102],[104,91],[104,93],[104,94],[104,95],[104,102],[104,103],[104,105],[107,108],[108,109],[108,111],[108,113],[108,114],[108,115],[108,116],[109,110],[111,110],[112,110],[113,110],[114,110],[115,110],[116,110],[117,118],[118,19],[118,21],[118,119]],"pe":[["__main__","cli",1],["advisory","graph",4],["advisory","install",1],["advisory","ledger",2],["advisory","loop",3],["advisory","models",3],["advisory","schemas",9],["audit","graph",2],["audit","ledger",1],["audit","loop",1],["audit","models",2],["audit","schemas",2],["ci","findings",1],["ci","ledger",1],["ci","schemas",1],["ci","triage",1],["cli","advisory",4],["cli","attest",2],["cli","audit",1],["cli","ci",1],["cli","findings",1],["cli","graph",10],["cli","install",1],["cli","ledger",5],["cli","loop",5],["cli","models",5],["cli","oracle",3],["cli","report",3],["cli","sandbox",1],["cli","scan",2],["cli","schemas",5],["dashboard","ci",2],["dashboard","graph",1],["dashboard","ledger",1],["dashboard","live",1],["dashboard","oracle",1],["dashboard","report",1],["dashboard","schemas",3],["findings","graph",1],["findings","oracle",2],["findings","schemas",1],["graph","findings",1],["graph","sandbox",1],["graph","schemas",7],["graph","triage",1],["ledger","schemas",3],["live","ledger",1],["live","oracle",1],["live","report",1],["live","schemas",3],["loop","findings",1],["loop","graph",3],["loop","ledger",1],["loop","models",1],["loop","oracle",10],["loop","sandbox",1],["loop","schemas",2],["oracle","schemas",1],["report","advisory",2],["report","findings",1],["report","schemas",1],["sandbox","oracle",4],["scan","schemas",1],["triage","ci",2]]};
const MODS = GRAPH.mod, ME = GRAPH.me, PE = GRAPH.pe;

window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { lv: 'net', ly: 'all', sel: 'oracle', mod: null, q: '', full: false, fn: true, runId: '', heat: [], heatNote: '', paths: [], pathSel: -1 };
  }
  runParams() {
    try {
      const q = new URLSearchParams(window.location.search);
      return { run: q.get('run') || '', focus: q.get('focus') || '' };
    } catch (e) { return { run: '', focus: '' }; }
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
    } catch (e) { /* static snapshot stays */ }
    if (!graph || !graph.available) {
      this.setState({ heatNote: 'No code tree for this run: tiles below show package size only.' });
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
      for (const f of n.findings || []) {
        if (f.verdict !== 'proven') continue;
        cell.proven += 1;
        if (rank(f.severity) > rank(cell.sev)) cell.sev = f.severity;
      }
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
    const LCK = { core: 'core', analysis: 'analysis', surface: 'surface' };
    const nodes = PK.map(([n, loc, l]) => ({ id: n, label: n, kind: 'file', layer: LCK[l] || 'core', pkg: n, loc, r: 7 + Math.sqrt(loc / 5971) * 17, title: n + ' · ' + loc.toLocaleString('en-US') + ' lines' }));
    const edges = PE.map(([a, b, w]) => ({ a, b, t: 'imp', w }));
    return { nodes, edges };
  }
  netData(withFn) {
    const FN = (window.DCGraphData || {}).fn || {}, USES = (window.DCGraphData || {}).uses || [];
    const nodes = [], edges = [];
    MODS.forEach(([n, loc, p]) => {
      const l = LAYER[p] || 'core';
      nodes.push({ id: n, label: n.split('.').pop(), kind: 'file', layer: l, pkg: p, loc, r: 4.5 + Math.sqrt(loc / 2293) * 11, title: n + ' · ' + loc.toLocaleString('en-US') + ' lines' });
    });
    ME.forEach(([i, j]) => edges.push({ a: MODS[i][0], b: MODS[j][0], t: 'imp' }));
    if (withFn) {
      const have = new Set();
      MODS.forEach(([n, , p]) => {
        const l = LAYER[p] || 'core';
        (FN[n] || []).forEach(([fname, kind, lines]) => {
          const id = n + '::' + fname;
          have.add(id);
          nodes.push({ id, label: fname, kind: 'func', cls: kind === 'c', parent: n, layer: l, pkg: p, loc: lines, r: 2.2 + Math.min(3.2, Math.sqrt(lines) * 0.28), title: (kind === 'c' ? 'class ' : 'def ') + fname + ' · ' + n + ' · ' + lines + ' lines' });
          edges.push({ a: n, b: id, t: 'own' });
        });
      });
      USES.forEach(([from, mod, fname]) => { const id = mod + '::' + fname; if (have.has(id) && from !== mod) edges.push({ a: from, b: id, t: 'use' }); });
    }
    return { nodes, edges };
  }
  cur() { return this.net || { zoomBy() {}, fit() {} }; }
  pkgOf(id) { const m = MODS.find((x) => x[0] === id); return m ? m[2] : null; }
  // Keeps the canvas in step with the page state after every render.
  componentDidRender() {
    const st = this.state, nv = this.net;
    this.mountNet();
    if (this.net) {
      const k = st.lv + (st.lv === 'net' && st.fn);
      if (this.netKey !== k) { this.netKey = k; this.net.set(st.lv === 'pkg' ? this.pkgNetData() : this.netData(st.lv === 'net' && st.fn)); }
      this.net.filter(st.ly === 'all' ? null : (d) => d.layer === st.ly);
      this.net.find(st.q);
      const attack = st.pathSel >= 0 && st.paths[st.pathSel] ? st.paths[st.pathSel].nodes : null;
      const pkgFiles = st.sel ? MODS.filter((m) => m[2] === st.sel).map((m) => m[0]) : null;
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
    else v.focus(st.sel ? MODS.filter((m) => m[2] === st.sel).map((m) => m[0]) : null);
    if (this.fullSeen !== st.full) { this.fullSeen = st.full; setTimeout(() => v.fit(), 60); }
  }
  graphData(lv) {
    if (lv === 'pkg') {
      return { key: 'pkg', arrows: true, nodes: PK.map(([n, loc, l]) => ({ id: n, label: n, layer: l, loc, r: 12 + Math.sqrt(loc / 5971) * 26, color: LC[l], title: n + ' · ' + loc.toLocaleString('en-US') + ' lines' })),
        edges: PE.map(([a, b, w]) => ({ a, b, w })) };
    }
    return { key: 'mod', nodes: MODS.map(([n, loc, p]) => { const l = LAYER[p] || 'core'; return { id: n, label: n.split('.').pop(), layer: l, loc, r: 4.5 + Math.sqrt(loc / 2293) * 10, color: LC[l], title: n + ' · ' + loc.toLocaleString('en-US') + ' lines' }; }),
      edges: ME.map(([i, j]) => ({ a: MODS[i][0], b: MODS[j][0], w: 1 })) };
  }
  renderVals() {
    const st = this.state;
    const LC = { core: '#0f2557', analysis: '#6a8fd8', surface: '#b7834f' };
    const P = [['oracle', 5971, 'core'], ['graph', 3063, 'analysis'], ['dashboard', 3017, 'surface'], ['advisory', 2918, 'analysis'], ['cli', 2800, 'surface'],
      ['sandbox', 2182, 'core'], ['loop', 1958, 'core'], ['report', 1576, 'surface'], ['models', 1206, 'core'], ['live', 828, 'surface'], ['ci', 809, 'surface'],
      ['findings', 675, 'analysis'], ['ledger', 612, 'core'], ['schemas', 594, 'core'], ['triage', 455, 'analysis'], ['audit', 453, 'analysis'],
      ['attest', 413, 'analysis'], ['scan', 283, 'analysis'], ['install', 80, 'core']];
    const opt = (list, key) => list.map(([k, l]) => ({ l, cls: 'sb' + (st[key] === k ? ' sb-on' : ''), pick: () => this.setState({ [key]: k }) }));
    const pk = P.map(([n, loc, l]) => ({ n, c: LC[l], w: (loc / 5971 * 100).toFixed(1), v: loc.toLocaleString('en-US'),
      op: st.ly === 'all' || st.ly === l ? 1 : 0.3, cls: 'pk' + (st.sel === n ? ' pk-on' : ''), pick: () => this.setState({ sel: n, mod: null }) }));
    const layers = [
      ['Proof core', 12603, '#0f2557', '#ffffff', 'Oracle, sandbox, loop, models, ledger and schemas. Everything needed to run an exploit and judge it.'],
      ['Surfaces', 9030, '#b7834f', '#ffffff', 'CLI, dashboard, reports, live view and the GitHub Action gate.'],
      ['Analysis', 8260, '#6a8fd8', '#0d1b3e', 'Call graph, advisories, findings, triage, audit, attestation and scan: deciding where to look.']
    ].map(([name, loc, c, fg, d]) => ({ name, c, fg, d, loc: loc.toLocaleString('en-US') + ' lines', pct: (loc / 29893 * 100).toFixed(1), pctL: Math.round(loc / 29893 * 100) + '%' }));
    const rank = (arr) => { const m = arr[0][1]; return arr.map(([mm, v]) => ({ m: mm, v: v > 999 ? (v / 1000).toFixed(1) + 'k' : String(v), pct: (v / m * 100).toFixed(0) })); };
    const hot = [
      { t: 'Most depended on', d: 'Modules imported by the most other modules.', c: '#0f2557', rows: rank([['schemas.graph', 16], ['schemas', 14], ['models.cost', 11], ['oracle.oracle', 11], ['ledger', 9], ['models.errors', 9]]) },
      { t: 'Orchestrators', d: 'Modules that pull in the most others to do their job.', c: '#2c4fc4', rows: rank([['advisory.deps_report', 14], ['cli.run', 14], ['loop.pipeline', 13], ['cli.parser', 11], ['advisory.proof', 9], ['dashboard.model', 9]]) },
      { t: 'Heaviest modules', d: 'Lines of code in a single file.', c: '#b7834f', rows: rank([['oracle.oracle', 2293], ['oracle.plugin', 1966], ['sandbox.runner', 1542], ['dashboard.model', 1491], ['oracle.guard', 1064], ['loop.pipeline', 971]]) }
    ];
    // Selection detail: what the selected node depends on and what depends on it.
    const lvl = st.lv, nm = lvl === 'pkg' ? st.sel : (st.mod || st.sel);
    let det = { on: false };
    if (nm) {
      let deps = [], users = [], meta = '';
      if (lvl === 'pkg' || !st.mod) {
        const w = (list, from, to) => list.filter((e) => e[from] === nm).map((e) => [e[to], e[2]]).sort((a, b) => b[1] - a[1]);
        deps = w(PE, 0, 1); users = w(PE, 1, 0);
        const p = PK.find((x) => x[0] === nm);
        meta = p ? p[2].replace('surface', 'surfaces') + ' layer · ' + p[1].toLocaleString('en-US') + ' lines · ' + MODS.filter((m) => m[2] === nm).length + ' modules' : '';
        det = { on: !!p, n: nm, c: p ? LC[p[2]] : '#0f2557', meta,
          deps: deps.map(([n, c]) => ({ n: n + ' ×' + c, pick: () => this.setState({ sel: n, mod: null }) })), users: users.map(([n, c]) => ({ n: n + ' ×' + c, pick: () => this.setState({ sel: n, mod: null }) })) };
      } else {
        const i = MODS.findIndex((m) => m[0] === nm);
        deps = ME.filter((e) => e[0] === i).map((e) => MODS[e[1]][0]); users = ME.filter((e) => e[1] === i).map((e) => MODS[e[0]][0]);
        const m = MODS[i];
        det = { on: i >= 0, n: nm, c: LC[LAYER[m[2]] || 'core'], meta: m[2] + ' package · ' + m[1].toLocaleString('en-US') + ' lines',
          deps: deps.map((n) => ({ n, pick: () => this.setState({ mod: n, sel: this.pkgOf(n) }) })), users: users.map((n) => ({ n, pick: () => this.setState({ mod: n, sel: this.pkgOf(n) }) })) };
      }
      det.hasDeps = deps.length > 0; det.hasUsers = users.length > 0; det.nDeps = deps.length; det.nUsers = users.length;
    }
    const heat = st.heat.length ? st.heat : P.map(([n, loc, l]) => ({
      n, v: loc.toLocaleString('en-US') + ' lines', w: Math.max(4, (loc / 5971) * 100).toFixed(1), c: LC[l],
      pick: () => this.setState({ sel: n, mod: null }),
    }));
    const heatNote = st.heatNote || 'Package size by lines, colored by layer (dark blue core, light blue analysis, bronze surfaces).';
    this.__d = { P, LC };
    return {
      det, q: st.q, onQ: (e) => this.setState({ q: e.target.value }),
      heat, heatNote, paths: st.paths, hasPaths: st.paths.length > 0, runId: st.runId,
      zin: () => this.cur().zoomBy(1.35), zout: () => this.cur().zoomBy(1 / 1.35), zfit: () => this.cur().fit(),
      nDisp: 'block', gDisp: 'none', fnDisp: st.lv === 'net' ? 'inline-flex' : 'none',
      fnOpts: [[true, 'Functions on'], [false, 'Files only']].map(([k, l]) => ({ l, cls: 'sb' + (st.fn === k ? ' sb-on' : ''), pick: () => this.setState({ fn: k }) })),
      gfull: st.full ? 'gfull' : '', full: String(st.full), fullL: st.full ? 'Close expanded view' : 'Expand', toggleFull: () => this.setState({ full: !st.full }),
      tot: [{ l: 'Packages', v: '19', u: 'top-level folders' }, { l: 'Modules', v: '120', u: 'Python files' }, { l: 'Imports', v: '317', u: 'internal dependencies' }, { l: 'Lines', v: '29.9k', u: '1,052 functions · 173 classes' }],
      layers, hot, pk,
      lvOpts: [['net', 'Network'], ['pkg', 'Packages'], ['mod', 'Modules']].map(([k, l]) => ({ l, cls: 'sb' + (st.lv === k ? ' sb-on' : ''), pick: () => this.setState({ lv: k, mod: null }) })),
      lyOpts: opt([['all', 'All'], ['core', 'Core'], ['analysis', 'Analysis'], ['surface', 'Surfaces']], 'ly')
    };
  }

  // The expanded version of each chart: same data, drawn in full (see fullchart.js).
  fullSpec(id) {
    const d = this.__d;
    if (!d || id !== 'layers') return null;
    const names = { core: 'Proof core', analysis: 'Analysis', surface: 'Surfaces' };
    const total = d.P.reduce((t, p) => t + p[1], 0);
    const groups = ['core', 'surface', 'analysis'].map((l) => {
      const list = d.P.filter((p) => p[2] === l).sort((a, b) => b[1] - a[1]);
      const sum = list.reduce((t, p) => t + p[1], 0);
      return { title: names[l], note: sum.toLocaleString('en-US') + ' lines \u00b7 ' + Math.round(sum / total * 100) + '%', max: 5971,
        rows: list.map((p) => ({ key: p[0], label: p[0], sub: Math.round(p[1] / total * 1000) / 10 + '% of the code', v: p[1], color: d.LC[l], value: p[1].toLocaleString('en-US') })) };
    });
    const rows = d.P.slice().sort((a, b) => b[1] - a[1]).map((p) => ({ key: p[0], label: p[0] + ' \u00b7 ' + names[p[2]], value: p[1].toLocaleString('en-US') + ' lines', n: p[1] }));
    return { type: 'hbars', title: 'Lines of code by layer', aria: 'Every package by layer', rowH: 30, labelW: 170, groups, rows };
  }
};

