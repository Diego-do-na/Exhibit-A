/* View logic for pr.html, rendered by ../dc-lite.js. */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { step: 0, acc: 0, el: 0, stamps: [], playing: true, speed: 1, status: null, confirm: false, cstep: 0, tag: null, bv: 'path', pos: null, evts: null, runId: '', safe: { show: false }, prs: [], authors: [], graph: null };
    this.timers = [];
  }
  runParam() {
    try { return new URLSearchParams(window.location.search).get('run') || ''; } catch (e) { return ''; }
  }
  prParam() {
    try { return new URLSearchParams(window.location.search).get('pr') || ''; } catch (e) { return ''; }
  }
  prRow() {
    const id = this.prParam();
    if (!id) return null;
    const list = this.state.prs || [];
    const row = list.find((r) => String(r.number) === String(id) || String(r.id) === String(id));
    if (!row) return { id, missing: true };
    const when = (row.merged_at || row.created_at || '').slice(0, 16).replace('T', ' ');
    return {
      id: String(row.number || row.id), title: row.title, when,
      author: row.author, commits: row.commits || 0, files: row.changed_files || (row.files || []).length,
      added: row.additions || 0, removed: row.deletions || 0, tests: false,
      area: row.area || '', cycle: 0, kind: row.author_kind || 'unclassified',
      color: row.author_color || '#4a5873', url: row.url || '',
    };
  }
  async loadRun() {
    const id = this.runParam();
    if (!id) return;
    this.setState({ runId: id, detail: null });
    try {
      const res = await fetch('/api/runs/' + encodeURIComponent(id) + '/events?limit=500', { headers: { Accept: 'application/json' } });
      if (res.ok) {
        const body = await res.json();
        const evts = (body && body.events) || [];
        if (Array.isArray(evts) && evts.length) this.setState({ evts, pos: evts.length, step: evts.length, playing: false });
      }
    } catch (e) { /* demo timeline stays */ }
    try {
      const res = await fetch('/api/runs/' + encodeURIComponent(id), { headers: { Accept: 'application/json' } });
      if (res.ok) {
        const detail = await res.json();
        this.setState({ detail: detail || null });
        const run = (detail && detail.run) || {};
        const discarded = (detail && detail.discarded) || [];
        const provenItems = (detail && detail.proven) || [];
        const firstD = discarded[0] || {};
        const firstP = provenItems[0] || {};
        this.setState({
          vkind: (run.proven || 0) > 0 ? 'proven' : (firstD.verdict || 'none'),
          vreason: firstD.reason || '',
          vwhere: (firstD.file || '') + (firstD.line ? ':' + firstD.line : ''),
          vhyp: firstP.hypothesis || firstP.reason || '',
          provenCount: run.proven || 0,
          safe: {
            show: (run.proven || 0) === 0 && !run.error,
            headline: run.headline || 'Nothing could be proven',
            suspicions: run.suspicions_raised || 0,
            exploits: run.exploits_written || 0,
            dropped: run.dropped || 0,
            items: discarded.slice(0, 60).map((d) => ({
              id: d.id || '?', cls: d.class || 'unknown class', verdict: d.verdict || 'discarded',
              reason: d.reason || 'no reason recorded',
              where: (d.file || '') + (d.line ? ':' + d.line : ''),
            })),
          },
        });
      }
    } catch (e) { /* no safe panel */ }
  }
  async loadPrs() {
    try {
      const res = await fetch('/api/prs', { headers: { Accept: 'application/json' } });
      if (!res.ok) return;
      const body = await res.json();
      this.setState({ prs: (body && body.pull_requests) || [], authors: (body && body.authors) || [] });
    } catch (e) { /* empty PR list stays */ }
  }
  componentDidMount() {
    if (!this.runParam()) this.iv = setInterval(() => this.tick(), 250);
    this.loadRun();
    this.loadPrs();
    const demo = !this.runParam() && !this.prParam();
    const host = document.getElementById('blast');
    if (demo && host && window.DCViz) {
      const A = '#a5703f', B = '#2c4fc4', G = '#4a5873';
      const chip = (id, x, y, kind, label, sub, extra) => Object.assign({ id, x, y, shape: 'chip', w: 164, h: 64, kind, label, sub, kindColor: G, r: 32 }, extra);
      const nodes = [
        chip('gp', 90, 200, 'Entry', 'GET /pamphlet', 'public request', { kindColor: B, stroke: 'rgba(44,79,196,.45)', note: 'Any caller of the public endpoint chooses the name parameter.' }),
        chip('hr', 300, 200, 'Entry point', 'App.handle_request', 'pamphlets.py:34', { kindColor: B, note: 'Dispatches the request and passes the requested name straight to _resolve.' }),
        chip('rs', 510, 200, 'Changed', 'App._resolve', 'pamphlets.py:32', { kindColor: A, stroke: A, note: 'The code this pull request changed: it now joins the name onto the shelf directory without confining it.' }),
        chip('rt', 720, 200, 'Calls', 'read_text', 'pamphlets.py:18', { note: 'Reads whatever path it is given.' }),
        chip('op', 930, 200, 'Sink', 'open()', 'pamphlets.py:20', { kindColor: A, stroke: A, note: 'The oracle watched this call open a file outside the shelf.' }),
        chip('ef', 1140, 200, 'Effect', 'Any readable file', 'outside the shelf', { kindColor: A, stroke: A, note: 'The canary file outside the shelf was read in 3 of 3 runs.' }),
        chip('gi', 90, 360, 'Entry', 'GET /index', 'lists pamphlet names', { muted: true, note: 'Not affected: it lists names and never calls _resolve.' }),
        chip('ts', 300, 360, 'Tests', 'test_pamphlets.py', 'baseline 5 / 5', { muted: true, note: 'The project\u2019s own tests: 5 of 5 pass on a clean clone.' }),
        chip('ls', 510, 360, 'Calls', 'os.listdir', 'names only', { muted: true, note: 'Not affected: it reads the shelf listing only.' }),
        chip('gh', 510, 40, 'Not written yet', 'any other caller', 'would inherit the problem', { muted: true, dashed: true, note: 'Today only handle_request calls _resolve. Any caller added later inherits the missing check.' })
      ];
      const hot = (a, b) => ({ a, b, hot: true, w: 3 });
      const edges = [hot('gp', 'hr'), hot('hr', 'rs'), hot('rs', 'rt'), hot('rt', 'op'), hot('op', 'ef'),
        { a: 'gi', b: 'hr', w: 1, dim: true }, { a: 'ts', b: 'hr', w: 1, dim: true }, { a: 'hr', b: 'ls', w: 1, dim: true }, { a: 'gh', b: 'rs', w: 1, dashed: true }];
      this.blast = window.DCViz.graph(host, { tools: true });
      this.blast.set({ key: 'blast', layout: 'fixed', nodes, edges, curve: false });
    }
    const nh = document.getElementById('blastnet');
    if (demo && nh && window.DCNet && window.DCGraphData) {
      // The whole code graph (every module and function, as on the Code graph
      // page), not just the affected path: the possibly damaged route for the
      // selected pull request is marked red so its blast radius is visible in
      // context. Focus = the package the selected PR touched (its area), or
      // the proof route itself for the recorded action-demo report.
      const GD = window.DCGraphData, FN = GD.fn || {}, USES = GD.uses || [];
      const selPr = this.prRow();
      const areaPkg = selPr && selPr.area ? selPr.area.replace(/^src\//, '').split('/')[0] : '';
      const focusPkg = FN[areaPkg] || FN[areaPkg + '.'] ? areaPkg : (Object.keys(FN).some((m) => m === areaPkg || m.startsWith(areaPkg + '.')) ? areaPkg : 'oracle');
      const inFocus = (mod) => mod === focusPkg || mod.startsWith(focusPkg + '.');
      const RED = '#ff6b6b', BLUE = '#7ea6ff';
      // Files only in the blast radius: every function node overpopulated the
      // view until nothing was readable, so module-to-module impact is enough.
      const nodes = [], edges = [], seen = new Set();
      Object.entries(FN).forEach(([mod, fns]) => {
        const hot = inFocus(mod);
        nodes.push({ id: mod, label: mod.split('.').pop(), kind: 'file', pkg: mod.split('.')[0], loc: fns.reduce((s, f) => s + (f[2] || 0), 0),
          r: hot ? 13 : 7, color: hot ? RED : BLUE, vuln: hot, title: mod + (hot ? ' · in the area this pull request touched (' + focusPkg + ')' : ' · full code graph') });
      });
      USES.forEach(([from, mod]) => {
        if (!FN[from] || !FN[mod] || from === mod) return;
        const key = from + '>' + mod;
        if (seen.has(key)) return;
        seen.add(key);
        const hot = inFocus(from) || inFocus(mod);
        edges.push({ a: from, b: mod, t: 'use', vuln: hot });
      });
      this.bnet = window.DCNet.create(nh, { labelAll: true, autoFit: true, onHover: (n, x, y) => {
        if (!this.btip) { this.btip = document.createElement('div'); this.btip.className = 'net-tip'; nh.appendChild(this.btip); }
        if (!n) { this.btip.classList.remove('net-tip-on'); return; }
        this.btip.textContent = n.title; this.btip.style.left = Math.round(x + 14) + 'px'; this.btip.style.top = Math.round(y + 14) + 'px'; this.btip.classList.add('net-tip-on');
      } });
      this.bnet.set({ nodes, edges });
    }
  }
  componentDidRender() {
    if (this.bvSeen !== this.state.bv) { this.bvSeen = this.state.bv; if (this.state.bv === 'net' && this.bnet) setTimeout(() => this.bnet.fit(), 80); }
  }
  componentWillUnmount() { clearInterval(this.iv); this.timers.forEach((t) => clearTimeout(t)); }
  tick() {
    const s = this.state, N = s.evts ? s.evts.length : 11;
    if (!s.playing || s.step >= N) return;
    const acc = s.acc + 250 * s.speed, el = s.el + 0.25 * s.speed;
    if (acc >= 1500) {
      const step = s.step + 1;
      this.setState({ step, acc: 0, el, stamps: s.stamps.concat([el]), playing: step < N, pos: s.evts ? step : s.pos });
    }
    else this.setState({ acc, el });
  }
  money(v) {
    if (v == null || v === '') return '';
    const n = Number(v);
    if (!isFinite(n)) return '';
    return '$' + n.toFixed(n !== 0 && Math.abs(n) < 0.01 ? 6 : 4).replace(/0+$/, '').replace(/\.$/, '');
  }
  int(v) {
    if (v == null || v === '') return '';
    return Number(v).toLocaleString('en-US');
  }
  text(v, fb) {
    const t = (v == null ? '' : String(v)).trim();
    return t || fb || '';
  }
  // Unified-diff text (untrusted run artifact) -> display rows. Rendered as
  // text only, never executed; hunk headers and counts are derived, not parsed.
  diffRows(patch) {
    const rows = [];
    let o = 0, n = 0;
    for (const line of String(patch || '').split('\n').slice(0, 400)) {
      if (line.startsWith('+++') || line.startsWith('---')) {
        rows.push({ bg: 'transparent', sc: '#7a86a1', tc: '#26365a', s: ' ', o: '', n: '', t: line.slice(0, 200) });
      } else if (line.startsWith('@@')) {
        rows.push({ bg: 'transparent', sc: '#7a86a1', tc: '#26365a', s: ' ', o: '', n: '', t: line.slice(0, 200) });
        o = 0; n = 0;
      } else if (line.startsWith('+')) {
        n += 1;
        rows.push({ bg: 'rgba(34,139,84,.11)', sc: '#1f7a4d', tc: '#0f3d26', s: '+', o: '', n: String(n), t: line.slice(1, 201) });
      } else if (line.startsWith('-')) {
        o += 1;
        rows.push({ bg: 'rgba(190,60,60,.11)', sc: '#b23a3a', tc: '#5a1c1c', s: '−', o: String(o), n: '', t: line.slice(1, 201) });
      } else {
        o += 1; n += 1;
        rows.push({ bg: 'transparent', sc: '#7a86a1', tc: '#26365a', s: ' ', o: String(o), n: String(n), t: line.slice(0, 200) });
      }
    }
    return rows;
  }
  // Recorded loop stages (from /api/runs/<id>) -> timeline rows for a run
  // whose event stream could not be loaded. Missing stages are omitted.
  stageRows(detail) {
    const stages = (detail && detail.stages) || [];
    const desc = { BASELINE: 'project tests on a clean clone', SUSPECT: 'adversary proposes suspicions', EXPLOIT: 'test writer turns one into a test',
      RUN: 'exploit runs in the isolated sandbox', VERDICT: 'oracle judges the intended effect', FIX: 'fixer proposes a patch',
      VERIFY: 'exploit re-run on the fix, bypass variants tried', PACKAGE: 'proof bundle signed and stored' };
    const rows = stages.filter((st) => st && st.reached).map((st) => [
      String(st.name || 'stage'), String(st.name || 'stage'),
      'ledger', (st.count || 0) + ' events' + (st.duration_s != null ? ' · ' + st.duration_s + 's' : '') + ' · ' + (desc[st.name] || 'recorded stage'),
      String(st.first_ts || '').slice(11, 19),
    ]);
    return rows.length ? rows : [['LEDGER', 'No ledger stages recorded', 'ledger', 'the run recorded no reachable loop stage', '']];
  }
  renderVals() {
    const s = this.state;
    const runId = this.runParam();
    const isRun = !!runId;
    const D = s.detail || null;
    const R = (D && D.run) || {};
    const status = s.status ?? (this.props.startStatus ?? 'pending');
    const evtRows = s.evts ? s.evts.map((e) => [(e.stage || e.type || 'event').toUpperCase(), e.summary || e.type, e.role || 'engine', e.summary || e.type, (e.ts || '').slice(11, 19)]) : null;
    const S = evtRows || (isRun ? this.stageRows(D) : [
      ['PR', 'Pull request opened', 'github', '1 file changed · pamphlets.py · +2 −6'],
      ['GATE', 'Risk triage', 'ci.gate', 'pamphlets.py matches "application code" → risk HIGH, exploits will run'],
      ['SCAN', 'Reachability', 'graph', 'App.handle_request → App._resolve → read_text → open() · 3 hops'],
      ['BASE', 'Baseline', 'sandbox', '5 / 5 project tests pass on a clean clone'],
      ['SUSP', 'Suspicion raised', 'adversary', 'S1 path_traversal: _resolve joins the name without confining it'],
      ['EXPL', 'Exploit written', 'test_writer', 'GET /pamphlet?name=../outside/canary.txt must return 404'],
      ['RUN', 'Sandbox run', 'sandbox', 'no network · read-only tree · test FAILED: 200 with canary text'],
      ['ORCL', 'Oracle verdict', 'oracle', 'canary_read via handle_request → _resolve → read_text · 3 / 3 runs → PROVEN'],
      ['FIX', 'Fix proposed', 'fixer', 'restore realpath + commonpath containment in _resolve'],
      ['VER', 'Fix verified', 'defender', 'exploit passes on fixed code · baseline 5 / 5 · 3 / 3 bypasses blocked'],
      ['PKG', 'Proof packaged', 'attest', 'exploit test, fix.patch, verdict and evidence signed into a bundle']
    ]);
    const N = S.length, rawDone = status === 'pending' ? s.step : N;
    const done = s.pos != null && evtRows ? Math.max(0, Math.min(N, s.pos)) : Math.min(rawDone, N);
    const RC = { github: '#c3cbd8', 'ci.gate': '#d9b98f', graph: '#9aa3e0', sandbox: '#8fb4ff', adversary: '#e8b07a', test_writer: '#8fb4ff', oracle: '#ffffff', fixer: '#a7c0ff', defender: '#a7c0ff', attest: '#c3cbd8' };
    const fmtT = (x) => '+' + String(Math.floor(x / 60)).padStart(2, '0') + ':' + (x % 60).toFixed(1).padStart(4, '0');
    const runDone = isRun ? N : done;
    const live = {
      player: !isRun,
      playing: !isRun && s.playing && done < N, paused: isRun || !(s.playing && done < N), playL: s.playing ? 'Pause' : 'Play', running: !isRun && done < N,
      toggle: () => this.setState({ playing: !s.playing }),
      replay: () => this.setState({ step: 0, acc: 0, el: 0, stamps: [], playing: true, status: 'pending', cstep: 0, pos: evtRows ? 0 : null }),
      speeds: [1, 2, 4].map((v) => ({ l: v + '×', cls: 'sb' + (s.speed === v ? ' sb-on' : ''), pick: () => this.setState({ speed: v }) })),
      pct: (runDone / Math.max(1, N) * 100).toFixed(1), clock: isRun ? (N + ' events') : fmtT(status === 'pending' ? s.el : 16.5),
      title: isRun ? 'Recorded ledger' : (done >= N ? 'Analysis complete' : 'Analyzing · ' + String(S[done][1]).toLowerCase().slice(0, 90)),
      dot: (isRun || done >= N) ? '#2c4fc4' : '#a5703f', dotCls: (isRun || done >= N) ? '' : 'pulse',
      next: !isRun && done < N ? S[done][2] + ' …' : '',
      src: isRun ? ('ledger.jsonl · ' + N + ' events, chronological') : 'ledger.jsonl · live demo (open with ?run= for the real ledger)',
      stages: S.map((x, i) => ({ k: x[0], n: String(x[1]).slice(0, 80), done: i < runDone, cls: (!isRun && i === done) ? 'pulse' : '',
        bg: i < runDone ? (i === 7 ? '#a5703f' : '#2c4fc4') : 'transparent', bd: i < runDone ? (i === 7 ? '#a5703f' : '#2c4fc4') : i === done ? '#2c4fc4' : 'rgba(13,27,62,.25)',
        op: i <= runDone ? 1 : 0.45, fw: i === done ? 600 : 400 })),
      log: S.slice(0, runDone).map((x, i) => ({ t: x[4] || fmtT(s.stamps[i] ?? (i + 1) * 1.5), r: x[2], rc: RC[x[2]] || '#e6ecfa', m: x[3], mc: i === 7 ? '#f0c08f' : '#e6ecfa' })),
      scrub: null,
    };
    let proven = s.evts ? (s.provenCount || 0) > 0 : done >= 8;
    let dec = status === 'approved'
      ? { t: 'Fixed · nothing could be proven on the new head', d: 'The applied suggestion restored the containment check. On the new head the exploit gets a 404, the project tests still pass and every bypass variant is blocked. Nothing could be proven against it, which is not the same as safe.', c: '#2c4fc4', bg: 'rgba(44,79,196,.07)', bd: 'rgba(44,79,196,.25)' }
      : proven
        ? { t: 'Vulnerability confirmed', d: 'A pamphlet name can now reach any readable file on the host. The exploit read the canary file through the public endpoint in 3 of 3 runs, from application code. Merge is blocked until a fix is applied.', c: '#a5703f', bg: 'rgba(165,112,63,.08)', bd: 'rgba(165,112,63,.3)' }
        : { t: 'Analyzing', d: 'The proof loop is running. Nothing is reported until the oracle observes the effect itself; a model suspicion alone never blocks a merge.', c: '#4a5873', bg: 'rgba(13,27,62,.04)', bd: 'rgba(13,27,62,.1)' };
    const ck = (ok, n, d, sOk) => ({ ok, n, d, s: ok ? sOk : 'waiting', sc: ok ? '#2c4fc4' : '#7a86a1', bg: ok ? '#2c4fc4' : 'transparent', bd: ok ? '#2c4fc4' : 'rgba(13,27,62,.25)' });
    let proof = [
      ck(done >= 4, 'Baseline passes', 'The project’s own tests pass on a clean clone.', '5 / 5'),
      ck(done >= 8, 'Exploit fails on vulnerable code', 'For the reason the oracle observed: the canary was read.', 'canary_read'),
      ck(done >= 8, 'Valid provenance', 'The read came from application code through a real entry point.', 'handle_request'),
      ck(done >= 8, 'Stable', 'Same verdict in every repeated run.', '3 / 3'),
      ck(done >= 10, 'Fix verified, bypasses fail', 'Exploit passes on the fix, baseline still green, defender variants blocked.', '3 / 3 blocked')
    ];

    const VK = {
      discarded_unproven: { t: 'Not reported: nothing could be proven', c: '#4a5873', bg: 'rgba(13,27,62,.05)', bd: 'rgba(13,27,62,.14)' },
      invalid_test: { t: 'Not reported: the exploit test was invalid', c: '#7d5229', bg: 'rgba(165,112,63,.08)', bd: 'rgba(165,112,63,.3)' },
      flaky: { t: 'Not reported: the result was not stable', c: '#7d5229', bg: 'rgba(165,112,63,.08)', bd: 'rgba(165,112,63,.3)' },
      env_failure: { t: 'Not reported: the environment failed', c: '#7d5229', bg: 'rgba(165,112,63,.08)', bd: 'rgba(165,112,63,.3)' },
      none: { t: 'Not reported: no verdict was recorded', c: '#4a5873', bg: 'rgba(13,27,62,.05)', bd: 'rgba(13,27,62,.14)' }
    };
    const vdec = runId && s.vkind && VK[s.vkind]
      ? { ...VK[s.vkind], d: (s.vreason || 'The recorded run ended with this verdict.') + (s.vwhere ? ' (' + s.vwhere + ')' : '') }
      : null;
    const notReached = (n, d) => ({ ok: false, n, d, s: 'not reached', sc: '#7a86a1', bg: 'transparent', bd: 'rgba(13,27,62,.25)' });
    const vproof = runId && s.vkind && s.vkind !== 'proven'
      ? [ck(true, 'Baseline passes', 'The recorded run completed its baseline stage.', 'recorded'),
         notReached('Exploit fails on vulnerable code', 'The oracle did not observe the intended effect for the recorded reason.'),
         notReached('Valid provenance', 'No proven effect, so there is no provenance to validate.'),
         notReached('Stable', 'Stability is only claimed for a proven verdict.'),
         notReached('Fix verified, bypasses fail', 'No fix is proposed when nothing was proven.')]
      : null;
    const showFixSection = !runId || !s.vkind || s.vkind === 'proven';
    const whyPanel = runId && s.vkind && s.vkind !== 'proven'
      ? { title: VK[s.vkind] ? VK[s.vkind].t : 'Why it was not reported', reason: s.vreason || 'No reason was recorded for this verdict.', where: s.vwhere || '', kind: s.vkind }
      : null;

    let risk = { l: 'High', c: '#a5703f', bars: [{ c: '#d9b98f' }, { c: '#c09060' }, { c: '#a5703f' }], d: 'Application code on a path reachable from a public entry point.' };
    let verdict = proven || status === 'approved' ? { l: 'Proven', d: 'Path traversal · CWE-22 · canary_read observed by the oracle.' } : { l: 'Running', d: 'Waiting for the oracle to observe an effect.' };
    let merge = status === 'approved' ? { l: 'Ready', d: 'Fix committed; checks green on the new head.' } : status === 'committing' ? { l: 'Updating', d: 'Bot commit in progress.' } : { l: 'Blocked', d: 'Not merged. Waiting for the fix to be approved.' };
    if (isRun) {
      // Real-data mode: every card comes from the recorded run detail.
      // Missing values hide the card; the page never invents a placeholder label.
      const items = (D ? (D.proven || []) : []);
      const firstP = items[0] || null;
      proven = (R.proven || 0) > 0;
      const ev0 = firstP ? (firstP.evidence || {}) : {};
      const eff0 = ev0.effect || {};
      const pv0 = ev0.provenance || {};
      const pf0 = ev0.passes_on_fixed || {};
      const by0 = ev0.bypass || {};
      if (firstP) {
        const where = (firstP.file || '') + (firstP.line ? ':' + firstP.line : '');
        dec = { t: 'Vulnerability confirmed', d: (firstP.hypothesis || firstP.reason || (firstP.class + ' observed by the oracle')) + (where ? ' (' + where + ').' : '.') + ' Merge is blocked until a fix is applied.',
          c: '#a5703f', bg: 'rgba(165,112,63,.08)', bd: 'rgba(165,112,63,.3)' };
        const fr = ev0.fails_on_vulnerable || {};
        const stable = (fr.runs != null && fr.of != null) ? fr.runs + ' / ' + fr.of : (fr.runs != null ? String(fr.runs) : 'recorded');
        proof = [
          ck(true, 'Baseline passes', 'The recorded run completed its baseline stage.', 'recorded'),
          ck(true, 'Exploit fails on vulnerable code', 'For the reason the oracle observed.', this.text(eff0.type)),
          ck(true, 'Valid provenance', 'The effect came from application code through a real entry point.', this.text(pv0.entry_point)),
          ck(true, 'Stable', 'Same verdict in every repeated run.', stable),
          ck(!!pf0.fix_verified, 'Fix verified, bypasses fail', 'Exploit passes on the fix, baseline still green, defender variants blocked.', (by0.tried || 0) + ' tried · ' + (by0.succeeded || 0) + ' got through'),
        ];
      } else if (vdec) {
        dec = vdec;
        proof = vproof || proof;
      } else {
        dec = { t: R.headline || 'Nothing could be proven', d: 'The recorded run ended with no proven finding. Nothing could be proven, which is not the same as safe.', c: '#4a5873', bg: 'rgba(13,27,62,.05)', bd: 'rgba(13,27,62,.14)' };
        proof = vproof || [
          ck(true, 'Baseline passes', 'The recorded run completed its baseline stage.', 'recorded'),
          notReached('Exploit fails on vulnerable code', 'The oracle did not observe the intended effect for the recorded reason.'),
        ];
      }
      const riskBars = { high: [{ c: '#d9b98f' }, { c: '#c09060' }, { c: '#a5703f' }], medium: [{ c: '#d9b98f' }, { c: '#c09060' }, { c: 'rgba(13,27,62,.12)' }], low: [{ c: '#d9b98f' }, { c: 'rgba(13,27,62,.12)' }, { c: 'rgba(13,27,62,.12)' }] };
      const rk = String(R.risk || '').toLowerCase();
      const reasons = R.risk_reasons && typeof R.risk_reasons === 'object' ? Object.entries(R.risk_reasons).map(([k, v]) => k + ': ' + v).join('; ') : '';
      risk = R.risk ? { l: R.risk[0].toUpperCase() + R.risk.slice(1), c: rk === 'high' ? '#a5703f' : '#2c4fc4', bars: riskBars[rk] || riskBars.low, d: reasons || 'Recorded by the CI risk gate.' }
        : { l: '', c: '', bars: [], d: '' };
      if (firstP) {
        verdict = { l: 'Proven', d: [firstP.class, ev0.cwe, eff0.type].filter((x) => x && x !== 'unknown').join(' · ') + ' observed by the oracle.' };
      } else {
        const v = R.verdicts || {};
        const parts = ['proven', 'discarded_unproven', 'invalid_test', 'flaky', 'env_failure'].filter((k) => (v[k] || 0) > 0).map((k) => v[k] + ' ' + k.replace(/_/g, ' '));
        verdict = { l: (R.proven || 0) > 0 ? 'Proven' : (R.headline || 'Nothing could be proven'), d: parts.length ? parts.join(' · ') : 'The run recorded no verdicts.' };
      }
      const toks = (R.tokens_in != null && R.tokens_out != null) ? this.int(R.tokens_in + R.tokens_out) + ' tokens' : '';
      const models = (R.models && R.models.length) ? R.models.join(', ') : '';
      merge = { l: this.text(R.status, 'recorded'), d: [this.money(R.cost_usd), toks, models].filter(Boolean).join(' · ') };
    }
    const stt = status === 'approved'
      ? { l: 'Ready', s: 'Fix committed', cls: 'state-done', isDone: true, bg: 'rgba(44,79,196,.12)', fg: '#16307a', bd: 'rgba(44,79,196,.3)' }
      : status === 'committing'
        ? { l: 'Updating', s: 'Bot commit in progress', cls: 'state-busy', isBusy: true, bg: 'rgba(13,27,62,.07)', fg: '#26365a', bd: 'rgba(13,27,62,.18)' }
        : { l: 'Open', s: 'Not merged', cls: 'state-open', isOpen: true, bg: 'rgba(165,112,63,.14)', fg: '#7d5229', bd: 'rgba(165,112,63,.4)' };
    const selPrEarly = this.prRow();
    const st = selPrEarly && !runId
      ? { l: 'MERGED', s: selPrEarly.when || 'Merged into main', cls: 'state-done', isDone: true, bg: 'rgba(44,79,196,.12)', fg: '#16307a', bd: 'rgba(44,79,196,.3)' }
      : stt;
    const mergeOut = selPrEarly && !runId ? { l: 'Merged', d: 'This pull request is already merged into main.' } : merge;

    const TAGS = {
      T1190: { cat: 'ATT&CK · Initial access', name: 'Exploit Public-Facing Application',
        desc: ['Adversaries exploit a weakness in an internet-facing system to gain an initial foothold. The weakness can be a software bug, a temporary glitch or a misconfiguration.', 'Web applications and services that accept requests from outside are the usual target. A successful exploit typically hands the attacker whatever access the application itself has.'],
        here: 'The pamphlet endpoint answers any caller. With this change, a request can name a file outside the shelf, turning a public endpoint into a way to read the host’s files.',
        mitL: 'Mitigations', mit: [['M1048', 'Application isolation and sandboxing'], ['M1050', 'Exploit protection'], ['M1051', 'Update software'], ['M1016', 'Vulnerability scanning']],
        world: [['CVE-2021-41773', 'Path traversal in Apache HTTP Server 2.4.49, exploited in the wild to read files outside the document root.']] },
      T1083: { cat: 'ATT&CK · Discovery', name: 'File and Directory Discovery',
        desc: ['Adversaries enumerate files and directories, or search specific locations, to learn what is on a host.', 'What they find shapes the next step: which credentials, configuration or data are worth taking.'],
        here: 'Once traversal is open, ../ sequences let a caller probe the host’s file layout one path at a time through the pamphlet endpoint.',
        mitL: 'Mitigations', mit: [['—', 'Hard to prevent with configuration alone because it abuses normal system features. Close the access path instead, as the fix does.']], world: [] },
      T1005: { cat: 'ATT&CK · Collection', name: 'Data from Local System',
        desc: ['Adversaries search local sources such as file systems, configuration files or local databases for sensitive data before taking it.', 'Keys, tokens and configuration files are the usual prize.'],
        here: 'This is the effect the oracle proved: the exploit read the canary file, which stands in for secrets such as keys or configuration.',
        mitL: 'Mitigations', mit: [['M1057', 'Data loss prevention']], world: [] },
      'CWE-22': { cat: 'Weakness · CWE', name: 'Improper Limitation of a Pathname to a Restricted Directory',
        desc: ['The software builds a file path from outside input that should stay under a restricted directory, but does not neutralize sequences such as ../ that resolve to a location outside it.', 'Attackers use it to read or overwrite files they should never reach: configuration, credentials or source code.'],
        here: 'Line 32 joins the requested name onto the shelf directory and returns it unchanged. Nothing checks that the result stays inside the shelf.',
        mitL: 'Potential mitigations', mit: [['Resolve', 'Canonicalize the path with realpath, then verify it is still inside the allowed root with commonpath.'], ['Allowlist', 'Accept only known file names or a strict set of characters.'], ['Privilege', 'Run the service so files outside its directory are not readable at all.']],
        world: [['CVE-2023-29159', 'Starlette StaticFiles before 0.27.0 allowed path traversal; the fix moved to a commonpath check.'], ['CVE-2024-23334', 'aiohttp static routes with follow_symlinks enabled allowed reading files outside the static root.'], ['CVE-2021-41773', 'Apache HTTP Server 2.4.49 path traversal, exploited in the wild.']] },
      'CWE-23': { cat: 'Weakness · CWE', name: 'Relative Path Traversal',
        desc: ['A form of path traversal that uses relative sequences such as ../ to climb out of the intended directory. It is a child of CWE-22.'],
        here: 'The proven exploit used exactly this form: ../outside/canary.txt.',
        mitL: 'Potential mitigations', mit: [['Resolve', 'Resolve relative segments before checking containment, never after.']], world: [] },
      'CAPEC-126': { cat: 'Attack pattern · CAPEC', name: 'Path Traversal',
        desc: ['The attack pattern behind CWE-22: the attacker supplies path segments that the application uses to access files, aiming at locations the developer never meant to expose.'],
        here: 'The defender replayed three variants of this pattern against the fix — an absolute path, a nested ../ and a symlinked folder — and all three were blocked.',
        mitL: 'Defences', mit: [['Contain', 'Check the resolved path against the allowed root on every request.']], world: [] },
      'A01:2021': { cat: 'OWASP Top 10 · 2021', name: 'Broken Access Control',
        desc: ['The first category of the OWASP Top 10 (2021). It covers failures to enforce what a user may access. Path traversal, CWE-22, is one of the weaknesses mapped to it.'],
        here: 'Any caller could read files the application never meant to serve.',
        mitL: 'Defences', mit: [['Deny', 'Deny by default and enforce access checks on the server side.']], world: [] }
    };
    const mk = (id, name) => ({ id, name, aria: id + ' ' + name + ', open details', open: () => this.setState({ tag: id }) });
    let attack = [mk('T1190', 'Exploit Public-Facing Application'), mk('T1083', 'File and Directory Discovery'), mk('T1005', 'Data from Local System')];
    let weak = [mk('CWE-22', 'Path Traversal'), mk('CWE-23', 'Relative Path Traversal'), mk('CAPEC-126', 'Path Traversal'), mk('A01:2021', 'Broken Access Control')];
    let hasAttack = true, hasWeak = true, mitNote = '';
    let rtags = null;
    if (isRun) {
      // No ATT&CK mapping is recorded in the ledger: never invent one.
      attack = []; hasAttack = false;
      mitNote = '';
      rtags = {};
      const seen = new Set();
      for (const it of ((D && D.proven) || []).concat((D && D.discarded) || [])) {
        const ev = it.evidence || {};
        const cwe = ev.cwe || '';
        const key = cwe || ('effect:' + ((ev.effect || {}).type || it.effect || it.class || 'recorded'));
        if (seen.has(key)) continue;
        seen.add(key);
        const where = (it.file || '') + (it.line ? ':' + it.line : '');
        rtags[key] = { cat: cwe ? 'Weakness · recorded' : 'Recorded effect', name: (cwe ? cwe + ' · ' : '') + (it.class || 'recorded suspicion'),
          desc: [it.hypothesis || it.reason || 'Recorded in the ledger.'],
          here: [where, it.entry_point ? 'entry point ' + it.entry_point : '', ev.effect && ev.effect.type ? 'effect ' + ev.effect.type : ''].filter(Boolean).join(' · ') || '',
          mitL: 'Recorded evidence', mit: [], world: [] };
      }
      weak = Object.keys(rtags).map((id) => mk(id, (rtags[id].name || id).slice(0, 60)));
      hasWeak = weak.length > 0;
      if (!hasWeak) mitNote = '';
    }
    const T = s.tag ? ((isRun && rtags) ? (rtags[s.tag] || null) : TAGS[s.tag]) : null;
    const tag = T ? { open: true, id: s.tag, cat: T.cat, name: T.name, desc: T.desc, here: T.here, mitL: T.mitL, mit: T.mit.map(([id, t]) => ({ id, t })),
      world: T.world.map(([id, t]) => ({ id, t })), hasWorld: T.world.length > 0, close: () => this.setState({ tag: null }) } : { open: false, close: () => this.setState({ tag: null }) };

    const DC = { ctx: ['transparent', '#7a86a1', '#26365a', ' '], del: ['rgba(190,60,60,.11)', '#b23a3a', '#5a1c1c', '−'], add: ['rgba(34,139,84,.11)', '#1f7a4d', '#0f3d26', '+'] };
    const row = ([k, o, n, t, v]) => ({ bg: v ? 'rgba(190,60,60,.2)' : DC[k][0], sc: DC[k][1], tc: DC[k][2], s: DC[k][3], o: o || '', n: n || '', t, vuln: !!v });
    let prDiff = [
      ['ctx', 28, 28, '        self.shelf_dir = shelf_dir'], ['ctx', 29, 29, ''], ['ctx', 30, 30, '    def _resolve(self, name):'],
      ['del', 31, 0, '        """Map a pamphlet name to a file inside the shelf, or None when it points outside."""'],
      ['del', 32, 0, '        root = os.path.realpath(self.shelf_dir)'], ['del', 33, 0, '        target = os.path.realpath(os.path.join(root, name))'],
      ['del', 34, 0, '        if os.path.commonpath([root, target]) != root:'], ['del', 35, 0, '            return None'], ['del', 36, 0, '        return target'],
      ['add', 0, 31, '        """Map a pamphlet name to a file in the shelf (nested folders are allowed)."""'],
      ['add', 0, 32, '        return os.path.join(self.shelf_dir, name)', true],
      ['ctx', 37, 33, ''], ['ctx', 38, 34, '    def handle_request(self, method, path, query=None):']
    ].map(row);
    let fixDiff = [
      ['ctx', 30, 30, '    def _resolve(self, name):'],
      ['del', 31, 0, '        """Map a pamphlet name to a file in the shelf (nested folders are allowed)."""'], ['del', 32, 0, '        return os.path.join(self.shelf_dir, name)'],
      ['add', 0, 31, '        """Map a pamphlet name to a file in the shelf; nested folders stay inside it."""'],
      ['add', 0, 32, '        root = os.path.realpath(self.shelf_dir)'], ['add', 0, 33, '        target = os.path.realpath(os.path.join(root, name))'],
      ['add', 0, 34, '        if os.path.commonpath([root, target]) != root:'], ['add', 0, 35, '            return None'], ['add', 0, 36, '        return target'],
      ['ctx', 33, 37, ''], ['ctx', 34, 38, '    def handle_request(self, method, path, query=None):']
    ].map(row);
    let expect = ['The exploit now gets 404 instead of the canary file.', 'Nested folders such as guides/intro.txt keep working.', 'All 5 project tests still pass.', 'Absolute paths, nested ../ and symlinked folders are blocked.'];

    let path = [['Entry', 'GET /pamphlet', 'public request', '#2c4fc4', 'rgba(44,79,196,.4)'], ['Entry point', 'App.handle_request', 'pamphlets.py:34', '#2c4fc4', 'rgba(13,27,62,.12)'],
      ['Changed', 'App._resolve', 'pamphlets.py:32', '#a5703f', 'rgba(165,112,63,.5)'], ['Calls', 'read_text', 'pamphlets.py:18', '#4a5873', 'rgba(13,27,62,.12)'],
      ['Sink', 'open()', 'pamphlets.py:20', '#a5703f', 'rgba(165,112,63,.5)'], ['Effect', 'Any readable file', 'outside the shelf', '#a5703f', 'rgba(165,112,63,.5)']]
      .map(([k, n, d, lc, bd], i, a) => ({ k, n, d, lc, bd, arrow: i < a.length - 1 }));

    // Run-mode artifacts: recorded files, fix patch, exploit test, suggestion link.
    let chg = { l: '1 file', sub: 'pamphlets.py', counts: '+2 −6' };
    let diffLead = 'Six lines of protection become one: a name like ../outside/canary.txt walks out of the shelf.';
    let diffFile = 'examples/action-demo/pamphlets.py', diffCounts = '+2 −6';
    let fixTitle = 'fix.patch · pamphlets.py', fixCounts = '+6 −2', fixMissing = false;
    let xtest = null, xtestMissing = false, xtestTitle = 'test_exploit.py · recorded artifact';
    let sugg = { show: false, hide: true, href: '' };
    let suggNote = '';
    let blastPaths = [], blastNote = '', hasBlast = false, noBlast = false;
    if (isRun) {
      const files = R.files_touched || [];
      const rawDiff = (D && D.pr_diff) || '';
      const diffSrc = (D && D.pr_diff_source) || '';
      chg = { l: files.length ? files.length + (files.length === 1 ? ' file' : ' files') : (rawDiff ? 'diff' : ''),
        sub: files.length ? files.slice(0, 6).join(', ') + (files.length > 6 ? ' (+' + (files.length - 6) + ' more)' : '') : (rawDiff ? 'from ' + (diffSrc || 'the recorded diff') : ''),
        counts: '' };
      if (rawDiff) {
        prDiff = this.diffRows(rawDiff);
        const adds = prDiff.filter((r) => r.s === '+').length, dels = prDiff.filter((r) => r.s === '−').length;
        diffFile = files[0] || (diffSrc === 'gh pr diff' ? 'gh pr diff' : 'payload.diff');
        diffCounts = '+' + adds + ' −' + dels;
        diffLead = 'Line-level diff from ' + (diffSrc === 'gh pr diff' ? 'gh pr diff' : (diffSrc === 'ledger' ? 'the pr_opened ledger payload' : 'the run folder')) + '. Highlighted as text only.';
      } else {
        prDiff = [];
        diffFile = '';
        diffCounts = '';
        diffLead = 'No pull-request diff for this run. Produce one with gh pr diff or record payload.diff on pr_opened.';
      }
      const patch = D && D.artifacts ? D.artifacts.fix_patch : null;
      if (patch) {
        fixDiff = this.diffRows(patch);
        fixTitle = 'fix.patch · recorded artifact';
        const adds = fixDiff.filter((r) => r.s === '+').length, dels = fixDiff.filter((r) => r.s === '−').length;
        fixCounts = '+' + adds + ' −' + dels;
      } else {
        fixDiff = []; fixMissing = true;
        fixTitle = ''; fixCounts = '';
      }
      const xt = D && D.artifacts ? D.artifacts.exploit_test : null;
      if (xt) {
        xtest = String(xt).split('\n').slice(0, 200).map((t, i) => ({ n: String(i + 1), t: t.slice(0, 200) }));
      } else {
        xtestMissing = true;
        xtestTitle = '';
      }
      const evx = ((D && D.proven) || [])[0];
      const evd = evx ? (evx.evidence || {}) : {};
      const pfx = evd.passes_on_fixed || {};
      const byx = evd.bypass || {};
      expect = evx ? [
        'Fix verified: ' + (pfx.fix_verified ? 'yes' : 'no') + ' (recorded).',
        'Effect seen after fix: ' + (pfx.effect_seen_after_fix ? 'yes' : 'no') + ' (recorded).',
        'Bypass variants: ' + (byx.tried || 0) + ' tried, ' + (byx.succeeded || 0) + ' got through (recorded).',
        'Exploit test path: ' + this.text(evd.exploit_test),
      ] : ['No fix is proposed when nothing was proven.'];
      const g = (D && D.graph) || {};
      const pps = g.proven_paths || g.paths || [];
      if (g.available && pps.length) {
        blastPaths = pps.slice(0, 8).map((p, i) => ({
          n: String(i + 1), entry: this.text(p.entry), sink: this.text(p.sink),
          effect: this.text(p.effect, ''), nodes: (p.nodes || []).map((x) => String(x)).slice(0, 12).join(' → '),
        }));
        const fp = pps[0] || {};
        path = (fp.nodes || []).map((x, i, a) => ({ k: i === 0 ? 'Entry' : (i === a.length - 1 ? 'Sink' : 'Calls'), n: String(x).slice(0, 80), d: fp.effect ? String(fp.effect).slice(0, 80) : '', lc: '#a5703f', bd: 'rgba(165,112,63,.5)', arrow: i < a.length - 1 }));
        blastNote = '';
        hasBlast = true;
      } else {
        const frames = (evd.provenance && evd.provenance.frames) || [];
        const obs = evd.observed_location || {};
        const entry = (evd.provenance && evd.provenance.entry_point) || evx && evx.entry_point || '';
        const sinkFile = (obs.file || evx && evx.file || '') + (obs.line || (evx && evx.line) ? ':' + (obs.line || evx.line) : '');
        const effect = (evd.effect && (evd.effect.label || evd.effect.type)) || '';
        if (entry || sinkFile || effect) {
          const nodes = [];
          if (entry) nodes.push({ k: 'Entry', n: entry, d: 'entry point the oracle matched', lc: '#2c4fc4', bd: 'rgba(44,79,196,.4)', arrow: true });
          frames.slice(0, 6).forEach((f, i, a) => {
            nodes.push({ k: f.function || 'frame', n: (f.file || '') + (f.line ? ':' + f.line : ''), d: f.function || '', lc: '#4a5873', bd: 'rgba(13,27,62,.12)', arrow: true });
          });
          if (sinkFile) nodes.push({ k: 'Sink', n: sinkFile, d: effect || 'oracle-observed location', lc: '#a5703f', bd: 'rgba(165,112,63,.5)', arrow: !!effect });
          if (effect) nodes.push({ k: 'Effect', n: effect, d: (evd.effect && evd.effect.path) || '', lc: '#a5703f', bd: 'rgba(165,112,63,.5)', arrow: false });
          if (nodes.length) nodes[nodes.length - 1].arrow = false;
          path = nodes;
          blastPaths = [{ n: '1', entry: entry || 'entry', sink: sinkFile || 'sink', effect: effect, nodes: nodes.map((x) => x.n).filter(Boolean).join(' → ') }];
          hasBlast = true;
          noBlast = false;
          blastNote = '';
        } else {
          path = [];
          blastPaths = [];
          hasBlast = false;
          noBlast = true;
          blastNote = 'No blast radius: the ledger has no proven entry, sink or effect for this run, and no code graph was built. Compute one with exhibit-a scan --graph.';
        }
      }
      // Recorded graph summary (artifact-schema.md): reachability proposals,
      // shown only when no proven path exists and labeled as proposals.
      const gs = (D && D.graph_summary) || null;
      if (!hasBlast && gs && gs.available && (gs.paths || []).length) {
        blastPaths = gs.paths.slice(0, 8).map((p, i) => ({
          n: String(i + 1),
          entry: this.text(p.entry_point),
          sink: this.text(p.changed),
          effect: this.text(p.vuln_class || gs.effect, ''),
          nodes: String(p.path || '').split(' -> ').map((x) => x.slice(0, 80)).slice(0, 12).join(' → '),
        }));
        path = [];
        hasBlast = true;
        noBlast = false;
        blastNote = 'Reachability proposal from the recorded graph summary, not a proven path.';
      }
      const disc = R.discussion_url || '';
      // A recorded review thread (…/pull/N#discussion_r<id>) opens on the PR
      // files tab anchored at the suggestion; a bare PR page opens its files.
      const hash = disc.indexOf('#');
      const base = hash < 0 ? disc : disc.slice(0, hash);
      const frag = hash < 0 ? '' : disc.slice(hash);
      const sid = String((R && R.suggestion_id) || (D && D.suggestion_id) || '').replace(/[^0-9]/g, '');
      const anchor = frag || (sid ? '#discussion_r' + sid : '');
      const outside = !!(D && D.fix_outside_pr_diff);
      sugg = disc && !outside ? { show: true, hide: false, href: base + '/files' + anchor } : { show: false, hide: false, href: '' };
      suggNote = outside
        ? 'GitHub cannot attach a suggestion outside the PR diff...'
        : (disc ? '' : '');
    }

    const CS = ['Suggestion applied by the author with Commit suggestion (GitHub creates the commit)', 'Proof loop re-run on the new head: exploit gets 404, nothing proven', 'Baseline 5 / 5 and bypass variants 3 / 3 blocked', 'Checks green · merge unblocked'];
    const commitSteps = CS.map((l, i) => ({ l, done: i < s.cstep, cls: i === s.cstep ? 'pulse' : '', op: i <= s.cstep ? 1 : 0.45,
      bg: i < s.cstep ? '#2c4fc4' : 'transparent', bd: i <= s.cstep ? '#2c4fc4' : 'rgba(13,27,62,.25)' }));
    const doCommit = () => {
      this.setState({ confirm: false, status: 'committing', cstep: 0 });
      CS.forEach((_, i) => { this.timers.push(setTimeout(() => this.setState({ cstep: i + 1 }), 900 * (i + 1))); });
      this.timers.push(setTimeout(() => this.setState({ status: 'approved' }), 900 * CS.length + 500));
    };
    let fx = status === 'approved'
      ? { title: 'Corrected', lead: 'The verified fix was posted as a review suggestion and the author applied it. These are the measured differences between the pull request as opened and after the suggestion.', approved: true }
      : status === 'committing' ? { title: 'Applying the fix', lead: 'The bot is pushing the commit and the proof loop is checking the new head.', committing: true }
        : { title: 'Proposed fix', lead: 'The fixer restored the containment check while keeping the feature: nested folders still work, they just cannot leave the shelf. The fix was verified before it was offered to you.', pending: true };
    if (isRun) {
      // Recorded wording only: the demo's pamphlet story never appears here.
      const evf = ((D && D.proven) || [])[0];
      const fixed = evf && (evf.evidence || {}).passes_on_fixed;
      fx = { title: 'Recorded fix', lead: evf
        ? 'The recorded fix ' + (fixed && fixed.fix_verified ? 'was verified in the sandbox' : 'has no verified fix recorded') + '. The full patch is rendered above as text; nothing here is executed or pushed.'
        : 'No fix was proposed: nothing was proven. The fix section is shown because the run recorded no verdict.',
        pending: !!evf };
    }
    const after = [
      { m: 'Request ../outside/canary.txt', b: '200 · canary text returned', a: '404 · not found' },
      { m: 'Request guides/intro.txt', b: '200', a: '200 · nested folders still work' },
      { m: 'Project tests', b: '5 / 5', a: '5 / 5' },
      { m: 'Bypass variants', b: 'not applicable', a: '3 / 3 blocked' },
      { m: 'Oracle verdict', b: 'proven · CWE-22', a: 'nothing could be proven' },
      { m: 'Merge gate', b: 'blocked', a: 'open' }
    ];

    const selPr = this.prRow();
    const allPrs = (this.state.prs || []).map((r) => ({
      id: String(r.number || r.id), title: r.title,
      when: (r.merged_at || r.created_at || '').slice(0, 16).replace('T', ' '),
      author: r.author, commits: r.commits || 0, files: r.changed_files || (r.files || []).length,
      added: r.additions || 0, removed: r.deletions || 0, tests: false, area: r.area || '',
      cycle: 0, lines: (r.additions || 0) + (r.deletions || 0),
      kind: r.author_kind || 'unclassified', color: r.author_color || '#4a5873',
    }));
    const median = (xs) => { const v = xs.slice().sort((a, b) => a - b); return v.length ? v[Math.floor(v.length / 2)] : 0; };
    const mean = (xs) => xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
    const medLines = median(allPrs.map((r) => r.lines)), avgLines = Math.round(mean(allPrs.map((r) => r.lines)));
    const medCycle = median(allPrs.map((r) => r.cycle)), avgFiles = mean(allPrs.map((r) => r.files));
    const byWhen = allPrs.slice().sort((a, b) => (a.when < b.when ? -1 : a.when > b.when ? 1 : 0));
    const prIndex = selPr ? byWhen.findIndex((r) => r.id === selPr.id) : -1;
    const relLink = (r) => ({ id: r.id, title: r.title, href: 'pr.html?pr=' + encodeURIComponent(r.id), author: r.author,
      ty: r.kind || 'unclassified', c: r.color || '#4a5873', when: r.when });
    const dayCounts = {};
    allPrs.forEach((r) => { const d = r.when.slice(0, 5); dayCounts[d] = (dayCounts[d] || 0) + 1; });
    const maxDay = Math.max(1, ...Object.values(dayCounts));
    const enriched = selPr && !selPr.missing ? {
      life: [
        { l: 'Opened', d: selPr.when, state: 'done', done: true, bg: '#2c4fc4' },
        { l: 'Tests green', d: 'Merged only with green tests (project rule)', state: 'done', done: true, bg: '#2c4fc4' },
        { l: 'Exhibit A check', d: 'Not evaluated for this pull request', state: 'neutral', neutral: true, bg: '#8b98b3' },
        { l: 'Merged', d: selPr.when + ' · into main', state: 'done', done: true, bg: '#2c4fc4' }
      ],
      ctx: [
        { l: 'Change size', v: (selPr.added + selPr.removed) + ' lines', d: 'mean ' + avgLines + ' · median ' + medLines + ' across ' + allPrs.length + ' PRs', pct: Math.min(100, Math.round((selPr.added + selPr.removed) / Math.max(1, medLines * 2) * 100)) },
        { l: 'Cycle', v: selPr.cycle + ' min', d: 'median ' + medCycle + ' min across all PRs', pct: Math.min(100, Math.round(selPr.cycle / Math.max(1, medCycle * 2) * 100)) },
        { l: 'Files', v: selPr.files + ' files', d: 'mean ' + avgFiles.toFixed(1) + ' files per PR', pct: Math.min(100, Math.round(selPr.files / Math.max(1, avgFiles * 2) * 100)) },
        { l: 'Tests', v: selPr.tests ? 'Touches tests' : 'No test files', d: selPr.tests ? 'At least one test file changed' : 'No test file in the change', pct: selPr.tests ? 100 : 8 }
      ],
      days: Object.entries(dayCounts).sort().map(([d, n]) => ({ d, n, h: Math.round(n / maxDay * 100), here: selPr.when.slice(0, 5) === d, bar: selPr.when.slice(0, 5) === d ? '#a5703f' : '#2c4fc4' })),
      sameArea: allPrs.filter((r) => r.area === selPr.area && r.id !== selPr.id).slice(0, 5).map(relLink),
      sameAuthor: allPrs.filter((r) => r.author === selPr.author && r.id !== selPr.id).slice(-4).map(relLink),
      prevPr: prIndex > 0 ? relLink(byWhen[prIndex - 1]) : null,
      nextPr: prIndex >= 0 && prIndex < byWhen.length - 1 ? relLink(byWhen[prIndex + 1]) : null,
      hasPrev: prIndex > 0, hasNext: prIndex >= 0 && prIndex < byWhen.length - 1
    } : null;
    let pr = selPr && !selPr.missing
      ? { crumb: selPr.id, title: selPr.title, meta: selPr.id + ' · ' + selPr.author + ' · ' + selPr.when + ' · ' + selPr.files + ' files · ' + selPr.area,
          lead: 'Pull request #' + selPr.id + ' from gh pr list --state all. Its recorded metadata is below.', author: selPr.author, authorType: selPr.kind || 'unclassified', when: selPr.when, files: selPr.files, added: selPr.added, removed: selPr.removed, commits: selPr.commits, areaShort: (selPr.area || '').replace(/^src\//, ''), testsLabel: selPr.tests ? 'touches tests' : 'listed files', cycle: selPr.cycle, ...enriched }
      : selPr
        ? { crumb: selPr.id, title: selPr.id, meta: selPr.id + ' · not in gh pr list --state all for this source', lead: 'No pull request with this number is in the current source. List them with gh pr list --state all.' }
        : { crumb: 'nested-pamphlets', title: 'Allow nested folders in pamphlet names', meta: 'examples/action-demo · nested-pamphlets → main · patch 01-path-traversal',
            lead: 'Removes the check that kept requested names inside the shelf. Exhibit A tested what that allows, live, in a sandbox.' };
    if (isRun) {
      // Header from the recorded run only: PR, repo, branch, commit, timing,
      // cost and tokens. Nothing here is estimated.
      const short = String(R.commit || '').slice(0, 12);
      const metaBits = [R.repo || '', R.pr ? 'PR #' + String(R.pr).replace(/^#/, '') : '', R.branch || '', short || '', R.started_at || ''].filter(Boolean);
      const firstP0 = ((D && D.proven) || [])[0] || null;
      const toks0 = (R.tokens_in != null && R.tokens_out != null) ? this.int(R.tokens_in + R.tokens_out) + ' tokens' : '';
      const cost0 = this.money(R.cost_usd);
      const models0 = ((R.models || []).length && R.models.join(', ')) || '';
      pr = { crumb: String(runId).slice(0, 40),
        title: firstP0 ? (firstP0.class || 'proven finding') + ' in ' + (firstP0.file || 'recorded file') : (R.headline || 'Run ' + runId),
        meta: metaBits.join(' · '),
        lead: [R.headline || 'Recorded run', cost0, toks0, models0].filter(Boolean).join(' · ') + '.' };
    }
    const bv = s.bv;
    const mode = { isAnalysis: !!runId || !selPr, isPr: !!selPr && !runId, isDemo: !runId && !selPr, isRun: !!runId };
    return { mode, pr, bPath: (!isRun && bv === 'path') ? 'block' : 'none', bNet: (!isRun && bv === 'net') ? 'block' : 'none',
      bvOpts: [['path', 'Path'], ['net', 'Graph']].map(([k, l]) => ({ l, cls: 'sb' + (bv === k ? ' sb-on' : ''), pick: () => this.setState({ bv: k }) })),
      st: isRun ? { l: this.text(R.status, 'recorded'), s: R.headline || 'Recorded run', cls: 'state-open', isOpen: true, bg: 'rgba(165,112,63,.14)', fg: '#7d5229', bd: 'rgba(165,112,63,.4)' } : st,
      risk, hasRisk: !!(risk && risk.l), verdict, merge: mergeOut, attack, weak, hasAttack, hasWeak, mitNote, tag, stop: (e) => e.stopPropagation(), live, dec: vdec || dec, proof: vproof || proof, showFixSection: showFixSection && !(isRun && fixMissing), whyPanel,
      prDiff, fixDiff, fixTitle, fixCounts, fixMissing, notFixMissing: !fixMissing, hasDiff: isRun ? prDiff.length > 0 : true, noDiff: isRun && prDiff.length === 0,
      xtest, xtestMissing, notXtestMissing: !xtestMissing, hasXtest: isRun && !xtestMissing, xtestTitle, expect, path, chg, diffLead, diffFile, diffCounts, sugg, suggNote, blastPaths, blastNote, hasBlast, noBlast, safe: s.safe,
      fx, commitSteps, after, confirm: s.confirm, askApprove: () => this.setState({ confirm: true }), cancel: () => this.setState({ confirm: false }), doCommit,
      reset: () => this.setState({ status: 'pending', cstep: 0 }) };
  }
};
