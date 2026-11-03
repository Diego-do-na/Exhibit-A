/* View logic for pr.html, rendered by ../dc-lite.js. */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { step: 0, acc: 0, el: 0, stamps: [], playing: true, speed: 1, status: null, confirm: false, cstep: 0, tag: null, bv: 'path', pos: null, evts: null, runId: '', safe: { show: false } };
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
    const row = (window.XA_PRS || []).find((r) => r[0] === id);
    if (!row) return { id, missing: true };
    return { id: row[0], title: row[1], when: row[2], author: row[3], commits: row[4], files: row[5], added: row[6], removed: row[7], tests: !!row[8], area: row[9], cycle: row[10] };
  }
  async loadRun() {
    const id = this.runParam();
    if (!id) return;
    this.setState({ runId: id });
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
  componentDidMount() {
    this.iv = setInterval(() => this.tick(), 250);
    this.loadRun();
    const host = document.getElementById('blast');
    if (host && window.DCViz) {
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
    if (nh && window.DCNet && window.DCGraphData) {
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
  renderVals() {
    const s = this.state;
    const runId = this.runParam();
    const status = s.status ?? (this.props.startStatus ?? 'pending');
    const evtRows = s.evts ? s.evts.map((e) => [(e.stage || e.type || 'event').toUpperCase(), e.summary || e.type, e.role || 'engine', e.summary || e.type, (e.ts || '').slice(11, 19)]) : null;
    const S = evtRows || [
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
    ];
    const N = S.length, rawDone = status === 'pending' ? s.step : N;
    const done = s.pos != null && evtRows ? Math.max(0, Math.min(N, s.pos)) : Math.min(rawDone, N);
    const RC = { github: '#c3cbd8', 'ci.gate': '#d9b98f', graph: '#9aa3e0', sandbox: '#8fb4ff', adversary: '#e8b07a', test_writer: '#8fb4ff', oracle: '#ffffff', fixer: '#a7c0ff', defender: '#a7c0ff', attest: '#c3cbd8' };
    const fmtT = (x) => '+' + String(Math.floor(x / 60)).padStart(2, '0') + ':' + (x % 60).toFixed(1).padStart(4, '0');
    const live = {
      playing: s.playing && done < N, paused: !(s.playing && done < N), playL: s.playing ? 'Pause' : 'Play', running: done < N,
      toggle: () => this.setState({ playing: !s.playing }),
      replay: () => this.setState({ step: 0, acc: 0, el: 0, stamps: [], playing: true, status: 'pending', cstep: 0, pos: evtRows ? 0 : null }),
      speeds: [1, 2, 4].map((v) => ({ l: v + '×', cls: 'sb' + (s.speed === v ? ' sb-on' : ''), pick: () => this.setState({ speed: v }) })),
      pct: (done / N * 100).toFixed(1), clock: fmtT(status === 'pending' ? s.el : 16.5),
      title: done >= N ? 'Analysis complete' : 'Analyzing · ' + String(S[done][1]).toLowerCase().slice(0, 90),
      dot: done >= N ? '#2c4fc4' : '#a5703f', dotCls: done >= N ? '' : 'pulse',
      next: done < N ? S[done][2] + ' …' : '',
      src: evtRows ? 'ledger.jsonl · event ' + done + ' of ' + N : 'ledger.jsonl · live demo (open with ?run= for the real ledger)',
      stages: S.map((x, i) => ({ k: x[0], n: String(x[1]).slice(0, 80), done: i < done, cls: i === done ? 'pulse' : '',
        bg: i < done ? (i === 7 ? '#a5703f' : '#2c4fc4') : 'transparent', bd: i < done ? (i === 7 ? '#a5703f' : '#2c4fc4') : i === done ? '#2c4fc4' : 'rgba(13,27,62,.25)',
        op: i <= done ? 1 : 0.45, fw: i === done ? 600 : 400 })),
      log: S.slice(0, done).map((x, i) => ({ t: x[4] || fmtT(s.stamps[i] ?? (i + 1) * 1.5), r: x[2], rc: RC[x[2]] || '#e6ecfa', m: x[3], mc: i === 7 ? '#f0c08f' : '#e6ecfa' })),
      scrub: evtRows ? {
        max: N, val: done, label: 'event ' + done + ' of ' + N,
        onScrub: (e) => this.setState({ pos: parseInt(e.target.value, 10), step: parseInt(e.target.value, 10), playing: false }),
      } : null,
    };
    const proven = s.evts ? (s.provenCount || 0) > 0 : done >= 8;
    const dec = status === 'approved'
      ? { t: 'Fixed · nothing could be proven on the new head', d: 'The applied suggestion restored the containment check. On the new head the exploit gets a 404, the project tests still pass and every bypass variant is blocked. Nothing could be proven against it, which is not the same as safe.', c: '#2c4fc4', bg: 'rgba(44,79,196,.07)', bd: 'rgba(44,79,196,.25)' }
      : proven
        ? { t: 'Vulnerability confirmed', d: 'A pamphlet name can now reach any readable file on the host. The exploit read the canary file through the public endpoint in 3 of 3 runs, from application code. Merge is blocked until a fix is applied.', c: '#a5703f', bg: 'rgba(165,112,63,.08)', bd: 'rgba(165,112,63,.3)' }
        : { t: 'Analyzing', d: 'The proof loop is running. Nothing is reported until the oracle observes the effect itself; a model suspicion alone never blocks a merge.', c: '#4a5873', bg: 'rgba(13,27,62,.04)', bd: 'rgba(13,27,62,.1)' };
    const ck = (ok, n, d, sOk) => ({ ok, n, d, s: ok ? sOk : 'waiting', sc: ok ? '#2c4fc4' : '#7a86a1', bg: ok ? '#2c4fc4' : 'transparent', bd: ok ? '#2c4fc4' : 'rgba(13,27,62,.25)' });
    const proof = [
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

    const risk = { l: 'High', c: '#a5703f', bars: [{ c: '#d9b98f' }, { c: '#c09060' }, { c: '#a5703f' }], d: 'Application code on a path reachable from a public entry point.' };
    const verdict = proven || status === 'approved' ? { l: 'Proven', d: 'Path traversal · CWE-22 · canary_read observed by the oracle.' } : { l: 'Running', d: 'Waiting for the oracle to observe an effect.' };
    const merge = status === 'approved' ? { l: 'Ready', d: 'Fix committed; checks green on the new head.' } : status === 'committing' ? { l: 'Updating', d: 'Bot commit in progress.' } : { l: 'Blocked', d: 'Not merged. Waiting for the fix to be approved.' };
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
    const attack = [mk('T1190', 'Exploit Public-Facing Application'), mk('T1083', 'File and Directory Discovery'), mk('T1005', 'Data from Local System')];
    const weak = [mk('CWE-22', 'Path Traversal'), mk('CWE-23', 'Relative Path Traversal'), mk('CAPEC-126', 'Path Traversal'), mk('A01:2021', 'Broken Access Control')];
    const T = s.tag ? TAGS[s.tag] : null;
    const tag = T ? { open: true, id: s.tag, cat: T.cat, name: T.name, desc: T.desc, here: T.here, mitL: T.mitL, mit: T.mit.map(([id, t]) => ({ id, t })),
      world: T.world.map(([id, t]) => ({ id, t })), hasWorld: T.world.length > 0, close: () => this.setState({ tag: null }) } : { open: false, close: () => this.setState({ tag: null }) };

    const D = { ctx: ['transparent', '#7a86a1', '#26365a', ' '], del: ['rgba(190,60,60,.11)', '#b23a3a', '#5a1c1c', '−'], add: ['rgba(34,139,84,.11)', '#1f7a4d', '#0f3d26', '+'] };
    const row = ([k, o, n, t, v]) => ({ bg: v ? 'rgba(190,60,60,.2)' : D[k][0], sc: D[k][1], tc: D[k][2], s: D[k][3], o: o || '', n: n || '', t, vuln: !!v });
    const prDiff = [
      ['ctx', 28, 28, '        self.shelf_dir = shelf_dir'], ['ctx', 29, 29, ''], ['ctx', 30, 30, '    def _resolve(self, name):'],
      ['del', 31, 0, '        """Map a pamphlet name to a file inside the shelf, or None when it points outside."""'],
      ['del', 32, 0, '        root = os.path.realpath(self.shelf_dir)'], ['del', 33, 0, '        target = os.path.realpath(os.path.join(root, name))'],
      ['del', 34, 0, '        if os.path.commonpath([root, target]) != root:'], ['del', 35, 0, '            return None'], ['del', 36, 0, '        return target'],
      ['add', 0, 31, '        """Map a pamphlet name to a file in the shelf (nested folders are allowed)."""'],
      ['add', 0, 32, '        return os.path.join(self.shelf_dir, name)', true],
      ['ctx', 37, 33, ''], ['ctx', 38, 34, '    def handle_request(self, method, path, query=None):']
    ].map(row);
    const fixDiff = [
      ['ctx', 30, 30, '    def _resolve(self, name):'],
      ['del', 31, 0, '        """Map a pamphlet name to a file in the shelf (nested folders are allowed)."""'], ['del', 32, 0, '        return os.path.join(self.shelf_dir, name)'],
      ['add', 0, 31, '        """Map a pamphlet name to a file in the shelf; nested folders stay inside it."""'],
      ['add', 0, 32, '        root = os.path.realpath(self.shelf_dir)'], ['add', 0, 33, '        target = os.path.realpath(os.path.join(root, name))'],
      ['add', 0, 34, '        if os.path.commonpath([root, target]) != root:'], ['add', 0, 35, '            return None'], ['add', 0, 36, '        return target'],
      ['ctx', 33, 37, ''], ['ctx', 34, 38, '    def handle_request(self, method, path, query=None):']
    ].map(row);
    const expect = ['The exploit now gets 404 instead of the canary file.', 'Nested folders such as guides/intro.txt keep working.', 'All 5 project tests still pass.', 'Absolute paths, nested ../ and symlinked folders are blocked.'];

    const path = [['Entry', 'GET /pamphlet', 'public request', '#2c4fc4', 'rgba(44,79,196,.4)'], ['Entry point', 'App.handle_request', 'pamphlets.py:34', '#2c4fc4', 'rgba(13,27,62,.12)'],
      ['Changed', 'App._resolve', 'pamphlets.py:32', '#a5703f', 'rgba(165,112,63,.5)'], ['Calls', 'read_text', 'pamphlets.py:18', '#4a5873', 'rgba(13,27,62,.12)'],
      ['Sink', 'open()', 'pamphlets.py:20', '#a5703f', 'rgba(165,112,63,.5)'], ['Effect', 'Any readable file', 'outside the shelf', '#a5703f', 'rgba(165,112,63,.5)']]
      .map(([k, n, d, lc, bd], i, a) => ({ k, n, d, lc, bd, arrow: i < a.length - 1 }));

    const CS = ['Suggestion applied by the author with Commit suggestion (GitHub creates the commit)', 'Proof loop re-run on the new head: exploit gets 404, nothing proven', 'Baseline 5 / 5 and bypass variants 3 / 3 blocked', 'Checks green · merge unblocked'];
    const commitSteps = CS.map((l, i) => ({ l, done: i < s.cstep, cls: i === s.cstep ? 'pulse' : '', op: i <= s.cstep ? 1 : 0.45,
      bg: i < s.cstep ? '#2c4fc4' : 'transparent', bd: i <= s.cstep ? '#2c4fc4' : 'rgba(13,27,62,.25)' }));
    const doCommit = () => {
      this.setState({ confirm: false, status: 'committing', cstep: 0 });
      CS.forEach((_, i) => { this.timers.push(setTimeout(() => this.setState({ cstep: i + 1 }), 900 * (i + 1))); });
      this.timers.push(setTimeout(() => this.setState({ status: 'approved' }), 900 * CS.length + 500));
    };
    const fx = status === 'approved'
      ? { title: 'Corrected', lead: 'The verified fix was posted as a review suggestion and the author applied it. These are the measured differences between the pull request as opened and after the suggestion.', approved: true }
      : status === 'committing' ? { title: 'Applying the fix', lead: 'The bot is pushing the commit and the proof loop is checking the new head.', committing: true }
        : { title: 'Proposed fix', lead: 'The fixer restored the containment check while keeping the feature: nested folders still work, they just cannot leave the shelf. The fix was verified before it was offered to you.', pending: true };
    const after = [
      { m: 'Request ../outside/canary.txt', b: '200 · canary text returned', a: '404 · not found' },
      { m: 'Request guides/intro.txt', b: '200', a: '200 · nested folders still work' },
      { m: 'Project tests', b: '5 / 5', a: '5 / 5' },
      { m: 'Bypass variants', b: 'not applicable', a: '3 / 3 blocked' },
      { m: 'Oracle verdict', b: 'proven · CWE-22', a: 'nothing could be proven' },
      { m: 'Merge gate', b: 'blocked', a: 'open' }
    ];

    const selPr = this.prRow();
    const pr = selPr && !selPr.missing
      ? { crumb: selPr.id, title: selPr.title, meta: selPr.id + ' · ' + selPr.author + ' · ' + selPr.when + ' · ' + selPr.files + ' files · ' + selPr.area,
          lead: 'Merged pull request ' + selPr.id + '. Its recorded metadata is below; no proof analysis is attached to it.', author: selPr.author, authorType: window.XA_authorType ? window.XA_authorType(selPr.author) : 'unattributed', when: selPr.when, files: selPr.files, added: selPr.added, removed: selPr.removed, commits: selPr.commits, areaShort: selPr.area.replace(/^src\//, ''), testsLabel: selPr.tests ? 'touches tests' : 'no test files', cycle: selPr.cycle }
      : selPr
        ? { crumb: selPr.id, title: selPr.id, meta: selPr.id + ' · not in the merged pull request list', lead: 'No merged pull request with this id exists in the demo data.' }
        : { crumb: 'nested-pamphlets', title: 'Allow nested folders in pamphlet names', meta: 'examples/action-demo · nested-pamphlets → main · patch 01-path-traversal',
            lead: 'Removes the check that kept requested names inside the shelf. Exhibit A tested what that allows, live, in a sandbox.' };
    const bv = s.bv;
    const mode = { isAnalysis: !!runId || !selPr, isPr: !!selPr && !runId, isDemo: !runId && !selPr, isRun: !!runId };
    return { mode, pr, bPath: bv === 'path' ? 'block' : 'none', bNet: bv === 'net' ? 'block' : 'none',
      bvOpts: [['path', 'Path'], ['net', 'Graph']].map(([k, l]) => ({ l, cls: 'sb' + (bv === k ? ' sb-on' : ''), pick: () => this.setState({ bv: k }) })),
      st, risk, verdict, merge: mergeOut, attack, weak, tag, stop: (e) => e.stopPropagation(), live, dec: vdec || dec, proof: vproof || proof, showFixSection, whyPanel, prDiff, fixDiff, expect, path, safe: s.safe,
      fx, commitSteps, after, confirm: s.confirm, askApprove: () => this.setState({ confirm: true }), cancel: () => this.setState({ confirm: false }), doCommit,
      reset: () => this.setState({ status: 'pending', cstep: 0 }) };
  }
};
