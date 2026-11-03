/* View logic for finding.html, rendered by ../dc-lite.js.
 *
 * One proven finding as a printable test package: the diff it blames, the
 * exploit that proved it, and the verdict with its evidence. Everything is
 * read from /api/runs/<id>; the page prints cleanly for the demo video.
 */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { item: null, run: null, err: '', fid: '' };
  }
  componentDidMount() {
    let runId = '', fid = '';
    try {
      const q = new URLSearchParams(window.location.search);
      runId = q.get('run') || ''; fid = q.get('finding') || '';
    } catch (e) { /* ignore */ }
    if (!runId) {
      fetch('/api/runs?per_page=1', { headers: { Accept: 'application/json' } })
        .then((r) => (r.ok ? r.json() : { runs: [] }))
        .then((body) => {
          const first = ((body && body.runs) || [])[0];
          if (first) this.loadRun(first.run_id, fid);
          else this.setState({ err: 'Open this page with ?run=<id>&finding=<suspicion-id>.' });
        })
        .catch(() => this.setState({ err: 'Open this page with ?run=<id>&finding=<suspicion-id>.' }));
      return;
    }
    this.loadRun(runId, fid);
  }
  loadRun(runId, fid) {
    this.setState({ fid });
    fetch('/api/runs/' + encodeURIComponent(runId), { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((detail) => {
        if (!detail || detail.run.error) { this.setState({ err: 'Run could not be read.' }); return; }
        const all = (detail.proven || []).concat(detail.discarded || []);
        const item = all.find((f) => f.id === fid) || detail.proven[0];
        if (!item) { this.setState({ err: 'Finding not found in this run.', run: detail.run }); return; }
        this.setState({ item: this.shape(item), run: detail.run, fid: item.id });
      })
      .catch(() => this.setState({ err: 'Could not load the run.' }));
  }
  sheetFor(item) {
    const SHEETS = {
      'CWE-22': ['Path traversal', 'A file path is built from caller input without proving the resolved path stays inside the directory meant to be served.', 'Read or overwrite any file the account can reach: configuration, keys, source code.', 'Resolve the path, then check containment with a common-path test against the allowed root on every call.'],
      'CWE-78': ['Command injection', 'Caller input reaches a shell or process call and is interpreted as command syntax, not data.', 'Runs arbitrary commands with the service identity.', 'Avoid the shell; pass arguments as a list and allowlist the values that may vary.'],
      'CWE-89': ['SQL injection', 'Caller input is interpolated into a query and changes its structure.', 'Reads, changes or deletes database rows the caller should never reach.', 'Use bound parameters everywhere; never build SQL by string concatenation.'],
      'CWE-94': ['Code injection', 'Caller input is evaluated as code, for example through template rendering or dynamic evaluation.', 'Runs arbitrary code in the service process.', 'Never evaluate caller input; use templates with auto-escaping and fixed expressions.'],
      'CWE-502': ['Unsafe deserialization', 'Untrusted bytes are deserialized into objects with behaviour attached.', 'Object construction becomes remote code execution.', 'Accept only signed data or use a plain data format with an explicit schema.'],
      'CWE-79': ['Cross-site scripting', 'Caller input is reflected into a page without escaping for that context.', 'Scripts run in another user\u2019s browser under the site\u2019s origin.', 'Escape on output for the exact HTML, attribute or script context; prefer text nodes.'],
      'CWE-918': ['Server-side request forgery', 'The server fetches a URL the caller chose, including internal addresses.', 'Reaches internal services and cloud metadata with the server\u2019s network position.', 'Allowlist hosts, resolve and re-check addresses, and block private ranges.'],
      'CWE-601': ['Open redirect', 'A redirect target comes from caller input without validation.', 'Trusted-looking links hand users to attacker sites.', 'Allowlist relative paths or known hosts; never redirect to raw input.'],
      'CWE-639': ['Insecure direct object reference', 'An object is fetched by caller-supplied id without an ownership check.', 'One user reads or changes another user\u2019s objects.', 'Check ownership or authorization on every object access, server side.'],
      'CWE-611': ['XML external entities', 'The XML parser resolves external entities from untrusted documents.', 'Reads local files or makes server-side requests from the parser.', 'Disable DTDs and external entities in the parser configuration.'],
    };
    const s = SHEETS[item.cwe] || ['Weakness ' + (item.cwe || 'unspecified'), item.cls || 'The weakness recorded for this finding.', 'Impact depends on what the reached sink can do; the oracle observed: ' + item.effect + '.', 'Constrain the caller-controlled input before it reaches the sink, and verify with the exploit test.'];
    return { id: item.cwe || '—', name: s[0], what: s[1], impact: s[2], fix: s[3] };
  }
  shape(f) {
    const ev = f.evidence || {};
    const eff = ev.effect || {}, obs = ev.observed_location || {}, prov = ev.provenance || {};
    const frames = (prov.frames || []).map((fr) => ({
      t: (fr.function || fr.qualname || '?') + ' · ' + (fr.file || '?') + ':' + (fr.line || 0),
      adm: fr.admitted === false ? 'not admitted' : (fr.entry_point ? 'entry point' : 'admitted'),
    }));
    const bypass = ev.bypass || {};
    return {
      id: f.id || '', cls: f.class || '', verdict: f.verdict || '',
      reason: f.reason || '', hypo: f.hypothesis || '',
      cwe: ev.cwe || '', severity: ev.severity || '',
      effect: (eff.label || eff.type || 'unknown') + (eff.path ? ' · ' + eff.path : ''),
      where: (obs.file || f.file || '') + ':' + (obs.line || f.line || 0),
      whereFn: obs.function || '', whereSrc: obs.line_source || '',
      entry: prov.entry_point || f.entry_point || '',
      frames, hasFrames: frames.length > 0,
      exploit: ev.exploit_test || '—',
      vulnRuns: ((ev.fails_on_vulnerable || {}).runs || 0) + ' run(s)',
      fixedRuns: ((ev.passes_on_fixed || {}).runs || 0) + ' run(s)',
      fixVerified: (ev.passes_on_fixed || {}).fix_verified ? 'yes' : 'no',
      fixDiff: (ev.fix || {}).diff || 'No patch text recorded.',
      fixPath: (ev.fix || {}).patch_path || '',
      bypassTried: bypass.tried || 0, bypassWon: bypass.succeeded || 0,
      variants: (bypass.variants || []).map((v) => ({ n: v.name || '?', s: v.bypassed ? 'BYPASSED' : 'blocked' })),
      hasVariants: (bypass.variants || []).length > 0,
      n: {
        vulnRuns: (ev.fails_on_vulnerable || {}).runs || 0,
        effectObserved: eff.observed === true,
        fixApplied: !!((ev.fix || {}).applied || (ev.fix || {}).proposed),
        fixedRuns: (ev.passes_on_fixed || {}).runs || 0,
        fixVerified: (ev.passes_on_fixed || {}).fix_verified === true,
        bypassTried: bypass.tried || 0, bypassWon: bypass.succeeded || 0,
      },
    };
  }
  replaySteps(item) {
    const n = item.n || {}, nr = { t: 'not recorded', rec: false };
    const step = (ok, t, d) => ok ? { t, d, rec: true } : { ...nr, d };
    return [
      step(n.vulnRuns > 0 && n.effectObserved, 'Exploit fails on vulnerable code', n.vulnRuns + ' run(s); oracle observed ' + item.effect),
      step(n.fixApplied, 'Fix applied', item.fixPath || 'patch recorded in the package'),
      step(n.fixedRuns > 0 && n.fixVerified, 'Exploit passes on fixed code', n.fixedRuns + ' run(s); baseline still green'),
      step(n.bypassTried > 0 && n.bypassWon === 0, 'Bypass blocked', n.bypassTried + ' variant(s) tried, ' + n.bypassWon + ' got through'),
    ];
  }
  startReplay() {
    const item = this.state.item;
    if (!item) return;
    const total = this.replaySteps(item).length;
    const REDUCE = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    if (this.timer) clearInterval(this.timer);
    if (REDUCE) { this.setState({ replayStep: total }); return; }
    this.setState({ replayStep: 0, replayPlaying: true });
    this.timer = setInterval(() => {
      const next = (this.state.replayStep || 0) + 1;
      if (next > total) { clearInterval(this.timer); this.setState({ replayPlaying: false }); return; }
      this.setState({ replayStep: next });
    }, 900);
  }
  renderVals() {
    const s = this.state;
    const item = s.item;
    const steps = item ? this.replaySteps(item) : [];
    const at = s.replayStep == null ? -1 : s.replayStep;
    return {
      err: s.err, ready: !!item, item: item || {},
      sheet: item ? this.sheetFor(item) : {},
      replay: {
        steps: steps.map((x, i) => ({ t: x.t, d: x.d, done: i < at, now: i === at, bg: i < at ? '#2c4fc4' : 'transparent', bd: i <= at ? '#2c4fc4' : 'rgba(13,27,62,.25)', op: i <= at ? 1 : 0.45 })),
        start: () => this.startReplay(),
        label: s.replayPlaying ? 'Replaying…' : 'Replay the proof',
        playing: !!s.replayPlaying,
      },
      runTitle: s.run ? (s.run.title || s.run.run_id) : '',
      runId: s.run ? s.run.run_id : '',
      printedAt: new Date().toISOString().slice(0, 10),
      doPrint: () => window.print(),
    };
  }
};
