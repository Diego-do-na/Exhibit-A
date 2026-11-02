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
    if (!runId) { this.setState({ err: 'Open this page with ?run=<id>&finding=<suspicion-id>.' }); return; }
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
    };
  }
  renderVals() {
    const s = this.state;
    return {
      err: s.err, ready: !!s.item, item: s.item || {},
      runTitle: s.run ? (s.run.title || s.run.run_id) : '',
      runId: s.run ? s.run.run_id : '',
      printedAt: new Date().toISOString().slice(0, 10),
      doPrint: () => window.print(),
    };
  }
};
