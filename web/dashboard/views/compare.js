/* View logic for compare.html, rendered by ../dc-lite.js.
 *
 * Two runs side by side (before and after a fix): every number comes from
 * /api/runs/<id>, so the comparison is ledger data, never a mock.
 */
window.Component = class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { a: '', b: '', opts: [], da: null, db: null, err: '' };
  }
  componentDidMount() {
    let a = '', b = '';
    try {
      const q = new URLSearchParams(window.location.search);
      a = q.get('a') || ''; b = q.get('b') || '';
    } catch (e) { /* ignore */ }
    fetch('/api/runs?per_page=100', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : { runs: [] }))
      .then((body) => {
        const rows = ((body && body.runs) || []).map((r) => ({ id: r.run_id, label: (r.pr ? 'PR ' + r.pr + ' · ' : '') + (r.title || r.run_id) }));
        const first = rows[0] ? rows[0].id : '', second = rows[1] ? rows[1].id : '';
        this.setState({ opts: rows.map((r) => ({ k: r.id, l: r.label })) });
        const A = a || first, B = b || second;
        if (A) this.pick('a', A);
        if (B && B !== A) this.pick('b', B);
      })
      .catch(() => this.setState({ err: 'Could not load the runs list.' }));
  }
  pick(side, id) {
    this.setState({ [side]: id, err: '' });
    fetch('/api/runs/' + encodeURIComponent(id), { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((detail) => {
        if (!detail) { this.setState({ err: 'Run not found: ' + id }); return; }
        this.setState({ [side === 'a' ? 'da' : 'db']: detail });
      })
      .catch(() => this.setState({ err: 'Could not load run ' + id }));
  }
  col(detail) {
    if (!detail) return { on: false };
    const run = detail.run || {};
    const proven = detail.proven || [], discarded = detail.discarded || [];
    return {
      on: true,
      title: run.title || run.run_id, id: run.run_id,
      headline: run.headline || '', status: run.status || '',
      proven: proven.length, discarded: discarded.length,
      suspicions: run.suspicions_raised || 0, exploits: run.exploits_written || 0,
      cost: '$' + Number(run.cost_usd || 0).toFixed(4),
      dur: run.duration_s != null ? run.duration_s + 's' : '—',
      effects: (run.effects || []).join(', ') || '—',
      findings: proven.slice(0, 8).map((f) => ({ id: f.id || '?', cls: f.class || '', cwe: ((f.evidence || {}).cwe) || '' })),
    };
  }
  renderVals() {
    const s = this.state;
    const A = this.col(s.da), B = this.col(s.db);
    const rows = [
      ['Headline', 'headline'], ['Status', 'status'], ['Proven findings', 'proven'],
      ['Discarded suspicions', 'discarded'], ['Suspicions raised', 'suspicions'],
      ['Exploits written', 'exploits'], ['Model cost', 'cost'], ['Duration', 'dur'], ['Effects', 'effects'],
    ].map(([label, key]) => {
      const av = A.on ? String(A[key]) : '—', bv = B.on ? String(B[key]) : '—';
      const same = av === bv;
      return { label, a: av, b: bv, ac: same ? '#3d4b68' : '#a5703f', bc: same ? '#3d4b68' : '#2c4fc4' };
    });
    const verdict = A.on && B.on
      ? (B.proven === 0 && A.proven > 0
        ? { t: 'Fix held: nothing could be proven after', d: 'The left run proved ' + A.proven + ' finding(s); on the right run the same loop proved nothing. That is the red-to-green moment, read from both ledgers.' }
        : { t: 'Two ledgers, side by side', d: 'Differences are highlighted: amber for the left run, blue for the right. Equal values mean the fix changed nothing there.' })
      : { t: 'Pick two runs', d: 'Choose the run before the fix on the left and the run after the fix on the right. Every number below is read from their ledgers.' };
    return {
      err: s.err, a: s.a, b: s.b, aOpts: s.opts, bOpts: s.opts,
      onA: (e) => this.pick('a', e.target.value), onB: (e) => this.pick('b', e.target.value),
      A, B, rows, verdict,
    };
  }
};
