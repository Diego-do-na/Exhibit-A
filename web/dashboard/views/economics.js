/* View logic for economics.html, rendered by ../dc-lite.js.
   Every figure comes from the recorded batch already shown on the
   Benchmark page; the calculator is an explicitly labelled simulation
   recomputed from the recorded 223k tokens. */
window.Component = class extends DCLogic {
  fullSpec(id) {
    if (id !== 'econroles' || !this.__econ) return null;
    const roles = this.__econ.roles;
    const total = roles.reduce((t, r) => t + r.v, 0);
    const rows = roles.map((r) => ({ key: r.n, label: r.n, sub: r.d, v: r.v, color: r.c, value: r.v + ' calls \u00b7 ' + Math.round(r.v / total * 100) + '%' }));
    return { type: 'hbars', title: 'Calls by role', aria: 'Model calls for each of the four roles', rowH: 48, labelW: 220, groups: [{ rows, max: roles[0].v }], rows };
  }
  getInitialState() { return { inP: 4, outP: 20, profile: 'compact' }; }
  renderVals() {
    const s = this.state;
    const cards = [
      { i: 'M12 2v20M16.5 6.5C15.8 5.4 14 4.5 12 4.5c-2.5 0-4.5 1.6-4.5 3.7 0 5 9 2.6 9 7.1 0 2.1-2 3.7-4.5 3.7-2 0-3.8-.9-4.5-2', l: 'Total spend', v: '$2.42', u: 'of the $4.00 batch budget' },
      { i: 'M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3ZM8.8 12l2.2 2.2 4.3-4.4', l: 'Per proven finding', v: '$0.081', u: '30 proven across 32 cases' },
      { i: 'M4 6h16M4 12h10M4 18h13', l: 'Tokens', v: '223k', u: '142 model calls in 4 roles' },
      { i: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 7v5l3 2', l: 'Budget left', v: '$1.58', u: '$4.00 budget minus $2.42 spent' }
    ];
    const roleRows = [['Test writer', 44, '#0f2557', 'writes exploits'], ['Fixer', 33, '#2c4fc4', 'proposes patches'], ['Defender', 33, '#6a8fd8', 'tries to bypass fixes'], ['Adversary', 32, '#9aa3e0', 'raises suspicions']];
    const roles = roleRows.map(([n, v, c, d]) => ({ n, v, c, d, pct: (v / 44 * 100).toFixed(1) }));
    const buy = [
      { l: 'Reports still to triage', a: '0', b: '3' },
      { l: 'Exploit tests written', a: '2', b: '0' },
      { l: 'Fixes verified', a: '2', b: '0' },
      { l: 'Proven findings', a: '2', b: '0' }
    ];
    // Simulation: output share implied by $2.42 over 223k tokens at $4/$20.
    const tokens = 223000, outShare = 0.428, scale = s.profile === 'standard' ? 1.6 : 1;
    const est = tokens * scale * (((1 - outShare) * (Number(s.inP) || 0)) + outShare * (Number(s.outP) || 0)) / 1e6;
    const calc = {
      inP: s.inP, outP: s.outP, profile: s.profile,
      opts: [{ k: 'compact', l: 'compact (recorded)' }, { k: 'standard', l: 'standard (simulation)' }],
      onIn: (e) => this.setState({ inP: e.target.value }),
      onOut: (e) => this.setState({ outP: e.target.value }),
      onProfile: (e) => this.setState({ profile: e.target.value }),
      est: '$' + est.toFixed(2), per: '$' + (est / 30).toFixed(3)
    };
    this.__econ = { roles };
    return { cards, roles, buy, calc };
  }
};
