/* View logic for economics.html, rendered by ../dc-lite.js.
 *
 * Every figure comes from the dashboard API for the current --source
 * (/api/repos, then /api/repos/<id>): cumulative spend, cost per run and per
 * proven finding, tokens and cost per role and per model, and the spend trend
 * over time. Cards without a recorded value (budget cap, missing artifacts)
 * are hidden rather than labelled.
 */
window.Component = class extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { info: null, repos: [], repoId: '', detail: null, err: '', view: 'cost', trend: 'per_run', hover: '' };
  }
  componentDidMount() {
    fetch('/api/info', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((info) => { if (info) this.setState({ info }); })
      .catch(() => {});
    fetch('/api/repos', { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((body) => {
        const repos = (body && body.repos) || [];
        if (!repos.length) { this.setState({ repos: [] }); return; }
        this.setState({ repos });
        this.loadRepo(repos[0].id);
      })
      .catch(() => this.setState({ err: 'Could not load repositories.' }));
  }
  loadRepo(id) {
    this.setState({ repoId: id, detail: null, err: '' });
    fetch('/api/repos/' + encodeURIComponent(id), { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((detail) => {
        if (!detail) { this.setState({ err: 'Could not load this repository.' }); return; }
        this.setState({ detail });
      })
      .catch(() => this.setState({ err: 'Could not load this repository.' }));
  }
  money(v) {
    if (v == null) return '';
    const s = Number(v).toFixed(6).replace(/0+$/, '').replace(/\.$/, '');
    return '$' + s;
  }
  num(v) {
    if (v == null) return '';
    return Number(v).toLocaleString('en-US');
  }
  fullSpec(id) {
    if (id !== 'econroles' || !this.__econ) return null;
    const roles = this.__econ.roles;
    const total = roles.reduce((t, r) => t + r.v, 0);
    const rows = roles.map((r) => ({ key: r.n, label: r.n, sub: r.d, v: r.v, color: r.c, value: r.disp + ' · ' + Math.round(r.v / total * 100) + '%' }));
    return { type: 'hbars', title: 'Spend by role', aria: 'Recorded model spend for each role', rowH: 48, labelW: 220, groups: [{ rows, max: roles[0].v }], rows };
  }
  renderVals() {
    const s = this.state;
    const info = s.info || {};
    const detail = s.detail;
    const m = (detail && detail.metrics) || {};
    const repo = (detail && detail.repo) || {};
    const src = info.source || 'Exhibit A';
    const subtitle = src + (repo.name && !src.endsWith(repo.name) ? ' · ' + repo.name : '');
    const empty = !s.err && s.repos.length === 0;
    const cards = [
      { i: 'M12 2v20M16.5 6.5C15.8 5.4 14 4.5 12 4.5c-2.5 0-4.5 1.6-4.5 3.7 0 5 9 2.6 9 7.1 0 2.1-2 3.7-4.5 3.7-2 0-3.8-.9-4.5-2', l: 'Total spend', v: detail ? this.money(m.cost_usd) : '…', u: detail ? this.num(m.tokens_in + m.tokens_out) + ' tokens in and out' : 'loading recorded runs' },
      { i: 'M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3ZM8.8 12l2.2 2.2 4.3-4.4', l: 'Per proven finding', v: detail ? this.money(m.cost_per_proven) : '…', u: detail ? (m.proven || 0) + ' proven across ' + (m.runs || 0) + ' runs' : 'loading recorded runs' },
      { i: 'M4 6h16M4 12h10M4 18h13', l: 'Cost per run', v: detail ? this.money(m.cost_per_run) : '…', u: detail ? (m.runs || 0) + ' recorded runs' : 'loading recorded runs' },
    ];
    if (detail && detail.budget_usd != null) {
      cards.push({ i: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 7v5l3 2', l: 'Budget', v: this.money(detail.budget_usd), u: 'hard cap recorded for this source' });
    }
    const byRole = (detail && detail.cost_by_role) || {};
    const COLORS = { adversary: '#0f2557', test_writer: '#2c4fc4', fixer: '#6a8fd8', defender: '#9aa3e0' };
    const DESCS = { adversary: 'raises suspicions', test_writer: 'writes exploits', fixer: 'proposes patches', defender: 'tries to bypass fixes' };
    const roleNames = Object.keys(byRole).sort((a, b) => (byRole[b].cost_usd || 0) - (byRole[a].cost_usd || 0));
    const totalCost = roleNames.reduce((t, n) => t + (byRole[n].cost_usd || 0), 0);
    const totalTokens = roleNames.reduce((t, n) => t + (byRole[n].tokens_in || 0) + (byRole[n].tokens_out || 0), 0);
    const roleRows = roleNames.map((n, i) => {
      const r = byRole[n];
      const cost = r.cost_usd || 0, tokens = (r.tokens_in || 0) + (r.tokens_out || 0);
      const v = s.view === 'tokens' ? tokens : cost;
      const max = s.view === 'tokens'
        ? Math.max(1, ...roleNames.map((k) => (byRole[k].tokens_in || 0) + (byRole[k].tokens_out || 0)))
        : Math.max(totalCost, 1e-9);
      const share = s.view === 'share' ? (totalCost ? Math.round(cost / totalCost * 100) + '%' : '0%')
        : s.view === 'tokens' ? tokens.toLocaleString('en-US') + ' tokens' : this.money(cost);
      const tip = n + ': ' + this.money(cost) + ' (' + (totalCost ? Math.round(cost / totalCost * 100) : 0) + '% of ' +
        this.money(totalCost) + ') · ' + tokens.toLocaleString('en-US') + ' tokens · ' + (r.events || 0) +
        ' events · models: ' + (((r.models || []).length && r.models.join(', ')) || 'no model name');
      return {
        n, v, c: COLORS[n] || '#4b3fa0', d: DESCS[n] || ((r.models || []).join(', ') || 'recorded role'),
        pct: s.view === 'share' ? (totalCost ? cost / totalCost * 100 : 0) : Math.max(v / max * 100, v > 0 ? 2 : 0),
        disp: share, tip,
        op: s.hover && s.hover !== n ? 0.45 : 1, onHover: () => this.setState({ hover: n }), onLeave: () => this.setState({ hover: '' }),
      };
    });
    const byModel = (detail && detail.cost_by_model) || {};
    const modelRows = Object.keys(byModel)
      .sort((a, b) => (byModel[b].cost_usd || 0) - (byModel[a].cost_usd || 0))
      .map((name) => {
        const r = byModel[name];
        return {
          n: name, cost: this.money(r.cost_usd),
          tok: ((r.tokens_in || 0) + (r.tokens_out || 0)).toLocaleString('en-US'),
          ev: String(r.events || 0), roles: (r.roles || []).join(', ') || '',
          tip: name + ': ' + this.money(r.cost_usd) + ' · ' + ((r.tokens_in || 0) + (r.tokens_out || 0)).toLocaleString('en-US') + ' tokens · roles: ' + ((r.roles || []).join(', ') || 'none'),
        };
      });
    const series = (detail && detail.run_series) || [];
    const trendMax = Math.max(1e-9, ...series.map((p) => s.trend === 'cumulative' ? (p.cumulative_cost_usd || 0) : (p.cost_usd || 0)));
    const trendRows = series.map((p) => {
      const v = s.trend === 'cumulative' ? (p.cumulative_cost_usd || 0) : (p.cost_usd || 0);
      const label = p.pr && String(p.pr).match(/^\d+$/) ? 'PR #' + p.pr : (p.run_id || 'run');
      return {
        label, v,
        pct: Math.max(v / trendMax * 100, v > 0 ? 2 : 0),
        disp: this.money(v),
        tip: label + ' · ' + (p.started_at || 'no timestamp') + ' · ' + this.money(p.cost_usd) +
          ' · proven: ' + (p.proven || 0) + ' · cumulative: ' + this.money(p.cumulative_cost_usd),
      };
    });
    const budget = detail ? detail.budget_usd : undefined;
    this.__econ = { roles: roleRows };
    const toggles = {
      view: s.view,
      cost: () => this.setState({ view: 'cost' }), tokens: () => this.setState({ view: 'tokens' }), share: () => this.setState({ view: 'share' }),
      trend: s.trend,
      perRun: () => this.setState({ trend: 'per_run' }), cumulative: () => this.setState({ trend: 'cumulative' }),
    };
    const repoOpts = s.repos.map((r) => ({ k: r.id, l: (r.name || r.id) + ' (' + r.runs + ')' }));
    return {
      subtitle, cards, roles: roleRows, hasRoles: roleRows.length > 0,
      models: modelRows, hasModels: modelRows.length > 0,
      trend: trendRows, hasTrend: trendRows.length > 0,
      budgetKnown: budget != null, budgetSpend: this.money(m.cost_usd), budgetCap: this.money(budget),
      budgetNote: budget != null ? '' : '',
      toggles, repoId: s.repoId, repoOpts, hasRepos: s.repos.length > 1,
      onRepo: (e) => this.loadRepo(e.target.value),
      err: s.err, empty, ready: !!detail,
    };
  }
};
