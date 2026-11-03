/*
 * fullchart: the expanded, fully broken-down version of each chart (SVG, no dependencies).
 *
 * The cards on the pages show a simplified chart. Opening one shows the same data drawn larger and in
 * full: every series, every label, a tooltip per mark, and a mark-to-table link (hover a mark and its
 * row lights up, and the other way round). Each page supplies a spec through its component's
 * fullSpec(id); this file only draws it.
 *
 *   DCFull.render(spec) -> { node, marks(key) }
 *   spec.type: 'bars' | 'hbars' | 'donuts' | 'scatter'
 *
 * Built with the DOM API and CSS classes only, so the strict CSP holds.
 */
(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const REDUCE = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const COLORISH = /^(fill|stroke|stop-color)$/;
  const theme = (v) => (window.DCTheme ? window.DCTheme.map(v) : v);

  const S = (tag, attrs, text) => {
    const el = document.createElementNS(NS, tag);
    for (const k in attrs || {}) el.setAttribute(k, COLORISH.test(k) ? theme(String(attrs[k])) : attrs[k]);
    if (text !== undefined) el.textContent = text;
    return el;
  };
  const H = (tag, cls, text) => { const el = document.createElement(tag); if (cls) el.className = cls; if (text !== undefined) el.textContent = text; return el; };
  const fmt = (n) => (Math.abs(n) >= 1000 ? n.toLocaleString('en-US') : String(Math.round(n * 100) / 100));
  const nice = (max) => { const p = Math.pow(10, Math.floor(Math.log10(max || 1))), m = max / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; };
  const light = (hex) => { const m = /^#([0-9a-f]{6})$/i.exec(hex || ''); if (!m) return false; const n = parseInt(m[1], 16); return (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) > 150; };

  function create(spec) {
    const wrap = H('div', 'fc');
    const tip = H('div', 'fc-tip');
    wrap.appendChild(tip);
    const byKey = new Map();
    const reg = (key, el) => { if (key === undefined) return; if (!byKey.has(key)) byKey.set(key, []); byKey.get(key).push(el); el.classList.add('zm-m'); };
    let order = 0;
    const grow = (el, axis) => {
      el.classList.add(axis === 'x' ? 'fc-gx' : 'fc-gy');
      if (!REDUCE) el.style.animationDelay = Math.min(900, order++ * 22) + 'ms';
    };
    const hover = (el, text, key) => {
      el.addEventListener('pointerenter', () => { tip.textContent = text; tip.classList.add('fc-tip-on'); wrap.classList.add('zm-has-hot'); (byKey.get(key) || [el]).forEach((m) => m.classList.add('zm-hot')); wrap.dispatchEvent(new CustomEvent('fchot', { detail: key })); });
      el.addEventListener('pointermove', (ev) => { const r = wrap.getBoundingClientRect(); tip.style.left = Math.round(ev.clientX - r.left + 14) + 'px'; tip.style.top = Math.round(ev.clientY - r.top + 14) + 'px'; });
      el.addEventListener('pointerleave', () => { tip.classList.remove('fc-tip-on'); wrap.classList.remove('zm-has-hot'); (byKey.get(key) || [el]).forEach((m) => m.classList.remove('zm-hot')); wrap.dispatchEvent(new CustomEvent('fchot', { detail: null })); });
    };

    // ---- vertical bars, stacked: categories along x, series stacked --------------------------
    function bars(sp) {
      const W = 920, Hh = 460, L = 64, R = 24, T = 34, B = 70, cw = (W - L - R) / sp.cats.length, bw = Math.min(88, cw * 0.62);
      const totals = sp.cats.map((c) => sp.series.reduce((t, s) => t + ((sp.values[c.k] || {})[s.k] || 0), 0));
      const top = nice(Math.max(...totals) * 1.08), ys = (v) => Hh - B - (v / top) * (Hh - B - T);
      const svg = S('svg', { viewBox: '0 0 ' + W + ' ' + Hh, width: '100%', role: 'img', 'aria-label': sp.aria || sp.title });
      for (let i = 0; i <= 5; i++) {
        const v = (top / 5) * i;
        svg.appendChild(S('line', { x1: L, x2: W - R, y1: ys(v), y2: ys(v), class: 'fc-grid' }));
        svg.appendChild(S('text', { x: L - 10, y: ys(v) + 4, 'text-anchor': 'end', class: 'fc-s' }, sp.axisFmt ? sp.axisFmt(v) : fmt(v)));
      }
      svg.appendChild(S('text', { x: L, y: 16, class: 'fc-s fc-b' }, sp.yTitle || ''));
      sp.cats.forEach((c, i) => {
        const x = L + i * cw + (cw - bw) / 2;
        let acc = 0;
        sp.series.forEach((s) => {
          const v = (sp.values[c.k] || {})[s.k] || 0;
          if (!v) return;
          const y1 = ys(acc + v), y0 = ys(acc), h = Math.max(1, y0 - y1 - 1);
          const r = S('rect', { x, y: y1, width: bw, height: h, rx: 2, fill: s.color, class: 'fc-bar' });
          grow(r, 'y'); reg(c.k, r);
          hover(r, c.l + ' · ' + s.name + ': ' + (sp.valFmt ? sp.valFmt(v) : fmt(v)) + (sp.totalNote ? ' · ' + sp.totalNote(c.k) : ''), c.k);
          svg.appendChild(r);
          if (h > 17 && bw > 30) svg.appendChild(S('text', { x: x + bw / 2, y: y1 + h / 2 + 4, 'text-anchor': 'middle', class: 'fc-in', fill: light(s.color) ? '#0d1b3e' : '#ffffff' }, sp.valFmt ? sp.valFmt(v) : fmt(v)));
          acc += v;
        });
        svg.appendChild(S('text', { x: x + bw / 2, y: ys(acc) - 9, 'text-anchor': 'middle', class: 'fc-t fc-b' }, sp.valFmt ? sp.valFmt(acc) : fmt(acc)));
        svg.appendChild(S('text', { x: x + bw / 2, y: Hh - B + 22, 'text-anchor': 'middle', class: 'fc-t' }, c.l));
        if (c.sub) svg.appendChild(S('text', { x: x + bw / 2, y: Hh - B + 40, 'text-anchor': 'middle', class: 'fc-s' }, c.sub));
      });
      wrap.appendChild(svg);
      if (sp.series.length > 1) {
        const lg = H('div', 'fc-legend');
        sp.series.forEach((s) => {
          const tot = sp.cats.reduce((t, c) => t + ((sp.values[c.k] || {})[s.k] || 0), 0);
          if (!tot) return;
          const it = H('span', 'fc-li'); const sw = H('i', 'fc-sw'); sw.setAttribute('data-c', s.color); sw.style.background = theme(s.color);
          it.appendChild(sw); it.appendChild(document.createTextNode(s.name + ' ')); const b = H('b', null, sp.valFmt ? sp.valFmt(tot) : fmt(tot)); it.appendChild(b); lg.appendChild(it);
        });
        wrap.appendChild(lg);
      }
    }

    // ---- horizontal bars in groups (each group has its own scale) -------------------------------
    function hbars(sp) {
      const W = 920, LBL = sp.labelW || 210, R = 90, rowH = sp.rowH || 34;
      let y = 6;
      const groups = sp.groups;
      const total = groups.reduce((t, g) => t + (g.title ? 44 : 0) + g.rows.length * rowH + 16, 12);
      const svg = S('svg', { viewBox: '0 0 ' + W + ' ' + total, width: '100%', role: 'img', 'aria-label': sp.aria || sp.title });
      groups.forEach((g) => {
        if (g.title) { svg.appendChild(S('text', { x: 4, y: y + 22, class: 'fc-t fc-h' }, g.title)); if (g.note) svg.appendChild(S('text', { x: W - R, y: y + 22, 'text-anchor': 'end', class: 'fc-s' }, g.note)); y += 44; }
        const max = g.max || Math.max(1, ...g.rows.map((r) => (r.parts ? r.parts.reduce((t, p) => t + p.v, 0) : r.v)));
        g.rows.forEach((r) => {
          const area = W - LBL - R, parts = r.parts || [{ v: r.v, color: r.color, name: r.label }];
          svg.appendChild(S('text', { x: LBL - 12, y: y + rowH / 2 - (r.sub ? 2 : -4), 'text-anchor': 'end', class: 'fc-t' }, r.label));
          if (r.sub) svg.appendChild(S('text', { x: LBL - 12, y: y + rowH / 2 + 11, 'text-anchor': 'end', class: 'fc-s fc-sm' }, r.sub));
          svg.appendChild(S('rect', { x: LBL, y: y + 6, width: area, height: rowH - 12, rx: 3, class: 'fc-track' }));
          let x = LBL;
          parts.forEach((p) => {
            const w = Math.max(p.v ? 2 : 0, (p.v / max) * area);
            if (!p.v) return;
            const rc = S('rect', { x, y: y + 6, width: w, height: rowH - 12, rx: 3, fill: p.color, class: 'fc-hb' });
            grow(rc, 'x'); reg(r.key, rc);
            hover(rc, (g.title ? g.title + ' · ' : '') + r.label + (r.parts ? ' · ' + (p.name || '') : '') + ': ' + (p.text || fmt(p.v)), r.key);
            svg.appendChild(rc);
            if (r.parts && w > 26) svg.appendChild(S('text', { x: x + w / 2, y: y + rowH / 2 + 4, 'text-anchor': 'middle', class: 'fc-in', fill: light(p.color) ? '#0d1b3e' : '#ffffff' }, p.label || fmt(p.v)));
            x += w;
          });
          svg.appendChild(S('text', { x: x + 10, y: y + rowH / 2 + 4, class: 'fc-t fc-b' }, r.value !== undefined ? r.value : fmt(parts.reduce((t, p) => t + p.v, 0))));
          y += rowH;
        });
        y += 16;
      });
      wrap.appendChild(svg);
      if (sp.legend) {
        const lg = H('div', 'fc-legend');
        sp.legend.forEach((l) => { const it = H('span', 'fc-li'); const sw = H('i', 'fc-sw'); sw.style.background = theme(l.color); it.appendChild(sw); it.appendChild(document.createTextNode(l.name)); lg.appendChild(it); });
        wrap.appendChild(lg);
      }
    }

    // ---- donuts side by side --------------------------------------------------------------------
    function donuts(sp) {
      const box = H('div', 'fc-donuts');
      sp.items.forEach((it, di) => {
        const col = H('div', 'fc-dcol');
        col.appendChild(H('h4', 'fc-dt', it.title));
        const svg = S('svg', { viewBox: '0 0 220 220', width: '100%', role: 'img', 'aria-label': it.title });
        const total = it.slices.reduce((t, s) => t + s.v, 0);
        let a = -Math.PI / 2;
        const P = (r, t) => (110 + r * Math.cos(t)).toFixed(2) + ' ' + (110 + r * Math.sin(t)).toFixed(2);
        it.slices.forEach((s) => {
          const s0 = a, e = a + (s.v / total) * Math.PI * 2; a = e;
          const lg = e - s0 > Math.PI ? 1 : 0;
          const p = S('path', { d: 'M' + P(104, s0) + ' A104 104 0 ' + lg + ' 1 ' + P(104, e - 0.001) + ' L' + P(70, e - 0.001) + ' A70 70 0 ' + lg + ' 0 ' + P(70, s0) + ' Z', fill: s.color, class: 'fc-sl' });
          grow(p, 'y'); reg(it.id + ':' + s.key, p);
          hover(p, it.title + ' · ' + s.label + ': ' + s.v + ' (' + Math.round(s.v / total * 100) + '%)', it.id + ':' + s.key);
          svg.appendChild(p);
        });
        svg.appendChild(S('text', { x: 110, y: 112, 'text-anchor': 'middle', class: 'fc-t fc-big' }, String(total)));
        svg.appendChild(S('text', { x: 110, y: 134, 'text-anchor': 'middle', class: 'fc-s' }, it.center));
        col.appendChild(svg);
        const lg = H('div', 'fc-dlist');
        it.slices.forEach((s) => {
          const row = H('div', 'fc-dli'); const sw = H('i', 'fc-sw'); sw.style.background = theme(s.color);
          row.appendChild(sw); row.appendChild(H('span', 'fc-dn', s.label)); row.appendChild(H('b', null, s.v + ' · ' + Math.round(s.v / total * 100) + '%'));
          lg.appendChild(row);
        });
        col.appendChild(lg);
        box.appendChild(col);
      });
      wrap.appendChild(box);
    }

    // ---- scatter over time -----------------------------------------------------------------------
    function scatter(sp) {
      const W = 940, Hh = 500, L = 64, R = 20, T = 36, B = 60, X0 = L, X1 = W - R, Y0 = Hh - B, Y1 = T;
      const xs = (v) => X0 + (v / sp.xMax) * (X1 - X0);
      const ys = (v) => Y0 - (Math.log10(Math.max(v, 1)) / sp.yMaxLog) * (Y0 - Y1);
      const svg = S('svg', { viewBox: '0 0 ' + W + ' ' + Hh, width: '100%', role: 'img', 'aria-label': sp.aria || sp.title });
      const dw = (X1 - X0) / sp.days.length;
      sp.days.forEach((d, i) => {
        if (i % 2) svg.appendChild(S('rect', { x: X0 + i * dw, y: Y1, width: dw, height: Y0 - Y1, class: 'fc-band' }));
        svg.appendChild(S('text', { x: X0 + i * dw + dw / 2, y: Y0 + 24, 'text-anchor': 'middle', class: 'fc-t' }, d.l));
        if (d.sub) svg.appendChild(S('text', { x: X0 + i * dw + dw / 2, y: Y0 + 42, 'text-anchor': 'middle', class: 'fc-s' }, d.sub));
      });
      sp.yTicks.forEach(([v, l]) => { svg.appendChild(S('line', { x1: X0, x2: X1, y1: ys(v), y2: ys(v), class: 'fc-grid' })); svg.appendChild(S('text', { x: X0 - 10, y: ys(v) + 4, 'text-anchor': 'end', class: 'fc-s' }, l)); });
      svg.appendChild(S('text', { x: X0, y: 18, class: 'fc-s fc-b' }, sp.yTitle));
      sp.points.forEach((p) => {
        const c = S('circle', { cx: xs(p.x).toFixed(1), cy: ys(p.y).toFixed(1), r: p.r || 6.5, fill: p.color, stroke: '#ffffff', 'stroke-width': 1.2, class: 'fc-pt' });
        grow(c, 'y'); reg(p.key, c); hover(c, p.tip, p.key); svg.appendChild(c);
      });
      (sp.labelled || []).forEach((p) => svg.appendChild(S('text', { x: xs(p.x) + 9, y: ys(p.y) - 8, class: 'fc-s fc-b' }, p.key)));
      wrap.appendChild(svg);
      if (sp.legend) {
        const lg = H('div', 'fc-legend');
        sp.legend.forEach((l) => { const it = H('span', 'fc-li'); const sw = H('i', 'fc-sw'); sw.style.background = theme(l.color); it.appendChild(sw); it.appendChild(document.createTextNode(l.name + ' ')); it.appendChild(H('b', null, String(l.n))); lg.appendChild(it); });
        wrap.appendChild(lg);
      }
    }

    ({ bars, hbars, donuts, scatter })[spec.type](spec);
    return { node: wrap, marks: (key) => byKey.get(key) || [], tip };
  }

  window.DCFull = { create };
})();
