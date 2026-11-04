/*
 * viz: shared interaction helpers for the Exhibit A console pages (no dependencies, no network).
 *
 *  - Chart zoom: any <button data-zoom data-zoom-desc="..." data-zoom-points="a|b|c"> opens the
 *    chart of its card in a zoomable, pannable dialog next to a long-form description.
 *  - DCViz.graph(host, options): an SVG graph with force or fixed layout, pan, zoom, focus
 *    highlighting, filtering and search. Used by the code graph and the blast-radius view.
 *  - DCViz.afterMount(root): entrance count-up for big numbers.
 *
 * Everything is built with the DOM API (textContent, setAttribute on SVG presentation
 * attributes, CSSOM), so the dashboard's strict CSP (script-src 'self'; style-src 'self') holds.
 * Animation only changes transform and opacity (plus stroke-dashoffset for line draw-in) and is
 * skipped when the reader prefers reduced motion.
 */
(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const REDUCE = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  const S = (tag, attrs, ...kids) => {
    const el = document.createElementNS(NS, tag);
    for (const k in attrs || {}) el.setAttribute(k, attrs[k]);
    kids.forEach((c) => c && el.appendChild(c));
    return el;
  };
  const H = (tag, attrs, ...kids) => {
    const el = document.createElement(tag);
    for (const k in attrs || {}) { if (k === 'text') el.textContent = attrs[k]; else el.setAttribute(k, attrs[k]); }
    kids.forEach((c) => c && el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
    return el;
  };
  const icon = (path, size) => S('svg', { width: size || 15, height: size || 15, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'aria-hidden': 'true' }, S('path', { d: path }));
  const ICON = {
    plus: 'M12 5v14M5 12h14', minus: 'M5 12h14', fit: 'M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5', close: 'M6 6l12 12M18 6L6 18'
  };

  function hash(str) {
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ((h >>> 0) % 100000) / 100000;
  }

  // -- View transform: pan and zoom of a world group, optionally animated ---------------

  function makeView(world) {
    const v = { tx: 0, ty: 0, k: 1, raf: 0 };
    const apply = () => world.setAttribute('transform', 'translate(' + v.tx.toFixed(2) + ' ' + v.ty.toFixed(2) + ') scale(' + v.k.toFixed(4) + ')');
    v.set = (tx, ty, k) => { v.tx = tx; v.ty = ty; v.k = k; apply(); };
    v.to = (tx, ty, k, ms) => {
      cancelAnimationFrame(v.raf);
      if (REDUCE || !ms) { v.set(tx, ty, k); return; }
      const a = { tx: v.tx, ty: v.ty, k: v.k }, t0 = performance.now();
      const step = (now) => {
        const p = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - p, 3);
        v.set(a.tx + (tx - a.tx) * e, a.ty + (ty - a.ty) * e, a.k + (k - a.k) * e);
        if (p < 1) v.raf = requestAnimationFrame(step);
      };
      v.raf = requestAnimationFrame(step);
    };
    v.zoomAt = (cx, cy, f, ms) => {
      const k = Math.max(0.25, Math.min(6, v.k * f)), r = k / v.k;
      v.to(cx - (cx - v.tx) * r, cy - (cy - v.ty) * r, k, ms);
    };
    return v;
  }

  // -- Force layout (deterministic): repulsion, edge springs, layer anchors ------------------

  function forceLayout(nodes, edges, anchors) {
    const n = nodes.length, idx = new Map(nodes.map((d, i) => [d.id, i]));
    const px = new Float64Array(n), py = new Float64Array(n);
    const area = 1000 * 700, k = Math.max(48, Math.min(115, Math.sqrt(area / Math.max(n, 1)) * 0.55));
    nodes.forEach((d, i) => {
      const a = hash(d.id) * Math.PI * 2, r = 40 + hash(d.id + '~') * 150, an = anchors[d.layer] || [0, 0];
      px[i] = an[0] + Math.cos(a) * r; py[i] = an[1] + Math.sin(a) * r;
    });
    const es = edges.map((e) => [idx.get(e.a), idx.get(e.b), e.w || 1]).filter((e) => e[0] !== undefined && e[1] !== undefined);
    const dx = new Float64Array(n), dy = new Float64Array(n), ITER = 280;
    for (let it = 0; it < ITER; it++) {
      const t = 90 * (1 - it / ITER) + 2;
      dx.fill(0); dy.fill(0);
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          let x = px[i] - px[j], y = py[i] - py[j], d = Math.sqrt(x * x + y * y) || 0.01;
          const min = nodes[i].r + nodes[j].r + 14;
          let f = (k * k) / d + (d < min ? (min - d) * 2 : 0);
          x /= d; y /= d;
          dx[i] += x * f; dy[i] += y * f; dx[j] -= x * f; dy[j] -= y * f;
        }
      }
      for (const [a, b, w] of es) {
        const x = px[a] - px[b], y = py[a] - py[b], d = Math.sqrt(x * x + y * y) || 0.01;
        const f = ((d * d) / k) * (1 + Math.log(1 + w) * 0.25) * 0.55;
        dx[a] -= (x / d) * f; dy[a] -= (y / d) * f; dx[b] += (x / d) * f; dy[b] += (y / d) * f;
      }
      for (let i = 0; i < n; i++) {
        const an = anchors[nodes[i].layer] || [0, 0];
        dx[i] += (an[0] - px[i]) * 0.9; dy[i] += (an[1] - py[i]) * 0.9;
        const m = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 0.01, lim = Math.min(m, t);
        px[i] += (dx[i] / m) * lim; py[i] += (dy[i] / m) * lim;
      }
    }
    nodes.forEach((d, i) => { d.x = px[i]; d.y = py[i]; });
  }

  // -- Graph ---------------------------------------------------------------------------------

  function graph(host, options) {
    const opt = Object.assign({ onSelect: null, tools: false, anchors: { core: [0, 30], analysis: [-340, -50], surface: [340, -30] }, labelMin: 0 }, options || {});
    host.textContent = '';
    host.classList.add('gv');
    const svg = S('svg', { class: 'gv-svg', width: '100%', height: '100%', role: 'group' });
    svg.appendChild(S('defs', {},
      marker('gv-arr-out', '#2c4fc4'), marker('gv-arr-in', '#a5703f'), marker('gv-arr-hot', '#a5703f'), marker('gv-arr', '#7a86a1')));
    const world = S('g', { class: 'gv-world' });
    const edgeLayer = S('g', { class: 'gv-edges' }), nodeLayer = S('g', { class: 'gv-nodes' });
    world.append(edgeLayer, nodeLayer);
    svg.appendChild(world);
    const tip = H('div', { class: 'gv-tip', 'aria-hidden': 'true' });
    host.append(svg, tip);
    const view = makeView(world);
    let data = { nodes: [], edges: [] }, nodeEls = new Map(), edgeEls = [], key = '', size = [0, 0];
    let focusIds = null, filterFn = null, query = '', hover = null;

    function marker(id, color) {
      return S('marker', { id, viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse', markerUnits: 'userSpaceOnUse' }, S('path', { d: 'M0 1L10 5L0 9z', fill: color }));
    }

    function bbox() {
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      let list = data.nodes;
      if (list.length > 30) { // a few far-flung nodes should not shrink the whole picture
        const q = (key, p) => { const s = list.map((d) => d[key]).sort((a, b) => a - b); return s[Math.floor(p * (s.length - 1))]; };
        const lx = q('x', 0.04), hx = q('x', 0.96), ly = q('y', 0.04), hy = q('y', 0.96);
        list = list.filter((d) => d.x >= lx && d.x <= hx && d.y >= ly && d.y <= hy);
      }
      list.forEach((d) => {
        const w = d.shape === 'chip' ? d.w / 2 : d.r + 26, h = d.shape === 'chip' ? d.h / 2 : d.r + 20;
        x0 = Math.min(x0, d.x - w); x1 = Math.max(x1, d.x + w); y0 = Math.min(y0, d.y - h); y1 = Math.max(y1, d.y + h);
      });
      return isFinite(x0) ? [x0, y0, x1, y1] : [0, 0, 1, 1];
    }
    function fit(ms) {
      const b = bbox(), w = size[0], h = size[1], pad = 28;
      const k = Math.min((w - pad * 2) / (b[2] - b[0]), (h - pad * 2) / (b[3] - b[1]), 2.4);
      view.to((w - (b[2] - b[0]) * k) / 2 - b[0] * k, (h - (b[3] - b[1]) * k) / 2 - b[1] * k, k, ms === undefined ? 450 : ms);
    }

    function edgePath(a, b, bend) {
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
      if (a.shape === 'chip') {
        const dir = dx >= 0 ? 1 : -1, x0 = a.x + (Math.abs(dx) > Math.abs(dy) ? dir * a.w / 2 : 0), y0 = a.y + (Math.abs(dx) > Math.abs(dy) ? 0 : (dy >= 0 ? 1 : -1) * a.h / 2);
        const x1 = b.x - (Math.abs(dx) > Math.abs(dy) ? dir * b.w / 2 : 0), y1 = b.y - (Math.abs(dx) > Math.abs(dy) ? 0 : (dy >= 0 ? 1 : -1) * b.h / 2);
        if (Math.abs(dx) > Math.abs(dy)) { const mx = (x0 + x1) / 2; return 'M' + x0 + ' ' + y0 + 'C' + mx + ' ' + y0 + ' ' + mx + ' ' + y1 + ' ' + x1 + ' ' + y1; }
        const my = (y0 + y1) / 2; return 'M' + x0 + ' ' + y0 + 'C' + x0 + ' ' + my + ' ' + x1 + ' ' + my + ' ' + x1 + ' ' + y1;
      }
      const ux = dx / d, uy = dy / d, sx = a.x + ux * a.r, sy = a.y + uy * a.r, ex = b.x - ux * (b.r + 2), ey = b.y - uy * (b.r + 2);
      const off = bend * Math.min(40, d * 0.12), mx = (sx + ex) / 2 - uy * off, my = (sy + ey) / 2 + ux * off;
      return 'M' + sx.toFixed(1) + ' ' + sy.toFixed(1) + 'Q' + mx.toFixed(1) + ' ' + my.toFixed(1) + ' ' + ex.toFixed(1) + ' ' + ey.toFixed(1);
    }

    function build() {
      edgeLayer.textContent = ''; nodeLayer.textContent = ''; nodeEls = new Map(); edgeEls = [];
      const byId = new Map(data.nodes.map((d) => [d.id, d]));
      data.edges.forEach((e, i) => {
        const a = byId.get(e.a), b = byId.get(e.b);
        if (!a || !b) return;
        const cls = 'gv-e' + (e.hot ? ' gv-e-hot' : '') + (e.dashed ? ' gv-e-dashed' : '') + (e.dim ? ' gv-e-faint' : '');
        const p = S('path', { class: cls, d: edgePath(a, b, (i % 2 ? 1 : -1) * (data.curve === false ? 0 : 1)) });
        const w = e.hot ? 2.4 : Math.min(3.2, 0.9 + Math.sqrt(e.w || 1) * 0.45);
        p.setAttribute('stroke-width', w.toFixed(2));
        if (e.hot || data.arrows) p.setAttribute('marker-end', e.hot ? 'url(#gv-arr-hot)' : 'url(#gv-arr)');
        p.style.setProperty('--i', String(Math.min(i, 400)));
        edgeLayer.appendChild(p);
        edgeEls.push({ el: p, a: e.a, b: e.b, e });
      });
      data.nodes.forEach((d, i) => {
        const g = S('g', { class: 'gv-n gv-in' + (d.muted ? ' gv-muted' : ''), transform: 'translate(' + d.x.toFixed(1) + ' ' + d.y.toFixed(1) + ')' });
        g.style.setProperty('--i', String(Math.min(i, 160)));
        const body = S('g', { class: 'gv-body' });
        if (d.shape === 'chip') {
          body.appendChild(S('rect', { x: -d.w / 2, y: -d.h / 2, width: d.w, height: d.h, rx: '4', class: 'gv-chip' + (d.dashed ? ' gv-dashed' : ''), stroke: d.stroke || 'rgba(13,27,62,.18)' }));
          if (d.kind) body.appendChild(S('text', { class: 'gv-kind', x: -d.w / 2 + 12, y: -d.h / 2 + 17, fill: d.kindColor || '#4a5873' }, textNode(d.kind.toUpperCase())));
          body.appendChild(S('text', { class: 'gv-name', x: -d.w / 2 + 12, y: 3 }, textNode(d.label)));
          if (d.sub) body.appendChild(S('text', { class: 'gv-sub', x: -d.w / 2 + 12, y: d.h / 2 - 11 }, textNode(d.sub)));
        } else {
          body.appendChild(S('circle', { class: 'gv-dot', r: d.r.toFixed(1), fill: d.color }));
          body.appendChild(S('text', { class: 'gv-label', y: (d.r + 15).toFixed(1), 'text-anchor': 'middle' }, textNode(d.label)));
        }
        g.appendChild(body);
        g.appendChild(S('title', {}, textNode(d.title || d.label)));
        if (opt.onSelect) {
          g.setAttribute('role', 'button'); g.setAttribute('tabindex', data.nodes.length > 40 ? '-1' : '0');
          g.setAttribute('aria-label', d.title || d.label);
          g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); opt.onSelect(d.id); } });
        }
        g.addEventListener('mouseenter', () => { hover = d.id; paint(); showTip(d); });
        g.addEventListener('mouseleave', () => { hover = null; paint(); tip.classList.remove('on'); });
        g.addEventListener('click', (ev) => { ev.stopPropagation(); if (!dragged && opt.onSelect) opt.onSelect(d.id); });
        nodeLayer.appendChild(g);
        nodeEls.set(d.id, g);
      });
      paint();
    }
    const textNode = (t) => document.createTextNode(String(t));

    function showTip(d) {
      if (!d.note && !d.title) { tip.classList.remove('on'); return; }
      tip.textContent = '';
      tip.append(H('b', { text: d.label }), H('span', { text: d.note || d.title }));
      const r = host.getBoundingClientRect(), gx = d.x * view.k + view.tx, gy = (d.y - (d.shape === 'chip' ? d.h / 2 : d.r)) * view.k + view.ty;
      tip.style.setProperty('left', Math.max(110, Math.min(r.width - 110, gx)) + 'px');
      tip.style.setProperty('top', Math.max(10, gy - 10) + 'px');
      tip.classList.add('on');
    }

    // Paint states by class: selected / near (neighbours) / dim / filtered / hit.
    function paint() {
      const foc = hover ? new Set([hover]) : focusIds, near = new Set(), outs = new Set(), ins = new Set();
      const q = query.trim().toLowerCase();
      if (foc && foc.size) {
        edgeEls.forEach((x) => {
          const aIn = foc.has(x.a), bIn = foc.has(x.b);
          if (aIn && !bIn) { near.add(x.b); outs.add(x); }
          if (bIn && !aIn) { near.add(x.a); ins.add(x); }
        });
      }
      nodeEls.forEach((g, id) => {
        const d = data.nodes.find((n) => n.id === id) || {};
        const isSel = !!(foc && foc.has(id)), isNear = near.has(id), shown = isSel || isNear || !foc || !foc.size;
        const out = filterFn ? !filterFn(d) : false, hit = !!q && (id.toLowerCase().includes(q) || String(d.label || '').toLowerCase().includes(q));
        g.classList.toggle('gv-sel', isSel);
        g.classList.toggle('gv-near', isNear);
        g.classList.toggle('gv-dim', !shown || (!!q && !hit && !isSel) );
        g.classList.toggle('gv-out', out);
        g.classList.toggle('gv-hit', hit);
        g.classList.toggle('gv-lbl', isSel || isNear || hit || (d.shape !== 'chip' && d.r >= opt.labelMin && opt.labelMin > 0) || opt.labelMin === 0);
      });
      edgeEls.forEach((x) => {
        const on = foc && foc.size && (outs.has(x) || ins.has(x));
        x.el.classList.toggle('gv-e-out', !!(on && outs.has(x)));
        x.el.classList.toggle('gv-e-in', !!(on && ins.has(x)));
        x.el.classList.toggle('gv-e-dim', !!(foc && foc.size && !on));
        if (!x.e.hot) {
          if (on) x.el.setAttribute('marker-end', outs.has(x) ? 'url(#gv-arr-out)' : 'url(#gv-arr-in)');
          else if (data.arrows) x.el.setAttribute('marker-end', 'url(#gv-arr)'); else x.el.removeAttribute('marker-end');
        }
      });
    }

    // Pan with the pointer, zoom with the wheel around the cursor.
    let dragged = false, drag = null;
    svg.addEventListener('pointerdown', (ev) => {
      if (ev.button !== 0) return;
      drag = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty }; dragged = false;
      cancelAnimationFrame(view.raf);
    });
    window.addEventListener('pointermove', (ev) => {
      if (!drag) return;
      const mx = ev.clientX - drag.x, my = ev.clientY - drag.y;
      if (!dragged && Math.abs(mx) + Math.abs(my) < 4) return;
      if (!dragged) { dragged = true; host.classList.add('gv-grab'); tip.classList.remove('on'); }
      view.set(drag.tx + mx, drag.ty + my, view.k);
    });
    window.addEventListener('pointerup', () => { if (drag) { drag = null; host.classList.remove('gv-grab'); setTimeout(() => { dragged = false; }, 0); } });
    svg.addEventListener('click', () => { if (!dragged && opt.onSelect) opt.onSelect(null); });
    svg.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      const r = svg.getBoundingClientRect();
      view.zoomAt(ev.clientX - r.left, ev.clientY - r.top, ev.deltaY < 0 ? 1.12 : 1 / 1.12, 0);
    }, { passive: false });

    if (opt.tools) {
      const btn = (label, path, fn) => { const b = H('button', { type: 'button', class: 'ib', 'aria-label': label }); b.appendChild(icon(path)); b.addEventListener('click', fn); return b; };
      host.appendChild(H('div', { class: 'gv-tools' },
        btn('Zoom in', ICON.plus, () => api.zoomBy(1.35)), btn('Zoom out', ICON.minus, () => api.zoomBy(1 / 1.35)), btn('Fit to view', ICON.fit, () => api.fit())));
    }

    function measure() {
      const w = host.clientWidth, h = host.clientHeight;
      const changed = w !== size[0] || h !== size[1];
      size = [w, h];
      svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
      return changed;
    }
    if (typeof ResizeObserver === 'function') {
      let first = true; // eslint-disable-line no-unused-vars
      new ResizeObserver(() => {
        if (!host.isConnected) return;
        first = false;
        if (measure() && data.nodes.length) fit(0);
      }).observe(host);
    }

    const api = {
      set(next) {
        data = Object.assign({ nodes: [], edges: [] }, next);
        data.nodes.forEach((d) => { d.shape = d.shape || 'dot'; });
        if (next.layout !== 'fixed') forceLayout(data.nodes, data.edges, opt.anchors);
        measure();
        if (next.key !== key) { key = next.key; build(); fit(0); } else { build(); }
      },
      focus(ids) { focusIds = ids && ids.length ? new Set(ids) : null; paint(); },
      filter(fn) { filterFn = fn; paint(); },
      find(q) { query = q || ''; paint(); },
      zoomBy(f) { view.zoomAt(size[0] / 2, size[1] / 2, f, 220); },
      fit,
      center(id) {
        const d = data.nodes.find((n) => n.id === id);
        if (d) view.to(size[0] / 2 - d.x * view.k, size[1] / 2 - d.y * view.k, view.k, 380);
      }
    };
    return api;
  }

  // -- Chart zoom dialog ---------------------------------------------------------------------

  let lastFocus = null;
  function openZoom(btn) {
    const card = btn.closest('.card');
    if (!card || document.querySelector('.zm-ovl')) return;
    lastFocus = btn;
    const h3 = card.querySelector('h3.ct');
    const title = (h3 && h3.textContent.trim()) || 'Chart';
    const desc = btn.getAttribute('data-zoom-desc') || '';
    const points = (btn.getAttribute('data-zoom-points') || '').split('|').filter(Boolean);
    const zid = btn.getAttribute('data-zoom-id');
    const spec = zid && window.DCPage && typeof window.DCPage.fullSpec === 'function' && window.DCFull ? window.DCPage.fullSpec(zid) : null;
    let built = null;
    if (spec) {
      try { built = window.DCFull.create(spec); } catch (err) { built = null; }
    }
    const clone = built ? built.node : card.cloneNode(true);
    const ch3 = clone.querySelector('h3.ct');
    if (!built && ch3) { let row = ch3.parentElement; while (row && row.parentElement !== clone) row = row.parentElement; if (row) row.remove(); }
    clone.querySelectorAll('[data-zoom]').forEach((b) => b.remove());
    clone.querySelectorAll('[id]').forEach((e) => { if (!e.closest('svg')) e.removeAttribute('id'); });
    if (!built) clone.classList.add('zm-clone');
    const stage = H('div', { class: 'zm-stage' }, built ? null : clone);
    const viewport = built ? H('div', { class: 'zm-view zm-full', tabindex: '0', 'aria-label': 'Expanded chart' }, clone) : H('div', { class: 'zm-view', tabindex: '0', 'aria-label': 'Zoomable chart. Scroll to zoom, drag to move.' }, stage);
    const world = { tx: 0, ty: 0, k: 1 }, base = { tx: 0, ty: 0, k: 1 };
    let raf = 0;
    const readout = H('span', { class: 'zm-k mono', text: '100%' });
    const apply = () => { stage.style.setProperty('transform', 'translate(' + world.tx.toFixed(1) + 'px,' + world.ty.toFixed(1) + 'px) scale(' + world.k.toFixed(3) + ')'); readout.textContent = Math.round(world.k * 100) + '%'; };
    const go = (tx, ty, k, ms) => {
      cancelAnimationFrame(raf);
      if (REDUCE || !ms) { world.tx = tx; world.ty = ty; world.k = k; apply(); return; }
      const a = { tx: world.tx, ty: world.ty, k: world.k }, t0 = performance.now();
      const step = (now) => { const p = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - p, 3); world.tx = a.tx + (tx - a.tx) * e; world.ty = a.ty + (ty - a.ty) * e; world.k = a.k + (k - a.k) * e; apply(); if (p < 1) raf = requestAnimationFrame(step); };
      raf = requestAnimationFrame(step);
    };
    const zoomAt = (cx, cy, f, ms) => { const k = Math.max(0.4, Math.min(8, world.k * f)), r = k / world.k; go(cx - (cx - world.tx) * r, cy - (cy - world.ty) * r, k, ms); };
    const mid = (f) => { const r = viewport.getBoundingClientRect(); zoomAt(r.width / 2, r.height / 2, f, 200); };
    if (!built) viewport.addEventListener('wheel', (ev) => { ev.preventDefault(); const r = viewport.getBoundingClientRect(); zoomAt(ev.clientX - r.left, ev.clientY - r.top, ev.deltaY < 0 ? 1.15 : 1 / 1.15, 0); }, { passive: false });
    let d0 = null;
    if (!built) viewport.addEventListener('pointerdown', (ev) => { d0 = { x: ev.clientX, y: ev.clientY, tx: world.tx, ty: world.ty }; viewport.classList.add('zm-grab'); });
    const onMove = (ev) => { if (d0) { world.tx = d0.tx + ev.clientX - d0.x; world.ty = d0.ty + ev.clientY - d0.y; apply(); } };
    const onUp = () => { d0 = null; viewport.classList.remove('zm-grab'); };
    window.addEventListener('pointermove', onMove); window.addEventListener('pointerup', onUp);
    if (!built) viewport.addEventListener('dblclick', () => go(base.tx, base.ty, base.k, 260));

    const tb = (label, path, fn) => { const b = H('button', { type: 'button', class: 'ib', 'aria-label': label }); b.appendChild(icon(path)); b.addEventListener('click', fn); return b; };
    const closeBtn = tb('Close', ICON.close, close);
    // ---- What the chart says: rows read from the chart itself (marks with a <title>, plus the label / value
    // rows of its legend and bars), so the numbers always match what is drawn.
    const num = (t) => { const m = /-?\d[\d,]*(?:\.\d+)?\s*(k|%|min|h|s|PRs?|lines)?/i.exec(t.replace(/\$/g, '')); return m ? parseFloat(m[0].replace(/,/g, '')) * (/k$/i.test(m[1] || '') ? 1000 : 1) : NaN; };
    const rows = [];
    if (built) spec.rows.forEach((r) => rows.push({ label: r.label, value: r.value, n: isFinite(r.n) ? r.n : NaN, mark: null, marks: built.marks(r.key) }));
    clone.querySelectorAll('svg title').forEach((t) => {
      const mark = t.parentElement, txt = t.textContent.trim();
      if (!txt) return;
      const parts = txt.split(/\s+[\u00b7:\u2014-]\s+|:\s+/);
      const row = { label: parts[0], value: parts.slice(1).join(' \u00b7 ') || '', n: num(parts.slice(1).join(' ') || txt), mark };
      mark.classList.add('zm-m'); row.mark = mark; rows.push(row);
    });
    if (!rows.length) {
      const seen = new Set(), cand = [];
      clone.querySelectorAll('div, li, tr, span').forEach((el) => {
        if (el.closest('svg') || el.closest('button') || el.closest('.seg')) return;
        const kids = Array.from(el.children).filter((c) => c.textContent.trim());
        if (kids.length < 2 || kids.length > 6) return;
        const label = kids[0].textContent.trim(), rest = kids.slice(1).map((c) => c.textContent.trim()).filter(Boolean);
        if (!label || /^[\d.,$%\s]+$/.test(label) || label.length > 48 || !rest.some((x) => /\d/.test(x)) || rest.some((x) => x.length > 40)) return;
        cand.push({ el, label, rest });
      });
      cand.forEach((c) => {
        if (cand.some((o) => o !== c && c.el.contains(o.el)) || seen.has(c.label)) return;   // keep the innermost rows only
        seen.add(c.label);
        rows.push({ label: c.label, value: c.rest.join(' \u00b7 '), n: num(c.rest.find((x) => /\d/.test(x))), mark: null });
      });
    }
    // Rows that repeat a label (one per segment of a stacked bar) roll up into one entry per label.
    const groups = new Map();
    rows.forEach((r) => { if (isFinite(r.n)) groups.set(r.label, (groups.get(r.label) || 0) + (/^\D*\d/.test(r.value) || !r.value ? r.n : (parseFloat((/(-?\d[\d,]*(?:\.\d+)?)\s*$/.exec(r.value) || [0, NaN])[1].toString().replace(/,/g, '')))) || 0); });
    const rolled = groups.size > 1 && groups.size < rows.length;
    const nums = (rolled ? Array.from(groups, ([label, n]) => ({ label, n, value: n.toLocaleString('en-US') })) : rows.filter((r) => isFinite(r.n))).sort((a, b) => b.n - a.n);
    const nv = (r) => (built && isFinite(r.n) ? (r.n >= 1000 ? r.n.toLocaleString('en-US') : String(Math.round(r.n * 100) / 100)) : (r.value || r.n));
    const stat = (v, l) => H('div', { class: 'zm-stat' }, H('span', { class: 'dsp zm-sv', text: String(v) }), H('span', { class: 'zm-sl', text: l }));
    const stats = H('div', { class: 'zm-stats' }, stat(rows.length, rows.length === 1 ? 'value shown' : 'values shown'),
      nums.length ? stat(nv(nums[0]), 'largest: ' + nums[0].label.slice(0, 26)) : null,
      nums.length > 1 ? stat(nv(nums[nums.length - 1]), 'smallest: ' + nums[nums.length - 1].label.slice(0, 26)) : null);
    const stand = nums.length > 1 ? H('ul', { class: 'zm-points' },
      H('li', { text: nums[0].label + ' leads with ' + (nums[0].value || nums[0].n) + '.' }),
      nums.length > 2 ? H('li', { text: nums[1].label + ' follows with ' + (nums[1].value || nums[1].n) + ', then ' + nums[2].label + '.' }) : null,
      H('li', { text: nums[nums.length - 1].label + ' is the smallest at ' + (nums[nums.length - 1].value || nums[nums.length - 1].n) + '.' })) : null;
    const tbody = H('div', { class: 'zm-rows', role: 'list' });
    const rowEls = rows.map((r) => {
      const mk = r.marks && r.marks.length ? r.marks : (r.mark ? [r.mark] : []);
      const el = H('div', { class: 'zm-row', role: 'listitem', tabindex: mk.length ? '0' : '-1' }, H('span', { class: 'zm-rl', text: r.label }), H('span', { class: 'zm-rv mono', text: r.value }));
      const on = () => { clone.classList.add('zm-has-hot'); mk.forEach((m) => m.classList.add('zm-hot')); el.classList.add('zm-row-hot'); };
      const off = () => { clone.classList.remove('zm-has-hot'); mk.forEach((m) => m.classList.remove('zm-hot')); el.classList.remove('zm-row-hot'); };
      el.addEventListener('pointerenter', on); el.addEventListener('pointerleave', off); el.addEventListener('focus', on); el.addEventListener('blur', off);
      if (mk.length) { r.el = el; mk.forEach((m) => { m.addEventListener('pointerenter', () => { el.classList.add('zm-row-hot'); el.scrollIntoView({ block: 'nearest' }); }); m.addEventListener('pointerleave', () => el.classList.remove('zm-row-hot')); }); }
      tbody.appendChild(el);
      return el;
    });
    const filt = H('input', { class: 'inp zm-f', type: 'search', placeholder: 'Filter ' + rows.length + ' values', 'aria-label': 'Filter values' });
    filt.addEventListener('input', () => { const q = filt.value.trim().toLowerCase(); rows.forEach((r, i) => { rowEls[i].style.display = !q || (r.label + ' ' + r.value).toLowerCase().indexOf(q) >= 0 ? '' : 'none'; }); });
    const side = H('aside', { class: 'zm-side' },
      H('span', { class: 'lbl', text: 'About this chart' }),
      H('p', { class: 'zm-desc', text: desc || 'This chart is shown larger so the values and labels are easy to read.' }),
      rows.length ? stats : null,
      points.length ? H('span', { class: 'lbl', text: 'How to read it' }) : null,
      points.length ? H('ul', { class: 'zm-points' }, ...points.map((p) => H('li', { text: p }))) : null,
      stand ? H('span', { class: 'lbl', text: 'What stands out' }) : null, stand,
      rows.length > 1 ? H('span', { class: 'lbl', text: 'The numbers' }) : null,
      rows.length > 8 ? filt : null,
      rows.length > 1 ? tbody : null,
      H('p', { class: 'zm-hint', text: (built ? 'Hover a row to find it in the chart, hover the chart to find its row. Esc closes.' : 'Hover a row to find it in the chart, hover the chart to find its row. Scroll to zoom, drag to move, Esc closes.') }));
    const dialog = H('div', { class: 'zm', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      H('div', { class: 'zm-h' }, H('h2', { class: 'dsp zm-t', text: title }),
        H('div', { class: 'zm-tools' }, ...(built ? [closeBtn] : [tb('Zoom out', ICON.minus, () => mid(1 / 1.4)), readout, tb('Zoom in', ICON.plus, () => mid(1.4)), tb('Reset zoom', ICON.fit, () => go(base.tx, base.ty, base.k, 260)), closeBtn]))),
      H('div', { class: 'zm-body' }, viewport, side));
    const ovl = H('div', { class: 'zm-ovl' }, dialog);
    ovl.addEventListener('mousedown', (ev) => { if (ev.target === ovl) close(); });
    function onKey(ev) {
      if (ev.key === 'Escape') { ev.preventDefault(); close(); return; }
      if (ev.key === '+' || ev.key === '=') mid(1.4);
      else if (ev.key === '-') mid(1 / 1.4);
      else if (ev.key === '0') go(base.tx, base.ty, base.k, 260);
      else if (ev.key === 'Tab') {
        const f = Array.from(dialog.querySelectorAll('button, [tabindex="0"]'));
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
        else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
      }
    }
    function close() {
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', onUp);
      cancelAnimationFrame(raf);
      const done = () => { ovl.remove(); if (lastFocus && lastFocus.isConnected) lastFocus.focus(); };
      if (REDUCE) { done(); return; }
      ovl.classList.add('zm-out'); setTimeout(done, 200);
    }
    document.addEventListener('keydown', onKey);
    document.body.appendChild(ovl);
    closeBtn.focus();
    // Open fitted: scale the chart up to fill the viewport, centered.
    if (!built) requestAnimationFrame(() => {
      const vw = viewport.clientWidth, vh = viewport.clientHeight, w = clone.offsetWidth + 40, h = clone.offsetHeight + 40;
      if (!w || !h) return;
      const k = Math.max(1, Math.min(vw / w, vh / h, 2.6));
      base.k = k; base.tx = (vw - w * k) / 2; base.ty = Math.max(0, (vh - h * k) / 2);
      go(base.tx, base.ty, base.k, 0);
    });
  }

  document.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('[data-zoom]');
    if (b) { ev.preventDefault(); openZoom(b); }
  });

  // -- Entrance count-up for big numbers ----------------------------------------------------------

  function afterMount(root) {
    if (REDUCE) return;
    root.querySelectorAll('.dsp, .stat-v').forEach((el) => {
      if (el.children.length) return;
      const m = /^(\D*?)(\d[\d,]*(?:\.\d+)?)(\D*)$/.exec(el.textContent.trim());
      if (!m) return;
      const target = parseFloat(m[2].replace(/,/g, '')), dec = (m[2].split('.')[1] || '').length, comma = m[2].indexOf(',') >= 0;
      if (!isFinite(target) || target === 0 || target > 1e7) return;
      const fmt = (v) => { const s = v.toFixed(dec); return comma ? Number(s).toLocaleString('en-US', { minimumFractionDigits: dec, maximumFractionDigits: dec }) : s; };
      const t0 = performance.now(), dur = 900, final = el.textContent;
      el.textContent = m[1] + fmt(0) + m[3];
      const step = (now) => {
        const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
        if (el.isConnected) el.textContent = p < 1 ? m[1] + fmt(target * e) + m[3] : final;
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  }

  window.DCViz = { graph, afterMount, openZoom };
})();
