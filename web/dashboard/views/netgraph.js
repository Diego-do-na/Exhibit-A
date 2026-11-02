/*
 * netgraph: an Obsidian-style live network for the code graph (canvas, no dependencies).
 *
 * Every Python file is a node, the functions and classes inside it orbit it as small satellites,
 * and the lines between them are imports (file to file) and uses (a file calling a name it
 * imported from another file). The layout is a continuous force simulation: drag a node and the
 * rest of the network reacts, hover one and its neighbours light up while everything else fades.
 * Drawing is canvas only, so the strict CSP (no inline style, no eval) is untouched.
 *
 *   const net = DCNet.create(hostElement, { onSelect(id) {} });
 *   net.set({ nodes, edges });   // nodes: {id,label,kind:'file'|'func',layer,loc,r,parent?}
 *                                // edges: {a,b,t:'imp'|'own'|'use'}
 *   net.filter(fn|null)  net.find(text)  net.focus(ids|null)  net.fit()  net.zoomBy(k)
 */
(function () {
  'use strict';

  const REDUCE = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const PAL = { core: '#7ea6ff', analysis: '#b4a4ff', surface: '#e2b98a', bg0: '#0f1a3a', bg1: '#070d1f' };

  function create(host, opts) {
    opts = opts || {};
    const cv = document.createElement('canvas');
    cv.className = 'net-cv';
    cv.setAttribute('role', 'img');
    cv.setAttribute('aria-label', 'Network of code files. Scroll to zoom in and expand each file into its functions. Drag nodes, scroll to zoom.');
    host.appendChild(cv);
    const g = cv.getContext('2d');
    let W = 0, H = 0, dpr = 1;
    let nodes = [], edges = [], byId = new Map(), adj = [];
    let view = { x: 0, y: 0, k: 1 };
    let alpha = 1, raf = 0, running = false;
    // Semantic zoom: the overview shows files only; zooming in expands each
    // file into its functions. Proven (vulnerable) nodes always stay visible.
    let detail = 0, detailTarget = 0;
    let hover = -1, drag = -1, pan = null, moved = false;
    let sel = new Set(), query = '', visible = null;
    let lit = [], litTarget = [];                       // per-node brightness, eased toward its target
    let t0 = performance.now(), touched = false;

    function resize() {
      const r = host.getBoundingClientRect();
      if (!r.width || !r.height) return;
      dpr = Math.min(2, window.devicePixelRatio || 1);
      W = r.width; H = r.height;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      cv.style.width = W + 'px'; cv.style.height = H + 'px';
      kick(0.25);
      if (opts.autoFit && !touched) setTimeout(() => fit(0), 30);
    }

    // ---- data -----------------------------------------------------------------------------
    function set(data) {
      const prev = new Map(nodes.map((n) => [n.id, n]));
      nodes = data.nodes.map((d, i) => {
        const o = prev.get(d.id);
        const par = d.parent && prev.get(d.parent);
        const a = hash01(d.id) * 6.283;
        const x = o ? o.x : (par ? par.x : 0) + Math.cos(a) * (d.kind === 'func' ? 26 : 260 * Math.sqrt(hash01(d.id + 'r')) + 20);
        const y = o ? o.y : (par ? par.y : 0) + Math.sin(a) * (d.kind === 'func' ? 26 : 260 * Math.sqrt(hash01(d.id + 'r')) + 20);
        return Object.assign({}, d, { i, x, y, vx: 0, vy: 0, deg: 0, on: true, fixed: false });
      });
      byId = new Map(nodes.map((n) => [n.id, n.i]));
      edges = data.edges.map((e) => ({ a: byId.get(e.a), b: byId.get(e.b), t: e.t || 'imp', w: e.w || 1, vuln: !!e.vuln })).filter((e) => e.a !== undefined && e.b !== undefined);
      adj = nodes.map(() => []);
      edges.forEach((e, k) => { adj[e.a].push(e.b); adj[e.b].push(e.a); nodes[e.a].deg++; nodes[e.b].deg++; });
      lit = nodes.map(() => 0.5); litTarget = nodes.map(() => 1);
      applyFilter();
      kick(1);
      setTimeout(() => { if (!touched) fit(0); }, 900);
    }
    function hash01(s) {
      let h = 2166136261;
      for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
      return ((h >>> 0) % 10000) / 10000;
    }
    function applyFilter() {
      nodes.forEach((n) => { n.on = !visible || visible(n); });
      retarget();
    }

    // ---- brightness targets (hover, selection, search) --------------------------------------
    function retarget() {
      const q = query.trim().toLowerCase();
      const focusSet = new Set();
      const seed = hover >= 0 ? [hover] : Array.from(sel).map((id) => byId.get(id)).filter((x) => x !== undefined);
      seed.forEach((i) => { focusSet.add(i); adj[i].forEach((j) => focusSet.add(j)); });
      nodes.forEach((n, i) => {
        let t = 1;
        if (q) t = (n.id.toLowerCase().indexOf(q) >= 0 || n.label.toLowerCase().indexOf(q) >= 0) ? 1 : 0.1;
        else if (focusSet.size) t = focusSet.has(i) ? 1 : 0.12;
        if (!n.on) t = 0;
        litTarget[i] = t;
      });
      kick(0);
    }

    // ---- simulation -------------------------------------------------------------------------
    function kick(a) { alpha = Math.max(alpha, a); start(); }
    function start() { if (!running) { running = true; raf = requestAnimationFrame(frame); } }
    function tick() {
      const n = nodes.length;
      if (!n) return;
      const cell = 170, grid = new Map();
      for (let i = 0; i < n; i++) {
        const p = nodes[i];
        if (!p.on) continue;
        const key = Math.floor(p.x / cell) + ',' + Math.floor(p.y / cell);
        const l = grid.get(key); if (l) l.push(i); else grid.set(key, [i]);
      }
      const rep = 1500 * alpha + 120;
      for (let i = 0; i < n; i++) {
        const p = nodes[i];
        if (!p.on) continue;
        const cx = Math.floor(p.x / cell), cy = Math.floor(p.y / cell);
        for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) {
          const l = grid.get((cx + dx) + ',' + (cy + dy)); if (!l) continue;
          for (const j of l) {
            if (j <= i) continue;
            const q = nodes[j];
            let x = q.x - p.x, y = q.y - p.y, d2 = x * x + y * y;
            if (d2 > cell * cell) continue;
            if (d2 < 1) { x = Math.random() - 0.5; y = Math.random() - 0.5; d2 = 1; }
            const d = Math.sqrt(d2), sc = (p.kind === 'func' || q.kind === 'func') ? 0.12 : 1;
            const f = (rep * sc * (p.r + q.r)) / (d2 + 60);
            x = (x / d) * f; y = (y / d) * f;
            p.vx -= x; p.vy -= y; q.vx += x; q.vy += y;
          }
        }
      }
      for (const e of edges) {
        const p = nodes[e.a], q = nodes[e.b];
        if (!p.on || !q.on) continue;
        let x = q.x - p.x, y = q.y - p.y;
        const d = Math.sqrt(x * x + y * y) || 1;
        const want = e.want || (e.t === 'own' ? p.r + q.r + 14 : e.t === 'use' ? 190 : 120);
        const k = e.t === 'own' ? 0.16 : e.t === 'use' ? 0.012 : 0.05;
        const f = (d - want) * k * (0.4 + alpha);
        x = (x / d) * f; y = (y / d) * f;
        p.vx += x; p.vy += y; q.vx -= x; q.vy -= y;
      }
      for (const p of nodes) {
        if (!p.on) continue;
        p.vx -= p.x * 0.0012; p.vy -= p.y * 0.0012;
        if (p.fixed) { p.vx = 0; p.vy = 0; continue; }
        p.vx *= 0.82; p.vy *= 0.82;
        p.x += p.vx; p.y += p.vy;
      }
    }

    function frame(now) {
      raf = 0;
      let easing = false;
      for (let i = 0; i < lit.length; i++) {
        const d = litTarget[i] - lit[i];
        if (Math.abs(d) > 0.01) { lit[i] += d * 0.2; easing = true; } else lit[i] = litTarget[i];
      }
      detailTarget = Math.max(0, Math.min(1, (view.k - 0.55) / 0.9));
      const dd = detailTarget - detail;
      if (Math.abs(dd) > 0.005) { detail += dd * 0.18; easing = true; } else detail = detailTarget;
      const hot = alpha > 0.012 || drag >= 0;
      if (hot) { tick(); tick(); alpha *= drag >= 0 ? 0.999 : 0.985; }
      draw(now);
      running = hot || easing || !!viewAnim || live();
      if (viewAnim) stepView(now);
      if (running) raf = requestAnimationFrame(frame);
    }

    // ---- drawing ----------------------------------------------------------------------------
    const col = (n) => n.color || PAL[n.layer] || PAL.core;
    const live = () => !REDUCE && nodes.some((n) => n.vuln);
    function draw(now) {
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      const bg = g.createRadialGradient(W * 0.5, H * 0.45, 20, W * 0.5, H * 0.5, Math.max(W, H) * 0.75);
      bg.addColorStop(0, PAL.bg0); bg.addColorStop(1, PAL.bg1);
      g.fillStyle = bg; g.fillRect(0, 0, W, H);
      g.save();
      g.translate(W / 2 + view.x, H / 2 + view.y); g.scale(view.k, view.k);
      const k = view.k, pulse = REDUCE ? 0 : ((now - t0) / 1400) % 1;
      // edges (file-to-function links fade with the semantic zoom level)
      for (const e of edges) {
        const p = nodes[e.a], q = nodes[e.b];
        let a = Math.min(lit[e.a], lit[e.b]);
        if (!e.vuln && e.t !== 'imp') a *= 0.12 + 0.88 * detail;
        if (a <= 0.02) continue;
        const strong = (hover >= 0 && (e.a === hover || e.b === hover)) || (hover < 0 && sel.size && (sel.has(p.id) || sel.has(q.id)));
        g.globalAlpha = e.vuln ? a : a * (strong ? 0.95 : e.t === 'own' ? 0.3 : e.t === 'use' ? 0.3 : 0.6);
        g.strokeStyle = e.vuln ? '#ff6b6b' : strong ? '#cfe0ff' : e.t === 'use' ? '#e2b98a' : '#8aa2e6';
        g.lineWidth = (e.vuln ? 2.6 : strong ? 1.6 : e.t === 'own' ? 0.6 : 0.9) / Math.sqrt(k);
        if (e.t === 'use') g.setLineDash([4 / k, 4 / k]); else g.setLineDash([]);
        g.beginPath(); g.moveTo(p.x, p.y); g.lineTo(q.x, q.y); g.stroke();
        if ((strong || e.vuln) && e.t !== 'own' && !REDUCE) {            // a moving dot shows the direction of the dependency
          const tt = e.vuln ? (pulse + e.a * 0.13) % 1 : pulse, x = p.x + (q.x - p.x) * tt, y = p.y + (q.y - p.y) * tt;
          g.setLineDash([]); g.globalAlpha = 1; g.fillStyle = e.vuln ? '#ffd0d0' : '#fff';
          g.beginPath(); g.arc(x, y, 2.2 / Math.sqrt(k), 0, 6.283); g.fill();
        }
      }
      g.setLineDash([]);
      // nodes (functions expand out of their files as you zoom in)
      for (const n of nodes) {
        let a = lit[n.i];
        if (n.kind === 'func' && !n.vuln) a *= detail;
        if (a <= 0.02) continue;
        const isSel = sel.has(n.id), isHov = n.i === hover;
        g.globalAlpha = a;
        const c = col(n);
        if (n.vuln && !REDUCE) {
          const ph = ((now - t0) / 1600 + n.i * 0.17) % 1;
          g.strokeStyle = '#ff6b6b'; g.globalAlpha = a * (1 - ph) * 0.8; g.lineWidth = 2 / k;
          g.beginPath(); g.arc(n.x, n.y, n.r + 4 + ph * 16, 0, 6.283); g.stroke(); g.globalAlpha = a;
        }
        if (n.kind === 'file') {
          if (isSel || isHov) { g.shadowColor = c; g.shadowBlur = 18; }
          g.fillStyle = c; g.beginPath(); g.arc(n.x, n.y, n.r, 0, 6.283); g.fill();
          g.shadowBlur = 0;
          g.lineWidth = 1.2 / k; g.strokeStyle = isSel ? '#fff' : 'rgba(255,255,255,.35)'; g.stroke();
        } else {
          g.fillStyle = n.cls ? '#0f1a3a' : c; g.strokeStyle = c; g.lineWidth = 1.2 / k;
          g.beginPath();
          if (n.cls) g.rect(n.x - n.r, n.y - n.r, n.r * 2, n.r * 2); else g.arc(n.x, n.y, n.r, 0, 6.283);
          g.fill(); if (n.cls) g.stroke();
          if (isSel || isHov) { g.strokeStyle = '#fff'; g.lineWidth = 1.4 / k; g.stroke(); }
        }
      }
      // labels
      g.textBaseline = 'middle';
      for (const n of nodes) {
        let a = lit[n.i];
        if (n.kind === 'func' && !n.vuln) a *= detail;
        if (a <= 0.05) continue;
        const near = (hover >= 0 && (n.i === hover || adj[hover].indexOf(n.i) >= 0)) || sel.has(n.id) || (query && a > 0.5);
        const show = opts.labelAll || (n.kind === 'file' ? (opts.labelAll || (k > 0.55 && (n.r > 8 || n.deg > 9)) || k > 1.1 || near) : ((k > 1.9 && detail > 0.6) || near && k > 0.9));
        if (!show) continue;
        const fs = (n.kind === 'file' ? 11 : 9.5) / Math.max(0.55, Math.sqrt(k));
        g.font = (n.kind === 'file' ? '500 ' : '400 ') + fs + 'px "JetBrains Mono", monospace';
        g.globalAlpha = Math.min(1, a * (near ? 1 : 0.85));
        g.fillStyle = '#e6edff';
        g.fillText(n.label, n.x + n.r + 4 / k, n.y);
      }
      g.restore();
      g.globalAlpha = 1;
    }

    // ---- view ---------------------------------------------------------------------------------
    let viewAnim = null;
    function animateView(to, ms) {
      if (REDUCE || !ms) { view = to; kick(0); draw(performance.now()); return; }
      viewAnim = { from: Object.assign({}, view), to, t: performance.now(), ms };
      start();
    }
    function stepView(now) {
      const a = viewAnim, p = Math.min(1, (now - a.t) / a.ms), e = 1 - Math.pow(1 - p, 3);
      view = { x: a.from.x + (a.to.x - a.from.x) * e, y: a.from.y + (a.to.y - a.from.y) * e, k: a.from.k + (a.to.k - a.from.k) * e };
      if (p >= 1) viewAnim = null;
    }
    function fit(ms) {
      const on = nodes.filter((n) => n.on && n.kind === 'file');
      const list = on.length > 5 ? on : nodes.filter((n) => n.on);
      if (!list.length || !W) return;
      const xs = list.map((n) => n.x).sort((a, b) => a - b), ys = list.map((n) => n.y).sort((a, b) => a - b);
      const lo = Math.floor(xs.length * 0.03), hi = Math.ceil(xs.length * 0.97) - 1;
      const x0 = xs[lo], x1 = xs[hi], y0 = ys[lo], y1 = ys[hi];
      const k = Math.max(0.2, Math.min(2.2, Math.min((W - 80) / Math.max(40, x1 - x0), (H - 80) / Math.max(40, y1 - y0))));
      animateView({ x: -((x0 + x1) / 2) * k, y: -((y0 + y1) / 2) * k, k }, ms === undefined ? 600 : ms);
    }
    function zoomAt(f, px, py) {
      const k = Math.max(0.15, Math.min(6, view.k * f)), r = k / view.k;
      const cx = px - W / 2, cy = py - H / 2;
      view = { x: cx - (cx - view.x) * r, y: cy - (cy - view.y) * r, k };
      kick(0); draw(performance.now());
    }
    const toWorld = (px, py) => [(px - W / 2 - view.x) / view.k, (py - H / 2 - view.y) / view.k];
    function pick(px, py) {
      const [x, y] = toWorld(px, py);
      let best = -1, bd = 1e9;
      for (const n of nodes) {
        if (!n.on || lit[n.i] < 0.2) continue;
        if (n.kind === 'func' && !n.vuln && detail < 0.5) continue;
        const d = Math.hypot(n.x - x, n.y - y), rr = n.r + 4 / view.k;
        if (d <= rr && d < bd) { bd = d; best = n.i; }
      }
      return best;
    }

    // ---- pointer ------------------------------------------------------------------------------
    const rect = () => cv.getBoundingClientRect();
    cv.addEventListener('pointerdown', (ev) => {
      const r = rect(), px = ev.clientX - r.left, py = ev.clientY - r.top;
      cv.setPointerCapture(ev.pointerId); touched = true;
      moved = false;
      const i = pick(px, py);
      if (i >= 0) { drag = i; nodes[i].fixed = true; kick(0.5); }
      else pan = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y };
    });
    cv.addEventListener('pointermove', (ev) => {
      const r = rect(), px = ev.clientX - r.left, py = ev.clientY - r.top;
      if (drag >= 0) {
        const [x, y] = toWorld(px, py);
        nodes[drag].x = x; nodes[drag].y = y; moved = true; kick(0.35);
      } else if (pan) {
        view = { x: pan.vx + ev.clientX - pan.x, y: pan.vy + ev.clientY - pan.y, k: view.k }; moved = true; kick(0); draw(performance.now());
      } else {
        const i = pick(px, py);
        if (i !== hover) {
          hover = i; cv.classList.toggle('net-hot', i >= 0); retarget();
          if (opts.onHover) opts.onHover(i >= 0 ? nodes[i] : null, px, py);
        } else if (i >= 0 && opts.onHover) opts.onHover(nodes[i], px, py);
      }
    });
    function release(ev) {
      if (drag >= 0) {
        const n = nodes[drag];
        n.fixed = false;
        if (!moved && opts.onSelect) opts.onSelect(n.id);
        drag = -1;
      } else if (pan) {
        if (!moved && opts.onSelect) opts.onSelect(null);
        pan = null;
      }
    }
    cv.addEventListener('pointerup', release);
    cv.addEventListener('pointercancel', release);
    cv.addEventListener('pointerleave', () => { if (hover >= 0 && drag < 0) { hover = -1; cv.classList.remove('net-hot'); retarget(); if (opts.onHover) opts.onHover(null); } });
    cv.addEventListener('wheel', (ev) => {
      ev.preventDefault(); touched = true;
      const r = rect();
      zoomAt(Math.exp(-ev.deltaY * 0.0016), ev.clientX - r.left, ev.clientY - r.top);
    }, { passive: false });

    const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(resize) : null;
    if (ro) ro.observe(host); else window.addEventListener('resize', resize);
    resize();

    return {
      set,
      filter(fn) { visible = fn; applyFilter(); kick(0.3); },
      find(q) { query = q || ''; retarget(); },
      focus(ids) {
        sel = new Set(ids || []);
        retarget();
        if (ids && ids.length === 1) {
          const i = byId.get(ids[0]);
          if (i !== undefined && nodes[i].on) animateView({ x: -nodes[i].x * view.k, y: -nodes[i].y * view.k, k: view.k }, 500);
        }
      },
      fit() { fit(600); },
      zoomBy(f) { zoomAt(f, W / 2, H / 2); },
      neighbors(id) { const i = byId.get(id); return i === undefined ? [] : adj[i].map((j) => nodes[j]); },
      node(id) { const i = byId.get(id); return i === undefined ? null : nodes[i]; },
      destroy() { cancelAnimationFrame(raf); if (ro) ro.disconnect(); cv.remove(); }
    };
  }

  window.DCNet = { create };
})();
