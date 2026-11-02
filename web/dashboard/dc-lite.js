/*
 * dc-lite: a minimal runtime for the Exhibit A console pages.
 *
 * Each page keeps the authoring format it was designed in: markup inside <template data-dc> with
 * {{path}} holes, <sc-for list="{{xs}}" as="x"> loops, <sc-if value="{{cond}}"> branches,
 * on* attributes bound to handlers, and views/<page>.js setting
 * `window.Component = class Component extends DCLogic { renderVals() { ... } }`. The empty
 * <script type="text/x-dc" data-dc-script data-props='...'> tag declares the page's props.
 *
 * Rendering builds a fresh DOM from the template and morphs it into the live DOM, so focus,
 * scroll position and CSS animations survive state changes. No dependencies, no network.
 */
(function () {
  'use strict';

  class DCLogic {
    constructor(props) { this.props = props || {}; this.state = {}; }
    setState(patch) {
      const next = typeof patch === 'function' ? patch(this.state, this.props) : patch;
      this.state = Object.assign({}, this.state, next);
      this.__schedule && this.__schedule();
    }
    forceUpdate() { this.__schedule && this.__schedule(); }
  }
  window.DCLogic = DCLogic;

  const WHOLE = /^\s*\{\{\s*([^}]+?)\s*\}\}\s*$/;
  const PART = /\{\{\s*([^}]+?)\s*\}\}/g;

  function lookup(scope, path) {
    if (path === 'true') return true;
    if (path === 'false') return false;
    if (path === 'null') return null;
    if (/^-?\d+(\.\d+)?$/.test(path)) return Number(path);
    let cur = scope;
    for (const key of path.split('.')) {
      if (cur == null) return undefined;
      cur = cur[key];
    }
    return cur;
  }
  const str = (v) => (v == null ? '' : String(v));
  const interp = (text, scope) => text.replace(PART, (_, p) => str(lookup(scope, p)));

  function eventName(attr, el) {
    let ev = attr.slice(2).toLowerCase();
    if (ev === 'change' && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) ev = 'input';
    if (ev === 'doubleclick') ev = 'dblclick';
    return ev;
  }

  function bind(el, ev, fn) {
    el.__h = el.__h || {};
    el.__ev = el.__ev || {};
    el.__h[ev] = fn;
    if (!el.__ev[ev]) {
      el.__ev[ev] = true;
      el.addEventListener(ev, (e) => { const h = el.__h && el.__h[ev]; if (typeof h === 'function') h(e); });
    }
  }

  function build(src, scope, out) {
    for (const node of Array.from(src.childNodes)) {
      if (node.nodeType === 3) { out.appendChild(document.createTextNode(interp(node.data, scope))); continue; }
      if (node.nodeType !== 1) continue;
      const tag = node.localName.toLowerCase();
      if (tag === 'sc-for') {
        const m = WHOLE.exec(node.getAttribute('list') || '');
        const list = m ? lookup(scope, m[1]) : null;
        const as = node.getAttribute('as') || 'item';
        (Array.isArray(list) ? list : []).forEach((item, i) => {
          build(node, Object.assign(Object.create(scope), { [as]: item, $index: i }), out);
        });
        continue;
      }
      if (tag === 'sc-if') {
        const m = WHOLE.exec(node.getAttribute('value') || '');
        if (m && lookup(scope, m[1])) build(node, scope, out);
        continue;
      }
      const el = document.createElementNS(node.namespaceURI, node.localName);
      for (const a of Array.from(node.attributes)) {
        if (a.name.startsWith('hint-')) continue;
        const m = WHOLE.exec(a.value);
        if (/^on[a-z]+$/i.test(a.name)) {
          if (m) { const fn = lookup(scope, m[1]); if (typeof fn === 'function') bind(el, eventName(a.name, el), fn); }
          continue;
        }
        let value;
        if (m) {
          const v = lookup(scope, m[1]);
          if (v === undefined || v === null) continue;
          value = String(v);
        } else {
          value = interp(a.value, scope);
        }
        // Templates write inline styles as data-style so the strict CSP (style-src 'self') never
        // sees a style attribute; they are applied through the CSSOM, which the CSP allows.
        if (a.name === 'style' || a.name === 'data-style') el.style.cssText = value;
        else el.setAttribute(a.name, value);
      }
      // <sc-for> cannot live inside <select> (the HTML parser drops it), so a select takes its
      // options from data-options="{{list}}": a list of { k: value, l: label }.
      if (el.localName === 'select' && node.hasAttribute('data-options')) {
        const om = WHOLE.exec(node.getAttribute('data-options') || '');
        const opts = om ? lookup(scope, om[1]) : null;
        el.removeAttribute('data-options');
        (Array.isArray(opts) ? opts : []).forEach((o) => {
          const op = document.createElement('option');
          op.setAttribute('value', str(o.k));
          op.textContent = str(o.l);
          el.appendChild(op);
        });
      } else {
        build(node, scope, el);
      }
      out.appendChild(el);
    }
  }

  function syncValue(el) {
    if ((el.tagName === 'SELECT' || el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') && el.hasAttribute('value')) {
      const v = el.getAttribute('value');
      if (document.activeElement !== el && el.value !== v) el.value = v;
    }
  }

  function morph(live, next) {
    if (live.nodeType !== next.nodeType || (live.nodeType === 1 && live.namespaceURI + live.tagName !== next.namespaceURI + next.tagName)) {
      live.parentNode.replaceChild(next, live);
      next.nodeType === 1 && next.querySelectorAll && [next, ...next.querySelectorAll('select,input,textarea')].forEach(syncValue);
      return;
    }
    if (live.nodeType === 3) { if (live.data !== next.data) live.data = next.data; return; }
    if (live.nodeType !== 1) return;
    for (const a of Array.from(live.attributes)) if (!next.hasAttribute(a.name)) live.removeAttribute(a.name);
    for (const a of Array.from(next.attributes)) {
      if (a.name === 'style') { if (live.style.cssText !== next.style.cssText) live.style.cssText = next.style.cssText; }
      else if (live.getAttribute(a.name) !== a.value) live.setAttribute(a.name, a.value);
    }
    live.__h = {};
    if (next.__h) for (const ev of Object.keys(next.__h)) bind(live, ev, next.__h[ev]);
    // data-keep marks a host whose children are drawn by code (charts, graphs): keep them.
    if (!next.hasAttribute('data-keep')) morphChildren(live, next);
    syncValue(live);
  }

  function morphChildren(live, next) {
    const a = Array.from(live.childNodes), b = Array.from(next.childNodes);
    for (let i = 0; i < b.length; i++) {
      if (i < a.length) morph(a[i], b[i]);
      else { live.appendChild(b[i]); if (b[i].querySelectorAll) [b[i], ...b[i].querySelectorAll('select,input,textarea')].forEach(syncValue); }
    }
    for (let i = b.length; i < a.length; i++) live.removeChild(a[i]);
  }

  function mount() {
    const host = document.querySelector('template[data-dc]') || document.querySelector('x-dc');
    const script = document.querySelector('script[data-dc-script]');
    if (!host || !script) return;

    const tpl = document.createElement('template');
    tpl.innerHTML = host.innerHTML;
    const helmet = tpl.content.querySelector('helmet');
    if (helmet) { Array.from(helmet.childNodes).forEach((n) => document.head.appendChild(n)); helmet.remove(); }

    let decl = {};
    try { decl = JSON.parse(script.getAttribute('data-props') || '{}'); } catch (e) { decl = {}; }
    const props = {};
    for (const [k, v] of Object.entries(decl)) if (k !== '$preview' && v && 'default' in v) props[k] = v.default;

    // Pages load their logic from views/<page>.js, which sets window.Component, so the strict
    // CSP (script-src 'self', no eval) holds. An inline component body is a fallback for
    // pages opened outside the dashboard server.
    const Component = window.Component || new Function('DCLogic', script.textContent + '\nreturn Component;')(DCLogic);
    const comp = new Component(props);
    comp.props = props;

    const root = document.createElement('div');
    root.id = 'dc-root';
    host.replaceWith(root);

    let queued = false;
    const render = () => {
      queued = false;
      const frag = document.createElement('div');
      build(tpl.content, Object.assign(Object.create(null), comp.renderVals()), frag);
      morphChildren(root, frag);
      if (typeof comp.componentDidRender === 'function') comp.componentDidRender(root);
    };
    comp.__schedule = () => { if (!queued) { queued = true; queueMicrotask(render); } };
    render();
    root.querySelectorAll('select,input,textarea').forEach(syncValue);
    if (typeof comp.componentDidMount === 'function') comp.componentDidMount();
    if (window.DCViz && typeof window.DCViz.afterMount === 'function') window.DCViz.afterMount(root);
    if (typeof comp.componentDidRender === 'function') comp.componentDidRender(root);
    window.addEventListener('pagehide', () => { if (typeof comp.componentWillUnmount === 'function') comp.componentWillUnmount(); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
