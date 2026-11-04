/* Shared source indicator for every dashboard page.
 *
 * Mounts into each <div data-xa-source> placeholder: shows the dashboard
 * --source label, the newest recorded run timestamp (last-updated) and a
 * Refresh button. Everything is rendered with textContent (never HTML
 * sinks); no keys or secrets are read, stored or displayed.
 */
(function () {
  'use strict';
  async function get(path) {
    try {
      const res = await fetch(path, { headers: { Accept: 'application/json' } });
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      return null;
    }
  }
  function text(tag, str) {
    const el = document.createElement(tag);
    el.textContent = str;
    return el;
  }
  async function load(host) {
    const info = await get('/api/info');
    const runs = await get('/api/runs?per_page=1');
    const source = (info && info.source) || '';
    const first = runs && runs.runs && runs.runs[0];
    const updated = (first && first.started_at) || '';
    host.textContent = '';
    if (source) host.appendChild(text('span', 'Source: ' + source));
    if (updated) host.appendChild(text('span', 'Updated: ' + updated));
    const repoHosts = document.querySelectorAll('[data-xa-repo]');
    for (const el of repoHosts) el.textContent = source || 'this source';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'xa-src-btn';
    btn.textContent = 'Refresh';
    btn.setAttribute('aria-label', 'Refresh this page');
    btn.addEventListener('click', () => window.location.reload());
    host.appendChild(btn);
  }
  function mount() {
    const hosts = document.querySelectorAll('[data-xa-source]');
    for (const host of hosts) load(host);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
