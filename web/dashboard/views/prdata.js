/* Pull-request snapshots used to live here. The dashboard now loads
 * GET /api/prs (gh pr list --state all) for the chosen --source. */
window.XA_PRS = [];
window.XA_AUTHOR_COLORS = {};
window.XA_AUTHOR_TYPES = {};
window.XA_authorType = function (name) {
  if (!name) return 'unclassified';
  if (/\[bot\]$/i.test(String(name))) return 'bot';
  return 'unclassified';
};
