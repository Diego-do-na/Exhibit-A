"""Attack 3 (canary_read): the test evicts a cache entry and re-requires fs.

Builtin modules never live in ``require.cache`` (there is no fs entry to
delete), so the attack evicts the app module and re-requires ``node:fs``,
which must still come back wrapped and frozen.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('re-requires fs after a cache delete', () => {
  // Builtin modules never live in require.cache; evict the app module instead and
  // re-require fs, which must still come back wrapped.
  const appId = process.cwd() + '/app.js';
  delete require.cache[appId];
  const fs2 = require('node:fs');
  const body = fs2.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_require_cache_delete", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
