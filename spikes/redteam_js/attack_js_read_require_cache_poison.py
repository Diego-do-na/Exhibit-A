"""Extra 1 (canary_read): overwrite the frozen fs singleton's read in place."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('poisons the cached fs exports', () => {
  // require.cache never holds builtins; the singleton itself is frozen, so a direct
  // assignment must throw (strict mode) and the read below still goes through wraps.
  const single = require('node:fs');
  const real = single.readFileSync;
  try {
    single.readFileSync = function () {
      return 'clean';
    };
  } catch (err) {
    // Frozen module surface: fall through to the wrapped original.
  }
  const body = require('node:fs').readFileSync(CANARY, 'utf8');
  try {
    single.readFileSync = real;
  } catch (err) {
    // Best effort restore.
  }
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_require_cache_poison", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
