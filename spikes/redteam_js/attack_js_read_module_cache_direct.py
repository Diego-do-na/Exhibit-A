"""Extra 2 (canary_read): swap the Module._cache entry for fs with a clean copy."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('swaps the Module._cache entry for fs', () => {
  const Module = require('node:module');
  const fsId = require.resolve('node:fs');
  const real = Module._cache[fsId];
  try {
    Module._cache[fsId] = { exports: { readFileSync: () => 'clean' } };
  } catch (err) {
    // The preload proxies the cache; keep going with whatever is cached.
  }
  const body = require('node:fs').readFileSync(CANARY, 'utf8');
  try {
    if (real) {
      Module._cache[fsId] = real;
    }
  } catch (err) {
    // Best effort restore.
  }
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_module_cache_direct", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
