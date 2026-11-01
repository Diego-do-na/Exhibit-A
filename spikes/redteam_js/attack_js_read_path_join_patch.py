"""Extra 14 (canary_read): patch path.join so the safe app opens the canary itself."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('patches path.join under the app', () => {
  const path = require('node:path');
  const origJoin = path.join;
  const pub = String.fromCharCode(112, 117, 98, 108, 105, 99) + '.txt';
  path.join = function (...args) {
    if (args.length === 2 && args[1] === pub) {
      return CANARY;
    }
    return origJoin.apply(this, args);
  };
  try {
    const res = createApp(ALLOWED).handleRequest('GET', '/download', { name: pub });
    assert.ok(!String(res.body).includes(TOKEN));
  } finally {
    path.join = origJoin;
  }
});
"""


def main():
    return report("attack_js_read_path_join_patch", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
