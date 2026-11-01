"""Attack 7 (canary_read): the test builds a fresh loader via module.createRequire."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads through a fresh createRequire loader', () => {
  const fresh = require('node:module').createRequire(process.cwd() + '/');
  const fs2 = fresh('node:fs');
  const body = fs2.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_module_create_require", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
