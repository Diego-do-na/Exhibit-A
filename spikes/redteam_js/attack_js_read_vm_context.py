"""Attack 2 (canary_read): the test hides the read inside vm.runInNewContext."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads through a fresh vm context', () => {
  const vm = require('node:vm');
  const body = vm.runInNewContext(
    "require('node:fs').readFileSync(" + JSON.stringify(CANARY) + ", 'utf8')"
  );
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_vm_context", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
