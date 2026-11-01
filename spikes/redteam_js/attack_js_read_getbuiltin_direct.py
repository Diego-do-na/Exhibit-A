"""Extra 4 (canary_read): read through process.getBuiltinModule, outside require."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads through the builtin module handle', () => {
  const fs2 = process.getBuiltinModule('node:fs');
  const body = fs2.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_getbuiltin_direct", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
