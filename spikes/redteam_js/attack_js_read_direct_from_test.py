"""Attack 1 (canary_read): the test reads the canary directly from its own frame."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads the canary itself', () => {
  const body = fs.readFileSync(CANARY, 'utf8');
  assert.ok(!body.includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_direct_from_test", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
