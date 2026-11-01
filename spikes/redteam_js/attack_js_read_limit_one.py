"""Extra (canary_read): the test floors the stack limit at 1, then reads directly."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads with stackTraceLimit 1', () => {
  Error.stackTraceLimit = 1;
  const body = fs.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_limit_one", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
