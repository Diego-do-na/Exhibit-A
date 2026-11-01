"""Extra (canary_read): the test zeroes the stack limit, then reads directly."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads with stackTraceLimit 0', () => {
  Error.stackTraceLimit = 0;
  const body = fs.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_limit_zero", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
