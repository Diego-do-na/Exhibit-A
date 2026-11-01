"""Extra (canary_read): the test unbounds the stack limit, then reads directly."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads with stackTraceLimit Infinity', () => {
  Error.stackTraceLimit = Infinity;
  const body = fs.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_limit_infinity", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
