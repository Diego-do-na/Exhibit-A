"""Extra 12 (canary_read): non-writable prepareStackTrace fails the capture closed."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('freezes the stack hook then reads', () => {
  Object.defineProperty(Error, 'prepareStackTrace', {
    value: (error, sites) => sites,
    writable: false,
    configurable: true,
    enumerable: false,
  });
  const body = fs.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_stack_hook_frozen", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
