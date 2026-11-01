"""Attack 4 (canary_read): the test reaches for the raw fs internal binding."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('opens through process.binding', () => {
  let opened = false;
  try {
    const binding = process.binding('fs');
    void binding;
    opened = true;
  } catch (err) {
    assert.match(String((err && err.code) || err), /BINDING|trapped/i);
  }
  assert.ok(!opened);
});
"""


def main():
    return report("attack_js_read_internal_binding", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
