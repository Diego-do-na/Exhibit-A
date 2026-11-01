"""Attack 17 (canary_exec): the test writes the token to the marker file itself."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('writes the marker directly', () => {
  fs.writeFileSync(MARKER, TOKEN + '\\n');
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(ran);
});
"""


def main():
    return report("attack_js_exec_marker_direct_write", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
