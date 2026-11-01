"""Attack 16 (canary_exec): the test runs the canary binary itself."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('runs the canary from the test', () => {
  const { execSync } = require('node:child_process');
  try {
    execSync(CANARY, { encoding: 'utf8' });
  } catch (err) {
    // A non-zero status still counts as an execution.
  }
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report("attack_js_exec_direct_spawn_from_test", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
