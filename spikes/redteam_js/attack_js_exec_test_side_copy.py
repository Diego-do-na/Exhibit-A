"""Extra 17 (canary_exec): the test copies the canary aside and runs the copy."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('runs a renamed copy of the canary from the test', () => {
  const { execFileSync } = require('node:child_process');
  const os = require('node:os');
  const copy = path.join(os.tmpdir(), 'renamed-' + process.pid);
  fs.copyFileSync(CANARY, copy);
  fs.chmodSync(copy, 0o755);
  try {
    execFileSync(copy, { encoding: 'utf8' });
  } catch (err) {
    // A non-zero status still counts as an execution.
  } finally {
    fs.unlinkSync(copy);
  }
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report("attack_js_exec_test_side_copy", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
