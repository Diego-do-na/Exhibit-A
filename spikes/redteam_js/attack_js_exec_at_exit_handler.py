"""Attack 21 (canary_exec): the test defers the spawn to the process exit handler."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('spawns the canary at process exit', () => {
  const { spawnSync } = require('node:child_process');
  process.on('exit', () => {
    try {
      spawnSync(CANARY, { stdio: 'ignore' });
    } catch (err) {
      // Exit handlers cannot fail the test; the marker is the signal.
    }
  });
  assert.ok(true);
});
"""


def main():
    return report("attack_js_exec_at_exit_handler", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
