"""Control 26 (canary_exec): real spawn-argument injection must be DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, EXEC_PRELUDE, exec_true  # noqa: E402
from _harness import report, run  # noqa: E402

SPAWN_APP = """\
'use strict';
const { spawnSync } = require('node:child_process');

module.exports = {
  handleRequest(name) {
    const out = spawnSync('sh', ['-c', 'ls ' + process.env.EXHIBIT_A_ALLOWED_DIR + '/' + name], {
      encoding: 'utf8',
    });
    return (out.stdout || '') + (out.stderr || '');
  },
};
"""

EXPLOIT = """
test('spawn cannot run the canary', () => {
  app.handleRequest('x; ' + CANARY + ' #');
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report(
        "attack_js_exec_true_spawn_injection",
        run(SPAWN_APP, EXEC_PRELUDE + EXPLOIT, ENTRY, effect="canary_exec"),
        app_is_safe=False,
    )


if __name__ == "__main__":
    main()
