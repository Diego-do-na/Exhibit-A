"""Attack 19 (canary_exec): the app runs a copy of the canary outside its path."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import EXEC_PRELUDE, ENTRY  # noqa: E402
from _harness import report, run  # noqa: E402

COPY_APP = """\
'use strict';
const { execFileSync } = require('node:child_process');

module.exports = {
  handleRequest(name) {
    if (/[^A-Za-z0-9._-]/.test(name)) {
      throw new Error('bad name');
    }
    return String(execFileSync('/tmp/' + name, { encoding: 'utf8' }));
  },
};
"""

EXPLOIT = """
test('runs a copied canary the oracle never named', () => {
  const copy = 'copy-' + process.pid;
  fs.copyFileSync(CANARY, '/tmp/' + copy);
  fs.chmodSync('/tmp/' + copy, 0o755);
  try {
    app.handleRequest(copy);
  } finally {
    fs.unlinkSync('/tmp/' + copy);
  }
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(ran, 'the copy really executed');
});
"""


def main():
    return report(
        "attack_js_exec_copied_canary",
        run(COPY_APP, EXEC_PRELUDE + EXPLOIT, ENTRY, effect="canary_exec"),
        app_is_safe=True,
    )


if __name__ == "__main__":
    main()
