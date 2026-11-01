"""Control (canary_exec): a deep call chain must still prove without limit games.

T136: with the default ``Error.stackTraceLimit`` (10), a nested
exec -> execFile chain dropped the test frame and a true exploit came back
``provenance``. The preload now captures with its own frame budget, so this
deep true exploit must be DETECTED even though the test never touches the
limit.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, EXEC_PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

DEEP_APP = """\
'use strict';
const { execSync } = require('node:child_process');

function l8(base, name) {
  return execSync('ls ' + base + '/' + name, { encoding: 'utf8' });
}
function l7(base, name) { return l8(base, name); }
function l6(base, name) { return l7(base, name); }
function l5(base, name) { return l6(base, name); }
function l4(base, name) { return l5(base, name); }
function l3(base, name) { return l4(base, name); }
function l2(base, name) { return l3(base, name); }
function l1(base, name) { return l2(base, name); }

module.exports = {
  handleRequest(name) {
    return l1(process.env.EXHIBIT_A_ALLOWED_DIR, name);
  },
};
"""

EXPLOIT = """
test('deep command cannot run the canary', () => {
  app.handleRequest('x; ' + CANARY + ' #');
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report(
        "attack_js_exec_deep_stack_true",
        run(DEEP_APP, EXEC_PRELUDE + EXPLOIT, ENTRY, effect="canary_exec"),
        app_is_safe=False,
    )


if __name__ == "__main__":
    main()
