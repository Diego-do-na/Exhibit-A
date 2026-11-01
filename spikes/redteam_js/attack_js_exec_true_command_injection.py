"""Control 25 (canary_exec): real command injection must be DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_true  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('command cannot run the canary', () => {
  app.handleRequest('x; ' + CANARY + ' #');
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report("attack_js_exec_true_command_injection", exec_true(EXPLOIT), app_is_safe=False)


if __name__ == "__main__":
    main()
