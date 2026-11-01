"""Attack 20 (canary_exec): the app runs a benign process during the request."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('runs an unrelated binary through the entry point', () => {
  const out = app.handleRequest('public.txt');
  assert.ok(!String(out).includes(TOKEN));
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report("attack_js_exec_unrelated_process", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
