"""Attack 5 (canary_read): eval with a forged sourceURL claiming the app file."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('evals with a forged sourceURL', () => {
  const appFile = process.cwd() + '/app.js';
  const src = 'fs.readFileSync(' + JSON.stringify(CANARY) + ", 'utf8')" + '\\n//# sourceURL=' + appFile;
  const body = eval(src);
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_forged_source_url", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
