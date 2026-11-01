"""Extra 9 (canary_read): vm.runInThisContext with a filename forged as the app file."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('runs in this context under the app filename', () => {
  const vm = require('node:vm');
  const appFile = process.cwd() + '/app.js';
  const src =
    '(function handleRequest() {\\n' +
    "  const fs = process.getBuiltinModule('node:fs');\\n" +
    '  return fs.readFileSync(' + JSON.stringify(CANARY) + ", 'utf8');\\n" +
    '})();\\n';
  const body = vm.runInThisContext(src, { filename: appFile });
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_vm_this_context_filename", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
