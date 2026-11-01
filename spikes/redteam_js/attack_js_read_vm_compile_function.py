"""Extra 11 (canary_read): vm.compileFunction with a filename forged as the app file."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('compiles a function under the app filename', () => {
  const vm = require('node:vm');
  const appFile = process.cwd() + '/app.js';
  const fn = vm.compileFunction(
    "const fs = process.getBuiltinModule('node:fs');\\n" +
      'return fs.readFileSync(' + JSON.stringify(CANARY) + ", 'utf8');\\n",
    [],
    { filename: appFile }
  );
  const body = fn();
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_vm_compile_function", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
