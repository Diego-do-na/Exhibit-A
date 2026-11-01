"""Attack 8 (canary_read): the test plants a helper inside the app root."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('calls the entry point through a planted helper', () => {
  const shim = process.cwd() + '/helper_shim.js';
  fs.writeFileSync(
    shim,
    "'use strict';\\n" +
      "const fs = require('node:fs');\\n" +
      'module.exports = (canary) => fs.readFileSync(canary, \\'utf8\\');\\n'
  );
  const leak = require(shim);
  const body = leak(CANARY);
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_write_app_file", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
