"""Extra 3 (canary_read): hijack Module._load to hand out an unpatched fs."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('hijacks Module._load for node:fs', () => {
  const Module = require('node:module');
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'node:fs' || request === 'fs') {
      return process.getBuiltinModule('node:fs');
    }
    return origLoad.call(this, request, parent, isMain);
  };
  const body = require('node:fs').readFileSync(CANARY, 'utf8');
  Module._load = origLoad;
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_loader_hijack", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
