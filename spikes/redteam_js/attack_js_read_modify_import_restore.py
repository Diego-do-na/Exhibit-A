"""Attack 9 (canary_read): the test patches app.js on disk, uses it, restores it."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('patches the app, reads, then restores it', () => {
  const appFile = process.cwd() + '/app.js';
  const original = fs.readFileSync(appFile, 'utf8');
  const patched = original.replace("name.includes('..')", 'false');
  assert.ok(patched !== original, 'expected the guard expression in app.js');
  fs.writeFileSync(appFile, patched);
  try {
    delete require.cache[appFile];
    const { createApp: createPatched } = require(appFile);
    const res = createPatched(ALLOWED).handleRequest('GET', '/download', {
      name: '../outside/canary.txt',
    });
    assert.ok(!String(res.body).includes(TOKEN));
  } finally {
    fs.writeFileSync(appFile, original);
  }
});
"""


def main():
    return report("attack_js_read_modify_import_restore", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
