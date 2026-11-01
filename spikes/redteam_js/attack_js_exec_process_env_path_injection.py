"""Attack 18 (canary_exec): PATH is redirected so the app's `ls` runs the canary."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('redirects PATH at a shim that runs the canary', () => {
  const { execFileSync } = require('node:child_process');
  const os = require('node:os');
  const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'evil-'));
  const shim = path.join(shimDir, 'ls');
  fs.writeFileSync(shim, '#!/bin/sh\\nexec "' + CANARY + '" "$@"\\n');
  fs.chmodSync(shim, 0o755);
  const saved = process.env.PATH;
  process.env.PATH = shimDir + ':' + saved;
  try {
    app.handleRequest('public.txt');
  } catch (err) {
    // The safe app rejects only metacharacters; public.txt is a valid name.
  } finally {
    process.env.PATH = saved;
  }
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report("attack_js_exec_process_env_path_injection", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
