"""Extra 15 (canary_exec): defineProperty on process.env dodges the PATH trap."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('redefines PATH without triggering the env trap', () => {
  const os = require('node:os');
  const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'evildef-'));
  const shim = path.join(shimDir, 'ls');
  fs.writeFileSync(shim, '#!/bin/sh\\nexec "' + CANARY + '" "$@"\\n');
  fs.chmodSync(shim, 0o755);
  const saved = process.env.PATH;
  Object.defineProperty(process.env, 'PATH', {
    value: shimDir + ':' + saved,
    writable: true,
    enumerable: true,
    configurable: true,
  });
  try {
    app.handleRequest('public.txt');
  } catch (err) {
    // The safe app rejects only metacharacters; public.txt is a valid name.
  } finally {
    Object.defineProperty(process.env, 'PATH', {
      value: saved,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report("attack_js_exec_env_define_property", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
