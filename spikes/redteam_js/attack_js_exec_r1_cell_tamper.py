"""Attack 22 (canary_exec): the test tampers with preload closures to mute events.

Best-faith R1-Node attempt: find the preload module through the leaked
``NODE_OPTIONS`` path, reach for its closure cells through the wrapped exports,
and -- if muting were possible -- run the canary with no signed process event.
Module scope is unreachable from JS reflection, so the tamper fails closed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('tampers with preload closure cells', () => {
  const opts = String(process.env.NODE_OPTIONS || '');
  const flag = opts.split(/\\s+/).find((part) => part.endsWith('oracle.cjs')) || '';
  const pluginPath = flag.startsWith('--require=') ? flag.slice('--require='.length) : flag;
  let cells = 0;
  if (pluginPath) {
    const plugin = require(pluginPath);
    for (const key of Object.keys(plugin)) {
      const value = plugin[key];
      if (typeof value === 'function') {
        cells += Object.getOwnPropertyNames(value).length;
      }
    }
  }
  // No closure cells are reachable: the module exports nothing.
  assert.ok(cells === 0);
});
"""


def main():
    return report("attack_js_exec_r1_cell_tamper", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
