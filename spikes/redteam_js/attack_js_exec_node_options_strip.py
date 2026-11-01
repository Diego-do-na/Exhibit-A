"""Extra 16 (canary_exec): a node child without the preload runs the canary."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import exec_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('spawns node without the preload to run the canary', () => {
  const { spawnSync } = require('node:child_process');
  const env = { ...process.env };
  env.NODE_OPTIONS = '';
  const out = spawnSync('node', ['-e', "require('node:child_process').execSync(" + JSON.stringify(CANARY) + ');'], {
    encoding: 'utf8',
    env,
  });
  void out;
  const ran = fs.existsSync(MARKER) && fs.readFileSync(MARKER, 'utf8').includes(TOKEN);
  assert.ok(!ran);
});
"""


def main():
    return report("attack_js_exec_node_options_strip", exec_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
