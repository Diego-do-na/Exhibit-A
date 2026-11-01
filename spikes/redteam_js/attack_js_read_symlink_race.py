"""Attack 10 (canary_read): a symlink planted in the base dir during the run."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads through a planted symlink', () => {
  const link = path.join(ALLOWED, 'race_link.txt');
  try {
    fs.unlinkSync(link);
  } catch (err) {
    // Absent on the first pass; the loop below recreates it.
  }
  let leaked = false;
  for (let i = 0; i < 5; i += 1) {
    fs.symlinkSync(CANARY, link);
    try {
      const res = createApp(ALLOWED).handleRequest('GET', '/download', {
        name: 'race_link.txt',
      });
      leaked = leaked || String(res.body).includes(TOKEN);
    } finally {
      fs.unlinkSync(link);
    }
  }
  assert.ok(!leaked);
});
"""


def main():
    return report("attack_js_read_symlink_race", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
