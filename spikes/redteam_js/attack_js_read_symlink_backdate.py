"""Extra 6 (canary_read): backdate a planted symlink to dodge the run-window check."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('backdates a planted symlink', () => {
  const link = path.join(ALLOWED, 'aged_link.txt');
  try {
    fs.unlinkSync(link);
  } catch (err) {
    // Absent on the first pass.
  }
  fs.symlinkSync(CANARY, link);
  const old = new Date(Date.now() - 30 * 24 * 3600 * 1000);
  fs.utimesSync(link, old, old);
  let body = '';
  try {
    const res = createApp(ALLOWED).handleRequest('GET', '/download', {
      name: 'aged_link.txt',
    });
    body = String(res.body);
  } finally {
    fs.unlinkSync(link);
  }
  assert.ok(!body.includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_symlink_backdate", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
