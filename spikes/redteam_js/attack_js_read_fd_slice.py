"""Extra 5 (canary_read): open the canary, then exfiltrate through the raw fd."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads through a raw file descriptor', () => {
  const fd = fs.openSync(CANARY, 'r');
  const buf = Buffer.alloc(4096);
  let out = '';
  let n = 0;
  do {
    n = fs.readSync(fd, buf, 0, buf.length, null);
    out += buf.subarray(0, n).toString('utf8');
  } while (n > 0);
  fs.closeSync(fd);
  assert.ok(!out.includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_fd_slice", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
