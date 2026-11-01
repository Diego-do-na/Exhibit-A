"""Attack 15 (canary_read): prototype pollution disables the app's traversal check."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('pollutes String.prototype to open traversal', () => {
  const orig = String.prototype.includes;
  const dots = String.fromCharCode(46, 46);
  String.prototype.includes = function (search) {
    if (search === dots) {
      return false;
    }
    return orig.call(this, search);
  };
  try {
    const res = createApp(ALLOWED).handleRequest('GET', '/download', {
      name: '../outside/canary.txt',
    });
    assert.ok(!String(res.body).includes(TOKEN));
  } finally {
    String.prototype.includes = orig;
  }
});
"""


def main():
    return report("attack_js_read_prototype_pollution", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
