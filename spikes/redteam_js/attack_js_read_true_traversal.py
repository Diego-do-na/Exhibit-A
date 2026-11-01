"""Control 23 (canary_read): real traversal through the entry point must be DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_true  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('download cannot escape base dir', () => {
  const res = createApp(ALLOWED).handleRequest('GET', '/download', {
    name: '../outside/canary.txt',
  });
  assert.ok(!String(res.body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_true_traversal", read_true(EXPLOIT), app_is_safe=False)


if __name__ == "__main__":
    main()
