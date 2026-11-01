"""Attack 12 (canary_read): the read fires from a detached timer, outside any entry."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads from a detached microtask', async () => {
  const body = await new Promise((resolve) => {
    setImmediate(() => {
      resolve(fs.readFileSync(CANARY, 'utf8'));
    });
  });
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_async_detached_promise", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
