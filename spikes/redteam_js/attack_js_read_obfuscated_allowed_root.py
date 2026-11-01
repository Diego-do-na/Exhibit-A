"""Attack 11 (canary_read): the app is rooted at the canary dir via computed names."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('serves from a computed canary ancestor', () => {
  const at = (s, i) => String.fromCharCode(s.charCodeAt(i));
  // Rebuild "../outside" without writing it literally.
  const dots = at('..', 0) + at('..', 1);
  const sep = String.fromCharCode(47);
  const leaf = ['o', 'u', 't', 's', 'i', 'd', 'e'].map((c) => c).join('');
  const root = ALLOWED + sep + dots + sep + leaf;
  const res = createApp(root).handleRequest('GET', '/download', { name: 'canary.txt' });
  assert.ok(!String(res.body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_obfuscated_allowed_root", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
