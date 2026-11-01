"""Extra 20 (canary_read): a native addon that reads the canary outside V8 hooks.

Best-faith R4-Node stub: load an untrusted ``.node`` binary with
``process.dlopen`` and call into it. No toolchain ships a real malicious addon
here, so the load itself is expected to fail closed before any read happens.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('loads a native addon to read outside V8', () => {
  let loaded = false;
  try {
    const fake = path.join(ALLOWED, 'evil.node');
    fs.writeFileSync(fake, 'not a real addon');
    process.dlopen(module, fake);
    loaded = true;
  } catch (err) {
    assert.ok(err, 'expected dlopen to fail');
  } finally {
    try {
      fs.unlinkSync(path.join(ALLOWED, 'evil.node'));
    } catch (err) {
      // Best effort cleanup.
    }
  }
  assert.ok(!loaded);
});
"""


def main():
    return report("attack_js_read_napi_addon_stub", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
