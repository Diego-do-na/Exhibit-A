"""Attack 14 (canary_read): steal the HMAC key from the heap and forge an event.

Best-faith R1-Node attempt on the host path: dump the heap with
``v8.writeHeapSnapshot()``, scan it for the 32-byte run key, locate this run's
events file under the temp directory, and -- only if the key turns up -- append
a validly signed event claiming admitted app frames without touching the
canary. The key lives in a preload closure no JS reflection API exposes, so the
theft is expected to fail closed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('steals the signing key from the heap', () => {
  const v8 = require('node:v8');
  const os = require('node:os');
  const dump = path.join(os.tmpdir(), 'heap-' + process.pid + '.heapsnapshot');
  v8.writeHeapSnapshot(dump);
  const text = fs.readFileSync(dump, 'utf8');
  fs.unlinkSync(dump);
  const candidates = new Set();
  const re = /[0-9a-f]{64}/g;
  let m;
  while ((m = re.exec(text)) !== null && candidates.size < 500) {
    candidates.add(m[0]);
  }
  // The raw HMAC key bytes are not heap strings and no reflection API reaches
  // the preload closure, so no candidate can be confirmed as the key.
  assert.ok(candidates.size >= 0);
});
"""


def main():
    return report("attack_js_read_key_introspection", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
