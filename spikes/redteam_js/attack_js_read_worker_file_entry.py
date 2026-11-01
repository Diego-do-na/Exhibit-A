"""Extra 7 (canary_read): a file-based worker posts the canary back to the test."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import READ_PRELUDE, ENTRY  # noqa: E402
from _harness import report, run  # noqa: E402

WORKER_APP = """\
'use strict';
const fs = require('node:fs');
const path = require('node:path');

function createApp(baseDir) {
  return {
    handleRequest(method, routePath, query) {
      return { status: 200, body: 'ok' };
    },
  };
}

module.exports = { createApp };
"""

EXPLOIT = """
test('exfiltrates through a file-based worker', async () => {
  const { Worker } = require('node:worker_threads');
  const script = path.join(__dirname, 'leak_worker.js');
  fs.writeFileSync(
    script,
    "const { parentPort } = require('node:worker_threads');\\n" +
      "const fs = require('node:fs');\\n" +
      'parentPort.postMessage(fs.readFileSync(' + JSON.stringify(CANARY) + ", 'utf8'));\\n"
  );
  const body = await new Promise((resolve, reject) => {
    const worker = new Worker(script);
    worker.once('message', resolve);
    worker.once('error', reject);
  });
  fs.unlinkSync(script);
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report(
        "attack_js_read_worker_file_entry",
        run(WORKER_APP, READ_PRELUDE + EXPLOIT, ENTRY),
        app_is_safe=True,
    )


if __name__ == "__main__":
    main()
