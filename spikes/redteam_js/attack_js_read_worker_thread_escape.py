"""Attack 13 (canary_read): a worker with wiped execArgv reads without the preload."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('reads from a worker that drops the preload', async () => {
  const { Worker } = require('node:worker_threads');
  const code =
    "const { parentPort, workerData } = require('node:worker_threads');\\n" +
    "const fs = require('node:fs');\\n" +
    'parentPort.postMessage(fs.readFileSync(workerData.canary, \\'utf8\\'));\\n';
  const body = await new Promise((resolve, reject) => {
    const worker = new Worker(code, {
      eval: true,
      execArgv: [],
      workerData: { canary: CANARY },
    });
    worker.once('message', resolve);
    worker.once('error', reject);
  });
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_worker_thread_escape", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
