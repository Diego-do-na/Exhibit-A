"""Control 24 (canary_read): async traversal across awaits must be DETECTED."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, READ_PRELUDE, read_true  # noqa: E402
from _harness import report, run  # noqa: E402

ASYNC_APP = """\
'use strict';
const fsp = require('node:fs/promises');
const path = require('node:path');

function createApp(baseDir) {
  return {
    async handleRequest(method, routePath, query) {
      const name = (query && query.name) || '';
      await new Promise((resolve) => setTimeout(resolve, 5));
      const body = await fsp.readFile(path.join(baseDir, name), 'utf8');
      await new Promise((resolve) => setImmediate(resolve));
      return { status: 200, body };
    },
  };
}

module.exports = { createApp };
"""

EXPLOIT = """
test('async download cannot escape base dir', async () => {
  const res = await createApp(ALLOWED).handleRequest('GET', '/download', {
    name: '../outside/canary.txt',
  });
  assert.ok(!String(res.body).includes(TOKEN));
});
"""


def main():
    return report(
        "attack_js_read_true_async_traversal",
        run(ASYNC_APP, READ_PRELUDE + EXPLOIT, ENTRY),
        app_is_safe=False,
    )


if __name__ == "__main__":
    main()
