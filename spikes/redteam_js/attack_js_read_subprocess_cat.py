"""Extra 19 (canary_read, recall): the app leaks through a subprocess, not fs.

The vulnerable app shells out to ``cat`` for the file bytes. The read is
performed by an external process, so the in-process ``fs`` hooks observe
nothing: the oracle misses a real traversal. Recall limit, not a false proof.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, READ_PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

CAT_APP = """\
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');

function createApp(baseDir) {
  return {
    handleRequest(method, routePath, query) {
      const name = (query && query.name) || '';
      return {
        status: 200,
        body: String(execFileSync('cat', [path.join(baseDir, name)], { encoding: 'utf8' })),
      };
    },
  };
}

module.exports = { createApp };
"""

EXPLOIT = """
test('download cannot escape base dir', () => {
  const res = createApp(ALLOWED).handleRequest('GET', '/download', {
    name: '../outside/canary.txt',
  });
  assert.ok(!String(res.body).includes(TOKEN));
});
"""


def main():
    return report(
        "attack_js_read_subprocess_cat",
        run(CAT_APP, READ_PRELUDE + EXPLOIT, ENTRY),
        app_is_safe=False,
    )


if __name__ == "__main__":
    main()
