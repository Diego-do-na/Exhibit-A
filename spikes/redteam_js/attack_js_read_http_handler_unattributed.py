"""Extra (canary_read, residual R-JS4): a real HTTP handler leak is unattributable.

The vulnerable app serves traversal reads from an anonymous ``(req, res)``
handler dispatched by the HTTP server's ``request`` event. The test makes a
genuine HTTP request with a traversal payload and the canary leaks, but the
sink stack holds no test frame and no declared entry point: the request event
is not the test calling the entry, so the oracle records the read and refuses
provenance. Observed but unattributable.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, READ_PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

HTTP_APP = """\
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

function createServer(baseDir) {
  const server = http.createServer((req, res) => {
    const name = new URL(req.url, 'http://x').searchParams.get('name') || '';
    res.end(fs.readFileSync(path.join(baseDir, name), 'utf8'));
  });
  return server;
}

module.exports = { createServer };
"""

EXPLOIT = """
test('http download cannot escape base dir', async () => {
  const http = require('node:http');
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const body = await new Promise((resolve, reject) => {
    http
      .get('http://127.0.0.1:' + port + '/download?name=../outside/canary.txt', (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve(data));
      })
      .on('error', reject);
  });
  await new Promise((resolve) => server.close(resolve));
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report(
        "attack_js_read_http_handler_unattributed",
        run(HTTP_APP, READ_PRELUDE + EXPLOIT, ENTRY),
        app_is_safe=False,
    )


if __name__ == "__main__":
    main()
