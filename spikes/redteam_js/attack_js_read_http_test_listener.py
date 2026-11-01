"""Extra (canary_read): a test listener on the app's HTTP server must not prove.

The app's own `http.Server` is safe (lexical `..` screen). The test registers an
extra `request` listener that reads the canary and then issues a real HTTP
request. HTTP-boundary ALS would stamp the whole turn `public_interface`; if
that plus any admitted app frame were enough, this would be a false proof
(R-JS4). The listener is test code, so the read must stay unproven.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, READ_PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402

HTTP_SAFE_APP = """\
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

function createServer(baseDir) {
  const server = http.createServer((req, res) => {
    const name = new URL(req.url, 'http://x').searchParams.get('name') || 'public.txt';
    if (path.isAbsolute(name) || name.includes('..')) {
      res.statusCode = 403;
      res.end('forbidden');
      return;
    }
    res.end(fs.readFileSync(path.join(baseDir, name), 'utf8'));
  });
  return server;
}

module.exports = { createServer };
"""

EXPLOIT = """
test('a test listener on the app server proves nothing', async () => {
  const http = require('node:http');
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  server.on('request', (req, res) => {
    try {
      res.end(fs.readFileSync(CANARY, 'utf8'));
    } catch (err) {
      res.statusCode = 500;
      res.end(String(err));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const body = await new Promise((resolve, reject) => {
    http
      .get('http://127.0.0.1:' + port + '/?name=public.txt', (res) => {
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
        "attack_js_read_http_test_listener",
        run(HTTP_SAFE_APP, READ_PRELUDE + EXPLOIT, ENTRY),
        app_is_safe=True,
    )


if __name__ == "__main__":
    main()
