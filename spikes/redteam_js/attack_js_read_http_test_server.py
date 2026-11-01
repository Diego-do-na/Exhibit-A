"""Extra (canary_read): a server created by the test proves nothing.

The test builds its own HTTP server whose handler reads the canary and makes
a real request to it. The leak fails the assertion, but the sink stack holds
only test frames -- no admitted application code -- so there is no proof.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, READ_PRELUDE, SAFE_READ_APP  # noqa: E402
from _harness import report, run  # noqa: E402

EXPLOIT = """
test('a test-created server proves nothing', async () => {
  const http = require('node:http');
  const server = http.createServer((req, res) => {
    res.end(fs.readFileSync(CANARY, 'utf8'));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const body = await new Promise((resolve, reject) => {
    http
      .get('http://127.0.0.1:' + port + '/', (res) => {
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
        "attack_js_read_http_test_server",
        run(SAFE_READ_APP, READ_PRELUDE + EXPLOIT, ENTRY),
        app_is_safe=True,
    )


if __name__ == "__main__":
    main()
