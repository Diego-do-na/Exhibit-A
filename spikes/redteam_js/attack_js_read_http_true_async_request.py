from _http_cases import true_http


def main():
    return true_http("attack_js_read_http_true_async_request", """
test('a real request proves an anonymous traversal handler', async () => {
  const http = require('node:http');
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const body = await new Promise((resolve, reject) => {
    http.get('http://127.0.0.1:' + server.address().port +
      '/?name=../outside/canary.txt', (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve(data));
      }).on('error', reject);
  });
  await new Promise((resolve) => server.close(resolve));
  assert.ok(!String(body).includes(TOKEN));
});
""")
