from _http_cases import safe


def main():
    return safe("attack_js_read_http_benign", """
test('a benign public request does not prove anything', async () => {
  const http = require('node:http');
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const body = await new Promise((resolve, reject) => {
    http.get('http://127.0.0.1:' + server.address().port +
      '/?name=public.txt', (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve(data));
      }).on('error', reject);
  });
  await new Promise((resolve) => server.close(resolve));
  assert.ok(!String(body).includes(TOKEN));
});
""")
