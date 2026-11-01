from _http_cases import safe


def main():
    return safe("attack_js_read_http_subclass", """
test('a Server subclass does not create an app boundary', () => {
  const http = require('node:http');
  class FakeServer extends http.Server {}
  const server = new FakeServer();
  server.on('request', (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8')));
  server.emit('request', {}, { end(value) { assert.ok(!String(value).includes(TOKEN)); } });
});
""")
