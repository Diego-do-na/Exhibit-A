from _http_cases import safe


def main():
    return safe("attack_js_read_http_proxy", """
test('a test proxy into app code does not become public input', () => {
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  server.on('request', (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8')));
  const proxy = { request: () => server.emit('request', {
    url: '/?name=../outside/canary.txt',
  }, {
    end(value) { assert.ok(!String(value).includes(TOKEN)); },
  }) };
  proxy.request();
});
""")
