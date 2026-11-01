from _http_cases import safe


def main():
    return safe("attack_js_read_http_emit_fake", """
test('fake request arguments do not make a test read public', () => {
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  server.on('request', (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8')));
  server.emit('request', { url: '/?name=../outside/canary.txt' }, {
    end(value) { assert.ok(!String(value).includes(TOKEN)); },
  });
});
""")
