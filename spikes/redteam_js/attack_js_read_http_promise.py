from _http_cases import safe


def main():
    return safe("attack_js_read_http_promise", """
test('promise continuation listener remains test-originated', async () => {
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  await Promise.resolve();
  server.on('request', (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8')));
  server.emit('request', {}, { end(value) { assert.ok(!String(value).includes(TOKEN)); } });
});
""")
