from _http_cases import safe


def main():
    return safe("attack_js_read_http_set_immediate", """
test('setImmediate listener remains test-originated', async () => {
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  await new Promise((resolve) => setImmediate(() => {
    server.on('request', (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8')));
    server.emit('request', {}, { end(value) { assert.ok(!String(value).includes(TOKEN)); resolve(); } });
  }));
});
""")
