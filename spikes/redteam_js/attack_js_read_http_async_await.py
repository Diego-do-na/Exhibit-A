from _http_cases import safe


def main():
    return safe("attack_js_read_http_async_await", """
async function forge(server) {
  await Promise.resolve('continued');
  server.on('request', (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8')));
  server.emit('request', {}, { end(value) { assert.ok(!String(value).includes(TOKEN)); } });
}
test('async function continuation remains test-originated', async () => {
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  await forge(createServer(ALLOWED));
});
""")
