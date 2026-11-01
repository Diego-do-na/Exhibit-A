from _http_cases import safe


def main():
    return safe("attack_js_read_http_once_listener", """
test('once listener cannot forge an app request', async () => {
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  server.once('request', (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8')));
  server.emit('request', {}, { end(value) { assert.ok(!String(value).includes(TOKEN)); } });
});
""")
