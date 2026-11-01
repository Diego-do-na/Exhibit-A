from _http_cases import safe


def main():
    return safe("attack_js_read_http_router_handle", """
test('a router handle obtained by the test is not an entry point', () => {
  const { createServer } = require(path.join(process.cwd(), 'app.js'));
  const server = createServer(ALLOWED);
  const handle = (_req, res) => res.end(fs.readFileSync(CANARY, 'utf8'));
  const router = { stack: [{ handle }] };
  router.stack[0].handle({}, { end(value) { assert.ok(!String(value).includes(TOKEN)); } });
});
""")
