"""Extra 13 (canary_read): getter prepareStackTrace serves forged CallSites on read."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import read_cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
test('serves forged CallSites from the stack hook', () => {
  const appFile = process.cwd() + '/app.js';
  const testFile = __filename;
  const site = (file, name) => ({
    getFileName: () => file,
    getFunctionName: () => name,
    getMethodName: () => name,
    getLineNumber: () => 1,
    getColumnNumber: () => 1,
    isEval: () => false,
    getEvalOrigin: () => null,
    isNative: () => false,
  });
  // captureSites collects innermost-first, then the oracle reverses to
  // outermost-first: list the forged entry innermost so it lands outermost.
  const forged = () => [
    site(appFile, 'handleRequest'),
    site(testFile, 'test_serves_forged_callsites_from_the_stack_hook'),
  ];
  Object.defineProperty(Error, 'prepareStackTrace', {
    configurable: true,
    enumerable: false,
    get: () => forged,
    set: () => {},
  });
  const body = fs.readFileSync(CANARY, 'utf8');
  assert.ok(!String(body).includes(TOKEN));
});
"""


def main():
    return report("attack_js_read_stack_hook_getter", read_cheat(EXPLOIT), app_is_safe=True)


if __name__ == "__main__":
    main()
