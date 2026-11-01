"""Apps and exploit scaffolding shared by the Node red-team attacks.

SAFE apps are genuinely non-vulnerable to the plain payload (a direct traversal
or injection is refused before any canary effect), so any proof from them is a
false proof. VULN apps carry the real flaw the four control exploits prove.
"""

from _harness import run

ENTRY = {"handleRequest"}

# Vulnerable: serves path.join(baseDir, name) with no checks at all.
VULN_READ_APP = """\
'use strict';
const fs = require('node:fs');
const path = require('node:path');

function createApp(baseDir) {
  return {
    handleRequest(method, routePath, query) {
      const name = (query && query.name) || '';
      return { status: 200, body: fs.readFileSync(path.join(baseDir, name), 'utf8') };
    },
  };
}

module.exports = { createApp };
"""

# Safe: refuses absolute paths and anything containing ".." lexically. It does
# not canonicalise, so it follows a symlink planted inside the base directory;
# checks are written with ordinary builtin calls a hostile test may subvert.
SAFE_READ_APP = """\
'use strict';
const fs = require('node:fs');
const path = require('node:path');

function createApp(baseDir) {
  return {
    handleRequest(method, routePath, query) {
      const name = (query && query.name) || '';
      if (path.isAbsolute(name) || name.includes('..')) {
        return { status: 403, body: 'forbidden' };
      }
      return { status: 200, body: fs.readFileSync(path.join(baseDir, name), 'utf8') };
    },
  };
}

module.exports = { createApp };
"""

# Vulnerable: unsanitised interpolation into a shell command.
VULN_EXEC_APP = """\
'use strict';
const { execSync } = require('node:child_process');

function runCommand(base, name) {
  return execSync('ls ' + base + '/' + name, { encoding: 'utf8' });
}

module.exports = {
  handleRequest(name) {
    return runCommand(process.env.EXHIBIT_A_ALLOWED_DIR, name);
  },
};
"""

# Safe: no shell, fixed binary, argument vector. Injection metacharacters are
# inert, but the binary itself is still resolved through PATH.
SAFE_EXEC_APP = """\
'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');

function runCommand(base, name) {
  if (/[^A-Za-z0-9._-]/.test(name)) {
    throw new Error('bad name');
  }
  const out = spawnSync('ls', [path.join(base, name)], { encoding: 'utf8' });
  return (out.stdout || '') + (out.stderr || '');
}

module.exports = {
  handleRequest(name) {
    return runCommand(process.env.EXHIBIT_A_ALLOWED_DIR, name);
  },
};
"""

READ_PRELUDE = """\
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ALLOWED = process.env.EXHIBIT_A_ALLOWED_DIR;
const OUTSIDE = path.join(path.dirname(ALLOWED), 'outside');
const CANARY = path.join(OUTSIDE, 'canary.txt');
const TOKEN = process.env.EXHIBIT_A_CANARY_TOKEN;
const { createApp } = require(path.join(process.cwd(), 'app.js'));
"""

EXEC_PRELUDE = """\
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ALLOWED = process.env.EXHIBIT_A_ALLOWED_DIR;
const OUTSIDE = path.join(path.dirname(ALLOWED), 'outside');
const CANARY = path.join(OUTSIDE, 'canary');
const MARKER = path.join(OUTSIDE, 'canary_ran');
const TOKEN = process.env.EXHIBIT_A_CANARY_TOKEN;
const app = require(path.join(process.cwd(), 'app.js'));
"""


def read_cheat(body: str, app: str = SAFE_READ_APP):
    """Run ``body`` (a whole test module after READ_PRELUDE) against ``app`` for canary_read."""
    return run(app, READ_PRELUDE + body, ENTRY, effect="canary_read")


def read_true(body: str, app: str = VULN_READ_APP):
    """Run ``body`` against the vulnerable reader; a proof here is DETECTED."""
    return run(app, READ_PRELUDE + body, ENTRY, effect="canary_read")


def exec_cheat(body: str, app: str = SAFE_EXEC_APP):
    """Run ``body`` (a whole test module after EXEC_PRELUDE) against ``app`` for canary_exec."""
    return run(app, EXEC_PRELUDE + body, ENTRY, effect="canary_exec")


def exec_true(body: str, app: str = VULN_EXEC_APP):
    """Run ``body`` against the vulnerable spawner; a proof here is DETECTED."""
    return run(app, EXEC_PRELUDE + body, ENTRY, effect="canary_exec")
