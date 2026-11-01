"""Shared HTTP apps and attack helpers for the independent red team."""

from _cases import ENTRY, READ_PRELUDE
from _harness import report, run

SAFE_HTTP_APP = """\
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

function createServer(baseDir) {
  return http.createServer((req, res) => {
    const name = new URL(req.url, 'http://x').searchParams.get('name') || 'public.txt';
    if (path.isAbsolute(name) || name.includes('..')) {
      res.statusCode = 403;
      res.end('forbidden');
      return;
    }
    res.end(fs.readFileSync(path.join(baseDir, name), 'utf8'));
  });
}

module.exports = { createServer };
"""

VULN_HTTP_APP = """\
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

function createServer(baseDir) {
  return http.createServer((req, res) => {
    const name = new URL(req.url, 'http://x').searchParams.get('name') || '';
    res.end(fs.readFileSync(path.join(baseDir, name), 'utf8'));
  });
}

module.exports = { createServer };
"""


def safe(name: str, body: str):
    return report(name, run(SAFE_HTTP_APP, READ_PRELUDE + body, ENTRY), app_is_safe=True)


def true_http(name: str, body: str):
    return report(name, run(VULN_HTTP_APP, READ_PRELUDE + body, ENTRY), app_is_safe=False)
