"""Extra 18 (canary_read): an ESM test reads the canary through import syntax."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _cases import ENTRY, SAFE_READ_APP  # noqa: E402
from _harness import report, run  # noqa: E402

ESM_EXPLOIT = """\
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ALLOWED = process.env.EXHIBIT_A_ALLOWED_DIR;
const CANARY = path.join(path.dirname(ALLOWED), 'outside', 'canary.txt');
const TOKEN = process.env.EXHIBIT_A_CANARY_TOKEN;
const { createApp } = require(path.join(process.cwd(), 'app.js'));

test('esm test reads the canary itself', () => {
  const body = fs.readFileSync(CANARY, 'utf8');
  assert.ok(!body.includes(TOKEN));
});
"""


def main():
    return report(
        "attack_js_read_esm_import_direct",
        run(
            SAFE_READ_APP,
            ESM_EXPLOIT,
            ENTRY,
            exploit_name="test_exploit.mjs",
        ),
        app_is_safe=True,
    )


if __name__ == "__main__":
    main()
