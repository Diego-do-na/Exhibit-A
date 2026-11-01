"""Node/TypeScript oracle helpers: plugin path, language names, test argv.

The preload itself is plain CommonJS (`oracle.cjs` beside this file). This
package is the Python side of that contract: where the file lives, which
language values select it, and the `node --test` argv the sandbox and host
runners share.
"""

from __future__ import annotations

from pathlib import Path

JS_LANGUAGES = frozenset({"javascript", "typescript"})
PLUGIN_CJS = Path(__file__).resolve().parent / "oracle.cjs"
PLUGIN_MOUNT = "/opt/exhibit_a_plugin/oracle.cjs"
# ESM --import does not consult NODE_PATH; pin the loader the Node image installs.
TSX_IMPORT = "/opt/sandbox/node_modules/tsx/dist/loader.mjs"
TS_SUFFIXES = frozenset({".ts", ".mts", ".cts", ".tsx"})
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", *TS_SUFFIXES})


def is_js(language: str | None) -> bool:
    return language in JS_LANGUAGES


def language_of(test_path: str | Path, language: str = "python") -> str:
    """Declared language, or a JS/TS guess from the test suffix when still python."""
    if language in JS_LANGUAGES:
        return language
    suffix = Path(test_path).suffix.lower()
    if suffix in TS_SUFFIXES:
        return "typescript"
    if suffix in JS_SUFFIXES:
        return "javascript"
    return language


def uses_tsx(language: str, test_path: str | Path) -> bool:
    return language == "typescript" or Path(test_path).suffix.lower() in TS_SUFFIXES


def node_test_argv(rel_test: str, *, typescript: bool = False) -> list[str]:
    """Argv for `node --test` inside the container (cwd `/workspace`)."""
    args = ["node"]
    if typescript:
        args += ["--import", TSX_IMPORT]
    args += [
        "--test",
        "--experimental-test-isolation=none",
        "--test-concurrency=1",
        "--test-reporter=tap",
        f"/workspace/{rel_test}",
    ]
    return args
