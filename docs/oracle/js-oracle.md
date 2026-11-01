# JavaScript and TypeScript oracle (design)

This document specifies the design for the Exhibit A JavaScript and TypeScript (Node.js) proof oracle. It defines how Exhibit A observes `canary_read` and `canary_exec` in Node environments to the exact same proof standard as Python: an in-process observation hook, cryptographic event signing, authenticated stack provenance, workspace tamper detection, differential verification against a fix, and cross-validation against an out-of-process OS witness.

Execution runs exclusively in an isolated and resource-limited container (`node:22.23.4-slim` pinned in `src/exhibit_a/sandbox/image_node.py`). A non-vulnerable baseline or a successful differential run means only that "nothing could be proven", never an assertion of absolute security.

---

## a. Test runner

### Built-in `node:test` runner
The Node verification harness executes tests using Node's built-in test runner (`node:test`), invoked via `node --test`. 

**Rationale for zero third-party runner dependencies:**
In Python, Exhibit A relies on `pytest` because pytest is universal in the Python ecosystem and provides programmatic plugin hooks (`pytest_configure`, `pytest_runtest_protocol`). In the Node ecosystem, third-party test runners (Jest, Vitest, Mocha) introduce massive dependency graphs, complex userland module-loader monkeypatching (e.g., Jest's custom VM contexts and module registry), and external network footprints during installation. 
Using the standard built-in `node:test` runner (stable in Node 22 LTS):
1. Eliminates third-party test framework dependencies, keeping the container image minimal and reproducible.
2. Runs natively on top of Node's standard ECMAScript Module (ESM) and CommonJS (CJS) loaders without custom VM sandbox layers that interfere with stack traces.
3. Provides native subtest nesting, concurrency controls (`--test-concurrency=1` to guarantee deterministic sequential execution), and structured reporting.

### TypeScript support via pinned loader (`tsx`)
TypeScript exploit tests and application code are executed through the pinned loader `tsx` (`tsx@4.19.2`, installed at `/opt/sandbox` as defined in `src/exhibit_a/sandbox/image_node.py`).

**Why `tsx` is chosen:**
- **Zero ahead-of-time compilation:** Transpiles TypeScript files on the fly in-memory using esbuild, avoiding multi-step build pipelines and disk artifacts that could tamper with workspace digests.
- **Unified CJS/ESM interop:** Transparently handles `.ts`, `.tsx`, `.mts`, and `.cts` files alongside plain `.js` and `.mjs` without requiring synthetic transpilation artifacts in the application tree.
- **Run-time type stripping without validation blocking:** Strips type annotations instantly without performing full semantic type-checking, preventing compile-time type errors from suppressing real runtime exploit execution.
- **Integration via official module flags:** Loaded seamlessly via Node's `--import tsx` (ESM loader hooks) without requiring global binaries.

**Alternative considered and rejected (`node --experimental-strip-types`):**
Node 22 introduces native type-stripping via `--experimental-strip-types`. While appealing for zero-dependency purity, this feature remains experimental in Node 22 LTS, intentionally rejects TypeScript features that require code transformation (such as `enums`, `namespaces`, and parameter properties), and ignores `tsconfig.json` path mappings. `tsx@4.19.2` provides deterministic, full-fidelity TypeScript support across all modern syntax constructs while maintaining strict pinned reproducibility.

### Exit-code and report contract
The orchestrator runner (`SandboxRunner`) expects a strict contract from the containerized test execution:

1. **Exit codes:**
   - `exit_code === 0`: All tests passed. In an exploit run against vulnerable code, an exit code of 0 means the exploit failed to trigger an assertion failure; no proof is established (`outcome="passed"`, resulting in `discarded_unproven`). In a verification run against fixed code, exit code 0 satisfies the requirement that the exploit passes on the fixed tree.
   - `exit_code === 1`: At least one test failed. In an exploit run, an assertion failure indicates that the exploit succeeded in proving the unintended effect, provided valid signed oracle events corroborate the failure (`outcome="failed"`).
   - `exit_code > 1` or signal termination: Runner crash, unhandled asynchronous rejection outside a test, syntax error, or environment fault. Handled as `outcome="env_failure"` or `invalid_test`.

2. **Report format:**
   Tests are executed with `--test-reporter=tap` (Test Anything Protocol v13). TAP output is streamed to standard output while diagnostic logs and oracle notices route to standard error. The runner parses TAP streams to verify:
   - Presence of `not ok <n> - <test_name>` indicating a specific test failure.
   - Diagnostic YAML blocks containing `operator: fail` or assertion error details.
   - Distinction between test assertion failures (valid exploit outcome) and collection/syntax errors (invalid test).

---

## b. Observation

### Observation mechanism (`canary_read` and `canary_exec`)
Node does not expose CPython's `sys.addaudithook` or `sys.setprofile`. To observe low-level filesystem access and process creation with equivalent rigor, Exhibit A uses an authoritative preload module injected before any application or test code executes:

```bash
NODE_OPTIONS="--require /opt/exhibit_a_plugin/oracle.cjs --import /opt/exhibit_a_plugin/oracle.mjs"
```

The preload module intercepts both CommonJS (`require`) and ESM (`import`) paths, wrapping the following entry points:

#### 1. `canary_read` observation
The oracle wraps both high-level APIs and low-level internal bindings:
- **`node:fs` synchronous and callback APIs:** `fs.open`, `fs.openSync`, `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`, `fs.read`, `fs.readSync`, `fs.opendir`, `fs.opendirSync`.
- **`node:fs/promises` asynchronous APIs:** `fs.promises.open`, `fs.promises.readFile`, `fs.promises.opendir`.
- **Low-level bindings:** `internalBinding('fs').open`, `process.binding('fs')` (where exposed), and `FileHandle.prototype`.

**Inspection and route checking:**
When an intercepted `fs` method is called:
- The path is resolved against `process.cwd()`: `requested = path.resolve(process.cwd(), userPath)`.
- The real target is resolved via `fs.realpathSync`.
- The oracle verifies whether `requested` matches the canary target:
  - Lexically starts with `EXHIBIT_A_ALLOWED_DIR + path.sep` (e.g. `allowed/../outside/canary.txt`), or
  - Equals the canonical real path of the canary file (handling apps that canonicalize before opening).
- If the access attempts to reach the canary through a path outside the allowed directory hierarchy, the event is recorded with route failure.
- File flags (`O_RDONLY`, `O_RDWR`, `'r'`, `'r+'`) are classified at call time into `access: "read"` or `access: "write"`.
- The call records whether any symlink created during the run was traversed (`via_symlink`).

#### 2. `canary_exec` observation
The oracle wraps process creation APIs:
- **`node:child_process` exports:** `child_process.exec`, `child_process.execSync`, `child_process.spawn`, `child_process.spawnSync`, `child_process.execFile`, `child_process.execFileSync`, `child_process.fork`.
- **Low-level process spawning:** `internalBinding('spawn_sync')` and `ChildProcess.prototype.spawn`.

**Inspection and execution checking:**
When a process spawn is intercepted:
- The command and argument array (`file`, `args`, `env`, `cwd`) are inspected.
- `names_canary` is evaluated: true if any argument or command token resolves to `<work>/outside/canary`.
- `sink_named` is evaluated: true if the calling application function names a recognized process sink (`exec`, `spawn`, `execFile`, `fork`).
- Environmental and process alterations are tracked:
  - Mutations to `process.env.PATH`, `process.env.NODE_OPTIONS`, `LD_PRELOAD` (classified as `op: "env"`).
  - Directory changes via `process.chdir()` (classified as `op: "chdir"`).
  - Dynamic code evaluation via `eval`, `new Function`, or `node:vm` (classified as `op: "codegen"`).

**Marker verification:**
Executing `<work>/outside/canary` triggers a standalone `/bin/sh` script that appends the run's secret token to `<work>/outside/canary_ran`. The marker is verified out-of-process by the host orchestrator after the container terminates: it must be a regular file with a single link, size <= 1 MiB, containing exclusively the expected token lines.

### Stack capture via V8 Structured Stack Trace API
Rather than parsing formatted string stack traces (which can be forged via error formatting or misleading function names), the oracle captures the call stack using the V8 engine's native structured stack API:

```javascript
const err = {};
Error.captureStackTrace(err, wrappedFunction);
const originalPrepare = Error.prepareStackTrace;
try {
  Error.prepareStackTrace = (error, structuredStackTrace) => structuredStackTrace;
  const sites = err.stack; // Array of V8 CallSite objects
  // Extract: site.getFileName(), site.getLineNumber(), site.getColumnNumber(),
  // site.getFunctionName(), site.getMethodName(), site.isNative(), site.isEval()
} finally {
  Error.prepareStackTrace = originalPrepare;
}
```

V8 `CallSite` objects provide tamper-resistant call attributes:
- `getFileName()`: Exact file path associated with the script in V8's internal isolate.
- `getLineNumber()` / `getColumnNumber()`: Exact 1-based source coordinates.
- `getFunctionName()` / `getMethodName()`: Resolved function identifier.
- `isEval()` / `getEvalOrigin()`: Detects whether the frame originated from `eval()` or `vm.runInContext`.

### HMAC-signed JSONL event channel
Events are signed using HMAC-SHA256 and written to a dedicated descriptor opened at startup:
- **Key exchange:** The host orchestrator generates a 32-byte cryptographically random key and transmits it over stdin (`fd 0`) as `EXHIBIT-A-KEY <hex>\n` followed by `EXHIBIT-A-MANIFEST <json>\n` before any test code runs.
- **Line signing:** Each event is formatted as canonical JSON and signed:
  ```json
  {"body": {...}, "seq": 0, "sig": "a1b2c3d4..."}
  ```
  `sig` is `HMAC-SHA256(key, seq + ":" + canonical_body)`.
- **Monotonic sequence:** `seq` increments monotonically from 0. The judge rejects any duplicate, out-of-order, or invalidly signed line.
- **Channel scrubbing:** `EXHIBIT_A_EVENTS` and `EXHIBIT_A_CANARY` environment variables are cleared from `process.env` immediately after initial binding.

### Comparison with independent OS-level witness (T114) and trusted signal
Task T114 introduced an independent OS-level supervisor (`src/exhibit_a/sandbox/witness/supervisor.py`) running as a sibling process inside the container:
- **OS Witness capabilities:** Watches the canary path, marker file, SQLite database, and loopback socket using Linux kernel `inotify` (`IN_OPEN`, `IN_ACCESS`, `IN_CREATE`, `IN_CLOSE_WRITE`). It possesses its own private HMAC key unknown to the test process and records observations to `/oracle/witness.jsonl`.
- **Signal comparison:**
  - *OS witness signal:* The OS witness is the **trusted signal for the FACT of the event**. Kernel-level inotify notifications cannot be fabricated by JavaScript memory manipulation or prototype pollution. If the OS witness did not observe an open on the canary file, no canary read occurred.
  - *In-process oracle signal:* The in-process preload is the **trusted signal for PROVENANCE**. The kernel knows only that the Node process opened a file descriptor; it cannot inspect V8 heap frames, module boundaries, or entry point call paths.
- **Verdict agreement rule:** The judge enforces strict agreement:
  - If the in-process oracle claims a canary read but the OS witness has no corresponding inotify event, the run is rejected as `witness_mismatch`.
  - If the OS witness is missing or tampered with, the run is rejected as `witness_unavailable`.
  - An exploit is proven only when both witnesses agree: the OS witness proves the physical effect occurred, and the in-process oracle proves it originated from admitted application code reached through a declared entry point.

---

## c. Provenance

### Boundary separation
A stack frame is classified based on canonical file path resolution:
- **Application frame:** File path resides within the staged application root (`/workspace`) and outside the excluded test directory (`staging_exclude`).
- **Test frame:** File path resides within the exploit test directory (`/workspace/test`, `/workspace/__tests__`, `test_exploit.ts`, or any file containing test suites).
- **Library/Runtime frame:** Built-in Node modules (`node:*`) or dependencies residing in `node_modules`.

### Admitted application frames rule (Layers 1 and 2 in Node)
To prevent tests from forging application frames (by dynamically creating files in the application root or compiling code with forged filenames), the Node oracle implements the four-layer admission rule:

1. **Manifest verification (Layer 1):**
   The host orchestrator computes a SHA-256 digest of every file in the staged application tree prior to container execution. The manifest is delivered to the preload via stdin. Any frame referencing a file not present in the pre-run manifest is rejected (`admission: "file_not_in_manifest"`).

2. **File digest immutability (Layer 2a):**
   When the canary event fires, the file on disk corresponding to `callSite.getFileName()` is read and hashed synchronously. If its current digest does not equal the manifest digest, the frame is rejected (`admission: "file_modified"`).

3. **AST structure validation (Layer 2b):**
   The verified staged source code is parsed into an Abstract Syntax Tree (AST) using an embedded parser (e.g. Babel or Acorn). The AST confirms that at `callSite.getLineNumber()` and `callSite.getColumnNumber()`, a declared function, method, or class member exists with the exact `callSite.getFunctionName()`. This defeats synthetic `eval` frames where an attacker attempts to claim an application function name.

4. **V8 CallSite authenticity (Layer 2c):**
   The frame is checked for V8 evaluation flags:
   - `callSite.isEval()` must be false.
   - `callSite.getEvalOrigin()` must be null.
   - The file path must be an absolute filesystem path, rejecting synthetic V8 `//# sourceURL=` overrides.
   - The frame must belong to the main V8 execution context, not a detached `node:vm` context.

**Host re-check:**
The orchestrator judge on the host independently verifies that the reported file, line, and function name in the signed event exist in the host-staged repository clone before granting a `proven` verdict.

### Async continuation tracking (`AsyncLocalStorage` and `async_hooks`)
Unlike synchronous Python code where callers remain on the call stack until completion, Node applications execute almost all I/O asynchronously via Promises, callbacks, and microtasks. When `fs.readFile` or `child_process.exec` is reached following an `await` or event loop tick, the physical V8 call stack terminates at `processTicksAndRejections` or the libuv event loop runner.

**The provenance solution:**
The preload initializes a global `AsyncLocalStorage` instance (`node:async_hooks`).

There are two attributable entry shapes. A sink is proven through an entry only if it matches one of them.

1. **Named entry called from the test (existing).** Exported application functions are wrapped. When the test calls them, the preload records a logical stack whose outermost admitted frame must be a declared `entry_points` name, and a test frame must sit above that frame. This is the T125 `handleRequest` shape.

2. **HTTP public-interface (anonymous Express handlers).** Express (and `node:http`) route handlers run from the HTTP server's `request` event, not from a stack that contains the test. Function-name matching and "the test called the entry" both fail on that turn. The preload wraps `EventEmitter.prototype.emit` and, when `type === 'request'` and `this` is an `http.Server` or `https.Server`, starts an AsyncLocalStorage context marked `publicInterface`. A sink on that turn counts as reached through the entry point if:
   - the event is stamped `public_interface: true`, and
   - at least one admitted application frame (manifest-hashed file under the app root) is on the stack, and
   - no test-directory frame is on the stack.

   Direct calls from the test (no `request` emit) stay on shape 1: an anonymous handler is not a declared name, so they are refused. A test-created `http.createServer` still emits `request`, but its listener is test code with no admitted app frame (or with a test frame on the stack), so it is refused.

3. **Context propagation across async continuations:**
   Node's V8 engine automatically propagates `AsyncLocalStorage` across Promise chains, `await` points, `setTimeout`, `setImmediate`, `queueMicrotask`, `fs` callbacks, and EventEmitter callbacks, including the `request` turn.

4. **If a test calls `fs.readFile` directly from a test tick**, there is no public-interface context and no admitted app frame (`reason_code: "provenance"`).

---

## d. Integrity

The preload module and signing key reside inside the test process. Protecting them from untrusted test code requires multiple defensive barriers:

### 1. Module cache protection (`require.cache` and ESM loader)
In CommonJS, `require.cache` is a mutable dictionary. A test could attempt `delete require.cache[require.resolve('node:fs')]` to force Node to re-load an unpatched copy.
- **Defense:** The preload wraps `require.cache` using a `Proxy` that rejects deletions or modifications of core module identifiers (`node:fs`, `node:child_process`, `fs`, `child_process`).
- **ESM immutability:** ECMAScript Modules loaded via `import` are cached in the V8 engine's internal module registry, which is fundamentally immutable from userland JavaScript.

### 2. Immutability of hooks (`Object.freeze`)
All wrapped functions and exported module surfaces are permanently frozen:
- `Object.freeze(fs)`
- `Object.freeze(fs.promises)`
- `Object.freeze(child_process)`
- Property descriptors of wrapped functions are configured with `{ writable: false, configurable: false }`.
- Core global prototypes (`Object.prototype`, `Function.prototype`, `Promise.prototype`, `Array.prototype`) are sealed or monitored to prevent prototype pollution attacks from neutralizing wrappers.

### 3. Native bindings interception (`process.binding`)
Node exposes internal C++ bindings through legacy and internal entry points:
- `process.binding('fs')`
- `process.binding('spawn_sync')`
- `process._linkedBinding(...)`
- `internalBinding(...)`
- **Defense:** The preload overwrites and freezes `process.binding` and `process._linkedBinding`. Any invocation attempting to retrieve raw filesystem or process bindings returns the wrapped oracle handlers or throws an exception, while logging an integrity tripwire event.

### 4. Context isolation in `node:vm`
A test could attempt to escape wrappers by creating a clean V8 execution environment:
```javascript
const vm = require('node:vm');
const context = vm.createContext();
vm.runInContext("const fs = require('fs'); fs.readFileSync(...) ", context);
```
- **Defense:** The preload intercepts `node:vm.createContext`, `node:vm.runInContext`, `node:vm.runInNewContext`, `node:vm.runInThisContext`, and `node:vm.Script`. Any context initialization is injected with the frozen oracle wrappers, and `require` inside synthetic VM contexts is constrained.

### 5. Worker threads (`node:worker_threads`)
A test might spawn a `new Worker(script)` which runs in a new V8 isolate without inherited preloads.
- **Defense:** The preload wraps `node:worker_threads.Worker`. Spawning a worker automatically injects `execArgv` containing `--require /opt/exhibit_a_plugin/oracle.cjs` and securely relays the signing channel parameters. If worker containment cannot be guaranteed, worker thread instantiation is blocked during verification.

### 6. Child processes that omit preload
If the test or application invokes `child_process.spawn('node', ['script.js'])`:
- Node inherits `NODE_OPTIONS` from the environment by default, ensuring child Node processes load the preload.
- If an exploit unsets `NODE_OPTIONS`, the child process executes without in-process hooks. However, any canary access by that child is caught by the OS-level witness (T114), while the in-process oracle records no event, triggering a `witness_mismatch` and failing closed.

### 7. Foreseen Node-specific bypass vectors
- **Prototype pollution:** An attacker mutates `Object.prototype` (e.g. setting `Object.prototype.origin = '/workspace/app.js'`). Mitigated by using `Object.create(null)` for all internal oracle dictionaries and freezing critical prototypes.
- **`Error.prepareStackTrace` tampering:** An attacker attempts to override `Error.prepareStackTrace` before triggering the canary read. Mitigated by binding and freezing the original function reference at preload load time and restoring it during capture.
- **Async context stripping:** An attacker calls an entry point through an un-instrumented scheduling mechanism (e.g., native C++ timer addon). Results in an empty async store, causing provenance to fail closed.

---

## e. Judge

The judge operates on the host outside the sandbox container.

### Reused unchanged from Python judge
1. **HMAC event verification:** `verify_lines` verifies line-by-line monotonic sequence numbers (`seq`) and HMAC-SHA256 signatures using the runner's per-run secret key. Any forged or invalid line is rejected and incremented in `forged_events`.
2. **App-tree integrity:** `app_tree_changes` re-hashes the entire staged repository after container exit. Any file added, removed, or modified invalidates the run (`reason_code: "app_tree_changed"`).
3. **Marker token verification:** For `canary_exec`, `marker_holds_token` inspects `/work/outside/canary_ran` on the host, requiring a regular file with a single link containing the exact run token.
4. **Differential verification rule:** The exploit test must fail on the vulnerable application tree, must pass on the fixed application tree, and baseline regression tests must remain green.
5. **Route verification:** Enforces that `requested` paths originate within `EXHIBIT_A_ALLOWED_DIR`.
6. **OS witness agreement (`_apply_witness`):** Cross-checks in-process events with OS-level `witness.jsonl`, failing closed on `witness_mismatch` or `witness_unavailable`.
7. **Verdict taxonomy:** Outputs `proven`, `discarded_unproven`, `invalid_test`, `flaky`, `env_failure`.

### New components for Node judge
1. **V8 CallSite structure parser:**
   Replaces CPython traceback frame parsing with a parser designed for V8 structured frames (`fileName`, `lineNumber`, `columnNumber`, `functionName`, `isAsync`, `evalOrigin`).
2. **JavaScript/TypeScript AST verifier:**
   A host-side AST inspector (using Babel or SWC) that parses the staged `.js` and `.ts` files on the host to verify that function names and line coordinates reported by V8 CallSite objects correspond to real declarations in the genuine application source.
3. **TAP v13 test outcome normalizer:**
   Parses `node:test` TAP output streams to classify test failures versus syntax or collection errors.
4. **Node static guard (`guard_node.py`):**
   A static AST tripwire for JavaScript/TypeScript tests, scanning test files prior to execution for forbidden constructs (`process.binding`, `child_process` invocation in test code, direct mentions of `EXHIBIT_A_CANARY`).

---

## f. Residual limits for Node (honest declarations)

Like the Python oracle (R1–R6), the Node oracle has declared residual limits. Every limit is marked **designed, not verified** until concrete red-team tests are implemented.

### R1-Node: In-process memory and closure introspection (designed, not verified)
- **Mechanism:** In Node, the preload runs inside the same V8 isolate and heap as the test code. A test can use V8 heap inspection, garbage collection hooks (`v8.getHeapSnapshot()`), or prototype crawling across module closures to locate the signing key or the unbuffered event file descriptor. With the key, the test can sign forged JSONL events claiming admitted application frames.
- **Red-team attack:** `attack_js_r1_v8_heap_theft`. The test traverses module closure scopes, extracts the HMAC key, and appends a validly signed `canary_read` event to `/oracle/events.jsonl` without calling the canary.
- **Status:** 
  - On the host execution path: **FALSE_PROVEN**.
  - In the container sandbox: **BLOCKED** by the OS witness (T114), which observes no kernel `inotify` access on the canary file and issues `witness_mismatch`.

### R2-Node: Application-level boot scripts and preload hijacking (designed, not verified)
- **Mechanism:** If an application repository contains an npm configuration (`.npmrc`), a local `package.json` with pre-test scripts, or a local file named `node_modules` that hijacks resolution, code can execute before or alongside the oracle preload on the host path.
- **Red-team attack:** `attack_js_r2_package_json_preload`. The application repository contains a malicious loader hook that runs before the preload and wraps `fs` to suppress canary events or forge credentials.
- **Status:** **FALSE_PROVEN** on the unconfined host path; in the sandbox, dependencies are pre-installed into `/opt/sandbox` with `--ignore-scripts`, mitigating container boot hijacking.

### R3-Node: Subprocess reads (designed, not verified)
- **Mechanism:** If an application vulnerability allows arbitrary argument injection into an existing non-canary binary (e.g. `cat ../outside/canary.txt`), the file read is performed by an external OS process rather than Node's `fs` module.
- **Red-team attack:** `attack_js_r3_subprocess_read`. Application executes `/bin/cat` on the canary file. The in-process `fs` hooks observe nothing.
- **Status:** **Recall limit (SUPPRESSED_TRUE)**. The read is missed by `canary_read`. If `canary_exec` is active, the process execution is observed, but the file read itself is not attributed to `fs`.

### R4-Node: Native C++ addons and N-API bypass (designed, not verified)
- **Mechanism:** Node applications can load compiled C++ addons (`.node` binaries) via `process.dlopen` or N-API. Native C++ code executing libc `open()` or `read()` directly does not trigger JavaScript V8 hooks or Node `fs` bindings.
- **Red-team attack:** `attack_js_r4_napi_addon_read`. Application loads a native addon that performs direct POSIX system calls to read the canary.
- **Status:** **Recall limit (SUPPRESSED_TRUE)**. In-process JavaScript hooks miss the access. In the sandbox, the OS witness detects the file access, but the in-process oracle cannot supply provenance, resulting in `witness_mismatch`.

### R5-Node: Dependency monkeypatching and prototype pollution via computed names (designed, not verified)
- **Mechanism:** JavaScript's dynamic object model allows modifying property bindings on imported modules or built-in prototypes using computed property names that evade static AST guards (e.g., `app[String.fromCharCode(115, 105, 110, 107)] = ...`). The application's genuine, admitted entry point executes, but its internal logic is subverted by test-polluted properties.
- **Red-team attack:** `attack_js_r5_prototype_pollution_sink`. Test injects properties into `Object.prototype` causing a path sanitizer in the application to evaluate to undefined, allowing path traversal.
- **Status:** **FALSE_PROVEN**. The oracle observes genuine application frames at the sink reached from the declared entry point. The fact that application behavior was altered via memory corruption cannot be distinguished from application code at the V8 frame level.

### R6-Node: Obfuscated test-chosen application root (designed, not verified)
- **Mechanism:** The test configures an application instance (e.g., an Express `serve-static` middleware) with its base directory pointing directly at the canary's ancestor directory using complex runtime arithmetic that static guards cannot fold (e.g. `path.join(ALLOWED, ...['..', 'outside'])`).
- **Red-team attack:** `attack_js_r6_computed_allowed_root`. Test passes a computed directory pointing to `/outside` as the base directory of a non-vulnerable static file server. The application serves the canary through its authentic entry point.
- **Status:** **FALSE_PROVEN**. Because the application requests the canary's exact real path, runtime route checks cannot separate "application configured with canary directory" from "traversal payload reaching canary". Only the static guard can intercept this, and dynamic evaluation evades it.

### R7-Node: Inbound HTTP that never emits `Server` `request` (declared residual)
- **Mechanism:** Attribution shape 2 keys off `http.Server`/`https.Server` `emit('request')`. A custom parser on a raw `net.Socket`, a replaced `EventEmitter.prototype.emit` that the freeze missed, or a non-HTTP public interface (Unix socket protocol, worker message) never sets `public_interface`. Anonymous handlers on those paths cannot be proven; they are not falsely proven either.
- **Attributable entry shapes that remain:** (1) named exported function called from the test, with that name in `entry_points`; (2) `http.Server`/`https.Server` `request` turn with an admitted app frame and no test frame.
- **Red-team attacks:** `attack_js_http_direct_from_test` (BLOCKED, `provenance`); `attack_js_http_test_created_server` (BLOCKED, `provenance`).
- **Status:** **Recall limit (SUPPRESSED_TRUE)** for non-`request` inbound HTTP. The two attacks above are blocked.

---

## g. Out of scope for v1

1. **Static call graph and context slicing for JavaScript/TypeScript:**
   - *Why:* Python has a single standard AST module and relatively straightforward synchronous call graphs. JavaScript and TypeScript feature asynchronous Promise chains, dynamic imports, complex module resolution (`tsconfig.json` paths, `package.json` conditional exports), higher-order function callbacks, and diverse web framework dispatchers (Express, Fastify, Koa, NestJS). Designing a sound, conservative static call graph for JS/TS requires a major independent static-analysis engine. v1 focuses strictly on whole-test verification on explicitly declared benchmark cases.
2. **`canary_sql` in Node:**
   - *Why:* Node lacks a standard library database interface. Relational database drivers (`better-sqlite3`, `sqlite3`, `pg`, `mysql2`) are third-party npm packages implemented primarily as native C++ N-API bindings. Instrumenting SQLite requires hooking C++ native bindings or intercepting diverse userland query builders (Knex, Prisma, TypeORM).
3. **`canary_connect` (SSRF) in Node:**
   - *Why:* Modern Node has multiple divergent HTTP networking layers: legacy `node:http`/`node:https`, modern global `fetch` (backed by the Undici native/Wasm client), and low-level `node:net` sockets. Providing comprehensive in-process SSRF observation without network access requires deep multi-client instrumentation.
4. **`canary_dos` (algorithmic complexity) in Node:**
   - *Why:* Node's single-threaded event loop lacks CPython's deterministic `sys.setprofile` thread-CPU accounting. Profiling V8 CPU execution requires V8 CPU profiler sessions via `node:inspector`, which introduces substantial timing jitter, microtask overhead, and non-deterministic event-loop delays in resource-limited containers.

---

## Attack list: Red-team attacks for Node oracle

Below is the specification of 29 named red-team attacks for the Node oracle, providing the concrete cheat/exploit mechanism and expected verdict for the implementation phase:

| # | Attack Name | Target Effect | Attack Mechanism | Expected Verdict | Reason Code |
|---|---|---|---|---|---|
| 1 | `attack_js_read_direct_from_test` | `canary_read` | Test directly invokes `fs.readFileSync(canaryPath)` from its own test frame. | BLOCKED | `provenance` (innermost frame is test) |
| 2 | `attack_js_read_vm_context` | `canary_read` | Test uses `vm.runInNewContext("fs.readFileSync(...)")` to strip test stack frames. | BLOCKED | `frame_not_admitted` (synthetic VM context) |
| 3 | `attack_js_read_require_cache_delete` | `canary_read` | Test executes `delete require.cache[require.resolve('fs')]` and re-requires clean `fs`. | BLOCKED | `invalid_test` (cache deletion trapped/frozen) |
| 4 | `attack_js_read_internal_binding` | `canary_read` | Test invokes `process.binding('fs').open(...)` to bypass high-level JavaScript wrappers. | BLOCKED | `invalid_test` (internal binding trapped) |
| 5 | `attack_js_read_forged_source_url` | `canary_read` | Test executes `eval('... //# sourceURL=/workspace/app.js')` to fake V8 frame file name. | BLOCKED | `frame_not_admitted` (`callSite.isEval() === true`) |
| 6 | `attack_js_read_prepare_stack_tamper` | `canary_read` | Test overrides `Error.prepareStackTrace` to doctor CallSite method names and paths. | BLOCKED | `invalid_test` (stack prepare hook frozen) |
| 7 | `attack_js_read_module_create_require` | `canary_read` | Test calls `module.createRequire()` to instantiate an unpatched CommonJS loader. | BLOCKED | `provenance` (wrapped factory returns wrapped `fs`) |
| 8 | `attack_js_read_write_app_file` | `canary_read` | Test writes `helper_shim.js` into `/workspace` and calls an entry point through it. | BLOCKED | `invalid_test` (`app_tree_changed` / manifest check) |
| 9 | `attack_js_read_modify_import_restore` | `canary_read` | Test modifies `app.js` on disk, imports it, and restores original file before reading canary. | BLOCKED | `frame_not_admitted` (AST/code object digest mismatch) |
| 10 | `attack_js_read_symlink_race` | `canary_read` | Test spawns asynchronous loop creating symlink to canary during app request and removing it. | BLOCKED | `provenance` (`via_symlink` flag set) |
| 11 | `attack_js_read_obfuscated_allowed_root` | `canary_read` | Test initializes static server rooted at canary directory via complex string concatenation. | BLOCKED | `canary_not_via_allowed_dir` |
| 12 | `attack_js_read_async_detached_promise` | `canary_read` | Test triggers canary read inside an unlinked `setImmediate` or microtask callback outside entry point context. | BLOCKED | `provenance` (missing/detached `AsyncLocalStorage`) |
| 13 | `attack_js_read_worker_thread_escape` | `canary_read` | Test spawns `worker_threads.Worker` with customized `execArgv` to evade preload hooks. | BLOCKED | `witness_mismatch` (OS witness sees read; no valid signed events) |
| 14 | `attack_js_read_key_introspection` | `canary_read` | Test crawls V8 heap or module closures to extract signing key and appends forged signed event without touching canary. | BLOCKED (Sandbox) / FALSE_PROVEN (Host) | `witness_mismatch` in sandbox; R1-Node on host |
| 15 | `attack_js_read_prototype_pollution` | `canary_read` | Test mutates `Object.prototype` using computed strings to disable path sanitization in non-vulnerable app. | FALSE_PROVEN | R5-Node (genuine app code executed) |
| 16 | `attack_js_exec_direct_spawn_from_test` | `canary_exec` | Test directly calls `child_process.exec(outside/canary)` from test file. | BLOCKED | `process_from_test` |
| 17 | `attack_js_exec_marker_direct_write` | `canary_exec` | Test writes token directly to `<work>/outside/canary_ran` using `fs.writeFileSync`. | BLOCKED | `canary_tampered` (file write intercepted) |
| 18 | `attack_js_exec_process_env_path_injection` | `canary_exec` | Test mutates `process.env.PATH` to redirect a standard binary execution to the canary script. | BLOCKED | `process_api_changed` (`op: "env"` recorded) |
| 19 | `attack_js_exec_copied_canary` | `canary_exec` | Application executes an arbitrary binary copied to `/tmp` that does not resolve to the declared canary. | BLOCKED | `no_effect` (`names_canary` is false) |
| 20 | `attack_js_exec_unrelated_process` | `canary_exec` | Application executes benign process (`node -v` or `ls`) during request processing. | BLOCKED | `no_effect` (`names_canary` is false) |
| 21 | `attack_js_exec_at_exit_handler` | `canary_exec` | Test schedules `process.on('exit', () => child_process.spawn(canary))`. | BLOCKED | `process_from_test` (no active application entry frame) |
| 22 | `attack_js_exec_r1_cell_tamper` | `canary_exec` | Test tampers with preload closure cells to suppress `process` event emission while running canary. | FALSE_PROVEN | R1-Node (marker written, judge lacks signed event) |
| 23 | `attack_js_read_true_traversal` | `canary_read` | Vulnerable path traversal in HTTP static handler reading `canary.txt` via `../` traversal. | DETECTED (Control) | `proven` |
| 24 | `attack_js_read_true_async_traversal` | `canary_read` | Vulnerable async `fs.promises.readFile` traversal across multiple `await` microtask boundaries. | DETECTED (Control) | `proven` |
| 25 | `attack_js_exec_true_command_injection` | `canary_exec` | Vulnerable command injection concatenating unsanitized parameter into `child_process.exec()`. | DETECTED (Control) | `proven` |
| 26 | `attack_js_exec_true_spawn_injection` | `canary_exec` | Vulnerable argument injection into `child_process.spawn` running shell with canary path. | DETECTED (Control) | `proven` |
| 27 | `attack_js_http_direct_from_test` | `canary_read` | Test invokes the anonymous route handler directly (no `Server` `request` emit). | BLOCKED | `provenance` (no public-interface stamp; name is not a declared entry) |
| 28 | `attack_js_http_test_created_server` | `canary_read` | Test `http.createServer` listener reads the canary. `request` is marked public-interface but no admitted app frame is on the stack. | BLOCKED | `provenance` (test-created server) |
| 29 | `attack_js_http_true_anonymous_handler` | `canary_read` | Vulnerable anonymous `http.Server`/`Express` handler reads the canary via `../` on a real `request` turn. | DETECTED (Control) | `proven` (`public_interface` + admitted app frame) |
