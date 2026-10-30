# Exhibit A — System Architecture and Contract Map

## 1. Overview and Core Philosophy

Exhibit A is a security-verification engine designed around a single thesis: **proof before accusation**.

Traditional security scanners overwhelm developers with speculative warnings that require manual triage. Exhibit A converts a suspected vulnerability into a reported finding only when it can synthesize a reproduction test that executes inside an isolated sandbox, triggers the intended security violation observed by an independent oracle, and satisfies strict provenance requirements. When an exploit is proven, the engine generates a remediation patch, verifies that the exploit now passes while baseline tests remain green, and challenges the patch against adversarial bypass attempts. If a suspicion cannot be proven, it is discarded silently and counted. A green report means "nothing could be proven", never "safe".

The system is architected as an orchestrator coordinating five decoupled boundaries:
1. **The Core Loop**: The state machine guiding an attack surface from baseline evaluation to packaged proof.
2. **The Event Ledger**: An append-only JSONL log acting as the single source of truth for the entire run.
3. **The Sandboxed Execution Runner**: A hardened, ephemeral container environment executing untrusted code with zero network access and dropped privileges.
4. **The Oracle**: An execution observer that monitors side-effects (e.g. file access via Python audit hooks) and validates call-stack provenance.
5. **The Model Roles**: Untrusted generative components confined strictly behind structured JSON schemas and a cost meter with hard limits.

```
                    +-------------------------------------------------------+
                    |                      ORCHESTRATOR                     |
                    |                                                       |
                    |   +-----------------------------------------------+   |
                    |   |              VerificationLoop                 |   |
                    |   +-----------------------------------------------+   |
                    |          |                   |                |       |
                    |          v                   v                v       |
                    |     [ModelRole]          [Ledger]       [Package Dir] |
                    +----------|-------------------|----------------|-------+
                               |                   |                |
             Prompt / Schema   |                   | Events         | Evidence
                               v                   v                v
                   +---------------------+  +-------------+  +--------------+
                   | Untrusted Providers |  | ledger.jsonl|  | packages/    |
                   | (Replay / Meta API) |  +-------------+  +--------------+
                   +---------------------+         |
                                                   | Read / SSE
                                                   v
                                            +-------------+
                                            | Live Server |
                                            | / web UI    |
                                            +-------------+
                               |
              Container / Host Execution Boundary
                               |
                               v
            +--------------------------------------+
            |         SANDBOX / RUNNER             |
            |   +------------------------------+   |
            |   | Ephemeral Docker Container   |   |
            |   | - unprivileged UID/GID       |   |
            |   | - cap-drop ALL, no network   |   |
            |   | - read-only root, 512MB RAM  |   |
            |   |                              |   |
            |   |   pytest test_exploit.py     |   |
            |   |         |                    |   |
            |   |         v                    |   |
            |   |   +----------------------+   |   |
            |   |   | Oracle (Audit Hook)  |   |   |
            |   |   | - Canary detection   |   |   |
            |   |   | - Stack provenance   |   |   |
            |   |   +----------------------+   |   |
            |   +------------------------------+   |
            +--------------------------------------+
```

---

## 2. The Verification Loop (Diagram-in-Prose)

The complete Exhibit A lifecycle follows ten distinct stages:

```
SCAN -> BASELINE -> SLICE -> SUSPECT -> EXPLOIT -> RUN -> VERDICT -> FIX -> VERIFY -> PACKAGE
```

### Stage-by-Stage Prose

#### 1. SCAN
The engine inspects the target repository to detect the language, interpreter version, dependency manager, test runner command, test framework, and dependencies.
- **Input**: Repository root or PR diff.
- **Output**: `RepoProfile` contract (`repo_profile.json`).
- **Current State**: The `RepoProfile` schema is fully implemented (`exhibit_a.schemas.repo_profile`). The CLI `scan` subcommand currently generates a validated placeholder profile. The automated scanner engine is scheduled for subsequent iterations.

#### 2. BASELINE
Before touching any exploit code, the target project's existing test suite is executed on a clean clone of the repository.
- **Invariants**: Baseline tests must pass. If the repository is broken before Exhibit A begins, execution aborts immediately with an `aborted` status.
- **Ledger Event**: Emits `EventType.BASELINE_DONE` with `ok=True/False` and runner `outcome`.
- **Runner**: Implemented via `baseline_runner` callable (defaulting to the Docker sandbox in `exhibit_a.sandbox.runner`, or `_local_baseline` in `cli.py` for benchmark environments).

#### 3. SLICE
To minimize token consumption and avoid hallucination, the orchestrator extracts only the minimal contextual slice required for each specific role, rather than presenting the entire repository.
- **Metric**: Measured as tokens consumed per proven finding versus whole-repository baselines.
- **Current State**: Handled in `exhibit_a.loop.prompts` by targeting specific source files and diffs associated with entry points. Dynamic dependency slicing is under active development.

#### 4. SUSPECT
The untrusted **Adversary** model inspects the targeted code slice and proposes candidate vulnerabilities.
- **Contract**: Proposes suspicions constrained strictly to `prompts.SUSPICIONS_SCHEMA`.
- **Validation**: Each candidate is validated against the `Suspicion` schema. Candidates with invalid schemas or duplicated IDs are dropped before reaching execution.
- **Ledger Event**: Emits `EventType.SUSPICION_RAISED` for every validated suspicion.

#### 5. EXPLOIT
For each valid `Suspicion`, the **Test Writer** model generates a targeted pytest test file (`test_exploit.py`).
- **Objective**: The test must trigger the vulnerability through an authenticated or declared entry point and fail on the vulnerable code.
- **Prompting**: Informs the test writer of the canary environment variables (`EXHIBIT_A_ALLOWED_DIR`, `EXHIBIT_A_CANARY_TOKEN`).
- **Ledger Event**: Emits `EventType.EXPLOIT_WRITTEN` with the generated test path. If the model output fails schema validation or disk write fails, the suspicion immediately terminates with verdict `invalid_test`.

#### 6. RUN
The orchestrator executes the exploit test against the target codebase for $N$ repeated runs (default $N = 3$) to guarantee deterministic reproducibility.
- **Execution**: Run via the `judge` callable (defaulting to `run_oracle` in `exhibit_a.oracle.oracle`).
- **Isolation**: Ephemeral container execution with dropped capabilities, read-only root filesystem, strict memory limits, and disabled networking.
- **Ledger Events**: Emits `EventType.RUN_STARTED` at the beginning of each run, and `EventType.ORACLE_EVENT` for each observed canary access.
- **Early Exit**: If any single run fails to demonstrate the required proof conditions, repetition halts immediately.

#### 7. VERDICT
The orchestrator aggregates the oracle judgements from all runs and classifies the outcome into a strict `VerdictValue`:
- `proven`: All $N$ runs failed as expected, the oracle confirmed the intended security effect (e.g. unauthorized canary read), and the call stack proved provenance (called through an entry point, not direct sink invocation).
- `discarded_unproven`: The test passed on vulnerable code, indicating the hypothesis did not materialize. Dropped silently from the report and counted.
- `invalid_test`: The test produced a syntax error, collection error, timeout, crashed without observing the canary, or attempted to cheat (reading the canary directly or bypassing entry points).
- `flaky`: The test yielded conflicting outcomes across repeated runs.
- `env_failure`: Docker or execution environment failure prevented completion.
- **Ledger Event**: Emits `EventType.VERDICT`.

#### 8. FIX
When (and only when) a suspicion reaches a `proven` verdict, the orchestrator invokes the **Fixer** model.
- **Input**: The suspicion details, vulnerable source code, exploit test source, and the oracle's proof reason.
- **Constraint**: Proposes a minimal file patch constrained to `prompts.FIX_SCHEMA`.
- **Application**: The orchestrator checks that paths do not escape the clone root, applies the patch to a dedicated `fixed` workspace, and computes a unified git diff.
- **Ledger Event**: Emits `EventType.FIX_PROPOSED` with `applied=True/False`.

#### 9. VERIFY
The orchestrator applies differential verification to the patched codebase:
1. **Exploit Inversion**: The exploit test is re-run against the patched code across $N$ runs; it must now **pass**.
2. **Regression Check**: The baseline test suite is re-run on the patched code; it must remain **passed**. Emits `EventType.BASELINE_DONE` with `on="fixed"`.
3. **Adversarial Bypass Defense**: The **Defender** model inspects the patch and generates bypass exploit variants (`prompts.VARIANTS_SCHEMA`). Each variant is executed against the patch. Emits `EventType.BYPASS_ATTEMPT` and `EventType.BYPASS_RESULT`.
- **Outcome**: If the exploit passes and baseline remains green, the fix is verified (`fix_verified = True`). The verdict records the number of bypass variants attempted and succeeded.

#### 10. PACKAGE
The orchestrator compiles the verified artifacts into an isolated bundle directory (`packages/<suspicion_slug>/`):
- `test_exploit.py`: The reproduction pytest exploit.
- `fix.patch`: Unified diff containing the remediation (included if verified).
- `verdict.json`: Serialized `Verdict` contract containing evidence metrics and bypass counts.
- `evidence.json`: Full context bundle including suspicion metadata, oracle call stack, and proof reasons.
- **Ledger Event**: Emits `EventType.PACKAGED`.

---

## 3. Module Map and Public Interfaces

### `src/exhibit_a/schemas/`
Defines the authoritative Pydantic data contracts across the system. All models inherit from `StrictModel` (`ConfigDict(extra="forbid")`), ensuring that unexpected fields trigger immediate validation errors.

- **`StrictModel`** (`schemas/base.py`):
  - Base class with `model_config = ConfigDict(extra="forbid")`. Unknown fields are rejected.
- **`RepoProfile`**, **`Baseline`**, **`Dependency`** (`schemas/repo_profile.py`):
  - Represents static and dynamic project traits from the `SCAN` step.
- **`Suspicion`**, **`Location`** (`schemas/suspicion.py`):
  - Represents an adversary's hypothesis. `vuln_class` is aliased to `"class"` in JSON output. Includes helper `to_json() -> str`.
- **`Verdict`**, **`VerdictValue`**, **`Evidence`**, **`Fix`**, **`BypassAttempts`** (`schemas/verdict.py`):
  - Captures the proof outcome. `VerdictValue` is an enum (`PROVEN`, `DISCARDED_UNPROVEN`, `INVALID_TEST`, `FLAKY`, `ENV_FAILURE`).
- **`Event`**, **`EventType`** (`schemas/events.py`):
  - Model for every event recorded in the append-only ledger.

### `src/exhibit_a/ledger/`
The single source of truth for all operational states, metrics, tokens, and audit events.

- **`Ledger`** (`ledger/ledger.py`):
  - `__init__(path: PathLike)`: Initializes ledger handle for the given JSONL file path.
  - `path -> Path`: Property returning the filesystem path.
  - `append(event: Event | dict[str, Any]) -> None`: Validates against `Event` schema, formats as compact JSON, opens file with `os.O_WRONLY | os.O_CREAT | os.O_APPEND`, issues a single atomic `os.write()`, and flushes with `os.fsync()`.
  - `read_all() -> list[Event]`: Returns all events parsed in sequential order. Missing file returns empty list.
  - `replay(run_id: str) -> Iterator[Event]`: Yields events matching a specific `run_id` in chronological order.
  - `totals(run_id: str) -> dict[str, Any]`: Aggregates `tokens_in`, `tokens_out`, `cost_usd`, and a dictionary of verdict counts for a specific run.

### `src/exhibit_a/models/`
Encapsulates all interactions with large language models. Models are treated as untrusted text generators; no provider exposes tools, shell access, or side-effecting channels.

- **`Role`** (`models/base.py`): Enum with members `ADVERSARY`, `TEST_WRITER`, `FIXER`, `DEFENDER`.
- **`Completion`** (`models/base.py`): Frozen dataclass holding raw text, tokens in/out, latency, model identifier, and cost.
- **`RoleResult`** (`models/base.py`): Frozen dataclass holding schema-validated output, usage metrics, and raw text.
- **`Provider`** (`models/base.py`): Protocol defining:
  - `name: str`
  - `pricing: Pricing`
  - `complete(role: Role, prompt: str, schema: dict[str, Any]) -> Completion`
- **`ModelRole`** (`models/base.py`):
  - `__init__(role: Role, provider: Provider, meter: CostMeter | None = None)`
  - `run(prompt: str, schema: dict[str, Any]) -> RoleResult`: Validates budget before execution, invokes provider, charges budget, parses JSON, and validates against the supplied JSON schema using `jsonschema.validate()`. Raises `BudgetExceeded` or `SchemaValidationError`.
- **`Pricing`** and **`CostMeter`** (`models/cost.py`):
  - `Pricing(input_per_mtok: float, output_per_mtok: float)`: Computes cost in USD.
  - `CostMeter(limit_usd: float)`: Thread-safe cumulative cost tracker enforcing a hard stop via `check()` and `charge()`.
- **`ReplayProvider`** (`models/replay.py`):
  - Deterministic provider loading recorded completions keyed by SHA-256 of `(role, prompt, schema)`. Can record live responses on cache miss if configured with a fallback recorder.
- **`OpenAICompatibleProvider`** (`models/openai_compat.py`):
  - HTTP provider targeting OpenAI-compatible inference endpoints (e.g. Meta Model API, Baseten, Modal). Sends schema both via `response_format` and in system instructions.
- **`OllamaProvider`** (`models/ollama.py`):
  - Local HTTP provider restricted strictly to localhost for debugging and pipeline testing.

### `src/exhibit_a/sandbox/`
Executes untrusted exploit and regression code in an isolated container.

- **`run(clone_path: str, test_path: str, timeout: float) -> dict[str, Any]`** (`sandbox/runner.py`):
  - Copies `clone_path` into an isolated temporary workspace directory.
  - Spins up a builder container to cache pytest dependencies.
  - Commits an ephemeral isolated container image.
  - Executes pytest under strict constraints:
    - User mapping: `--user <uid>:<gid>` (unprivileged).
    - Capabilities: `--cap-drop ALL`, `--security-opt no-new-privileges`.
    - Networking: `--network none`.
    - Filesystem: `--read-only`, with isolated memory-backed `--tmpfs /tmp:rw,size=64m,mode=1777`.
    - Resource controls: `--pids-limit 64`, `--memory 512m` with `--memory-swap 512m` (no swap), `--cpus 0.5`.
  - Cleans up containers and temporary image tags upon completion.
  - Returns dict with keys: `outcome` (`"passed"`, `"failed"`, `"timeout"`, or `"env_failure"`), `exit_code`, `stdout`, `stderr`, `oracle_events`.

### `src/exhibit_a/oracle/`
Judges whether an exploit test failure corresponds to a legitimate vulnerability through execution side-effects and call-stack provenance.

- **`run_oracle(app_root: Path, test_path: Path, entry_points: Collection[str], *, timeout: float = 60.0) -> Judgement`** (`oracle/oracle.py`):
  - Sets up isolated directories with public files and a secret canary file (`outside/canary.txt`) containing a unique random token.
  - Configures environment variables: `EXHIBIT_A_ALLOWED_DIR`, `EXHIBIT_A_CANARY`, `EXHIBIT_A_CANARY_TOKEN`, `EXHIBIT_A_EVENTS`.
  - Executes pytest loading `exhibit_a.oracle.plugin` via scrubbed child process.
  - Collects audit events and evaluates both observed effect and provenance.
- **`Judgement`**, **`OracleEvent`**, **`Frame`** (`oracle/oracle.py`):
  - Datamodels representing the oracle's verdict, recorded canary access events, and reversed call stacks from caller to sink.
- **`plugin.py`** (`oracle/plugin.py`):
  - Pytest plugin installing Python audit hook `sys.addaudithook()`.
  - Intercepts file `open` operations matching the canary path and records stack frames up to 200 callers deep into a JSONL events file.
- **Provenance Rules**:
  - `_provenance_problem()` checks that the canary was opened by application code under `app_root` (not test code directly).
  - Outermost application frame must match a declared entry point in `entry_points`.
  - Test code must appear higher on the stack calling the entry point.

### `src/exhibit_a/loop/`
Coordinates the state machine and data flow across roles, ledger, runner, and oracle.

- **`VerificationLoop`** (`loop/pipeline.py`):
  - `__init__(clone_path, out_dir, ledger, roles, baseline_test, *, runs=3, timeout=60.0, run_id=None, baseline_runner=_default_baseline, judge=run_oracle)`
  - `run(source_file: str) -> LoopResult`: Executes the full loop across the specified source file.
- **`Roles`** (`loop/pipeline.py`): Container dataclass holding `adversary`, `test_writer`, `fixer`, and `defender` `ModelRole` instances.
- **`LoopResult`**, **`SuspicionResult`** (`loop/pipeline.py`):
  - Tracks overall run status, baseline status, individual suspicion verdicts, and packaged artifact directories.
- **`classify(judgement: Judgement) -> VerdictValue`** (`loop/pipeline.py`):
  - Maps oracle results to verdict classifications.
- **`prompts.py`** (`loop/prompts.py`):
  - Prompt builders: `adversary_prompt`, `writer_prompt`, `fixer_prompt`, `defender_prompt`.
  - JSON schemas: `SUSPICIONS_SCHEMA`, `EXPLOIT_SCHEMA`, `FIX_SCHEMA`, `VARIANTS_SCHEMA`.

### `src/exhibit_a/live/`
Provides a live view and replay server streaming events from the append-only ledger via Server-Sent Events (SSE).

- **`create_server(ledger_path: str | Path, web_dir: str | Path, host: str = "127.0.0.1", port: int = 0) -> LiveServer`** (`live/server.py`):
  - Creates the threaded HTTP server binding JSON endpoints and SSE stream.
- **`build_summary(events: Sequence[Event]) -> dict[str, Any]`** (`live/summary.py`):
  - Projects ledger events into the UI view-model: PR diff, suspect lines, timeline items, sandbox output, red-to-green state, regression wall, and dropped count.
- **`Replayer`**, **`format_sse`**, **`format_done`** (`live/replay.py`):
  - SSE serialization and paced event replay with configurable speed multipliers.

### `src/exhibit_a/cli.py`
The headless command-line interface entry point (`python -m exhibit_a.cli`).

- Subcommands:
  - `scan`: Evaluates a repository and prints a `RepoProfile` contract.
  - `run`: Executes the verification loop. Supports `--case <path>` for replaying benchmark test cases.
  - `ledger <run_id> --ledger <path>`: Aggregates and prints token usage, costs, and verdict totals.

---

## 4. The JSON Contracts

All Exhibit A data contracts are strictly defined and validated.

### 1. `repo_profile.json` (`RepoProfile`)

Created during the `SCAN` phase to summarize repository metadata, dependencies, and baseline test metrics.

```json
{
  "commit": "24c1fac62a80bb153c6548145334fc643991e35a",
  "language": "python",
  "interpreter": "3.11",
  "dependency_manager": "pip",
  "install_cmd": "pip install -e .",
  "test_cmd": "pytest",
  "framework": "pytest",
  "dependencies": [
    {
      "name": "starlette",
      "version": "0.26.1"
    },
    {
      "name": "anyio",
      "version": "3.7.1"
    }
  ],
  "baseline": {
    "passed": 42,
    "failed": 0,
    "seconds": 1.25
  }
}
```

#### Fields:
- `commit` (`str`): Target repository commit hash.
- `language` (`str`): Detected programming language (e.g. `"python"`).
- `interpreter` (`str`): Interpreter version (e.g. `"3.11"`).
- `dependency_manager` (`str`): Tool managing packages (e.g. `"pip"`, `"poetry"`).
- `install_cmd` (`str`): Command to install dependencies.
- `test_cmd` (`str`): Command to run the test suite.
- `framework` (`str`): Testing framework name (e.g. `"pytest"`).
- `dependencies` (`list[Dependency]`): List of objects containing `name` and `version`.
- `baseline` (`Baseline`): Contains `passed` (int $\ge 0$), `failed` (int $\ge 0$), and `seconds` (float $\ge 0$).

---

### 2. `suspicion.json` (`Suspicion`)

Created by the Adversary role during the `SUSPECT` phase to formulate a vulnerability hypothesis.

```json
{
  "id": "starlette-staticfiles-prefix",
  "class": "path_traversal",
  "location": {
    "file": "starlette/staticfiles.py",
    "line": 48
  },
  "entry_point": "StaticFiles.__call__",
  "hypothesis": "lookup_path uses os.path.commonprefix, which checks character prefixes instead of path components, allowing access to outside files when directory names share a common prefix.",
  "source": "adversary"
}
```

#### Fields:
- `id` (`str`): Unique identifier for this suspicion.
- `class` (`str`): The vulnerability category (aliased from `vuln_class` in Python code).
- `location` (`Location`): Code coordinates with `file` (`str`) and `line` (`int` $\ge 0$).
- `entry_point` (`str`): Public application function or method through which requests enter.
- `hypothesis` (`str`): Detailed technical explanation of the flaw and exploit strategy.
- `source` (`str`): Origin of suspicion (e.g. `"adversary"`, `"diff_analysis"`).

---

### 3. `verdict.json` (`Verdict`)

Emitted after `RUN` and `VERIFY` phases to document the final verification status and evidence.

```json
{
  "suspicion_id": "starlette-staticfiles-prefix",
  "verdict": "proven",
  "evidence": {
    "test_path": "runs/first-cve/packages/starlette-staticfiles-prefix/test_exploit.py",
    "fails_on": "vulnerable",
    "passes_on": "fixed",
    "runs": 3,
    "oracle": {
      "reason": "canary read by application code reached through an entry point; test failed",
      "events": [
        {
          "type": "canary_read",
          "path": "/private/tmp/work/outside/canary.txt",
          "mode": "r",
          "stack": [
            {
              "file": "/app/test_exploit.py",
              "function": "test_exploit_prefix",
              "qualname": "test_exploit_prefix"
            },
            {
              "file": "/app/starlette/staticfiles.py",
              "function": "__call__",
              "qualname": "StaticFiles.__call__"
            },
            {
              "file": "/app/starlette/staticfiles.py",
              "function": "lookup_path",
              "qualname": "StaticFiles.lookup_path"
            }
          ]
        }
      ]
    },
    "provenance": {
      "ok": true,
      "entry_point": "StaticFiles.__call__"
    }
  },
  "fix": {
    "patch_path": "runs/first-cve/packages/starlette-staticfiles-prefix/fix.patch"
  },
  "bypass_attempts": {
    "tried": 2,
    "succeeded": 0
  }
}
```

#### Fields:
- `suspicion_id` (`str`): ID linking to the original `Suspicion`.
- `verdict` (`VerdictValue`): Enum value (`"proven"`, `"discarded_unproven"`, `"invalid_test"`, `"flaky"`, `"env_failure"`).
- `evidence` (`Evidence | None`): Populated for proven findings.
  - `test_path` (`str`): Path to reproduction test file.
  - `fails_on` (`str`): Branch/tree state where test failed (e.g. `"vulnerable"`).
  - `passes_on` (`str`): Branch/tree state where test passed (e.g. `"fixed"`).
  - `runs` (`int` $\ge 1$): Number of repeated evaluation iterations.
  - `oracle` (`dict[str, Any]`): Oracle telemetry, reason, and event records.
  - `provenance` (`dict[str, Any]`): Proof confirming call stack routed through declared entry point.
- `fix` (`Fix | None`): Contains `patch_path` (`str`) pointing to `fix.patch`.
- `bypass_attempts` (`BypassAttempts | None`): Contains `tried` (`int` $\ge 0$) and `succeeded` (`int` $\ge 0$).

---

### 4. `event.json` (`Event`)

A single JSON line in the append-only ledger (`ledger.jsonl`).

```json
{
  "ts": "2026-10-27T22:30:00.123456+00:00",
  "run_id": "starlette-cve-2023-29159",
  "type": "verdict",
  "role": "",
  "model": "",
  "tokens_in": 0,
  "tokens_out": 0,
  "cost_usd": 0.0,
  "latency_ms": 0,
  "payload": {
    "suspicion_id": "starlette-staticfiles-prefix",
    "verdict": "proven",
    "reason": "canary read by application code reached through an entry point; test failed"
  }
}
```

#### Fields:
- `ts` (`str`): ISO-8601 UTC timestamp.
- `run_id` (`str`): Unique identifier for the overall pipeline execution run.
- `type` (`EventType`): Event type enum (`pr_opened`, `scan_done`, `baseline_done`, `suspicion_raised`, `exploit_written`, `run_started`, `oracle_event`, `verdict`, `fix_proposed`, `bypass_attempt`, `bypass_result`, `packaged`).
- `role` (`str`): Model role responsible if triggered by a model call (e.g. `"adversary"`), else empty.
- `model` (`str`): Model name/identifier used for the call.
- `tokens_in` (`int` $\ge 0$): Prompt token count.
- `tokens_out` (`int` $\ge 0$): Completion token count.
- `cost_usd` (`float` $\ge 0.0$): Calculated financial cost of this step.
- `latency_ms` (`int` $\ge 0$): Model call or operation wall-clock latency in milliseconds.
- `payload` (`dict[str, Any]`): Type-specific event details.

---

## 5. System Boundaries: Orchestrator, Sandbox, Oracle, and Models

The security and integrity of Exhibit A rest on clean, uncrossable boundaries between the orchestrator, model providers, execution sandboxes, and verification oracles.

```
+-----------------------------------------------------------------------------------------+
| HOST ORCHESTRATOR BOUNDARY                                                              |
| - Controls lifecycle (VerificationLoop)                                                 |
| - Reads PR diffs & source files                                                         |
| - Manages CostMeter & enforces token budgets                                            |
| - Writes to append-only Event Ledger (fsync)                                            |
| - Serves SSE Live View stream                                                           |
+-----------------------------------------------------------------------------------------+
       |                                       |                                    |
       | Schema-validated JSON only            | Ephemeral container volume         | Scrubbed env
       v                                       v                                    v
+-----------------------+   +---------------------------------------+   +-----------------+
| UNTRUSTED MODEL       |   | HARDENED DOCKER SANDBOX               |   | ORACLE BOUNDARY |
| BOUNDARY              |   | - Linux namespaces & cgroups          |   |                 |
| - Text in, JSON out   |   | - --cap-drop ALL                      |   | - Plants canary |
| - Strict JSONSchema   |   | - --security-opt no-new-privileges    |   | - Audit hook:   |
|   validation          |   | - --network none (no egress/ingress)  |   |   sys.addaudit- |
| - No side effects     |   | - --read-only root + 64MB /tmp tmpfs  |   |   hook("open")  |
| - No tool calls       |   | - --user uid:gid (non-root)           |   | - Call-stack    |
| - Never mounts host   |   | - 512MB RAM, 0.5 CPU, 64 PIDs limit   |   |   provenance    |
| - Cannot touch disk   |   | - Never mounts Docker socket          |   |   inspection    |
+-----------------------+   +---------------------------------------+   +-----------------+
```

### Boundary 1: The Model / Orchestrator Boundary
- **Untrusted Output**: Model responses are treated as untrusted text. They are never evaluated as code on the host machine.
- **Strict Schema Enforcement**: Outputs must parse into valid JSON matching explicit schemas (`SUSPICIONS_SCHEMA`, `EXPLOIT_SCHEMA`, `FIX_SCHEMA`, `VARIANTS_SCHEMA`). Any extra fields or syntax anomalies fail schema validation immediately.
- **No Side-Effecting Tools**: Unlike autonomous agent harnesses, models in Exhibit A receive zero tool definitions, zero file-system functions, and zero network primitives. They act solely as pure functions from text prompt to structured JSON.
- **Budget Metering**: The orchestrator wraps model calls with a thread-safe `CostMeter`. If cumulative cost exceeds `limit_usd`, further calls are barred before hitting the provider.

### Boundary 2: The Sandbox Execution Boundary
- **Isolated and Resource-Limited**: Untrusted exploit tests run exclusively within ephemeral Docker containers. The product specification strictly avoids claims of "100% safe", designating the environment as "isolated and resource-limited".
- **Network Isolation**: Containers run with `--network none`. No data can be exfiltrated, and exploit tests cannot reach remote hosts.
- **Dropped Privileges**: Containers run with `--cap-drop ALL`, `--security-opt no-new-privileges`, and under the host user's non-root UID/GID (`--user uid:gid`).
- **Filesystem Lockdown**: Root filesystem is mounted read-only (`--read-only`), with a strictly limited tmpfs mounted at `/tmp` (`size=64m,mode=1777`).
- **Host Separation**: Neither the Docker daemon socket (`/var/run/docker.sock`) nor host directories (other than a temporary isolated copy of the repository clone) are ever mounted into the container.
- **Resource Constraints**: Strict cgroup boundaries prevent denial of service (`--memory 512m`, `--memory-swap 512m`, `--cpus 0.5`, `--pids-limit 64`).

### Boundary 3: The Oracle / Runner Boundary
- **Separation of Concerns**: The sandbox determines *how* to run code safely without compromising the host. The oracle determines *what the execution meant*.
- **Canary Defense**: The oracle places unique canary files (`outside/canary.txt`) outside the application's permitted working directory with randomly generated tokens.
- **Audit Interception**: Using Python's `sys.addaudithook()`, the oracle tracks low-level `open` syscall events during test execution.
- **Call-Stack Provenance Analysis**: An exploit does not qualify simply because an exception was thrown or a file was touched. The oracle traverses the stack frames:
  1. The canary read must originate from application code under `app_root`.
  2. The outermost application caller must match a declared entry point.
  3. The exploit test must be higher on the stack invoking that entry point.
  4. If the test reads the canary directly, or invokes private sinks without routing through the entry point, the test is rejected as `invalid_test`.

### Boundary 4: Current Implementation State vs. Roadmap
- **Present State**: In the current codebase, `VerificationLoop` can invoke the Docker sandbox runner (`exhibit_a.sandbox.runner`) or host child processes (`_local_baseline` in `cli.py` and `run_oracle` in `exhibit_a.oracle.oracle`). As noted in `AGENTS.md` and `docs/design/first-cve.md`, the oracle and the Starlette benchmark baseline currently execute in scrubbed host child processes while containerization tasks (T026/T027) are in flight.
- **Target State**: Both baseline testing and oracle-observed exploit execution will run unified inside the hardened Docker container image with pre-baked language and dependency environments.

---

## 6. Verification Artifacts and Packages

When a vulnerability is verified, the orchestrator produces a standalone evidence bundle in `packages/<slug(suspicion_id)>/`:

```
packages/starlette-staticfiles-prefix/
|-- test_exploit.py      # Reproducing exploit pytest test
|-- fix.patch            # Unified git diff remediating the vulnerability
|-- verdict.json         # Serialized Verdict contract with evidence and bypass metrics
`-- evidence.json        # Detailed telemetry, reason, and oracle call-stack trace
```

This packaged bundle represents the complete, self-contained proof of the vulnerability: human reviewers receive the reproduction test, the verified fix, and the unforgeable execution evidence without manual triage overhead.
