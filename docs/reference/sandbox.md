# Sandbox — isolation, images, and requirements

This document explains the sandbox guarantees, the image/requirements mechanism, the macOS Colima note, and the honest wording to use when describing the runtime.

Summary
- The sandbox is an ephemeral container runner intended to execute untrusted exploit tests in an _isolated and resource-limited_ environment. It is not, and must never be described as, "100% safe".

Isolation flags and what they guarantee
- `--read-only` (container root filesystem): prevents persistent writes to image layers; only tmpfs and explicitly mounted volumes are writable.
- `--tmpfs /tmp:rw,size=64m,mode=1777`: gives a small writable temporary filesystem, limiting data an exploit can persist in-memory/disk.
- `--network none`: no network access from the test runtime; prevents remote exfiltration and external callbacks during the run.
- `--cap-drop ALL` and `--security-opt no-new-privileges`: removes Linux capabilities and blocks privilege escalation inside the container.
- `--security-opt seccomp=<src/exhibit_a/sandbox/seccomp.json>`: applies a restrictive allowlist seccomp profile (`defaultAction: SCMP_ACT_ERRNO`) by default on every sandbox container (including the SQL seed container). Only syscalls required by the Python test runner are permitted; privilege-changing, mount, namespace, tracing, kernel-module, eBPF, `io_uring`, keyring, and file-handle syscalls (`ptrace`, `unshare`, `setns`, `mount`, `umount2`, `pivot_root`, `chroot`, `setuid`, `setgid`, `setgroups`, `capset`, `chown`, `bpf`, `perf_event_open`, `io_uring_setup`, `userfaultfd`, `keyctl`, `init_module`, `finit_module`, `kexec_load`, `open_by_handle_at`, etc.) fail with `EPERM`.
- `--user uid:gid` (non-root user): maps to the invoking non-root user (or falls back to `65534:65534` if the host orchestrator runs as UID 0), never running as root inside the container.
- `--pids-limit 64`, `--memory 512m`, `--memory-swap 512m`, `--cpus 0.5`: caps processes, RAM (with swap disabled so swap cannot extend the memory limit), and CPU usage to bound resource consumption and reduce DoS risk.
- Optional runtime (`EXHIBIT_A_DOCKER_RUNTIME=runsc`): when `EXHIBIT_A_DOCKER_RUNTIME` is set (for example `runsc` for gVisor), the runner verifies that the runtime is registered in Docker and passes `--runtime <name>`. If the requested runtime is not installed or invalid, the run fails closed with `outcome="env_failure"` and a clear message, and never silently falls back to the default runtime.
- Audited mounts only (`DECLARED_MOUNTS` and `_verify_declared_mounts`): the runner never mounts `/var/run/docker.sock` or arbitrary host directories; every bind mount source must reside inside the per-run temporary directory (`~/.cache/exhibit-a/sandbox/exhibit_a_sandbox_<id>/`), and any undeclared mount flag fails closed before `docker run`.
- Committed run image with `--network none`: builder phase (with network) is separate from run phase; the runtime image is committed after installing required tooling so the actual test run can be executed offline.

Audited container mounts (`DECLARED_MOUNTS`)

Every container mount is audited before execution. No host directory outside the per-run temporary directory is ever mounted:

| Container target | Kind | Mode | Scope | Source |
|---|---|---|---|---|
| `/workspace` | bind | `rw` | all test runs | `<tmpdir>/workspace` (staged copy of `clone_path`) |
| `/tmp` | tmpfs | `rw,size=64m,mode=1777` | all runs | in-memory tmpfs (64 MiB cap) |
| `/opt/exhibit_a_plugin/exhibit_a_oracle_plugin.py` | bind | `ro` | oracle active | `<tmpdir>/exhibit_a_oracle_plugin.py` (per-run copy of `plugin.py`) |
| `/oracle/events.jsonl` | bind | `rw` | oracle active | `<tmpdir>/events.jsonl` (HMAC-signed event sink) |
| `/oracle/canary` (or `/tmp/<work>/<dir>/<file>`) | bind | `ro` | `canary_read`, `canary_exec` | `<tmpdir>/canary` (per-run copy of `canary_path`) |
| `/tmp/<work>` | tmpfs | `rw,size=16m,mode=1777` | custom `canary_mount` | in-memory tmpfs (16 MiB cap) |
| `/tmp/<work>/<dir>` | bind | `rw` | `canary_exec` | `<tmpdir>/outside` (per-run directory for `canary_ran` marker) |
| `/oracle/outside.json` | bind | `rw` | `canary_write` | `<tmpdir>/outside.json` (post-run tmpfs listing) |
| `/workspace/<sql_db>` | bind | `ro` | `canary_sql` | `<tmpdir>/seed/seeded.db` (seeded SQLite database copy) |
| `/workspace/<access_db>` | bind | `ro` | `canary_access` | `<tmpdir>/seed/seeded.json` (seeded access-store copy) |
| `/seed/original.db` | bind | `ro` | `canary_sql` / `canary_access` seed container | `<tmpdir>/workspace/<sql_db or access_db>` (staged application store) |
| `/seed/out` | bind | `rw` | `canary_sql` / `canary_access` seed container | `<tmpdir>/seed` (per-run seed output directory) |

Self-check (`exhibit-a doctor`)
- `exhibit-a doctor` (and `exhibit-a doctor --json`, implemented in `src/exhibit_a/cli/ext/doctor.py`) starts an ephemeral probe container with the sandbox's isolation flags and inspects the effective isolation from inside the container:
  - **runtime**: effective and configured runtime (`EXHIBIT_A_DOCKER_RUNTIME` or default `runc`) and available runtimes from `docker info`.
  - **network**: only `lo` present in `/proc/net/dev` and external connections blocked.
  - **capabilities**: `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb` all `0000000000000000` and `NoNewPrivs=1` in `/proc/self/status`.
  - **seccomp**: `Seccomp=2` (`SECCOMP_MODE_FILTER`), `defaultAction=SCMP_ACT_ERRNO`, live syscall probes (`ptrace`, `unshare`, `mount`, `chroot`, `setuid`, `chown`) returning `EPERM`, plus the full allowed syscall list from `src/exhibit_a/sandbox/seccomp.json`.
  - **user**: non-root `uid`, `euid`, `gid`, `egid` (`> 0`).
  - **filesystem**: read-only rootfs, writable `/tmp` tmpfs, no `/var/run/docker.sock`.
  - **limits**: cgroup memory (`536870912` bytes / `512m`), swap (`0`), PIDs (`64`), and CPU (`50000 100000` / `0.5` CPUs).
- If any check is weaker than documented, `exhibit-a doctor` prints `FAIL` for that check and exits non-zero (`1`).

What these flags do not guarantee
- The sandbox shares the host kernel. Kernel-level vulnerabilities, misconfigured container runtimes, or host-level bugs can still be exploited. For this reason we use the honest phrasing "isolated and resource-limited" rather than "100% safe".
- Some container runtimes or privileged host configurations may weaken the above guarantees; keep the host and container engine up to date and follow best practices.

Image / requirements mechanism
- Base image is pinned (project code pins `BASE_IMAGE`) so builds are reproducible.
- `image_tag(requirements)` deterministically derives an image tag from the pinned base plus normalized requirements (hash of the normalized pip requirements). This allows reuse of identical images and avoids rebuilding the same environment repeatedly.
- Build step:
  - Runs in a short-lived builder container with network access to install pip packages (this step requires network).
  - The builder is committed into a new image tag containing the installed requirements.
- Run step:
  - Executes the committed image with `--network none` and the isolation flags above.
  - The runner copies the repository into a temporary workspace directory (under the user's home cache) and mounts that copy read-only (except the workspace mount).
  - The run image therefore contains only what the builder installed; no build context files are sent during build (the implementation sends a Dockerfile on stdin), and no host files other than the workspace copy are exposed.

Colima on macOS
- On macOS we require a Docker-compatible runtime that reliably bind-mounts host paths under the user's home. Colima is the recommended runtime for macOS in development and CI for this project because it shares `$HOME` with the host in a predictable way; the runner creates temporary workspaces under `$HOME` (e.g. `~/.cache/exhibit-a/sandbox`) so mounts succeed under Colima.
- Docker Desktop may work, but users must ensure the container engine is configured to allow the temporary workspace bind-mounts; if bind-mounts fail tests will report `env_failure`.
- In short: Docker (Linux) or Colima (macOS) must be running for sandbox tests.

Operational notes and limitations
- The builder step requires network (pip). The committed run image is executed with no network.
- The runner uses a pinned `PYTEST_VERSION` and pins the base image for reproducibility.
- Tests rely on the oracle for intended-effect observation and provenance — the sandbox provides execution isolation but the oracle determines whether a failure is proof for the right reason.
- Always treat model outputs and PR diffs as untrusted input; validation and provenance checks are mandatory.
- If `docker info` fails or the container runtime is not available, sandbox tests must stop and report `env_failure` rather than attempting to skip or ignore sandbox tests.

The `canary_exec` effect
- `SandboxRunner.run_exploit(..., effect="canary_exec")` proves command execution: the application, reached through an entry point, starts a process that runs an executable outside the allowed directory. Proof rules: `docs/oracle/oracle-provenance.md`, section 3.9.
- The container keeps every flag above (`--read-only`, `--network none`, `--cap-drop ALL`, `no-new-privileges`, memory and pids limits, its unprivileged user).
- `/tmp/exhibit_a_oracle/outside/canary` is a host file bind-mounted read-only with mode 0555. It has to be a bind mount: a Docker `--tmpfs` is `noexec`, so a test cannot run its own executables from `/tmp` or the scratch tmpfs either. It can from `outside/` and `/workspace`, which are bind mounts; that is why the plugin also watches `PATH`-like variables, `os.chdir` and links to the canary.
- `/tmp/exhibit_a_oracle/outside/` is a writable bind mount of a temporary host directory, so the canary can create its marker, `canary_ran`, there. The directory is gone after the run. Unlike the write effect's tmpfs it is not size-capped, like the writable `/workspace` copy.
- The host reads the marker itself after the container exits: no symlinks, a regular file with a single link, at most 1 MiB, each line exactly the run's token. Nothing the container says about it is trusted, and a run that was never checked is not a proof.
- What it cannot see: a process started by a C extension without an audit event, a shell that never execs the canary (`echo <token> > marker` is real command execution but not this effect), and a command that computes the canary's name. A green result still means "nothing could be proven".

The `canary_sql` effect
- `SandboxRunner(sql_db="<path in the clone>").run_exploit(..., effect="canary_sql")` proves SQL injection: the application, reached through an entry point, reads a canary row from a table it never queries. Proof rules: `docs/oracle/oracle-provenance.md`, section 3.10. `sql_db` comes from `case.json` `run.sql_db`; without it, or if the file is missing, a link or not a regular file, the run fails closed before any container starts.
- Seeding happens in a short-lived init container with the same flags as the test container (`--network none`, `--cap-drop ALL`, `no-new-privileges`, memory, pids and time limits). It mounts the original database read-only and writes a seeded copy (the canary table with the run's token) to a temporary host directory; the original is never modified.
- The test container mounts that copy read-only over `/workspace/<sql_db>`, nested inside the writable `/workspace` copy, and keeps every flag above. The test gets the token, not the database path.
- What it cannot see: a driver other than `sqlite3`, and an app that needs to write to its own database during the run (the seeded copy is read-only). A green result still means "nothing could be proven".

The `canary_redirect` effect
- `SandboxRunner(redirect_meta=...).run_exploit(..., effect="canary_redirect")` proves open redirect: the application, reached through an entry point, answers with a redirect to a per-run canary host. Proof rules: `docs/oracle/oracle-provenance.md`, section 3.13. No canary file is mounted and nothing is ever fetched from the canary host; the test learns only the canary URL and the plugin's `redirect_probe` fixture calls the entry point and signs the observed response.
- A green result still means "nothing could be proven".

The `canary_access` effect
- `SandboxRunner(access_db="<path in the clone>", access={"attacker": ..., "victim": ..., "resource": ...}).run_exploit(..., effect="canary_access")` proves broken access control: the application, reached through an entry point as the attacker, returns a victim-owned resource. Proof rules: `docs/oracle/oracle-provenance.md`, section 3.14. Both come from `case.json` `run.access_db` / `run.access`; without them, or if the file is missing, a link or not a regular file, the run fails closed before any container starts.
- Seeding happens in a short-lived init container with the same flags as the test container. It mounts the original JSON store read-only and writes a seeded copy (the victim-owned resource with the run's token) to a temporary host directory; the original is never modified. The victim credential travels as a seed argument only, never in the test's environment.
- The test container mounts that copy read-only over `/workspace/<access_db>`, nested inside the writable `/workspace` copy, and keeps every flag above. The test gets the attacker credential and the resource id, not the store path and never the victim credential.
- What it cannot see: an app whose authentication is anything but a credential-plus-resource call, and an app that needs to write to its own store during the run (the seeded copy is read-only). A green result still means "nothing could be proven".

Wording and guidance
- Always say "isolated and resource-limited" when summarizing the sandbox guarantees.
- Never say "100% safe" or imply the sandbox is impenetrable.

References
- Implementation: `src/exhibit_a/sandbox/runner.py` and `src/exhibit_a/sandbox/image.py`.

