# Sandbox — isolation, images, and requirements

This document explains the sandbox guarantees, the image/requirements mechanism, the macOS Colima note, and the honest wording to use when describing the runtime.

Summary
- The sandbox is an ephemeral container runner intended to execute untrusted exploit tests in an _isolated and resource-limited_ environment. It is not, and must never be described as, "100% safe".

Isolation flags and what they guarantee
- `--read-only` (container root filesystem): prevents persistent writes to image layers; only tmpfs and explicitly mounted volumes are writable.
- `--tmpfs /tmp:rw,size=64m,mode=1777`: gives a small writable temporary filesystem, limiting data an exploit can persist in-memory/disk.
- `--network none`: no network access from the test runtime; prevents remote exfiltration and external callbacks during the run.
- `--cap-drop ALL` and `--security-opt no-new-privileges`: removes Linux capabilities and blocks privilege escalation inside the container.
- `--user uid:gid` (map to invoking user): avoids running as root inside the container, reducing attack surface and accidental host-level file access.
- `--pids-limit`, `--memory`, `--cpus`: caps processes, RAM and CPU usage to bound resource consumption and reduce DoS risk.
- Not mounting the Docker socket or host systems: the runner never mounts `/var/run/docker.sock` or arbitrary host directories; only a temporary copy of the repository is mounted into the container.
- Committed run image with `--network none`: builder phase (with network) is separate from run phase; the runtime image is committed after installing required tooling so the actual test run can be executed offline.

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
- `/tmp/exhibit_a_oracle/outside/canary` is a host file bind-mounted read-only with mode 0555. It has to be a bind mount: a Docker `--tmpfs` is `noexec`, and a test cannot write its own executables into `/tmp` or the scratch tmpfs either.
- `/tmp/exhibit_a_oracle/outside/` is a writable bind mount of a temporary host directory, so the canary can create its marker, `canary_ran`, there. The directory is gone after the run. Unlike the write effect's tmpfs it is not size-capped, like the writable `/workspace` copy.
- The host reads the marker itself after the container exits: no symlinks, a regular file with a single link, at most 1 MiB, each line exactly the run's token. Nothing the container says about it is trusted, and a run that was never checked is not a proof.
- What it cannot see: a process started by a C extension without an audit event, a shell that never execs the canary (`echo <token> > marker` is real command execution but not this effect), and a command that computes the canary's name. A green result still means "nothing could be proven".

Wording and guidance
- Always say "isolated and resource-limited" when summarizing the sandbox guarantees.
- Never say "100% safe" or imply the sandbox is impenetrable.

References
- Implementation: `src/exhibit_a/sandbox/runner.py` and `src/exhibit_a/sandbox/image.py`.

