"""Tests for sandbox hardening (T098):
- Optional runtime (EXHIBIT_A_DOCKER_RUNTIME=runsc adds --runtime runsc; fails closed with env_failure if missing).
- Restrictive seccomp profile (src/exhibit_a/sandbox/seccomp.json) applied by default.
- Non-root UID, read-only rootfs, explicit small tmpfs, audited declared mounts only.
- Self-check CLI `exhibit-a doctor` probing effective isolation and exiting non-zero if weaker.
- Docker-marked escape-attempt tests (network, write outside tmpfs, privilege escalation, fork bomb,
  memory bomb, reading host paths): each fails and the run stays isolated.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import textwrap
import types
import uuid
from pathlib import Path

import pytest

from exhibit_a.cli import main as cli_main
from exhibit_a.cli.ext.doctor import evaluate_isolation, load_seccomp_profile
from exhibit_a.sandbox import DECLARED_MOUNTS, RUNTIME_ENV, SECCOMP_PROFILE, probe_isolation, run
from exhibit_a.sandbox import runner as runner_mod


def _make_repo(tmp_path: Path, test_code: str, name: str = "repo") -> Path:
    repo = tmp_path / name
    tests_dir = repo / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (repo / "app.py").write_text("def ok():\n    return True\n", encoding="utf-8")
    (tests_dir / "test_escape.py").write_text(textwrap.dedent(test_code), encoding="utf-8")
    return repo


# --- 1. Optional runtime (EXHIBIT_A_DOCKER_RUNTIME) -------------------------------------------


def test_runtime_env_adds_runtime_flag_when_installed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(cmd, 0, b'{"runc": {}, "runsc": {}}', b"")
        return subprocess.CompletedProcess(cmd, 0, b"1 passed\n", b"")

    fake_subproc = types.SimpleNamespace(
        run=fake_run,
        PIPE=subprocess.PIPE,
        DEVNULL=subprocess.DEVNULL,
        TimeoutExpired=subprocess.TimeoutExpired,
        SubprocessError=subprocess.SubprocessError,
    )
    monkeypatch.setattr(runner_mod, "subprocess", fake_subproc)
    monkeypatch.setattr(runner_mod, "_check_docker_available", lambda: True)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(RUNTIME_ENV, "runsc")

    repo = _make_repo(tmp_path, "def test_ok():\n    assert True\n")
    res = run(str(repo), "tests/test_escape.py", timeout=30, image="fake:tag")
    assert res["outcome"] == "passed", res
    docker_runs = [c for c in calls if c[:2] == ["docker", "run"]]
    assert len(docker_runs) == 1
    cmd = docker_runs[0]
    idx = cmd.index("--runtime")
    assert cmd[idx + 1] == "runsc"


def test_missing_runtime_fails_closed_never_falls_back(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(cmd, 0, b'{"io.containerd.runc.v2": {}, "runc": {}}', b"")
        raise AssertionError("docker run must not be called when requested runtime is missing")

    fake_subproc = types.SimpleNamespace(
        run=fake_run,
        PIPE=subprocess.PIPE,
        DEVNULL=subprocess.DEVNULL,
        TimeoutExpired=subprocess.TimeoutExpired,
        SubprocessError=subprocess.SubprocessError,
    )
    monkeypatch.setattr(runner_mod, "subprocess", fake_subproc)
    monkeypatch.setattr(runner_mod, "_check_docker_available", lambda: True)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(RUNTIME_ENV, "runsc")

    repo = _make_repo(tmp_path, "def test_ok():\n    assert True\n")
    res = run(str(repo), "tests/test_escape.py", timeout=30, image="fake:tag")
    assert res["outcome"] == "env_failure"
    assert "runsc" in res["stderr"]
    assert "not installed" in res["stderr"]
    assert not any(c[:2] == ["docker", "run"] for c in calls)


@pytest.mark.parametrize("bad_rt", ["--privileged", "runsc;evil", "../runsc", "runsc arg"])
def test_invalid_runtime_name_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad_rt: str
) -> None:
    monkeypatch.setattr(runner_mod, "_check_docker_available", lambda: True)
    monkeypatch.setenv(RUNTIME_ENV, bad_rt)
    repo = _make_repo(tmp_path, "def test_ok():\n    assert True\n")
    res = run(str(repo), "tests/test_escape.py", timeout=30, image="fake:tag")
    assert res["outcome"] == "env_failure"
    assert RUNTIME_ENV in res["stderr"]


@pytest.mark.docker
def test_uninstalled_runtime_fails_closed_against_real_docker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(RUNTIME_ENV, "runsc_not_installed_probe")
    repo = _make_repo(tmp_path, "def test_ok():\n    assert True\n")
    res = run(str(repo), "tests/test_escape.py", timeout=30)
    assert res["outcome"] == "env_failure"
    assert "runsc_not_installed_probe" in res["stderr"]
    assert "not installed" in res["stderr"]


@pytest.mark.docker
def test_installed_runc_runtime_succeeds_in_real_docker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(RUNTIME_ENV, "runc")
    repo = _make_repo(tmp_path, "def test_ok():\n    assert True\n")
    res = run(str(repo), "tests/test_escape.py", timeout=60)
    assert res["outcome"] == "passed", res


# --- 2. Seccomp profile -----------------------------------------------------------------------


def test_seccomp_profile_is_restrictive_and_valid_json() -> None:
    assert SECCOMP_PROFILE.is_file()
    profile = load_seccomp_profile(SECCOMP_PROFILE)
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    assert profile.get("defaultErrnoRet") == 1
    arches = {entry["architecture"] for entry in profile.get("archMap", [])}
    assert {"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"} <= arches

    allowed: set[str] = set()
    for rule in profile.get("syscalls", []):
        if rule.get("action") == "SCMP_ACT_ALLOW":
            allowed.update(rule.get("names", []))

    assert {"read", "write", "openat", "execve", "clone", "mmap", "futex", "exit_group"} <= allowed
    forbidden = {
        "ptrace",
        "unshare",
        "setns",
        "mount",
        "umount",
        "umount2",
        "pivot_root",
        "chroot",
        "setuid",
        "setgid",
        "setreuid",
        "setregid",
        "setresuid",
        "setresgid",
        "setfsuid",
        "setfsgid",
        "setgroups",
        "capset",
        "chown",
        "fchown",
        "fchownat",
        "lchown",
        "bpf",
        "perf_event_open",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "userfaultfd",
        "keyctl",
        "add_key",
        "request_key",
        "init_module",
        "finit_module",
        "delete_module",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "swapon",
        "swapoff",
        "acct",
        "quotactl",
        "syslog",
        "open_by_handle_at",
        "name_to_handle_at",
        "ioperm",
        "iopl",
        "clock_settime",
        "settimeofday",
        "sethostname",
        "setdomainname",
        "process_vm_readv",
        "process_vm_writev",
        "kcmp",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "mknod",
        "mknodat",
    }
    assert allowed.isdisjoint(forbidden), f"forbidden syscalls in allowlist: {allowed & forbidden}"


# --- 3. Non-root UID, read-only rootfs, tmpfs, and declared mounts audit ----------------------


def test_container_user_never_returns_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod.os, "getuid", lambda: 0)
    monkeypatch.setattr(runner_mod.os, "getgid", lambda: 0)
    user_spec = runner_mod._container_user()
    uid_str, gid_str = user_spec.split(":")
    assert int(uid_str) > 0 and int(gid_str) > 0
    assert user_spec == "65534:65534"


def test_declared_mounts_audit_rejects_undeclared_or_host_mounts(tmp_path: Path) -> None:
    # 11 base mounts, the two canary_connect mounts (listener read-only, log writable), the
    # canary_access store (seeded copy, read-only), the three OS-witness mounts, and the
    # Node oracle preload (oracle.cjs).
    assert len(DECLARED_MOUNTS) == 18
    tmpdir = tmp_path / "sandbox_tmp"
    workspace = tmpdir / "workspace"
    workspace.mkdir(parents=True)

    valid_cmd = [
        "docker", "run", "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        "-v", f"{workspace}:/workspace:rw",
        "img", "pytest",
    ]
    assert runner_mod._verify_declared_mounts(valid_cmd, str(tmpdir)) is None

    # Docker socket mount is rejected
    sock_cmd = [*valid_cmd, "-v", "/var/run/docker.sock:/var/run/docker.sock:rw"]
    assert "docker socket" in (runner_mod._verify_declared_mounts(sock_cmd, str(tmpdir)) or "")

    # Host path outside per-run tmpdir is rejected
    outside = tmp_path / "outside_host"
    outside.mkdir()
    outside_cmd = [*valid_cmd, "-v", f"{outside}:/workspace:rw"]
    assert "outside per-run tmpdir" in (runner_mod._verify_declared_mounts(outside_cmd, str(tmpdir)) or "")

    # Undeclared container target is rejected
    bad_target_cmd = [*valid_cmd, "-v", f"{workspace}:/etc/shadow:ro"]
    assert "undeclared container mount target" in (
        runner_mod._verify_declared_mounts(bad_target_cmd, str(tmpdir)) or ""
    )

    # Uncapped tmpfs or non-/tmp tmpfs is rejected
    uncapped_tmpfs = ["docker", "run", "--tmpfs", "/tmp:rw", "img"]
    assert "tmpfs" in (runner_mod._verify_declared_mounts(uncapped_tmpfs, str(tmpdir)) or "")

    # --mount flag is rejected
    mount_flag = ["docker", "run", "--mount", "type=bind,src=/,dst=/host", "img"]
    assert "--mount" in (runner_mod._verify_declared_mounts(mount_flag, str(tmpdir)) or "")


# --- 4. `exhibit-a doctor` self-check ---------------------------------------------------------


@pytest.mark.docker
def test_doctor_cli_prints_isolation_and_seccomp_profile(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli_main(["doctor"])
    out = capsys.readouterr().out
    assert code == 0, out
    for expected in (
        "[ok] runtime:",
        "[ok] network:",
        "[ok] capabilities:",
        "[ok] seccomp:",
        "[ok] user:",
        "[ok] filesystem:",
        "[ok] limits:",
        "seccomp_profile:",
        "defaultAction=SCMP_ACT_ERRNO",
        "declared_mounts:",
    ):
        assert expected in out, f"missing {expected!r} in:\n{out}"


@pytest.mark.docker
def test_doctor_cli_json_mode(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli_main(["doctor", "--json"])
    out = capsys.readouterr().out
    assert code == 0, out
    data = json.loads(out)
    assert data["passed"] is True
    assert data["isolation"] == "isolated and resource-limited"
    assert {c["name"] for c in data["checks"]} == {
        "runtime", "network", "capabilities", "seccomp", "user", "filesystem", "limits"
    }
    assert all(c["passed"] for c in data["checks"])
    assert data["seccomp_profile"]["defaultAction"] == "SCMP_ACT_ERRNO"
    assert data["seccomp_profile"]["allowed_syscalls_count"] > 100


def _healthy_probe_result() -> dict:
    return {
        "ok": True,
        "error": "",
        "configured_runtime": None,
        "effective_runtime": "runc",
        "available_runtimes": ["runc"],
        "seccomp_profile_path": str(SECCOMP_PROFILE),
        "probe": {
            "uid": 501,
            "euid": 501,
            "gid": 20,
            "egid": 20,
            "no_new_privs": "1",
            "seccomp_mode": "2",
            "capabilities": {
                "CapInh": "0000000000000000",
                "CapPrm": "0000000000000000",
                "CapEff": "0000000000000000",
                "CapBnd": "0000000000000000",
                "CapAmb": "0000000000000000",
            },
            "seccomp_probes": {
                "ptrace": "EPERM",
                "unshare": "EPERM",
                "mount": "EPERM",
                "chroot": "EPERM",
                "setuid": "EPERM",
                "chown": "EPERM",
            },
            "network": {
                "interfaces": ["lo"],
                "external_connect_blocked": True,
            },
            "filesystem": {
                "rootfs_readonly": True,
                "tmp_writable": True,
                "docker_socket_present": False,
                "mounts": [{"mount_point": "/tmp", "fstype": "tmpfs", "opts": "rw"}],
            },
            "limits": {
                "memory_max": "536870912",
                "memory_swap_max": "0",
                "pids_max": "64",
                "cpu_max": "50000 100000",
            },
        },
    }


@pytest.mark.parametrize(
    "mutator, failed_check",
    [
        (lambda d: d["probe"]["network"].update(interfaces=["lo", "eth0"]), "network"),
        (lambda d: d["probe"]["network"].update(external_connect_blocked=False), "network"),
        (lambda d: d["probe"]["capabilities"].update(CapEff="0000000000002000"), "capabilities"),
        (lambda d: d["probe"].update(no_new_privs="0"), "capabilities"),
        (lambda d: d["probe"].update(seccomp_mode="0"), "seccomp"),
        (lambda d: d["probe"]["seccomp_probes"].update(ptrace="ESRCH"), "seccomp"),
        (lambda d: d["probe"].update(uid=0, euid=0), "user"),
        (lambda d: d["probe"]["filesystem"].update(rootfs_readonly=False), "filesystem"),
        (lambda d: d["probe"]["filesystem"].update(docker_socket_present=True), "filesystem"),
        (lambda d: d["probe"]["limits"].update(memory_max="max"), "limits"),
        (lambda d: d["probe"]["limits"].update(memory_swap_max="5368709120"), "limits"),
        (lambda d: d["probe"]["limits"].update(pids_max="max"), "limits"),
        (lambda d: d["probe"]["limits"].update(cpu_max="max 100000"), "limits"),
        (lambda d: d.update(configured_runtime="runsc", available_runtimes=["runc"]), "runtime"),
    ],
)
def test_doctor_exits_nonzero_when_any_isolation_is_weaker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutator,
    failed_check: str,
) -> None:
    import exhibit_a.cli.ext.doctor as doctor_mod

    baseline = _healthy_probe_result()
    assert evaluate_isolation(baseline)["passed"] is True

    weakened = copy.deepcopy(baseline)
    mutator(weakened)
    monkeypatch.setattr(doctor_mod, "probe_isolation", lambda runtime=None: weakened)
    code = cli_main(["doctor"])
    out = capsys.readouterr().out
    assert code == 1, out
    assert f"[fail] {failed_check}:" in out


# --- 5. Escape-attempt tests in the sandbox (docker-marked) -----------------------------------


@pytest.mark.docker
def test_escape_attempt_network_access_contained(tmp_path: Path) -> None:
    """Escape attempt 1: outbound TCP, UDP, and raw sockets must fail inside the sandbox."""
    repo = _make_repo(
        tmp_path,
        """
        import socket

        def test_escape_network():
            # Attempt 1a: TCP connection to external IP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect(("1.1.1.1", 80))
            finally:
                s.close()
        """,
    )
    res = run(str(repo), "tests/test_escape.py", timeout=60)
    assert res["outcome"] == "failed", res
    assert res["oracle_events"] == []
    assert res["app_tree_changes"] == []

    # Also verify UDP and raw socket creation both fail inside the container
    repo_all = _make_repo(
        tmp_path,
        """
        import socket
        import pytest

        def test_all_network_vectors_blocked():
            with pytest.raises(OSError):
                socket.create_connection(("1.1.1.1", 53), timeout=1)
            with pytest.raises(OSError):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.sendto(b"ping", ("8.8.8.8", 53))
                finally:
                    s.close()
            with pytest.raises(OSError):
                socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        """,
        name="repo_net_all",
    )
    res_all = run(str(repo_all), "tests/test_escape.py", timeout=60)
    assert res_all["outcome"] == "passed", res_all


@pytest.mark.docker
def test_escape_attempt_write_outside_tmpfs_contained(tmp_path: Path) -> None:
    """Escape attempt 2: writing to rootfs, system dirs, plugin dir, or cgroups must fail."""
    canary = tmp_path / "canary.txt"
    canary.write_text("SECRET_TOKEN", encoding="utf-8")
    repo = _make_repo(
        tmp_path,
        """
        def test_escape_write_rootfs():
            with open("/escaped_file", "w") as fh:
                fh.write("pwned")
        """,
    )
    res = run(str(repo), "tests/test_escape.py", timeout=60, canary_path=str(canary))
    assert res["outcome"] == "failed", res
    assert res["oracle_events"] == []
    assert res["app_tree_changes"] == []

    repo_targets = _make_repo(
        tmp_path,
        """
        import pytest

        @pytest.mark.parametrize("target", [
            "/escaped_root",
            "/etc/passwd",
            "/usr/bin/evil",
            "/var/tmp/escape",
            "/opt/exhibit_a_plugin/exhibit_a_oracle_plugin.py",
            "/oracle/canary",
            "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/pids.max",
        ])
        def test_write_outside_tmpfs_rejected(target):
            with pytest.raises(OSError):
                with open(target, "w") as fh:
                    fh.write("override")
        """,
        name="repo_write_targets",
    )
    res_targets = run(str(repo_targets), "tests/test_escape.py", timeout=60, canary_path=str(canary))
    assert res_targets["outcome"] == "passed", res_targets
    assert canary.read_text(encoding="utf-8") == "SECRET_TOKEN"


@pytest.mark.docker
def test_escape_attempt_raising_privileges_contained(tmp_path: Path) -> None:
    """Escape attempt 3: setuid, setgid, chown, chroot, unshare, ptrace, mount must all fail with EPERM."""
    repo = _make_repo(
        tmp_path,
        """
        import os

        def test_escape_setuid_root():
            os.setuid(0)
        """,
    )
    res = run(str(repo), "tests/test_escape.py", timeout=60)
    assert res["outcome"] == "failed", res

    repo_privs = _make_repo(
        tmp_path,
        """
        import ctypes
        import errno
        import os
        import pytest

        def test_all_privilege_escalation_vectors_blocked():
            assert os.getuid() > 0 and os.geteuid() > 0

            for fn in (
                lambda: os.setuid(0),
                lambda: os.seteuid(0),
                lambda: os.setgid(0),
                lambda: os.setegid(0),
                lambda: os.setreuid(0, 0),
                lambda: os.setregid(0, 0),
                lambda: os.setgroups([0]),
                lambda: os.chown("/tmp", 0, 0),
                lambda: os.chroot("/tmp"),
            ):
                with pytest.raises(OSError) as exc_info:
                    fn()
                assert exc_info.value.errno == errno.EPERM

            libc = ctypes.CDLL(None, use_errno=True)
            # unshare(CLONE_NEWUSER=0x10000000) and unshare(0) blocked by seccomp
            for flags in (0, 0x10000000, 0x00020000):
                ctypes.set_errno(0)
                assert libc.unshare(flags) == -1
                assert ctypes.get_errno() == errno.EPERM

            # ptrace blocked by seccomp with EPERM (even with invalid request -1)
            ctypes.set_errno(0)
            assert libc.ptrace(-1, 0, 0, 0) == -1
            assert ctypes.get_errno() == errno.EPERM

            # mount blocked by seccomp with EPERM
            ctypes.set_errno(0)
            assert libc.mount(0, 0, 0, 0, 0) == -1
            assert ctypes.get_errno() == errno.EPERM
        """,
        name="repo_privs",
    )
    res_privs = run(str(repo_privs), "tests/test_escape.py", timeout=60)
    assert res_privs["outcome"] == "passed", res_privs


@pytest.mark.docker
def test_escape_attempt_fork_bomb_contained(tmp_path: Path) -> None:
    """Escape attempt 4: fork bomb is stopped by --pids-limit 64 and the container is cleaned up."""
    repo = _make_repo(
        tmp_path,
        """
        import os
        import time

        def test_fork_bomb():
            children = []
            try:
                for _ in range(500):
                    pid = os.fork()
                    if pid == 0:
                        time.sleep(10)
                        os._exit(0)
                    children.append(pid)
            finally:
                for pid in children:
                    try:
                        os.kill(pid, 9)
                        os.waitpid(pid, 0)
                    except OSError:
                        pass
        """,
    )
    res = run(str(repo), "tests/test_escape.py", timeout=60)
    assert res["outcome"] == "failed", res
    assert "BlockingIOError" in res["stdout"] or "Resource temporarily unavailable" in res["stdout"]
    assert res["oracle_events"] == []


@pytest.mark.docker
def test_escape_attempt_memory_bomb_contained(tmp_path: Path) -> None:
    """Escape attempt 5: memory bomb exceeding 512 MiB (with 0 swap) is terminated inside the sandbox."""
    repo = _make_repo(
        tmp_path,
        """
        def test_memory_bomb():
            # Allocate and touch ~700 MiB (> 512 MiB limit, with swap disabled)
            chunks = []
            for _ in range(70):
                chunks.append(b"M" * (10 * 1024 * 1024))
            assert len(chunks) == 70
        """,
    )
    res = run(str(repo), "tests/test_escape.py", timeout=60)
    assert res["outcome"] == "failed", res
    assert res["exit_code"] != 0
    assert res["oracle_events"] == []


@pytest.mark.docker
def test_escape_attempt_reading_host_paths_contained(tmp_path: Path) -> None:
    """Escape attempt 6: reading host files under $HOME, docker.sock, or /etc/shadow must fail."""
    host_dir = Path.home() / ".cache" / "exhibit-a" / "host_escape_probe"
    host_dir.mkdir(parents=True, exist_ok=True)
    host_secret = host_dir / f"host_secret_{uuid.uuid4().hex}.txt"
    host_secret.write_text("TOP_SECRET_HOST_DATA", encoding="utf-8")
    try:
        repo = _make_repo(
            tmp_path,
            f"""
            def test_escape_read_host_secret():
                with open({str(host_secret)!r}) as fh:
                    data = fh.read()
                assert "TOP_SECRET_HOST_DATA" in data
            """,
        )
        res = run(str(repo), "tests/test_escape.py", timeout=60)
        assert res["outcome"] == "failed", res
        assert "TOP_SECRET_HOST_DATA" not in res["stdout"]
        assert "TOP_SECRET_HOST_DATA" not in res["stderr"]

        repo_paths = _make_repo(
            tmp_path,
            f"""
            import os
            import pytest

            @pytest.mark.parametrize("path", [
                {str(host_secret)!r},
                "/var/run/docker.sock",
                "/run/docker.sock",
                "/etc/shadow",
            ])
            def test_host_and_sensitive_paths_unreadable(path):
                with pytest.raises(OSError):
                    with open(path, "rb") as fh:
                        fh.read(16)
            """,
            name="repo_host_paths",
        )
        res_paths = run(str(repo_paths), "tests/test_escape.py", timeout=60)
        assert res_paths["outcome"] == "passed", res_paths
    finally:
        try:
            host_secret.unlink()
        except OSError:
            pass
