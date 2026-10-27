import errno
import subprocess
import sys
import time

import pytest


def _run_python_one_liner(code, timeout=30):
    try:
        p = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return None, "", "timeout"


def test_memory_limit_enforced():
    """
    Attempt to allocate ~600MB inside a subprocess. The sandbox sets --memory=512m,
    so the allocation should fail (process exit code != 0 or be killed).
    """
    code = "a = bytearray(600 * 1024 * 1024); print('allocated')"
    rc, out, err = _run_python_one_liner(code, timeout=20)
    assert rc is not None and rc != 0, f"Allocation subprocess returned {rc}; memory limit may be missing. stdout={out!r} stderr={err!r}"


def test_pids_limit_blocks_many_forks():
    """
    Try to spawn a bounded number of child processes. The sandbox uses --pids-limit=64,
    so starting a very large number (200) should be prevented; we assert we cannot
    reach the target spawn count.
    """
    procs = []
    target = 200
    try:
        for i in range(target):
            try:
                p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
                procs.append(p)
            except OSError:
                # Reached system/process limit
                break
        # Ensure we did not reach the full target; the pids limit should have stopped us.
        assert len(procs) < target, f"Spawned all {target} processes; pids limit may be missing"
        # Be conservative: expect we spawned no more than 80 procs in this environment.
        assert len(procs) <= 80, f"Spawned too many processes ({len(procs)}); pids limit may be too high or missing"
    finally:
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=1)
            except Exception:
                pass


def test_no_new_privs_and_capabilities_dropped(tmp_path):
    """
    Verify we cannot perform privileged operations inside the sandbox:
    - chown a file to UID 0 should fail with EPERM
    - mounting a tmpfs should fail (requires CAP_SYS_ADMIN); if mount isn't present, skip that check
    """
    f = tmp_path / "file"
    f.write_text("x")

    # chown to root should not be allowed for an unprivileged user
    try:
        # os.chown would raise PermissionError / OSError if not permitted
        import os

        os.chown(str(f), 0, 0)
        pytest.fail("os.chown succeeded unexpectedly; no-new-privileges / cap-drop may be missing")
    except PermissionError:
        pass
    except OSError as e:
        # Some platforms raise OSError with EPERM
        assert e.errno in (errno.EPERM, errno.EINVAL), f"Unexpected chown error: {e!r}"

    # Attempt to mount tmpfs; should fail without CAP_SYS_ADMIN. If `mount` binary is missing, skip.
    try:
        mount_point = tmp_path / "mnt"
        mount_point.mkdir()
        res = subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(mount_point)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        assert res.returncode != 0, f"mount unexpectedly succeeded: stdout={res.stdout!r} stderr={res.stderr!r}"
    except FileNotFoundError:
        pytest.skip("mount command not available in image; skipping mount capability check")

