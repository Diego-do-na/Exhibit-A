"""Implementation of the ``doctor`` CLI subcommand (extension module).

``exhibit-a doctor`` launches an ephemeral probe container with the sandbox's
isolation flags and inspects the kernel-enforced effective isolation from inside
the container: runtime, network, capabilities, seccomp mode and profile, user,
filesystem/mounts, and cgroup resource limits. It prints the effective values
and the seccomp profile, and exits non-zero (1) if any check is weaker than
documented.

The sandbox is isolated and resource-limited, never "safe".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from exhibit_a.sandbox.runner import (
    CPUS_LIMIT,
    DECLARED_MOUNTS,
    MEMORY_LIMIT,
    MEMORY_LIMIT_BYTES,
    PIDS_LIMIT,
    SECCOMP_PROFILE,
    probe_isolation,
)

_ZERO_CAPS = "0000000000000000"
_EXPECTED_CPU_MAX = "50000 100000"


def load_seccomp_profile(path: Path = SECCOMP_PROFILE) -> dict[str, Any]:
    """Load and return the sandbox seccomp profile JSON."""
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_isolation(
    probe_result: dict[str, Any],
    profile_path: Path = SECCOMP_PROFILE,
) -> dict[str, Any]:
    """Evaluate probe container results against documented sandbox guarantees."""
    checks: list[dict[str, Any]] = []
    profile_data: dict[str, Any] = {}
    allowed_syscalls: list[str] = []
    profile_ok = False
    try:
        profile_data = load_seccomp_profile(profile_path)
        for rule in profile_data.get("syscalls", []):
            if isinstance(rule, dict) and rule.get("action") == "SCMP_ACT_ALLOW":
                allowed_syscalls.extend(rule.get("names", []))
        profile_ok = (
            profile_data.get("defaultAction") == "SCMP_ACT_ERRNO"
            and len(allowed_syscalls) > 0
            and "ptrace" not in allowed_syscalls
            and "unshare" not in allowed_syscalls
            and "mount" not in allowed_syscalls
            and "setuid" not in allowed_syscalls
        )
    except (OSError, ValueError):
        profile_ok = False

    if not probe_result.get("ok") or not isinstance(probe_result.get("probe"), dict):
        err = probe_result.get("error") or "probe container did not return isolation data"
        for name in ("runtime", "network", "capabilities", "seccomp", "user", "filesystem", "limits"):
            checks.append({"name": name, "passed": False, "detail": err})
        return {
            "passed": False,
            "isolation": "isolated and resource-limited",
            "checks": checks,
            "seccomp_profile": {
                "path": str(profile_path),
                "defaultAction": profile_data.get("defaultAction"),
                "allowed_syscalls_count": len(allowed_syscalls),
                "allowed_syscalls": allowed_syscalls,
            },
            "declared_mounts": list(DECLARED_MOUNTS),
        }

    probe = probe_result["probe"]
    configured_rt = probe_result.get("configured_runtime")
    effective_rt = probe_result.get("effective_runtime") or "unknown"
    avail_rts = probe_result.get("available_runtimes") or []

    # 1. Runtime check
    rt_ok = bool(effective_rt and effective_rt != "unknown")
    if configured_rt and avail_rts and configured_rt not in avail_rts:
        rt_ok = False
    checks.append({
        "name": "runtime",
        "passed": rt_ok,
        "detail": (
            f"effective={effective_rt} configured={configured_rt or 'default'} "
            f"available={','.join(avail_rts) if avail_rts else effective_rt}"
        ),
    })

    # 2. Network check
    net = probe.get("network") or {}
    interfaces = net.get("interfaces") if isinstance(net.get("interfaces"), list) else []
    ext_blocked = net.get("external_connect_blocked") is True
    net_ok = ext_blocked and set(interfaces) <= {"lo"} and len(interfaces) <= 1
    checks.append({
        "name": "network",
        "passed": net_ok,
        "detail": f"mode=none interfaces={interfaces} external_connect_blocked={ext_blocked}",
    })

    # 3. Capabilities & no-new-privileges check
    caps = probe.get("capabilities") or {}
    no_new_privs = str(probe.get("no_new_privs", ""))
    caps_ok = (
        no_new_privs == "1"
        and caps.get("CapInh") == _ZERO_CAPS
        and caps.get("CapPrm") == _ZERO_CAPS
        and caps.get("CapEff") == _ZERO_CAPS
        and caps.get("CapBnd") == _ZERO_CAPS
        and caps.get("CapAmb") == _ZERO_CAPS
    )
    checks.append({
        "name": "capabilities",
        "passed": caps_ok,
        "detail": (
            f"CapEff={caps.get('CapEff')} CapPrm={caps.get('CapPrm')} "
            f"CapBnd={caps.get('CapBnd')} CapInh={caps.get('CapInh')} "
            f"CapAmb={caps.get('CapAmb')} NoNewPrivs={no_new_privs}"
        ),
    })

    # 4. Seccomp mode & profile check
    seccomp_mode = str(probe.get("seccomp_mode", ""))
    probes = probe.get("seccomp_probes") or {}
    probes_ok = all(
        probes.get(k) == "EPERM"
        for k in ("ptrace", "unshare", "mount", "chroot", "setuid", "chown")
    )
    seccomp_ok = seccomp_mode == "2" and profile_ok and probes_ok
    checks.append({
        "name": "seccomp",
        "passed": seccomp_ok,
        "detail": (
            f"mode={seccomp_mode} (filter) defaultAction={profile_data.get('defaultAction')} "
            f"allowed_syscalls={len(allowed_syscalls)} probes={probes} "
            f"profile={profile_path.name}"
        ),
    })

    # 5. User check (non-root UID/GID)
    uid = probe.get("uid")
    euid = probe.get("euid")
    gid = probe.get("gid")
    egid = probe.get("egid")
    user_ok = (
        isinstance(uid, int) and uid > 0
        and isinstance(euid, int) and euid > 0
        and isinstance(gid, int) and gid > 0
        and isinstance(egid, int) and egid > 0
    )
    checks.append({
        "name": "user",
        "passed": user_ok,
        "detail": f"uid={uid} euid={euid} gid={gid} egid={egid}",
    })

    # 6. Filesystem & mounts check
    fs = probe.get("filesystem") or {}
    rootfs_ro = fs.get("rootfs_readonly") is True
    tmp_rw = fs.get("tmp_writable") is True
    sock_present = fs.get("docker_socket_present") is True
    mounts = fs.get("mounts") if isinstance(fs.get("mounts"), list) else []
    tmp_is_tmpfs = any(
        isinstance(m, dict) and m.get("mount_point") == "/tmp" and m.get("fstype") == "tmpfs"
        for m in mounts
    )
    fs_ok = rootfs_ro and tmp_rw and not sock_present and tmp_is_tmpfs
    checks.append({
        "name": "filesystem",
        "passed": fs_ok,
        "detail": (
            f"rootfs_readonly={rootfs_ro} tmp_tmpfs={tmp_is_tmpfs} "
            f"tmp_writable={tmp_rw} docker_socket={sock_present}"
        ),
    })

    # 7. Resource limits check
    lim = probe.get("limits") or {}
    mem_max = str(lim.get("memory_max", ""))
    swap_max = str(lim.get("memory_swap_max", ""))
    pids_max = str(lim.get("pids_max", ""))
    cpu_max = str(lim.get("cpu_max", ""))
    mem_ok = mem_max == str(MEMORY_LIMIT_BYTES)
    swap_ok = swap_max in ("0", str(MEMORY_LIMIT_BYTES))
    pids_ok = pids_max == str(PIDS_LIMIT)
    cpu_ok = cpu_max == _EXPECTED_CPU_MAX
    limits_ok = mem_ok and swap_ok and pids_ok and cpu_ok
    checks.append({
        "name": "limits",
        "passed": limits_ok,
        "detail": (
            f"memory={mem_max} ({MEMORY_LIMIT}) memory_swap={swap_max} "
            f"pids_max={pids_max} cpu_max={cpu_max!r} ({CPUS_LIMIT} cpus)"
        ),
    })

    all_passed = all(c["passed"] for c in checks)
    return {
        "passed": all_passed,
        "isolation": "isolated and resource-limited",
        "checks": checks,
        "seccomp_profile": {
            "path": str(profile_path),
            "defaultAction": profile_data.get("defaultAction"),
            "defaultErrnoRet": profile_data.get("defaultErrnoRet"),
            "archMap": profile_data.get("archMap", []),
            "allowed_syscalls_count": len(allowed_syscalls),
            "allowed_syscalls": allowed_syscalls,
        },
        "declared_mounts": list(DECLARED_MOUNTS),
    }


def cmd_doctor(args: argparse.Namespace) -> int:
    """Run the sandbox isolation self-check and print the report."""
    runtime = getattr(args, "runtime", None)
    probe_res = probe_isolation(runtime=runtime)
    report = evaluate_isolation(probe_res)

    if getattr(args, "json", False):
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1

    print("Exhibit A sandbox self-check (isolated and resource-limited):")
    for check in report["checks"]:
        status = "PASS" if check["passed"] else "FAIL"
        print(f"{status} {check['name']}: {check['detail']}")

    prof = report["seccomp_profile"]
    print(
        f"seccomp_profile: path={prof['path']} "
        f"defaultAction={prof['defaultAction']} "
        f"allowed_syscalls ({prof['allowed_syscalls_count']}): "
        f"{', '.join(prof['allowed_syscalls'])}"
    )
    print(
        "declared_mounts: "
        + ", ".join(f"{m['target']} ({m['kind']}:{m['mode']})" for m in report["declared_mounts"])
    )
    return 0 if report["passed"] else 1


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``doctor`` subcommand to the CLI."""
    parser = sub.add_parser(
        "doctor",
        help="Verify the effective isolation and limits of a sandbox probe container.",
    )
    parser.add_argument(
        "--runtime",
        default=None,
        help="Docker runtime to verify (overrides EXHIBIT_A_DOCKER_RUNTIME, e.g. runsc).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the isolation report and seccomp profile as JSON.",
    )
    parser.set_defaults(func=cmd_doctor)
