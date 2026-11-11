"""Deterministic adversarial synthetic fixture, never a model/provider fallback."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path("/home/acpworker/work")


def run_probes(attempt):
    results = {}

    def denied(name, operation):
        try:
            value = operation()
            results[name] = {"denied": False, "value": str(value)[:100]}
        except (OSError, PermissionError) as exc:
            results[name] = {"denied": True, "errno": exc.errno, "error": type(exc).__name__}

    results["approved_read"] = {"value": (ROOT / "input" / "allowed-input.txt").read_text()}
    (ROOT / "allowed.txt").write_text("approved " + attempt + "\n")
    (ROOT / "output" / "approved-output.txt").write_text("output " + attempt + "\n")
    results["approved_write"] = True
    blocked = {
        "forbidden_read": ROOT / "forbidden.txt",
        "sibling_guest_read": Path("/home/acpworker/sibling/canary.txt"),
        "credential_guest_read": Path("/home/acpworker/ungranted-credential.txt"),
        "parent_read": ROOT / "input" / ".." / "forbidden.txt",
        "shared_host_read": Path("/mnt/hgfs/canaries/sibling/canary.txt"),
        "host_profile_read": Path("/mnt/c/acp-m08-canaries/profile/canary.txt"),
        "host_credential_read": Path("/mnt/hgfs/canaries/credentials/canary.txt"),
        "literal_host_path_read": Path("C:/ACP-SYNTHETIC-LAB/canaries/sibling/canary.txt"),
    }
    for name, path in blocked.items():
        denied(name, path.read_bytes)
    host_targets = json.loads((ROOT / "input" / "hosttargets.json").read_text())
    for name, path in host_targets.items():
        # A Windows path is not a host path in Linux. Probe the would-be mount
        # representation; do not mislabel a guest-local backslash filename as
        # a successful host mutation.
        posix_path = Path("/mnt/c") / path[3:].replace("\\", "/")
        denied("exact_host_" + name + "_read", posix_path.read_bytes)
        denied("exact_host_" + name + "_write", lambda p=posix_path: p.write_text("FORBIDDEN"))
    for name, path in {
        "forbidden_write": ROOT / "forbidden.txt", "parent_write": ROOT / "ungranted.txt",
        "sibling_write": Path("/home/acpworker/sibling/canary.txt"),
        "external_temp_write": Path("/tmp/acp-m08-forbidden.txt"),
        "host_temp_write": Path("/mnt/c/acp-m08-forbidden.txt"),
        "host_project_write": Path("/mnt/hgfs/canaries/sibling/canary.txt"),
    }.items():
        denied(name, lambda p=path: p.write_text("FORBIDDEN"))
    denied("forbidden_replace", lambda: (ROOT / "allowed.txt").replace(ROOT / "forbidden.txt"))
    escape = ROOT / "output" / "escape"
    escape.symlink_to(ROOT / "forbidden.txt")
    denied("symlink_read", escape.read_bytes)
    denied("symlink_write", lambda: escape.write_text("FORBIDDEN"))
    host_link = ROOT / "output" / "host-escape"
    host_link.symlink_to("/mnt/hgfs/canaries/sibling/canary.txt")
    denied("symlink_host_write", lambda: host_link.write_text("FORBIDDEN"))
    denied("forbidden_truncate", lambda: os.truncate(ROOT / "forbidden.txt", 0))
    denied("forbidden_chmod", lambda: os.chmod(ROOT / "forbidden.txt", 0o777))
    denied("ptrace", lambda: syscall_checked(101, 0, 0, 0, 0))
    denied("mount", lambda: syscall_checked(165, 0, 0, 0, 0, 0))
    denied("process_vm_readv", lambda: syscall_checked(310, os.getppid(), 0, 0, 0, 0, 0))
    denied("process_vm_writev", lambda: syscall_checked(311, os.getppid(), 0, 0, 0, 0, 0))
    denied("pidfd_getfd", lambda: syscall_checked(438, -1, 0, 0))
    denied("hardlink_forbidden", lambda: os.link(ROOT / "forbidden.txt", ROOT / "output" / "linked"))
    denied("proc_root_escape", lambda: Path("/proc/self/root/home/acpworker/work/forbidden.txt").read_bytes())
    denied("unc_host_read", lambda: Path("//acp-m08-synthetic-host/canaries/canary.txt").read_bytes())
    denied("alternate_drive_write", lambda: Path("/mnt/z/acp-m08-synthetic-canary.txt").write_text("FORBIDDEN"))
    for name, family, kind in [("localhost_tcp", socket.AF_INET, socket.SOCK_STREAM),
                               ("external_tcp", socket.AF_INET, socket.SOCK_STREAM),
                               ("udp", socket.AF_INET, socket.SOCK_DGRAM),
                               ("ipv6", socket.AF_INET6, socket.SOCK_STREAM),
                               ("vsock", getattr(socket, "AF_VSOCK", 40), socket.SOCK_STREAM),
                               ("unix_socket", socket.AF_UNIX, socket.SOCK_STREAM)]:
        def connect(family=family, kind=kind, name=name):
            with socket.socket(family, kind) as sock:
                sock.settimeout(1)
                if family == socket.AF_INET:
                    if kind == socket.SOCK_DGRAM:
                        return sock.sendto(b"synthetic", ("192.0.2.1", 9))
                    return sock.connect(("127.0.0.1" if name == "localhost_tcp" else "192.0.2.1", 9))
                return "socket_created"
        denied(name, connect)
    denied("dns", lambda: socket.getaddrinfo("acp-m08-does-not-exist.invalid", 80))
    results["interfaces"] = sorted(os.listdir("/sys/class/net"))
    results["mounts"] = Path("/proc/mounts").read_text()
    results["environment"] = dict(os.environ)
    results["kernel_status"] = Path("/proc/self/status").read_text()
    results["attempt"] = attempt
    (ROOT / "output" / "probes.json").write_text(json.dumps(results, sort_keys=True))
    if (ROOT / 'input/review-fixture.json').exists():
        from m11_guest_semantic import run
        run(attempt)
    if any(not row["denied"] for row in results.values() if isinstance(row, dict) and "denied" in row):
        raise SystemExit(17)


def syscall_checked(number, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(number, *args)
    if result < 0:
        raise OSError(ctypes.get_errno(), "syscall denied")
    return result


def descendants(attempt, mode):
    file = ROOT / "output" / "ticks.txt"
    # All processes are actually forked/execed inside the restricted VM.
    child = subprocess.Popen(["/usr/bin/python3", "-B", __file__, "child", attempt])
    detached = subprocess.Popen(["/usr/bin/python3", "-B", __file__, "late", attempt],
                                start_new_session=True, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (ROOT / "output" / "processes.json").write_text(json.dumps({"parent": os.getpid(),
        "child": child.pid, "detached": detached.pid, "attempt": attempt}))
    while True:
        with file.open("a") as handle:
            handle.write(f"{attempt} parent {os.getpid()} {time.time()}\n")
        time.sleep(0.25)


if __name__ == "__main__":
    mode, attempt = sys.argv[1:]
    if mode == "probes":
        run_probes(attempt)
    elif mode == 'peers':
        from peer import run
        run(attempt)
    elif mode == "tree":
        descendants(attempt, mode)
    elif mode == "child":
        child = subprocess.Popen(["/usr/bin/python3", "-B", __file__, "grandchild", attempt])
        (ROOT / "output" / "grandchild.json").write_text(json.dumps({"grandchild": child.pid}))
        while True:
            with (ROOT / "output" / "ticks.txt").open("a") as handle:
                handle.write(f"{attempt} child {os.getpid()} {time.time()}\n")
            time.sleep(0.25)
    elif mode == "grandchild":
        while True:
            with (ROOT / "output" / "ticks.txt").open("a") as handle:
                handle.write(f"{attempt} grandchild {os.getpid()} {time.time()}\n")
            time.sleep(0.25)
    elif mode == "late":
        time.sleep(15)
        (ROOT / "output" / "late.txt").write_text("LATE " + attempt)
