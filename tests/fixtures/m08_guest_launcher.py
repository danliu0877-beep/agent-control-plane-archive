"""Trusted synthetic launcher: Linux x86_64 Landlock + seccomp, fail closed."""
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import sys


class Ruleset(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("access", ctypes.c_uint64), ("fd", ctypes.c_int32)]


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]


def checked(result, label):
    if result < 0:
        raise OSError(ctypes.get_errno(), label)
    return result


def main():
    if platform.machine() != "x86_64" or len(sys.argv) != 4:
        raise RuntimeError("Only the tested x86_64 synthetic fixture profile is supported")
    root = Path("/home/acpworker/work")
    fixture, mode, attempt = sys.argv[1:]
    if Path(fixture).resolve() != root / "tools" / "worker.py":
        raise RuntimeError("Unapproved fixture path")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = checked(libc.syscall(444, 0, 0, 1), "Landlock ABI query")
    if abi < 3:
        raise RuntimeError("Landlock ABI >= 3 required; no weaker fallback")
    checked(libc.prctl(38, 1, 0, 0, 0), "no_new_privs")
    all_fs = (1 << 15) - 1
    read = (1 << 0) | (1 << 2) | (1 << 3)
    rules = Ruleset(all_fs)
    rules_fd = checked(libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0), "ruleset")
    try:
        grants = [(str(p), read) for p in [Path("/usr"), Path("/etc"), Path("/proc"), Path("/sys")]]
        grants += [(str(root / "tools"), read), (str(root / "input"), read),
                   (str(root / "output"), all_fs), (str(root / "scratch"), all_fs),
                   (str(root / "allowed.txt"), (1 << 1) | (1 << 2) | (1 << 14)),
                   ("/dev/null", (1 << 1) | (1 << 2)),
                   ("/dev/urandom", 1 << 2), ("/dev/random", 1 << 2)]
        # Ubuntu's /bin, /sbin and /lib links resolve under /usr.
        for name, rights in grants:
            fd = os.open(name, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(rights, fd)
                checked(libc.syscall(445, rules_fd, 1, ctypes.byref(rule), 0), f"grant {name}")
            finally:
                os.close(fd)
        checked(libc.syscall(446, rules_fd, 0), "restrict_self")
    finally:
        os.close(rules_fd)

    # seccomp checks architecture first, rejects x32 and bypass surfaces, and
    # denies all socket operations including guest loopback/Unix/vsock.
    ins = [Filter(0x20, 0, 0, 4), Filter(0x15, 1, 0, 0xc000003e),
           Filter(0x06, 0, 0, 0x80000000), Filter(0x20, 0, 0, 0),
           Filter(0x45, 0, 1, 0x40000000), Filter(0x06, 0, 0, 0x80000000)]
    denied = set(range(41, 56)) | {101, 165, 166, 272, 308, 288, 299, 307, 321,
                                  425, 426, 427, 90, 91, 92, 93, 94, 132, 235,
                                  260, 268, 280, 188, 189, 190, 197, 198, 199,
                                  310, 311, 438, 298, 303, 304}
    for number in sorted(denied):
        ins.extend([Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x00050000 | errno.EPERM)])
    # glibc can safely fall back from clone3 to clone; namespace flags on clone
    # remain forbidden. Ordinary fork/exec and detached descendants are allowed
    # inside this VM and inherit both filters.
    ins.extend([Filter(0x15, 0, 1, 435), Filter(0x06, 0, 0, 0x00050000 | errno.ENOSYS),
                Filter(0x15, 0, 3, 56), Filter(0x20, 0, 0, 16),
                Filter(0x45, 0, 1, 0x7e020000), Filter(0x06, 0, 0, 0x00050000 | errno.EPERM),
                Filter(0x06, 0, 0, 0x7fff0000)])
    array = (Filter * len(ins))(*ins)
    prog = Program(len(ins), array)
    checked(libc.prctl(22, 2, ctypes.byref(prog), 0, 0), "seccomp filter")
    (root / "output" / "launcher.json").write_text(json.dumps({"landlock_abi": abi, "seccomp": True,
        "no_new_privs": True, "attempt": attempt}), encoding="utf-8")
    # Single-threaded trusted launcher: enumerate its own descriptors, not a
    # guessed upper limit. No pre-opened high descriptor may bypass Landlock.
    for descriptor in os.listdir("/proc/self/fd"):
        number = int(descriptor)
        if number > 2:
            try:
                os.close(number)
            except OSError as exc:
                if exc.errno != errno.EBADF:  # listdir's own fd is already closed
                    raise
    os.chdir(root / "scratch")
    os.execve("/usr/bin/python3", ["python3", "-B", fixture, mode, attempt],
              {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/home/acpworker/work/scratch",
               "TMPDIR": "/home/acpworker/work/scratch", "PYTHONDONTWRITEBYTECODE": "1"})


if __name__ == "__main__":
    main()
