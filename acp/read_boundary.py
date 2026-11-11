"""Bounded local reads. No symlink/reparse following; no writes or execution."""
from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
import hashlib
import ntpath
import os
from pathlib import Path
import stat

from .domain import ACPError, require


def relative_name(value, root=False):
    require(isinstance(value, str) and value, "EMPTY_PATH")
    if root and value == ".":
        return "."
    value = value.replace("\\", "/")
    require(not ntpath.isabs(value) and not ntpath.splitdrive(value)[0], "ABSOLUTE_PATH")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    parts = value.split("/")
    require(all(p and p not in {".", ".."} and p == p.rstrip(" .") and
                p.split(".")[0].casefold() not in reserved for p in parts), "AMBIGUOUS_PATH")
    require(not any(c in value for c in ':*?<>|"~') and all(ord(c) >= 32 for c in value), "AMBIGUOUS_PATH")
    return value


def sensitive(name):
    parts = name.replace("\\", "/").casefold().split("/")
    denied = {".git", ".hg", ".svn", ".ssh", ".aws", ".azure", ".config", ".codex", ".agents",
              "node_modules", "__pycache__", "appdata", "cookies", "login data", "local storage", "session storage"}
    for part in parts:
        if part in denied or part.startswith(".env") or any(word in part for word in ("credential", "secret", "token", "private_key", "private-key", "session", "browser")):
            return True
        if part.startswith(("id_rsa", "id_ed25519")) or part.endswith((".pem", ".key", ".pfx", ".p12", ".sqlite", ".sqlite3", ".db", ".db-wal", ".db-shm")):
            return True
    return False


class _Info(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME), ("accessed", wintypes.FILETIME),
                ("modified", wintypes.FILETIME), ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD), ("links", wintypes.DWORD), ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]


@contextmanager
def _windows_open(path, directory, parent_fd=None):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Info)]
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # OPEN_EXISTING, OPEN_REPARSE_POINT; retained ancestor handles deny rename/delete.
    handle = kernel.CreateFileW(str(path), 0x80 if directory else 0x80000000, 1, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        code = ctypes.get_last_error()
        if code in {2, 3}:
            raise FileNotFoundError(str(path))
        raise ACPError(f"READ_BLOCKED_WIN32_{code}")
    try:
        info = _Info()
        require(kernel.GetFileInformationByHandle(handle, ctypes.byref(info)), "HANDLE_INFO_UNAVAILABLE")
        require(not info.attributes & 0x400, "REPARSE_POINT_BLOCKED")
        require(bool(info.attributes & 0x10) == directory, "WRONG_FILE_TYPE")
        require(directory or info.links == 1, "HARDLINK_BLOCKED")
        buf = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, buf, len(buf), 0)
        require(0 < length < len(buf), "CANONICAL_TARGET_UNAVAILABLE")
        final = buf.value
        require(final.startswith("\\\\?\\") and not final.startswith("\\\\?\\UNC\\"), "NONLOCAL_TARGET")
        final = final[4:]
        require(ntpath.normcase(ntpath.normpath(final)) == ntpath.normcase(ntpath.normpath(str(path))), "CANONICAL_TARGET_CHANGED")
        size = (info.size_high << 32) | info.size_low
        def read(limit):
            data = ctypes.create_string_buffer(limit + 1)
            count = wintypes.DWORD()
            require(kernel.ReadFile(handle, data, limit + 1, ctypes.byref(count), None), "READ_FAILED")
            return data.raw[:count.value]
        yield {"path": final, "size": size, "read": read}
    finally:
        kernel.CloseHandle(handle)


@contextmanager
def _posix_open(path, directory, parent_fd=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
    fd = os.open(path.name if parent_fd is not None else path, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode), "WRONG_FILE_TYPE")
        require(directory or before.st_nlink == 1, "HARDLINK_BLOCKED")
        def read(limit):
            data = os.read(fd, limit + 1)
            after = os.fstat(fd)
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "FILE_CHANGED_DURING_READ")
            return data
        yield {"path": str(path), "size": before.st_size, "read": read, "fd": fd}
    finally:
        os.close(fd)


class ReadBoundary:
    def __init__(self, project_path, read_roots, other_projects=()):
        self.root = Path(project_path)
        require(self.root.is_absolute(), "PROJECT_PATH_NOT_ABSOLUTE")
        if os.name == "nt":
            require(len(self.root.drive) == 2 and self.root.drive[1] == ":", "UNC_OR_DEVICE_ROOT_BLOCKED")
        self.read_roots = [relative_name(p, root=True) for p in read_roots]
        self.other_projects = [Path(p) for p in other_projects if Path(p) != self.root]

    def name(self, name, directory=False):
        name = relative_name(name, root=directory)
        require(not sensitive(name), "SENSITIVE_PATH")
        require(any(r == "." or name.casefold() == r.casefold() or name.casefold().startswith(r.casefold() + "/") for r in self.read_roots), "OUTSIDE_APPROVED_READ_ROOT")
        target = self.root if name == "." else self.root / name
        require(target.is_relative_to(self.root), "OUTSIDE_PROJECT")
        require(not any(target.is_relative_to(p) for p in self.other_projects), "OTHER_REGISTERED_PROJECT")
        return target

    @contextmanager
    def opened(self, name, directory=False):
        target = self.name(name, directory)
        opener = _windows_open if os.name == "nt" else _posix_open
        with ExitStack() as stack:
            ancestors = list(reversed(target.parents))
            parent_fd = None
            for parent in ancestors:
                parent_item = stack.enter_context(opener(parent, True, parent_fd))
                parent_fd = parent_item.get("fd")
                if parent != self.root and parent.is_relative_to(self.root):
                    for marker in (".git", ".hg", ".svn"):
                        try:
                            os.stat(parent / marker, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        raise ACPError("NESTED_REPOSITORY_BLOCKED")
            result = stack.enter_context(opener(target, directory, parent_fd))
            if directory and target != self.root:
                for marker in (".git", ".hg", ".svn"):
                    try:
                        os.stat(target / marker, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ACPError("NESTED_REPOSITORY_BLOCKED")
            yield result

    def children(self, root, max_entries=256):
        with self.opened(root, directory=True) as item:
            names = []
            with os.scandir(item.get("fd", item["path"])) as entries:
                for entry in entries:
                    names.append(entry.name)
                    require(len(names) <= max_entries, "DISCOVERY_LIMIT_ENTIRE_ROOT_EXCLUDED")
            return sorted(names, key=lambda x: (x.casefold(), x))

    def read(self, name, limit):
        with self.opened(name) as item:
            metadata = {"canonical_path": item["path"], "file_size": item["size"]}
            if item["size"] > limit:
                return metadata, None
            data = item["read"](limit)
            require(len(data) == item["size"] and len(data) <= limit, "FILE_CHANGED_DURING_READ")
            return {**metadata, "file_sha256": hashlib.sha256(data).hexdigest()}, data
