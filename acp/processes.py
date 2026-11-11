"""Read-only Windows process census; never a termination or ownership proof."""
import ctypes
from ctypes import wintypes
import os


def inspect_candidates():
    if os.name != "nt":
        return {"supported": False, "termination_proven": False}
    class Entry(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
                    ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                    ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
                    ("exe", wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "Process snapshot unavailable")
    candidates = []
    try:
        entry = Entry()
        entry.size = ctypes.sizeof(entry)
        found = kernel.Process32FirstW(handle, ctypes.byref(entry))
        while found:
            if entry.exe.casefold() in {"codex.exe", "node.exe", "pwsh.exe", "powershell.exe", "agentctl.exe"}:
                candidates.append({"pid": entry.pid, "parent_pid": entry.parent, "name": entry.exe})
            found = kernel.Process32NextW(handle, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(handle)
    return {"supported": True, "candidate_processes": candidates, "termination_proven": False,
            "limitation": "Name/parent snapshot cannot attribute all descendants to this attempt. Unrelated candidates are never terminated."}
