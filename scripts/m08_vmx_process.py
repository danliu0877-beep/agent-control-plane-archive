"""Read only the VMX process named by an owned M08 VM's current host log.

Diagnostic only: this does not constitute a durable fencing receipt.
Never enumerates or terminates processes; never enables debug privileges.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import re

ROOT = Path(r"C:\ACP-SYNTHETIC-LAB")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vmx", type=Path)
    args = parser.parse_args()
    vmx = args.vmx.resolve(strict=True)
    if not vmx.is_relative_to(ROOT.resolve(strict=True)) or vmx.suffix != ".vmx":
        parser.error("Exact owned disposable VMX required")
    line = (vmx.parent / "vmware.log").read_text(encoding="utf-8").splitlines()[0]
    match = re.search(r"Log for VMware Workstation pid=(\d+)", line)
    if not match:
        raise RuntimeError("No current exact-VM host process identity")
    pid = int(match[1])
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    handle = api.OpenProcess(0x100000 | 0x1000, False, pid)
    result = {"vmx": str(vmx), "log_pid": pid, "log_first_line": line}
    if not handle:
        result.update(state="unknown", open_error=ctypes.get_last_error())
    else:
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not api.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                raise ctypes.WinError(ctypes.get_last_error())
            result["creation_filetime"] = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            text = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(text))
            if api.QueryFullProcessImageNameW(handle, 0, text, ctypes.byref(size)):
                result["image"] = text.value
            else:
                result["image_error"] = ctypes.get_last_error()
            result["wait_code"] = api.WaitForSingleObject(handle, 0)
        finally:
            api.CloseHandle(handle)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
