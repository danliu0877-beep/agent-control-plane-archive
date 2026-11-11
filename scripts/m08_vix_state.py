"""Read one explicitly named disposable M08 VMware VM's host-side state.

This is a diagnostic probe, not an ACP dispatch or fencing implementation.
It does not enumerate VMs, start services, mutate VMs, or grant retry.
"""

import argparse
import ctypes
import json
from pathlib import Path
import sys


ROOT = Path(r"C:\ACP-SYNTHETIC-LAB")
VIX_DLL = Path(r"C:\Program Files\VMware\VMware Workstation\vix.dll")
JOB_RESULT_HANDLE = 3010
VM_VMX_PATHNAME = 103
VM_POWER_STATE = 129
VM_IS_RUNNING = 196
POWERED_OFF = 0x0002
POWERED_ON = 0x0008
AMBIGUOUS_POWER = 0x0001 | 0x0004 | 0x0010 | 0x0020 | 0x0080 | 0x0100 | 0x0200 | 0x0800


def decode_power(flags, running, running_error=0):
    # Vendor flags may contain reserved bits. Unknown combinations are not
    # forward-compatible fencing proof; accept only the tested steady states.
    if running_error:
        return "unknown"
    if flags in {POWERED_ON, POWERED_ON | 0x0040} and running == 1:
        return "powered_on"
    if flags == POWERED_OFF and running == 0:
        return "powered_off"
    return "transition_or_uncertain" if flags & AMBIGUOUS_POWER else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vmx", type=Path)
    args = parser.parse_args()
    root = ROOT.resolve(strict=True)
    vmx = args.vmx.resolve(strict=True)
    if not vmx.is_relative_to(root) or vmx.suffix.lower() != ".vmx":
        parser.error("VMX must be an existing file inside the dedicated M08 directory")

    dll = ctypes.CDLL(str(VIX_DLL))
    dll.VixHost_Connect.restype = ctypes.c_int32
    dll.VixHost_Connect.argtypes = [
        ctypes.c_int32, ctypes.c_int32, ctypes.c_char_p, ctypes.c_int32,
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int32, ctypes.c_int32,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    dll.VixHost_OpenVM.restype = ctypes.c_int32
    dll.VixHost_OpenVM.argtypes = [
        ctypes.c_int32, ctypes.c_char_p, ctypes.c_int32, ctypes.c_int32,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    dll.VixJob_Wait.restype = ctypes.c_uint64
    dll.Vix_GetProperties.restype = ctypes.c_uint64
    dll.Vix_ReleaseHandle.argtypes = [ctypes.c_int32]
    dll.VixHost_Disconnect.argtypes = [ctypes.c_int32]
    dll.Vix_FreeBuffer.argtypes = [ctypes.c_void_p]

    host = ctypes.c_int32(-1)
    vm = ctypes.c_int32(-1)
    try:
        job = dll.VixHost_Connect(-1, 3, None, 0, None, None, 0, -1, None, None)
        try:
            error = dll.VixJob_Wait(job, JOB_RESULT_HANDLE, ctypes.byref(host), 0)
        finally:
            dll.Vix_ReleaseHandle(job)
        if error:
            raise RuntimeError(f"VIX host connect failed: {error}")

        job = dll.VixHost_OpenVM(host, str(vmx).encode("utf-8"), 0, -1, None, None)
        try:
            error = dll.VixJob_Wait(job, JOB_RESULT_HANDLE, ctypes.byref(vm), 0)
        finally:
            dll.Vix_ReleaseHandle(job)
        if error:
            raise RuntimeError(f"VIX exact VM open failed: {error}")

        path_ptr = ctypes.c_void_p()
        power = ctypes.c_int32()
        try:
            error = dll.Vix_GetProperties(
                vm, VM_VMX_PATHNAME, ctypes.byref(path_ptr),
                VM_POWER_STATE, ctypes.byref(power), 0,
            )
            if error:
                raise RuntimeError(f"VIX property query failed: {error}")
            observed_path = Path(ctypes.string_at(path_ptr).decode("utf-8")).resolve(strict=True)
        finally:
            if path_ptr.value:
                dll.Vix_FreeBuffer(path_ptr)
        if observed_path != vmx:
            raise RuntimeError("VIX VM path did not match the requested VMX")
        running = ctypes.c_int32()
        running_error = dll.Vix_GetProperties(vm, VM_IS_RUNNING, ctypes.byref(running), 0)
        flags = power.value
        state = decode_power(flags, running.value, running_error)
        print(json.dumps({"vmx": str(vmx), "vix_power_flags": flags,
                          "vix_is_running": running.value if not running_error else None,
                          "vix_is_running_error": running_error, "state": state,
                          "fencing_evidence": False}))
        return 0 if state in {"powered_on", "powered_off"} else 2
    finally:
        if vm.value != -1:
            dll.Vix_ReleaseHandle(vm)
        if host.value != -1:
            dll.VixHost_Disconnect(host)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({"state": "unknown", "error": str(exc)}), file=sys.stderr)
        sys.exit(2)
