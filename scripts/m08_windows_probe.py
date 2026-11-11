"""Rejected M08 experimental primitives, NOT an ACP runtime or approved sandbox.

Only used by m08_probe.py with newly created synthetic fixtures. Known gaps
include ambient package ACL readability, incomplete setup cleanup hardening,
and no canonical immutable envelope, durable ownership or retry integration.
Do not import this into the canonical execution path.
"""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import subprocess
import time
import uuid

from acp.domain import require


class STARTUPINFO(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
                ("x", w.DWORD), ("y", w.DWORD), ("cx", w.DWORD), ("cy", w.DWORD),
                ("charsx", w.DWORD), ("charsy", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
                ("show", w.WORD), ("reserved2size", w.WORD), ("reserved2", c.c_void_p),
                ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]


class STARTUPINFOEX(c.Structure):
    _fields_ = [("startup", STARTUPINFO), ("attributes", c.c_void_p)]


class PROCESS_INFORMATION(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class SECURITY_CAPABILITIES(c.Structure):
    _fields_ = [("sid", c.c_void_p), ("capabilities", c.c_void_p), ("count", w.DWORD), ("reserved", w.DWORD)]


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [("sid", c.c_void_p), ("attributes", w.DWORD)]


class BASIC_LIMIT(c.Structure):
    _fields_ = [("process_time", c.c_longlong), ("job_time", c.c_longlong), ("flags", w.DWORD),
                ("min_ws", c.c_size_t), ("max_ws", c.c_size_t), ("active_limit", w.DWORD),
                ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class EXTENDED_LIMIT(c.Structure):
    _fields_ = [("basic", BASIC_LIMIT), ("io", c.c_ulonglong * 6), ("process_memory", c.c_size_t),
                ("job_memory", c.c_size_t), ("peak_process", c.c_size_t), ("peak_job", c.c_size_t)]


class WindowsBoundary:
    """Controller-owned handles. No worker receives a job/profile API handle."""
    def __init__(self):
        require(os.name == "nt", "Windows isolation unavailable")
        self.k = c.WinDLL("kernel32", use_last_error=True)
        self.a = c.WinDLL("advapi32", use_last_error=True)
        self.u = c.WinDLL("userenv", use_last_error=True)
        self.profile = "acp.m08." + uuid.uuid4().hex
        self.sid = c.c_void_p()
        self.job = None
        self.processes = []
        self._signatures()
        hr = self.u.CreateAppContainerProfile(self.profile, self.profile, "ACP M08 disposable boundary", None, 0, c.byref(self.sid))
        if hr < 0:
            raise OSError(hr, "CreateAppContainerProfile failed")
        self.sid_text = self.sid_string(self.sid)
        self.job_name = "Local\\ACP-M08-" + uuid.uuid4().hex
        self.job = self.k.CreateJobObjectW(None, self.job_name)
        self.check(self.job)
        limits = EXTENDED_LIMIT()
        limits.basic.flags = 0x2000 | 0x8 # KILL_ON_JOB_CLOSE, ACTIVE_PROCESS; no breakaway
        limits.basic.active_limit = 16
        self.check(self.k.SetInformationJobObject(self.job, 9, c.byref(limits), c.sizeof(limits)))

    def _signatures(self):
        specs = [
            (self.u, "CreateAppContainerProfile", [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)], c.c_long),
            (self.u, "DeleteAppContainerProfile", [w.LPCWSTR], c.c_long),
            (self.k, "CreateJobObjectW", [c.c_void_p, w.LPCWSTR], w.HANDLE),
            (self.k, "SetInformationJobObject", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
            (self.k, "QueryInformationJobObject", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL),
            (self.k, "AssignProcessToJobObject", [w.HANDLE, w.HANDLE], w.BOOL),
            (self.k, "IsProcessInJob", [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
            (self.k, "TerminateJobObject", [w.HANDLE, w.UINT], w.BOOL),
            (self.k, "TerminateProcess", [w.HANDLE, w.UINT], w.BOOL),
            (self.k, "WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD),
            (self.k, "GetExitCodeProcess", [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
            (self.k, "CloseHandle", [w.HANDLE], w.BOOL),
            (self.k, "ResumeThread", [w.HANDLE], w.DWORD),
            (self.k, "InitializeProcThreadAttributeList", [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL),
            (self.k, "UpdateProcThreadAttribute", [c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p], w.BOOL),
            (self.k, "DeleteProcThreadAttributeList", [c.c_void_p], None),
            (self.k, "CreateProcessW", [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD, c.c_void_p, w.LPCWSTR, c.c_void_p, c.c_void_p], w.BOOL),
            (self.k, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
            (self.k, "LocalFree", [c.c_void_p], c.c_void_p),
            (self.a, "ConvertSidToStringSidW", [c.c_void_p, c.POINTER(w.LPWSTR)], w.BOOL),
            (self.a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p], w.BOOL),
            (self.a, "SetFileSecurityW", [w.LPCWSTR, w.DWORD, c.c_void_p], w.BOOL),
            (self.a, "OpenProcessToken", [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL),
            (self.a, "GetTokenInformation", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
            (self.a, "FreeSid", [c.c_void_p], c.c_void_p),
        ]
        for library, name, args, result in specs:
            function = getattr(library, name); function.argtypes = args; function.restype = result

    @staticmethod
    def check(ok):
        if not ok:
            raise c.WinError(c.get_last_error())
        return ok

    def sid_string(self, sid):
        value = w.LPWSTR()
        self.check(self.a.ConvertSidToStringSidW(sid, c.byref(value)))
        try:
            return value.value
        finally:
            self.k.LocalFree(value)

    def token(self, process):
        token = w.HANDLE()
        self.check(self.a.OpenProcessToken(process, 8, c.byref(token)))
        try:
            yes = w.DWORD(); size = w.DWORD()
            self.check(self.a.GetTokenInformation(token, 29, c.byref(yes), c.sizeof(yes), c.byref(size)))
            self.a.GetTokenInformation(token, 31, None, 0, c.byref(size))
            buffer = c.create_string_buffer(size.value)
            self.check(self.a.GetTokenInformation(token, 31, buffer, size.value, c.byref(size)))
            sid = c.c_void_p.from_buffer(buffer)
            return {"appcontainer": bool(yes.value), "sid": self.sid_string(sid) if sid.value else None}
        finally:
            self.k.CloseHandle(token)

    def grant(self, path, *, writable=False, inherit=False, fixture_all_packages=False, fixture_restricted_packages=False):
        """Only caller-owned M08 fixture targets; never host-wide ACL mutation."""
        target = Path(path).resolve()
        require(any(part.startswith("acp-m08-") for part in target.parts), "Only M08 fixture ACL changes permitted")
        # Preserve ordinary controller access through owner/system/admin; package
        # access is explicitly limited and never includes WRITE_DAC/WRITE_OWNER.
        flags = "OICI" if inherit else ""
        rights = "0x12019f" if writable else "0x1200a9"
        sid = "S-1-15-2-1" if fixture_all_packages else self.sid_text
        if fixture_restricted_packages:
            sid = "S-1-15-2-2"
        sddl = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;" + flags + ";" + rights + ";;;" + sid + ")"
        descriptor = c.c_void_p()
        self.check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(descriptor), None))
        try:
            self.check(self.a.SetFileSecurityW(str(target), 4 | 0x80000000, descriptor))
        finally:
            self.k.LocalFree(descriptor)

    def launch(self, executable, arguments, cwd, environment, *, log_path=None, lpac=False, registry_read=False):
        require(self.job is not None, "Job unavailable")
        require(set(environment) <= {"SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "USERPROFILE", "LOCALAPPDATA", "APPDATA"}, "Environment allowlist")
        size = c.c_size_t()
        count = (2 if log_path else 1) + int(lpac)
        self.k.InitializeProcThreadAttributeList(None, count, 0, c.byref(size))
        attributes = c.create_string_buffer(size.value)
        self.check(self.k.InitializeProcThreadAttributeList(attributes, count, 0, c.byref(size)))
        caps = SECURITY_CAPABILITIES(self.sid, None, 0, 0)
        allocated = []
        if registry_read:
            library = c.WinDLL("api-ms-win-security-base-l1-2-2", use_last_error=True)
            derive = library.DeriveCapabilitySidsFromName
            derive.argtypes = [w.LPCWSTR, c.POINTER(c.POINTER(c.c_void_p)), c.POINTER(w.DWORD), c.POINTER(c.POINTER(c.c_void_p)), c.POINTER(w.DWORD)]
            derive.restype = c.c_long
            groups = c.POINTER(c.c_void_p)(); group_count = w.DWORD()
            capabilities = c.POINTER(c.c_void_p)(); cap_count = w.DWORD()
            hr = derive("registryRead", c.byref(groups), c.byref(group_count), c.byref(capabilities), c.byref(cap_count))
            require(hr >= 0 and cap_count.value > 0, "registryRead capability unavailable")
            cap_entries = (SID_AND_ATTRIBUTES * cap_count.value)(*[SID_AND_ATTRIBUTES(capabilities[i], 4) for i in range(cap_count.value)])
            caps.capabilities = c.cast(cap_entries, c.c_void_p); caps.count = cap_count.value
            allocated = [groups[i] for i in range(group_count.value)] + [capabilities[i] for i in range(cap_count.value)] + [groups, capabilities]
        self.check(self.k.UpdateProcThreadAttribute(attributes, 0, 0x20009, c.byref(caps), c.sizeof(caps), None, None))
        package_policy = w.DWORD(1) # PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
        if lpac:
            self.check(self.k.UpdateProcThreadAttribute(attributes, 0, 0x2000f, c.byref(package_policy), c.sizeof(package_policy), None, None))
        startup = STARTUPINFOEX(); startup.startup.cb = c.sizeof(startup); startup.attributes = c.cast(attributes, c.c_void_p)
        log = None
        if log_path:
            require(any(part.startswith("acp-m08-") for part in Path(log_path).resolve().parts), "Only M08 fixture log handle allowed")
            security = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), None, True)
            log = self.k.CreateFileW(str(log_path), 0x40000000, 3, c.byref(security), 2, 0x80, None)
            require(log not in (None, c.c_void_p(-1).value), "Fixture log creation failed")
            handles = (w.HANDLE * 1)(log)
            self.check(self.k.UpdateProcThreadAttribute(attributes, 0, 0x20002, handles, c.sizeof(handles), None, None))
            startup.startup.flags = 0x100
            startup.startup.stdout = log; startup.startup.stderr = log
        info = PROCESS_INFORMATION()
        command = c.create_unicode_buffer(subprocess.list2cmdline([str(executable), *map(str, arguments)]))
        env = c.create_unicode_buffer("\0".join(k + "=" + v for k, v in sorted(environment.items())) + "\0\0")
        try:
            self.check(self.k.CreateProcessW(str(executable), command, None, None, bool(log), 0x80000 | 0x400 | 0x4 | 0x08000000,
                                            env, str(cwd), c.byref(startup), c.byref(info)))
            self.processes.append(info)
            try:
                self.check(self.k.AssignProcessToJobObject(self.job, info.process))
                member = w.BOOL()
                self.check(self.k.IsProcessInJob(info.process, self.job, c.byref(member)))
                security = self.token(info.process)
                require(member.value and security == {"appcontainer": True, "sid": self.sid_text}, "Isolation token/job mismatch")
                require(self.k.ResumeThread(info.thread) != 0xffffffff, "Resume failed")
                return info
            except BaseException:
                self.k.TerminateProcess(info.process, 90)
                raise
        finally:
            self.k.DeleteProcThreadAttributeList(attributes)
            if log:
                self.k.CloseHandle(log)
            for pointer in allocated:
                self.k.LocalFree(pointer)

    def wait(self, info, milliseconds=10000):
        require(self.k.WaitForSingleObject(info.process, milliseconds) == 0, "Worker wait incomplete")
        result = w.DWORD(); self.check(self.k.GetExitCodeProcess(info.process, c.byref(result)))
        return result.value

    def members(self):
        buffer = c.create_string_buffer(8 + 16 * c.sizeof(c.c_size_t))
        self.check(self.k.QueryInformationJobObject(self.job, 3, buffer, c.sizeof(buffer), None))
        count = w.DWORD.from_buffer(buffer, 4).value
        return [c.c_size_t.from_buffer(buffer, 8 + i * c.sizeof(c.c_size_t)).value for i in range(count)]

    def stop(self):
        self.check(self.k.TerminateJobObject(self.job, 91))
        for info in self.processes:
            self.k.WaitForSingleObject(info.process, 10000)
        deadline = time.monotonic() + 5
        while self.members() and time.monotonic() < deadline:
            time.sleep(0.02)
        require(not self.members(), "Whole job cessation not yet observed")

    def close(self):
        if self.job:
            self.stop(); self.k.CloseHandle(self.job); self.job = None
        for info in self.processes:
            self.k.CloseHandle(info.thread); self.k.CloseHandle(info.process)
        self.processes.clear()
        if self.sid.value:
            self.a.FreeSid(self.sid); self.sid = c.c_void_p()
            hr = self.u.DeleteAppContainerProfile(self.profile)
            if hr < 0:
                raise OSError(hr, "Disposable profile cleanup failed")
