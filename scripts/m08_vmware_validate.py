"""Explicit disposable-VM Phase B validation, NOT canonical dispatch.

Only the installed VMware CLI, one known template, and newly owned full
clones are used. No unrelated VM/process inventory or security changes.
"""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(r"C:\ACP-SYNTHETIC-LAB")
TEMPLATE = ROOT / "template/acp-m08-ubuntu-template/acp-m08-ubuntu-template.vmx"
VMRUN = Path(r"C:\Program Files\VMware\VMware Workstation\vmrun.exe")
REPO = Path(__file__).resolve().parent.parent
GUEST = "/home/acpworker/work"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def config(vmx):
    if not __debug__:
        raise RuntimeError("Optimized host Python is unsupported; no weakened validation")
    values = {}
    for line in vmx.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        key, value = key.strip().lower(), value.strip().strip('"')
        if key in values:
            raise RuntimeError("Duplicate VMX key")
        values[key] = value
    for key in ("ethernet0.present", "vmci0.present", "floppy0.present", "ide1:0.present",
                "serial0.present", "usb.present", "ehci.present", "usb_xhci.present"):
        assert values.get(key, "").lower() == "false", key
    for key in ("isolation.tools.hgfs.disable", "isolation.tools.copy.disable",
                "isolation.tools.paste.disable", "isolation.tools.dnd.disable"):
        assert values.get(key, "").lower() == "true", key
    assert values.get("sharedfolder.maxnum") == "0"
    for key, value in values.items():
        if re.match(r"(?:ethernet\d+|sharedfolder\d+|usb\d+|parallel\d+).*", key):
            if key.endswith(("present", "enabled")):
                assert value.lower() == "false", key
    disk = vmx.parent / values["scsi0:0.filename"]
    assert disk.resolve(strict=True).parent == vmx.parent.resolve(strict=True)
    header = disk.open("rb").read(16384)
    assert b"parentFileNameHint" not in header
    return {"config_sha256": digest(vmx), "uuid": values.get("uuid.bios"),
            "disk": str(disk), "disk_file_id": disk.stat().st_ino,
            "integration_disabled": True, "no_nic": True}


class ProcessWitness:
    def __init__(self, vmx):
        if not __debug__:
            raise RuntimeError("Optimized host Python is unsupported; no weakened ownership checks")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.api.WaitForSingleObject.restype = wintypes.DWORD
        self.api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        self.api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        line = (vmx.parent / "vmware.log").read_text(encoding="utf-8").splitlines()[0]
        self.pid = int(re.search(r"Log for VMware Workstation pid=(\d+)", line)[1])
        self.handle = self.api.OpenProcess(0x100000 | 0x1000, False, self.pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        times = [wintypes.FILETIME() for _ in range(4)]
        if not self.api.GetProcessTimes(self.handle, *[ctypes.byref(t) for t in times]):
            raise ctypes.WinError(ctypes.get_last_error())
        self.created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        image = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(image))
        if not self.api.QueryFullProcessImageNameW(self.handle, 0, image, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        assert Path(image.value).resolve() == VMRUN.parent / "x64/vmware-vmx.exe"
        assert self.api.WaitForSingleObject(self.handle, 0) == 258

    def ceased(self):
        # Retained handle is identity, not a PID absence inference.
        return self.api.WaitForSingleObject(self.handle, 10000) == 0

    def close(self):
        self.api.CloseHandle(self.handle)


class Validation:
    def __init__(self):
        if not __debug__:
            raise RuntimeError("Optimized host Python is unsupported; no unchecked VM launch")
        self.run = ROOT / ("phase-b-" + uuid.uuid4().hex)
        self.run.mkdir()
        (self.run / "owned-by-m08.txt").write_text("disposable synthetic validation\n")
        self.events = []
        self.vms = []
        self.witnesses = {}
        self.report = {"run": str(self.run), "canonical_integration": False}

    def cli(self, operation, vmx, *args, guest=False, timeout=90, allow_failure=False):
        assert vmx.resolve().is_relative_to(ROOT.resolve())
        command = [str(VMRUN), "-T", "ws"]
        if guest:
            password = os.environ.get("ACP_M08_GUEST_PASSWORD")
            if not password:
                raise RuntimeError("Explicit disposable guest credential required; no credential discovery/fallback")
            command += ["-gu", "acpworker", "-gp", password]
        command += [operation, str(vmx), *map(str, args)]
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.events.append({"operation": operation, "vmx": str(vmx), "uncertain": True})
            raise RuntimeError("Transport/lifecycle timeout: no retry authorized")
        self.events.append({"operation": operation, "vmx": str(vmx), "exit": result.returncode,
                            "observed_at_unix": time.time()})
        if result.returncode and not allow_failure:
            raise RuntimeError(f"{operation}: {result.stdout.decode(errors='replace')} {result.stderr.decode(errors='replace')}")
        return result

    def observe(self, vmx):
        result = subprocess.run([sys.executable, "-B", str(REPO / "scripts/m08_vix_state.py"), str(vmx)],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError("EXECUTION_OWNERSHIP_UNCERTAIN: exact state unavailable")
        data = json.loads(result.stdout)
        self.events.append(data)
        return data

    def clone(self, name):
        directory = self.run / name
        directory.mkdir()
        vmx = directory / (name + ".vmx")
        self.cli("clone", TEMPLATE, vmx, "full", timeout=120)
        self.vms.append(vmx)
        config(vmx)
        return vmx

    def start(self, vmx):
        self.cli("start", vmx, "nogui")
        assert self.observe(vmx)["state"] == "powered_on", "Host API conformance failed"
        self.witnesses[vmx] = ProcessWitness(vmx)
        self.events.append({"vmx": str(vmx), "pid": self.witnesses[vmx].pid,
                            "creation_filetime": self.witnesses[vmx].created})
        self.cli("fileExistsInGuest", vmx, "/usr/bin/python3", guest=True)

    def prepare(self, vmx):
        script = f"mkdir -p {GUEST}/input {GUEST}/output {GUEST}/scratch {GUEST}/tools {GUEST}/transport /home/acpworker/sibling; printf 'approved input\\n' > {GUEST}/input/allowed-input.txt; printf 'original\\n' > {GUEST}/allowed.txt; printf 'forbidden\\n' > {GUEST}/forbidden.txt; printf 'sibling\\n' > /home/acpworker/sibling/canary.txt; printf 'synthetic credential\\n' > /home/acpworker/ungranted-credential.txt"
        self.cli("runScriptInGuest", vmx, "/bin/sh", script, guest=True)
        manifest = self.run / "hosttargets.json"
        self.cli("CopyFileFromHostToGuest", vmx, manifest, f"{GUEST}/input/hosttargets.json", guest=True)
        for source, dest in [("m08_guest_launcher.py", "tools/launcher.py"),
                             ("m08_guest_worker.py", "tools/worker.py"),
                             ("m08_guest_export.py", "transport/export.py")]:
            self.cli("CopyFileFromHostToGuest", vmx, REPO / "tests/fixtures" / source,
                     f"{GUEST}/{dest}", guest=True)

    def launch(self, vmx, mode, attempt):
        args = ["-noWait"] if mode == "tree" else []
        self.cli("runProgramInGuest", vmx, *args, "/usr/bin/python3", "-B",
                 f"{GUEST}/tools/launcher.py", f"{GUEST}/tools/worker.py", mode, attempt, guest=True,
                 allow_failure=mode == "probes")

    def export(self, vmx, name):
        self.cli("runProgramInGuest", vmx, "/usr/bin/python3", "-B",
                 f"{GUEST}/transport/export.py", name, guest=True)
        destination = self.run / (vmx.stem + "-" + name)
        assert not destination.exists()
        self.cli("CopyFileFromGuestToHost", vmx, f"{GUEST}/transport/{name}", destination, guest=True)
        assert destination.stat().st_size <= 65536
        return destination

    def fence(self, vmx):
        self.cli("stop", vmx, "hard")
        witness = self.witnesses[vmx]
        ceased = witness.ceased()
        observation = self.observe(vmx)
        if not ceased or observation["state"] != "powered_off":
            raise RuntimeError("EXECUTION_OWNERSHIP_UNCERTAIN: NO RETRY")
        self.events.append({"vmx": str(vmx), "process_handle_signaled": True,
                            "pid": witness.pid, "creation_filetime": witness.created,
                            "cli_jobs_reaped": True, "diagnostic_fence": True})
        witness.close()
        del self.witnesses[vmx]

    def execute(self):
        assert self.observe(TEMPLATE)["state"] == "powered_off"
        self.report["template"] = config(TEMPLATE)
        self.report["template"]["disk_sha256"] = digest(Path(self.report["template"]["disk"]))
        canaries = self.run / "canaries"
        canaries.mkdir()
        paths = []
        for name in ("sibling", "profile", "credentials"):
            path = canaries / name
            path.mkdir()
            path = path / "canary.txt"
            path.write_text("synthetic host canary " + name)
            paths.append(path)
        initial = {str(p): digest(p) for p in paths}
        (self.run / "hosttargets.json").write_text(json.dumps({p.parent.name: str(p) for p in paths}))
        a = self.clone("attempt-a")
        self.start(a)
        self.prepare(a)
        self.launch(a, "probes", "synthetic-a")
        output = json.loads(self.export(a, "probes.json").read_text())
        assert output["approved_write"] and output["approved_read"]["value"] == "approved input\n"
        for key, value in output.items():
            if isinstance(value, dict) and "denied" in value:
                assert value["denied"], key
        assert output["interfaces"] == ["lo"]
        assert "hgfs" not in output["mounts"]
        assert "NoNewPrivs:\t1" in output["kernel_status"]
        assert "Seccomp:\t2" in output["kernel_status"]
        self.report["probes"] = output
        self.report["launcher"] = json.loads(self.export(a, "launcher.json").read_text())
        self.launch(a, "tree", "synthetic-a")
        time.sleep(3)
        self.report["processes"] = json.loads(self.export(a, "processes.json").read_text())
        self.report["grandchild"] = json.loads(self.export(a, "grandchild.json").read_text())
        ticks = self.export(a, "ticks.txt").read_text()
        assert all(kind in ticks for kind in ("parent", "child", "grandchild"))
        self.report["a_identity"] = config(a)
        self.fence(a)
        self.report["a_fenced"] = True
        # New full clone, never old disks/outputs. This is physical isolation
        # evidence only, not canonical retry authorization or acceptance.
        b = self.clone("attempt-b")
        self.start(b)
        self.prepare(b)
        self.launch(b, "probes", "synthetic-b")
        retry_output = json.loads(self.export(b, "probes.json").read_text())
        assert retry_output["attempt"] == "synthetic-b"
        self.report["b_identity"] = config(b)
        assert self.report["a_identity"]["uuid"] != self.report["b_identity"]["uuid"]
        assert self.report["a_identity"]["disk_file_id"] != self.report["b_identity"]["disk_file_id"]
        self.fence(b)
        assert initial == {str(p): digest(p) for p in paths}
        self.report["host_canaries_unchanged"] = True
        self.report["physical_fresh_clone"] = True
        self.report["deterministic_vm_gate"] = "PASS"

    def finish(self):
        # Cleanup is exact owned clone only. Failure never authorizes retry.
        for vmx in list(self.witnesses):
            try:
                self.fence(vmx)
            except Exception as exc:
                self.events.append({"cleanup_failed": str(exc), "vmx": str(vmx)})
        self.report["events"] = self.events
        (self.run / "report.json").write_text(json.dumps(self.report, indent=2), encoding="utf-8")
        print(json.dumps({"report": str(self.run / "report.json"),
                          "gate": self.report.get("deterministic_vm_gate", "NOT PASSED"),
                          "error": self.report.get("error"), "live_witnesses": len(self.witnesses)}))


if __name__ == "__main__":
    validation = Validation()
    try:
        validation.execute()
    except Exception as exc:
        validation.report["error"] = str(exc)
        raise
    finally:
        validation.finish()
