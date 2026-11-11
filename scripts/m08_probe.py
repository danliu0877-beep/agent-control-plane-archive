"""Rejected-candidate diagnostic probe, not M08 acceptance or a worker runtime.

Creates synthetic fixtures only. Its per-case exit codes must be interpreted
with positive controls; a successful harness exit does not approve isolation.
See docs/validation/ACP-M08-isolation-red-gate.md before any future use.
"""
import json
import hashlib
import http.server
import os
import shutil
from pathlib import Path
import sys
import tempfile
import threading
import urllib.request
import zipfile
import uuid
import winreg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m08_windows_probe import WindowsBoundary


def main():
    root = Path(tempfile.mkdtemp(prefix="acp-m08-probe-"))
    workspace = root / "workspace"; workspace.mkdir()
    sibling = root / "sibling"; sibling.mkdir()
    allowed = workspace / "allowed.txt"; allowed.write_text("synthetic approved\n")
    forbidden = workspace / "forbidden.txt"; forbidden.write_text("synthetic forbidden\n")
    secret = sibling / "credential-canary.txt"; secret.write_text("M08-SYNTHETIC-NOT-A-SECRET\n")
    ambient = sibling / "package-readable-canary.txt"; ambient.write_text("M08-SYNTHETIC-AMBIENT-CANARY\n")
    restricted = sibling / "restricted-package-readable-canary.txt"; restricted.write_text("M08-SYNTHETIC-RESTRICTED-PACKAGE-CANARY\n")
    files = (allowed, forbidden, secret, ambient, restricted)
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    hits = []
    class Canary(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200); self.end_headers(); self.wfile.write(b"M08-SYNTHETIC")
        def log_message(self, *_):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Canary)
    server.daemon_threads = True
    serving = threading.Thread(target=server.serve_forever, daemon=True); serving.start()
    port = server.server_address[1]
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://127.0.0.1:{port}/controller", timeout=3) as response:
        assert response.read() == b"M08-SYNTHETIC"
    os.environ["M08_SECRET_CANARY"] = "SYNTHETIC-NOT-A-SECRET"
    registry_key = "Software\\ACP-M08-" + uuid.uuid4().hex
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_key) as key:
        winreg.SetValueEx(key, "canary", 0, winreg.REG_SZ, "M08-SYNTHETIC-REGISTRY-CANARY")
    exe = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    startup_only = "--startup-only" in sys.argv or "--powershell-startup-only" in sys.argv
    boundary = WindowsBoundary()
    result = {"fixture": str(root), "profile": boundary.profile, "sid": boundary.sid_text, "lpac_requested": "--lpac" in sys.argv, "registry_read_requested": "--registry-read" in sys.argv}
    try:
        print(json.dumps({"fixture": str(root), "startup_only": startup_only}), flush=True)
        boundary.grant(workspace, inherit=True)
        boundary.grant(allowed, writable=True)
        boundary.grant(ambient, fixture_all_packages=True)
        boundary.grant(restricted, fixture_restricted_packages=True)
        env = {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows", "TEMP": str(workspace), "TMP": str(workspace),
               "USERPROFILE": str(workspace), "LOCALAPPDATA": str(workspace), "APPDATA": str(workspace)}
        quote = lambda path: "'" + str(path).replace("'", "''") + "'"
        commands = {
            "approved_read": "Get-Content -LiteralPath " + quote(allowed) + " -ErrorAction Stop | Out-Null",
            "approved_write": "Add-Content -LiteralPath " + quote(allowed) + " -Value M08-WRITE -ErrorAction Stop",
            "forbidden_write": "Add-Content -LiteralPath " + quote(forbidden) + " -Value M08-WRITE -ErrorAction Stop",
            "sibling_read": "Get-Content -LiteralPath " + quote(secret) + " -ErrorAction Stop | Out-Null",
            "sibling_write": "Add-Content -LiteralPath " + quote(secret) + " -Value M08-WRITE -ErrorAction Stop",
            "ambient_package_read": "Get-Content -LiteralPath " + quote(ambient) + " -ErrorAction Stop",
            "restricted_package_read": "Get-Content -LiteralPath " + quote(restricted) + " -ErrorAction Stop",
            "environment": "if (Test-Path Env:M08_SECRET_CANARY) { exit 92 }",
            "language_diagnostic": "Write-Output $ExecutionContext.SessionState.LanguageMode",
            "tcp_loopback": f"Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:{port}/worker' -TimeoutSec 2 -ErrorAction Stop | Out-Null",
            "tcp_testnet": "Invoke-WebRequest -UseBasicParsing -Uri 'http://192.0.2.1:49199/m08-canary' -TimeoutSec 2 -ErrorAction Stop | Out-Null",
        }
        cases = {name: ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "try {" + command + "; exit 0} catch {$e=$_.Exception; while ($e.InnerException) {$e=$e.InnerException}; Write-Output $e.Message; if ($e.NativeErrorCode) {exit $e.NativeErrorCode}; exit ($e.HResult -band 65535)}"] for name, command in commands.items()}
        if "--cmd-filesystem" in sys.argv:
            assert not any(ch in str(root) for ch in ' &|<>^"'), "Fixture path unsupported by fixed cmd probe"
            exe = Path(r"C:\Windows\System32\cmd.exe")
            cases = {name: ["/d", "/c", "type", str(path)] for name, path in {
                "approved_read": allowed, "sibling_read": secret, "ambient_package_read": ambient,
                "restricted_package_read": restricted}.items()}
            cases.update({name: ["/d", "/c", "echo M08-WRITE>>" + str(path)] for name, path in {
                "approved_write": allowed, "forbidden_write": forbidden, "sibling_write": secret}.items()})
        if "--python-startup-only" in sys.argv or "--python-matrix" in sys.argv:
            runtime = root / "runtime"; runtime.mkdir()
            boundary.grant(runtime, inherit=True)
            source = Path(sys.executable).parent
            for name in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
                shutil.copy2(source / name, runtime / name)
            shutil.copytree(source / "DLLs", runtime / "DLLs")
            with zipfile.ZipFile(runtime / "python312.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for module in (source / "Lib").rglob("*.py"):
                    relative = module.relative_to(source / "Lib")
                    if not set(relative.parts) & {"site-packages", "test", "tests", "idlelib", "tkinter", "ensurepip"}:
                        archive.write(module, str(relative))
            shutil.copy2(Path(__file__).resolve().parents[1] / "tests/fixtures/m08_worker.py", runtime / "worker.py")
            for child in runtime.rglob("*"):
                boundary.grant(child, inherit=child.is_dir())
            exe = runtime / "python.exe"
            cases = {"python_startup": ["-I", "-S", "-B", "-c", "import os, socket, subprocess, ctypes; print('M08-LPAC-PYTHON'); print(os.name)"]}
            if "--python-matrix" in sys.argv:
                prefix = ["-I", "-S", "-B", str(runtime / "worker.py")]
                cases.update({name: prefix + ["read", str(path)] for name, path in {
                    "approved_read": allowed, "sibling_read": secret, "ambient_package_read": ambient,
                    "restricted_package_read": restricted}.items()})
                cases.update({name: prefix + ["write", str(path)] for name, path in {
                    "approved_write": allowed, "forbidden_write": forbidden, "sibling_write": secret}.items()})
                cases.update({"registry_canary": prefix + ["registry", registry_key],
                              "environment": prefix + ["environment"],
                              "tcp_loopback": prefix + ["tcp", "127.0.0.1", str(port)],
                              "udp_loopback": prefix + ["udp", "127.0.0.1", str(port)],
                              "tcp_testnet": prefix + ["tcp", "192.0.2.1", "49199"],
                              "udp_testnet": prefix + ["udp", "192.0.2.1", "49199"]})
        if "--curl-network" in sys.argv:
            exe = Path(r"C:\Windows\System32\curl.exe")
            cases = {"curl_startup": ["--disable", "--version"],
                     "curl_loopback": ["--disable", "--noproxy", "*", "--max-time", "3", f"http://127.0.0.1:{port}/worker"],
                     "curl_testnet": ["--disable", "--noproxy", "*", "--max-time", "3", "http://192.0.2.1:49199/m08-canary"]}
        if startup_only:
            exe = Path(r"C:\Windows\System32\cmd.exe")
            cases = {"signed_system_startup": ["/d", "/c", "exit", "0"]}
            if "--powershell-startup-only" in sys.argv:
                exe = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                cases = {"signed_powershell_startup": ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"]}
        for name, args in cases.items():
            log_path = root / (name + ".log")
            process = boundary.launch(exe, args, workspace, env, log_path=log_path, lpac="--lpac" in sys.argv, registry_read="--registry-read" in sys.argv)
            result[name] = boundary.wait(process)
            result[name + "_log"] = log_path.read_text(encoding="utf-8", errors="replace")[:1500]
        result["job_members_after"] = boundary.members()
        result["canary_hits"] = list(hits)
        result["file_changed"] = {str(p): before[str(p)] != hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        print(json.dumps(result, indent=2))
    finally:
        boundary.close()
        server.shutdown(); server.server_close(); serving.join(timeout=2)
        os.environ.pop("M08_SECRET_CANARY", None)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)


if __name__ == "__main__":
    main()
