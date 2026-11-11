"""Explicit real-worker harness, never discovered by the normal unit suite.

prepare creates ONLY a new disposable root. start/observe/cancel operate one
recorded scenario through fresh ACP CLI processes. No polling or auto-acceptance.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from acp.kandev import LIMITATIONS


def write(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def cli(root, *args):
    command = [sys.executable, "-B", "-m", "acp", "--data-dir", str(root / "state"),
               "--backend-config", str(root / "config.json"), "--actor", "principal-authorized-M03-fixture",
               "--source", "explicit-synthetic-integration", *args]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=120)
    record = {"command": command, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    evidence = root / "evidence"
    evidence.mkdir(exist_ok=True)
    write(evidence / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f") + ".json"), record)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout)


def prepare(root, connection):
    if root.exists():
        raise ValueError("Use a new disposable directory; no overwrite")
    root.mkdir(parents=True)
    repo = root / "repo"
    repo.mkdir()
    (repo / ".acp-synthetic").write_text("DISPOSABLE ACP M03\n", encoding="utf-8")
    (repo / "value.py").write_text("VALUE = 0\n", encoding="utf-8")
    (repo / "forbidden.txt").write_text("SYNTHETIC DO NOT CHANGE\n", encoding="utf-8")
    for args in (["init", "-b", "main"], ["add", "."], ["-c", "user.name=ACP Fixture", "-c", "user.email=fixture@invalid", "commit", "-m", "synthetic baseline"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    verifier = root / "verify.py"
    # No imports/evaluation of worker-controlled code. Deterministic source check.
    verifier.write_text("from pathlib import Path\nimport sys\np = Path(sys.argv[1])\nactual = (p / 'value.py').read_text(encoding='utf-8').strip()\nprint('expected VALUE = 42; actual:', actual)\nsys.exit(0 if actual == 'VALUE = 42' else 1)\n", encoding="utf-8")
    config = {**connection, "profile_name": "m03-disposable-agent", "backend_version": "0.95.0", "codex_acp_version": "1.12.0",
              "disposable_only": True, "synthetic_root": str(root), "repositories": [str(repo)], "limitations": LIMITATIONS,
              "verification": {"python": sys.executable, "script": str(verifier), "sha256": hashlib.sha256(verifier.read_bytes()).hexdigest()}}
    write(root / "config.json", config)
    project = cli(root, "project", "add", "--id", "m03-fixture", "--path", str(repo))
    write(root / "project.json", project)
    return project


def start(root, scenario):
    record_path = root / (scenario + ".json")
    if record_path.exists():
        raise ValueError("Scenario already allocated; observe/reconcile, never recreate")
    config = json.loads((root / "config.json").read_text())
    project = json.loads((root / "project.json").read_text())
    instruction = {"success": "Use apply_patch to replace value.py with exactly VALUE = 42 and a newline. Do not run commands or change other files. Report completion and stop.",
                   "negative": "Use apply_patch to replace value.py with exactly VALUE = 7 and a newline. This is an authorized negative test: the independent acceptance check expects 42 and must reject 7. Do not change any other files or run commands. Report completion and stop.",
                   "cancel": "Use apply_patch to replace value.py with exactly VALUE = 1 and a newline. Then run only PowerShell Start-Sleep -Seconds 180. Only after that command returns normally, use apply_patch to replace value.py with VALUE = 42. If cancelled, do not perform the final edit. No other commands/files."}[scenario]
    task = cli(root, "task", "create", "--project", project["id"], "--title", "M03 " + scenario, "--request", instruction)
    write(record_path, {"task": task["id"], "scenario": scenario})
    cli(root, "task", "transition", task["id"], "TRIAGE", "--reason", "Principal-authorized synthetic scenario")
    plan = {"task_revision": 1, "plan_revision": 1, "primary_project": project["id"], "repository_identity": project["repository_identity"],
            "base_commit": project["observed_head"], "context_manifest": {"source": "synthetic fixture", "files": ["value.py"]},
            "write_scope": ["value.py"], "forbidden_scope": ["forbidden.txt", ".acp-synthetic"], "allowed_operations": ["read", "write", "test"],
            "prohibited_operations": ["network", "credentials", "merge", "deploy", "push", "external_read"], "runtime_profile": config["profile_name"],
            "network_capability": "none", "credential_capability": "none", "risk_class": "low", "change_kind": "executable",
            "acceptance_criteria": [{"id": "checked", "description": "Independent scope and value verifier pass", "evidence_class": "independent_result", "trust": "independently_verified"}],
            "verification": config["verification"], "limitations_acknowledged": LIMITATIONS, "worker_instruction": instruction}
    write(root / (scenario + "-plan.json"), plan)
    cli(root, "task", "plan", task["id"], "--file", str(root / (scenario + "-plan.json")), "--reason", "Bounded synthetic contract")
    approval = cli(root, "approval", "record", "--task", task["id"], "--kind", "human", "--expires", (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat())
    cli(root, "task", "transition", task["id"], "READY", "--reason", "Explicit scenario approval")
    attempt = cli(root, "attempt", "create", "--task", task["id"], "--approval", approval["id"])
    write(record_path, {"task": task["id"], "attempt": attempt["id"], "scenario": scenario})
    return cli(root, "attempt", "submit", attempt["id"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "start", "observe", "collect", "verify", "cancel", "accept"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--connection", type=Path)
    parser.add_argument("--scenario", choices=["success", "negative", "cancel"], default="success")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.action == "prepare":
        result = prepare(root, json.loads(args.connection.read_text(encoding="utf-8-sig")))
    elif args.action == "start":
        result = start(root, args.scenario)
    else:
        scenario = json.loads((root / (args.scenario + ".json")).read_text())
        if args.action == "accept":
            result = cli(root, "attempt", "verify", scenario["attempt"])
            write(root / (args.scenario + "-accept.json"), {"checked": result["verification_evidence_id"]})
            result = cli(root, "task", "accept", scenario["task"], "--attempt", scenario["attempt"], "--file", str(root / (args.scenario + "-accept.json")), "--reason", "Explicit independent acceptance of synthetic result only")
        else:
            result = cli(root, "attempt", "reconcile" if args.action == "observe" else args.action, scenario["attempt"])
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
