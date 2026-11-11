"""Real synthetic VM + canonical SQLite acceptance/recovery harness.

Explicit manual invocation only. Never executes a real managed project.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

# Running a saved script must use the calling source checkout, not another ACP.
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from acp import context, isolation, planning
from acp.decision_provider import SyntheticDecisionProvider
from acp.domain import ACPError, Actor, canonical_json, identity
from acp.runtime import Runtime
from acp.vmware_host import VMwareHost, ROOT
from tests.test_planning import fixture

HUMAN = Actor("M08 Principal", "human", "synthetic validation")
CONTROL = Actor("M08 host controller", "controller", "synthetic validation")


def setup():
    root = ROOT / ("canonical-" + uuid.uuid4().hex)
    root.mkdir()
    (root / "owned-by-m08.txt").write_text("synthetic canonical validation\n")
    canaries = {}
    for category in ("sibling", "profile", "credentials"):
        directory = root / "canaries" / category
        directory.mkdir(parents=True)
        path = directory / "canary.txt"
        path.write_text("synthetic host " + category, newline="\n")
        canaries[category] = str(path)
    (root / "hosttargets.json").write_text(json.dumps(canaries))
    repo = root / "synthetic-project"
    repo.mkdir()
    (repo / "STATUS.md").write_text(isolation.SYNTHETIC_STATUS, newline="\n")
    runtime = Runtime(root / "canonical-state")
    runtime.project_add("demo", repo)
    task = runtime.task_create("demo", "synthetic", "M08 disposable isolation proof", HUMAN)["id"]
    ctx = context.load(runtime, "demo", HUMAN)["id"]
    proposal = fixture()
    assessment = {"state": "NONE", "evaluated": True, "rationale": "The disposable fixture resolves no real project or business decision", "sources": ["STATUS.md"]}
    proposal["human_assessment"] = copy.deepcopy(assessment)
    proposal["work_items"][0].update(work_type="documentation", proposed_write_scope=["allowed.txt"],
        forbidden_scope=["forbidden.txt"], allowed_operations=["inspect_context", "analyze", "propose_edit"],
        execution_risk="R1", human_assessment=assessment, human_approval_required=True, suggested_profile="future_isolated_write")
    run = planning.prepare(runtime, task, ctx, HUMAN, test_only=True)
    result = planning.complete(runtime, run["run_id"], SyntheticDecisionProvider(json.dumps(proposal), testing=True), HUMAN)
    plan = planning.show(runtime, result["plan_id"])
    host = VMwareHost(root)
    binding = isolation.materialize(runtime, plan["plan_id"], plan["plan_revision"], plan["work_items"][0]["work_item_id"], host.template(), HUMAN)
    approval = runtime.approve(binding["task_id"], "human", HUMAN, "2099-01-01T00:00:00+00:00")
    runtime.transition(binding["task_id"], "READY", HUMAN, "Exact synthetic-only approval")
    return root, runtime, host, binding, approval


def fresh_readback(root, attempt):
    code = "from acp.runtime import Runtime; from acp.isolation import recover; from acp.domain import Actor; import sys,json; r=Runtime(sys.argv[1]); print(json.dumps(recover(r,sys.argv[2],Actor('fresh-controller','controller','synthetic')))); r.close()"
    run = subprocess.run([sys.executable, "-B", "-c", code, str(root / "canonical-state"), attempt], cwd=REPO, capture_output=True, timeout=30)
    if run.returncode:
        raise RuntimeError(run.stderr.decode(errors="replace"))
    return json.loads(run.stdout)


def resumed_fence(root, attempt):
    # A separate OS controller process reopens the live VMX creation identity,
    # then establishes independent cessation and persists its receipt.
    code = "from acp.runtime import Runtime; from acp.isolation import operation,record_fence; from acp.vmware_host import VMwareHost; from acp.domain import Actor; import sys,json; r=Runtime(sys.argv[1]); h=VMwareHost(sys.argv[2]); a=Actor('resumed-controller','controller','synthetic'); operation(r,sys.argv[3],'stop',h,a); print(json.dumps(record_fence(r,sys.argv[3],a))); h.close(); r.close()"
    run = subprocess.run([sys.executable, "-B", "-c", code, str(root / "canonical-state"), str(root), attempt], cwd=REPO, capture_output=True, timeout=90)
    if run.returncode:
        raise RuntimeError(run.stderr.decode(errors="replace"))
    return json.loads(run.stdout)


def main():
    os.environ["ACP_M08_SYNTHETIC_SECRET"] = "synthetic-host-env-canary-only"
    root, runtime, host, binding, approval = setup()
    report = {"root": str(root), "sqlite": str(runtime.store.path), "binding": binding["id"], "real_agent": False}
    active = None
    try:
        old = runtime.attempt_create(binding["task_id"], approval["id"], CONTROL)["id"]
        active = old
        isolation.reserve(runtime, old, host, CONTROL)
        for name in ("clone", "start", "prepare", "probes", "tree"):
            isolation.operation(runtime, old, name, host, CONTROL)
        time.sleep(2)
        owned = isolation.instance(runtime, old)
        # Actual process artifacts are supporting data, not cessation proof.
        report["processes"] = json.loads(host.probe.export(Path(owned["vmx"]), "processes.json").read_text())
        report["grandchild"] = json.loads(host.probe.export(Path(owned["vmx"]), "grandchild.json").read_text())
        ticks = host.probe.export(Path(owned["vmx"]), "ticks.txt").read_text()
        assert all(kind in ticks for kind in ("parent", "child", "grandchild"))
        host.close()
        runtime.close()
        running = fresh_readback(root, old)
        assert running["disposition"] == "HOST_RECONCILIATION_REQUIRED" and not running["retry_eligible"]
        runtime = Runtime(root / "canonical-state")
        host = VMwareHost(root)
        isolation.cancel(runtime, old, CONTROL)
        isolation.observe(runtime, old, "CANCEL_ACKNOWLEDGED", {"ack_only_not_cessation": True}, CONTROL)
        runtime.close()
        uncertain = fresh_readback(root, old)
        assert not uncertain["retry_eligible"] and not uncertain["automatic_retry"]
        runtime = Runtime(root / "canonical-state")
        try:
            runtime.resolve_hold(binding["task_id"], CONTROL, "uncertain retry negative test", retry_ready=True)
            raise AssertionError("Uncertain retry authorized")
        except ACPError:
            report["uncertain_retry"] = "DENIED"
        # Fault injection: off/ACK without handle evidence cannot fence.
        try:
            isolation.record_fence(runtime, old, CONTROL)
            raise AssertionError("ACK-only fence authorized")
        except ACPError:
            report["ack_only_fence"] = "DENIED"
        runtime.close()
        report["fence"] = resumed_fence(root, old)
        active = None
        fenced = fresh_readback(root, old)
        assert fenced["disposition"] == "FENCED" and fenced["retry_eligible"]
        runtime = Runtime(root / "canonical-state")
        runtime.resolve_hold(binding["task_id"], CONTROL, "Proven VM fence; fresh clone only", retry_ready=True)
        code = "from acp.runtime import Runtime; from acp.domain import Actor; import sys; r=Runtime(sys.argv[1]); print(r.attempt_create(sys.argv[2],sys.argv[3],Actor('candidate','controller','synthetic'))['id']); r.close()"
        command = [sys.executable, "-B", "-c", code, str(root / "canonical-state"), binding["task_id"], approval["id"]]
        controllers = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO) for _ in range(2)]
        outputs = [p.communicate(timeout=30) for p in controllers]
        assert sum(p.returncode == 0 for p in controllers) == 1
        new = next(out[0].decode().strip() for p, out in zip(controllers, outputs) if p.returncode == 0)
        report["concurrent_retry"] = {"controllers": 2, "allocated": 1}
        runtime.close()
        runtime = Runtime(root / "canonical-state")
        assert runtime.db.execute("SELECT candidate_attempt FROM isolation_retries WHERE previous_attempt=?", (old,)).fetchone()[0] == new
        host = VMwareHost(root)
        fresh = isolation.reserve(runtime, new, host, CONTROL)
        assert fresh["workspace"] != owned["workspace"]
        late = isolation.quarantine(runtime, old, {"attempt_id": old, "raw_old_probe_path": str(root / (owned["id"] + "-probes.json")), "late_payload": "OLD SYNTHETIC RESULT"}, CONTROL)
        assert late["attempt_id"] == old and not late["detail"]["acceptance_eligible"]
        active = new
        for name in ("clone", "start", "prepare", "probes", "stop"):
            isolation.operation(runtime, new, name, host, CONTROL)
        active = None
        old_start = next(o["detail"]["result"]["config"] for o in isolation.facts(runtime, old)["observations"] if o["kind"] == "OPERATION_COMPLETED" and o["detail"]["operation"] == "start")
        new_start = next(o["detail"]["result"]["config"] for o in isolation.facts(runtime, new)["observations"] if o["kind"] == "OPERATION_COMPLETED" and o["detail"]["operation"] == "start")
        assert old_start["uuid"] != new_start["uuid"] and old_start["disk_file_id"] != new_start["disk_file_id"] and old_start["disk"] != new_start["disk"]
        report["fresh_vm_disk_identity"] = {"old": old_start, "new": new_start, "distinct": True}
        evidence = isolation.complete(runtime, new, CONTROL)
        assert runtime.task_show(binding["task_id"])["state"] == "REVIEW"
        try:
            runtime.accept(binding["task_id"], new, {"synthetic-write": report["fence"]["evidence_id"]}, HUMAN, "old evidence negative test")
            raise AssertionError("Old evidence satisfied new attempt")
        except ACPError:
            report["old_output_acceptance"] = "DENIED"
        runtime.accept(binding["task_id"], new, {"synthetic-write": evidence}, HUMAN, "Independent synthetic-only bounded acceptance")
        report.update(result="PASS", running_restart="PASS", uncertain_restart="PASS", fenced_restart="PASS",
            candidate_restart="PASS", fresh_vm_retry="PASS", late_quarantine="PASS", task_state=runtime.task_show(binding["task_id"])["state"],
            old_attempt=old, new_attempt=new, old_instance=owned, new_instance=fresh,
            final_readback=isolation.facts(runtime, new), old_readback=isolation.facts(runtime, old))
        # Old VM cleanup only, after its durable fence. New stopped accepted VM
        # is retained as evidence; it is never reused or automatically restarted.
        isolation.operation(runtime, old, "destroy", host, CONTROL)
        report["old_vm_destroyed"] = True
    except BaseException as exc:
        report["result"], report["error"] = "NOT PASSED", str(exc)
        raise
    finally:
        if active:
            # Best-effort exact owned cleanup, never a replacement fence fact.
            try:
                saved = isolation.facts(runtime, active)
                vmx = Path(saved["instance"]["vmx"])
                if vmx.exists():
                    host.probe.cli("stop", vmx, "hard")
                report["failure_cleanup_stop_requested"] = True
            except Exception as exc:
                report["cleanup_error"] = str(exc)
        host.close()
        runtime.close()
        destination = root / "integration-report.json"
        destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"report": str(destination), "result": report.get("result"), "error": report.get("error")}))


if __name__ == "__main__":
    main()
