"""Durable guarded execution coordination; no backend-native lifecycle types."""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess

from .adapters import Observation, Outcome
from .domain import ACPError, TERMINAL_ATTEMPTS, canonical_json, digest, identity, now, require, validate_envelope
from .guarded import repository_facts


def operate(runtime, attempt_id, operation, adapter, actor):
    from .controlled import bound_task
    require(not bound_task(runtime, runtime.store.one("execution_attempts", attempt_id)["task_id"]), "M06 attempt cannot use external execution")
    from . import isolation
    require(not isolation.bound_task(runtime, runtime.store.one("execution_attempts", attempt_id)["task_id"]), "M08 cannot bypass VMware isolation through legacy execution")
    require(actor.role in {"human", "controller"}, "Controller authority required")
    require(operation in {"submit", "snapshot", "reconcile", "cancel", "collect", "verify"}, "Unknown execution operation")
    db = runtime.db
    with runtime.store.transaction():
        attempt = runtime.store.one("execution_attempts", attempt_id)
        require(not attempt["quarantined"], "Quarantined output cannot be reused")
        contract = json.loads(attempt["contract_json"])
        require(digest(contract) == attempt["contract_digest"], "Immutable attempt digest mismatch")
        task = runtime.store.one("tasks", attempt["task_id"])
        project = runtime.store.one("projects", task["project_id"])
        envelope = {k: v for k, v in contract.items() if k != "approval_reference"}
        validate_envelope(envelope, task, project)
        require(task["envelope_json"] == canonical_json(envelope), "Attempt plan is stale")
        intent = db.execute("SELECT details_json FROM attempt_events WHERE attempt_id=? AND kind='DISPATCH_INTENT'", (attempt_id,)).fetchone()
        if intent:
            bound = json.loads(intent[0])
            require(bound["backend"] == adapter.name and bound["binding"] == adapter.binding, "Backend configuration cannot change within an attempt")
        authorized = runtime._check_attempt_authorization(attempt, actor)
    if not authorized and operation not in {"cancel", "collect", "snapshot", "reconcile"}:
        return runtime.attempt_show(attempt_id)
    key = attempt["idempotency_key"]
    if hasattr(adapter, "bind_context"):
        adapter.bind_context(contract, project)
    if operation == "submit":
        if intent:
            # Never re-issue a create after a crash, even if no mapping was stored.
            return operate(runtime, attempt_id, "reconcile", adapter, actor)
        require(attempt["state"] == "CREATED", "Only an unsubmitted attempt may dispatch")
        try:
            adapter.prepare(contract, project)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            with runtime.store.transaction():
                runtime._event("attempt_events", attempt_id, "ADMISSION_REJECTED", actor, str(exc))
                runtime._attempt_state(runtime.store.one("execution_attempts", attempt_id), "FAILED", actor, "Admission rejected before any worker dispatch")
                runtime._hold(attempt["task_id"], actor, "UNSUPPORTED_CAPABILITY" if "UNSUPPORTED_CAPABILITY" in str(exc) else "DISPATCH_REJECTED")
            return runtime.attempt_show(attempt_id)
        with runtime.store.transaction():
            fresh = runtime.store.one("execution_attempts", attempt_id)
            require(fresh["state"] == "CREATED", "Concurrent dispatch already owns attempt")
            if not runtime._check_attempt_authorization(fresh, actor):
                authorized = False
            else:
                runtime._event("attempt_events", attempt_id, "DISPATCH_INTENT", actor, "Persist before external side effect", details={"backend": adapter.name, "binding": adapter.binding, "adapter_version": adapter.adapter_version, "capabilities": adapter.config["limitations"]})
                runtime._attempt_state(fresh, "QUEUED", actor, "Durable submission intent")
        if not authorized:
            return runtime.attempt_show(attempt_id)
    else:
        require(intent is not None, "No guarded dispatch intent; nothing to reconcile")
    if operation == "cancel":
        with runtime.store.transaction():
            fresh = runtime.store.one("execution_attempts", attempt_id)
            require(fresh["state"] not in TERMINAL_ATTEMPTS, "Attempt already terminal")
            runtime._attempt_state(fresh, "CANCEL_REQUESTED", actor, "Durable cancellation intent before transport")
            runtime._hold(attempt["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")
    try:
        if operation == "collect":
            records = adapter.collect_evidence(key)
            with runtime.store.transaction():
                for record in records:
                    runtime._evidence(attempt["task_id"], attempt_id, record, actor)
            return runtime.attempt_show(attempt_id)
        if operation == "verify":
            return verify(runtime, attempt, contract, project, adapter, actor)
        response = (adapter.submit(contract, key) if operation == "submit" else
                    adapter.cancel(key) if operation == "cancel" else adapter.reconcile(key))
        if operation == "cancel" and hasattr(adapter, "inspect_cancellation"):
            inspection = adapter.inspect_cancellation(key)
            with runtime.store.transaction():
                runtime._evidence(attempt["task_id"], attempt_id, inspection, actor)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if operation in {"collect", "verify"}:
            with runtime.store.transaction():
                runtime._evidence(attempt["task_id"], attempt_id, {"class": "artifact", "trust": "observed",
                    "producer": "ACP", "producer_role": "controller", "collector": "ACP", "collection_method": operation,
                    "outcome": "unknown", "content": {"error": str(exc)}}, actor)
                runtime._hold(attempt["task_id"], actor, "EVIDENCE_UNAVAILABLE")
            return runtime.attempt_show(attempt_id)
        response = Observation(Outcome.UNKNOWN, detail={"error": str(exc), "operation": operation})
    with runtime.store.transaction():
        fresh = runtime.store.one("execution_attempts", attempt_id)
        authorized = runtime._check_attempt_authorization(fresh, actor)
        fresh = runtime.store.one("execution_attempts", attempt_id)
        observed = asdict(response)
        runtime._event("attempt_events", attempt_id, "ADAPTER_OBSERVATION", actor, operation, details=observed)
        previous = db.execute("SELECT * FROM backend_mappings WHERE attempt_id=?", (attempt_id,)).fetchone()
        if response.backend_task_id:
            if previous:
                require(previous["backend"] == adapter.name and previous["backend_task_id"] == response.backend_task_id, "Backend mapping conflict")
            else:
                db.execute("INSERT INTO backend_mappings VALUES (?,?,?,?,?,?,?,?,?)", (identity("MAP"), attempt_id, adapter.name, adapter.version, response.backend_task_id, response.backend_session_id, key, canonical_json(observed), now()))
        cancelled = db.execute("SELECT 1 FROM attempt_events WHERE attempt_id=? AND to_state='CANCEL_REQUESTED'", (attempt_id,)).fetchone()
        if fresh["state"] in TERMINAL_ATTEMPTS:
            # Late snapshots cannot reopen execution or alter accepted state.
            pass
        elif cancelled or not authorized:
            runtime._attempt_state(fresh, "CANCEL_REQUESTED", actor, "Cancellation/invalid authority retained; no stop proof", observed)
            runtime._hold(attempt["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")
        elif response.outcome != Outcome.OK or response.state is None:
            runtime._attempt_state(fresh, "LOST", actor, "Unknown external execution ownership", observed)
            runtime._hold(attempt["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")
        else:
            runtime._attempt_state(fresh, response.state, actor, "Normalized execution observation", observed)
            task = runtime.store.one("tasks", attempt["task_id"])
            if response.state == "SUCCEEDED" and task["state"] == "RUNNING":
                runtime._task_state(task, "REVIEW", actor, "Backend completion only; independent checks and explicit acceptance required")
    return runtime.attempt_show(attempt_id)


def verify(runtime, attempt, contract, project, adapter, actor):
    require(attempt["state"] == "SUCCEEDED", "Verification requires completed execution")
    workspace = adapter.workspace(attempt["idempotency_key"])
    facts = repository_facts(workspace, project["path"], contract)
    specification = contract["verification"]
    script = Path(specification["script"]).resolve(strict=True)
    require(not script.is_relative_to(workspace), "Verifier must be controller-owned, outside worker worktree")
    require(hashlib.sha256(script.read_bytes()).hexdigest() == specification["sha256"], "Verifier script digest changed")
    command = [specification["python"], "-I", "-B", str(script), str(workspace)]
    # The approved trusted verifier reads data; it must not import worker code.
    result = (subprocess.run(command, capture_output=True, timeout=30) if facts["pass"] else
              subprocess.CompletedProcess(command, 1, b"Skipped verifier because scope/base inspection failed", b""))
    output = {"stdout": result.stdout.decode("utf-8", "replace"), "stderr": result.stderr.decode("utf-8", "replace")}
    after = repository_facts(workspace, project["path"], contract)
    passed = facts["pass"] and result.returncode == 0 and facts == after
    with runtime.store.transaction():
        fact_id = runtime._evidence(attempt["task_id"], attempt["id"], {
            "class": "repository_fact", "trust": "observed", "producer": "ACP git inspector", "producer_role": "controller",
            "collector": "ACP", "collection_method": "independent git and filesystem inspection", "base_commit": contract["base_commit"],
            "outcome": "pass" if facts["pass"] else "fail", "content": facts}, actor)
        verification_id = runtime._evidence(attempt["task_id"], attempt["id"], {
            "class": "independent_result", "trust": "independently_verified", "producer": "ACP deterministic verifier", "producer_role": "controller",
            "collector": "ACP", "collection_method": "separate trusted verifier process", "verification_reference": fact_id,
            "base_commit": contract["base_commit"], "outcome": "pass" if passed else "fail", "exit_code": result.returncode,
            "content": {"command": command, "output": output, "output_digest": digest(output), "repository_unchanged_during_verification": facts == after}}, actor)
        runtime._event("attempt_events", attempt["id"], "GUARD_VERIFIED", actor, "Independent scope and deterministic test result", details={"pass": passed, "evidence_id": verification_id, "repository_evidence_id": fact_id})
        if not passed:
            runtime._hold(attempt["task_id"], actor, "INDEPENDENT_VERIFICATION_FAILED")
    return {"pass": passed, "repository_evidence_id": fact_id, "verification_evidence_id": verification_id}
