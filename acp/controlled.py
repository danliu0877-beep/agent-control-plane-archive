"""M06: explicit synthetic, in-process execution over immutable supplied text only.

No executor plugins, shell, filesystem, network, workers, retries or acceptance.
The trusted controller owns SQLite; executor inputs carry no runtime capability.
"""
import copy
import json

from . import context, planning
from .domain import ACPError, canonical_json, digest, identity, now, require


EXECUTORS = frozenset({"synthetic-inspect-v1", "synthetic-fail-v1", "synthetic-reject-v1"})


def bound_task(runtime, task_id):
    return runtime.db.execute("SELECT * FROM execution_bindings WHERE task_id=?", (task_id,)).fetchone()


def _source(runtime, plan_id, revision, work_id):
    require(type(revision) is int and revision > 0, "Exact M05 revision required")
    plan = planning.show(runtime, plan_id, revision)
    from . import dag
    require(not dag.enrolled(runtime, plan_id, revision, work_id), 'M09 execution requires the M08 isolation path; no M06 fallback')
    # Compare eligibility only; never replace the selected revision with latest.
    latest = runtime.db.execute("SELECT max(revision) FROM plan_revisions WHERE plan_id=?", (plan_id,)).fetchone()[0]
    require(latest == revision, "STALE_AUTHORIZATION: source revision superseded")
    require(plan["test_only"] is True, "M06 requires an explicit test-only plan; no real execution fallback")
    require(plan["status"] == "READY_FOR_REVIEW" and not plan["decisions"] and not plan["context_requests"], "Unresolved plan hold")
    require(plan["human_assessment"]["state"] == "NONE" and plan["human_assessment"]["evaluated"], "Human assessment not cleared")
    items = [w for w in plan["work_items"] if w["work_item_id"] == work_id]
    require(len(items) == 1, "WorkItem does not belong to selected PlanRevision")
    work = items[0]
    require(work["primary_project"] == plan["primary_project"] and not plan["cross_project"], "Cross-project execution deferred")
    require(not work["dependencies"], "Dependency execution/acceptance deferred")
    require(work["human_assessment"]["state"] == "NONE" and work["human_assessment"]["evaluated"] and not work["human_approval_required"], "Unresolved work assessment")
    require(work["execution_risk"] == "R0" and work["work_type"] == "analysis" and not work["proposed_write_scope"], "M06 is non-writing analysis only")
    require("inspect_context" in work["allowed_operations"] and set(work["allowed_operations"]) <= {"inspect_context", "analyze", "synthesize"}, "Unsupported planning operation")
    project = runtime.store.one("projects", plan["primary_project"])
    require(project["enabled"], "Project disabled")
    source_task = runtime.store.one("tasks", plan["task_id"])
    require(source_task["state"] in {"NEW", "TRIAGE", "PLANNED"}, "Source task not eligible")
    package = context.get(runtime, plan["context_id"])
    require(package["package_digest"] == plan["context_digest"] and package["status"] != "BLOCKED", "Context binding mismatch")
    require(package["project"]["project"]["repository_identity"] == project["repository_identity"], "Repository identity mismatch")
    scope = work["current_read_scope"]
    require(not any(planning.covered(name, work["forbidden_scope"]) for name in scope), "Read scope overlaps forbidden scope")
    materials = [m for m in package["materials"] if m["relative_path"] in scope]
    require(len(materials) == len(scope) and bool(materials), "Missing approved source material")
    return plan, work, project, materials


def materialize(runtime, plan_id, revision, work_id, executor, actor):
    require(actor.role == "human", "Explicit human materialization required")
    require(executor in EXECUTORS, "Unsupported executor; no fallback")
    with runtime.store.transaction():
        plan, work, project, materials = _source(runtime, plan_id, revision, work_id)
        existing = runtime.db.execute("SELECT * FROM execution_bindings WHERE plan_id=? AND plan_revision=? AND work_item_id=?", (plan_id, revision, work_id)).fetchone()
        if existing:
            require(json.loads(existing["record_json"])["executor"] == executor, "No automatic executor rebinding")
            binding_id = existing["id"]
        else:
            binding_id, task_id, at = identity("BIND"), identity("TASK"), now()
            record = {"binding_id": binding_id, "task_id": task_id, "source_task_id": plan["task_id"],
                      "plan_id": plan_id, "plan_revision": revision, "plan_digest": plan["plan_digest"],
                      "work_item_id": work_id, "context_id": plan["context_id"], "context_digest": plan["context_digest"],
                      "executor": executor, "mapping_version": "m06-inspect-context-v1", "payload": materials,
                      "read_scope": work["current_read_scope"], "source_acceptance": work["acceptance"],
                      "required_evidence": work["required_evidence"], "created_at": at, "actor": actor.record()}
            envelope = {"task_revision": 1, "plan_revision": 1, "primary_project": project["id"],
                        "repository_identity": project["repository_identity"], "base_commit": plan["observed_head"],
                        "context_manifest": {"source": plan["context_id"], "files": work["current_read_scope"]},
                        "write_scope": [], "forbidden_scope": work["forbidden_scope"],
                        "allowed_operations": ["read"], "prohibited_operations": ["write", "shell", "network"],
                        "runtime_profile": executor, "network_capability": "none", "credential_capability": "none",
                        "risk_class": "low", "change_kind": "read_only", "controlled_binding": binding_id,
                        "binding_digest": digest(record), "acceptance_criteria": [{"id": "synthetic-observation",
                        "description": "Observe only the supplied synthetic context; no project findings or task acceptance",
                        "evidence_class": "artifact", "trust": "observed"}]}
            runtime.db.execute("INSERT INTO tasks (id,project_id,title,request,state,created_at,updated_at) VALUES (?,?,?,?,'NEW',?,?)",
                               (task_id, project["id"], "M06 synthetic context inspection", work["objective"], at, at))
            runtime._event("task_events", task_id, "CREATED", actor, "Explicit M05 work-item materialization; not authorization", after="NEW", details={"binding_id": binding_id})
            runtime._task_state(runtime.store.one("tasks", task_id), "TRIAGE", actor, "Bounded synthetic mapping")
            runtime.db.execute("UPDATE tasks SET envelope_json=?,plan_revision=1 WHERE id=?", (canonical_json(envelope), task_id))
            runtime._task_state(runtime.store.one("tasks", task_id), "PLANNED", actor, "Separate approval still required")
            runtime.db.execute("INSERT INTO execution_bindings VALUES (?,?,?,?,?,?,?,?,?)", (binding_id, task_id, plan_id, revision, work_id, canonical_json(record), digest(record), canonical_json(envelope), digest(envelope)))
    return binding_show(runtime, binding_id)


def binding_show(runtime, binding_id):
    row = runtime.db.execute("SELECT * FROM execution_bindings WHERE id=?", (binding_id,)).fetchone()
    require(row is not None, "Unknown execution binding")
    record, envelope = json.loads(row["record_json"]), json.loads(row["envelope_json"])
    require(digest(record) == row["digest"] and digest(envelope) == row["envelope_digest"], "Execution binding digest mismatch")
    return {"binding": record, "binding_digest": row["digest"], "envelope": envelope}


def validate_task(runtime, task):
    row = bound_task(runtime, task["id"])
    require(row is not None, "Missing immutable execution binding")
    saved = binding_show(runtime, row["id"])
    record = saved["binding"]
    plan, _, _, materials = _source(runtime, record["plan_id"], record["plan_revision"], record["work_item_id"])
    require(plan["plan_digest"] == record["plan_digest"] and canonical_json(materials) == canonical_json(record["payload"]), "Bound source changed")
    require(task["envelope_json"] == row["envelope_json"], "Execution envelope cannot rebind")
    return saved


def _authorized(runtime, attempt, request):
    saved = validate_task(runtime, runtime.store.one("tasks", attempt["task_id"]))
    contract = json.loads(attempt["contract_json"])
    require(digest(contract) == attempt["contract_digest"], "Attempt digest mismatch")
    require(canonical_json(request) == canonical_json(contract), "Execution request differs from immutable authorization")
    require(canonical_json({k: v for k, v in contract.items() if k != "approval_reference"}) == canonical_json(saved["envelope"]), "Envelope binding mismatch")
    require(contract["approval_reference"] == attempt["approval_id"], "Approval identity mismatch")
    approval = runtime.store.one("approvals", attempt["approval_id"])
    require(approval["task_id"] == attempt["task_id"], "Cross-task approval")
    runtime._valid_approval(approval, saved["envelope"])
    require(not attempt["quarantined"] and attempt["state"] in {"CREATED", "QUEUED", "STARTING"}, "Attempt is not dispatchable")
    return saved


def _row(runtime, table, attempt_id):
    row = runtime.db.execute(f"SELECT * FROM {table} WHERE attempt_id=?", (attempt_id,)).fetchone()
    if row is None:
        return None
    record = json.loads(row["record_json"])
    require(digest(record) == row["digest"], "Controlled execution record digest mismatch")
    return {**dict(row), "record": record}


def show(runtime, attempt_id):
    attempt = runtime.store.one("execution_attempts", attempt_id)
    require(bound_task(runtime, attempt["task_id"]) is not None, "Not an M06 attempt")
    receipt = _row(runtime, "execution_receipts", attempt_id)
    dispatched = _row(runtime, "execution_dispatches", attempt_id)
    outcome = _row(runtime, "execution_outcomes", attempt_id)
    lifecycle = "OUTCOME_RECORDED" if outcome else "DISPATCHED" if dispatched else "RECEIPT_PERSISTED" if receipt else "AUTHORIZED"
    evidence = None
    if outcome:
        row = runtime.store.one("evidence", outcome["evidence_id"])
        evidence = json.loads(row["record_json"])
        require(digest(evidence) == row["digest"] and row["attempt_id"] == attempt_id, "Execution evidence mismatch")
    return {"attempt_id": attempt_id, "task_id": attempt["task_id"], "lifecycle": lifecycle,
            "request": json.loads(attempt["contract_json"]), "receipt": receipt,
            "dispatch": dispatched, "outcome": outcome, "evidence": evidence,
            "external_side_effects_enabled": False, "isolation_validated": False}


def _finish(runtime, attempt_id, outcome, detail, actor, occurred):
    # Caller holds a short SQLite transaction. Outcome, evidence and state are atomic.
    attempt = runtime.store.one("execution_attempts", attempt_id)
    evidence_id = runtime._evidence(attempt["task_id"], attempt_id, {
        "class": "artifact", "trust": "observed", "producer": "ACP M06 controller", "producer_role": "controller",
        "collector": "ACP", "collection_method": "synthetic-execution-receipt", "outcome": "unknown" if outcome == "UNKNOWN" else "pass" if outcome == "SUCCEEDED" else "fail",
        "content": {"contract_digest": attempt["contract_digest"], "approval_id": attempt["approval_id"],
                    "binding_id": json.loads(attempt["contract_json"])["controlled_binding"],
                    "execution_occurred": occurred, "reported": detail, "outcome": outcome}}, actor)
    record = {"attempt_id": attempt_id, "outcome": outcome, "execution_occurred": occurred,
              "certainty": "UNKNOWN" if occurred is None else "KNOWN", "detail": detail,
              "evidence_id": evidence_id, "actor": actor.record(), "at": now()}
    runtime.db.execute("INSERT INTO execution_outcomes VALUES (?,?,?,?,?,?,?)", (identity("OUT"), attempt_id, outcome, evidence_id, canonical_json(record), digest(record), record["at"]))
    runtime._event("attempt_events", attempt_id, "OUTCOME_RECORDED", actor, outcome, details=record)
    if attempt["state"] != "CANCEL_REQUESTED":
        runtime._attempt_state(attempt, "LOST" if outcome == "UNKNOWN" else "SUCCEEDED" if outcome == "SUCCEEDED" else "FAILED", actor, "M06 outcome; not task acceptance")
    task = runtime.store.one("tasks", attempt["task_id"])
    if outcome == "SUCCEEDED" and task["state"] == "RUNNING":
        runtime._task_state(task, "REVIEW", actor, "Synthetic completion only; no project analysis or acceptance")
    else:
        runtime._hold(task["id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN" if outcome == "UNKNOWN" else "M06_" + outcome)


def _invoke(executor, request, payload):
    """Closed, pure executor. No runtime object, paths, callbacks or tool dispatch."""
    require(executor in EXECUTORS, "Unsupported executor")
    outcome = {"synthetic-inspect-v1": "SUCCEEDED", "synthetic-fail-v1": "FAILED", "synthetic-reject-v1": "REJECTED"}[executor]
    return {"outcome": outcome, "received_digest": digest({"request": request, "payload": payload}),
            "material_count": len(payload), "synthetic": True}


def _mark_dispatch(runtime, attempt_id, request, actor):
    with runtime.store.transaction():
        attempt = runtime.store.one("execution_attempts", attempt_id)
        _authorized(runtime, attempt, request)
        require(_row(runtime, "execution_receipts", attempt_id) is not None, "Receipt required before dispatch")
        require(_row(runtime, "execution_outcomes", attempt_id) is None, "Outcome already recorded")
        record = {"attempt_id": attempt_id, "at": now(), "meaning": "Invocation intent, not proof operation completed", "actor": actor.record()}
        runtime.db.execute("INSERT INTO execution_dispatches VALUES (?,?,?,?,?)", (identity("DSP"), attempt_id, canonical_json(record), digest(record), record["at"]))
        runtime._attempt_state(attempt, "STARTING", actor, "Receipt committed; dispatch intent recorded", record)


def execute(runtime, attempt_id, request, actor, *, executor):
    require(actor.role in {"human", "controller"}, "Controller authority required")
    # No plugin instances or implicit defaults, especially no real-to-synthetic fallback.
    require(type(executor) is str and executor in EXECUTORS, "Unsupported executor; no fallback")
    with runtime.store.transaction():
        attempt = runtime.store.one("execution_attempts", attempt_id)
        require(bound_task(runtime, attempt["task_id"]) is not None, "Not an M06 attempt")
        require(canonical_json(request) == attempt["contract_json"], "Execution request differs from immutable authorization")
        require(executor == request["runtime_profile"], "Executor substitution forbidden")
        previous = _row(runtime, "execution_receipts", attempt_id) or _row(runtime, "execution_outcomes", attempt_id)
        if previous:
            return show(runtime, attempt_id)  # Read only; no redispatch/retry/recovery hidden here.
        require(not runtime.db.execute("SELECT 1 FROM execution_receipts r LEFT JOIN execution_outcomes o ON o.attempt_id=r.attempt_id WHERE o.attempt_id IS NULL OR o.outcome='UNKNOWN'").fetchone(), "Parallel execution/uncertain prior execution prohibited")
        try:
            saved = _authorized(runtime, attempt, request)
        except ACPError as exc:
            _finish(runtime, attempt_id, "REJECTED", {"reason": str(exc), "phase": "pre-receipt"}, actor, False)
            return show(runtime, attempt_id)
        record = {"attempt_id": attempt_id, "contract_digest": attempt["contract_digest"],
                  "binding_digest": saved["binding_digest"], "request": copy.deepcopy(request),
                  "payload": saved["binding"]["payload"], "executor": executor, "actor": actor.record(), "at": now()}
        runtime.db.execute("INSERT INTO execution_receipts VALUES (?,?,?,?,?)", (identity("RCPT"), attempt_id, canonical_json(record), digest(record), record["at"]))
        runtime._attempt_state(attempt, "QUEUED", actor, "Execution receipt persisted before invocation", {"receipt_digest": digest(record)})
    try:
        _mark_dispatch(runtime, attempt_id, request, actor)
    except ACPError as exc:
        with runtime.store.transaction():
            if _row(runtime, "execution_outcomes", attempt_id) is None:
                _finish(runtime, attempt_id, "REJECTED", {"reason": str(exc), "phase": "pre-dispatch"}, actor, False)
        return show(runtime, attempt_id)
    receipt = _row(runtime, "execution_receipts", attempt_id)["record"]
    try:
        reported = _invoke(executor, copy.deepcopy(receipt["request"]), copy.deepcopy(receipt["payload"]))
        require(type(reported) is dict and set(reported) == {"outcome", "received_digest", "material_count", "synthetic"}, "Malformed executor output")
        require(reported["outcome"] in {"SUCCEEDED", "FAILED", "REJECTED"} and reported["synthetic"] is True, "Unknown executor outcome")
        require(type(reported["material_count"]) is int and reported["material_count"] == len(receipt["payload"]), "Malformed executor material count")
        require(reported["received_digest"] == digest({"request": receipt["request"], "payload": receipt["payload"]}), "Executor input evidence mismatch")
        outcome, occurred = reported["outcome"], True
    except Exception as exc:
        reported, outcome, occurred = {"error_class": type(exc).__name__, "reason": "Invocation/result uncertain"}, "UNKNOWN", None
    with runtime.store.transaction():
        if _row(runtime, "execution_outcomes", attempt_id) is not None:
            # Recovery can have closed uncertainty while an invocation was active.
            runtime._evidence(attempt["task_id"], attempt_id, {"class": "artifact", "trust": "observed", "producer": executor,
                "producer_role": "worker", "collector": "ACP", "collection_method": "late-synthetic-output", "outcome": "unknown",
                "content": {"quarantined": True, "reported": reported}}, actor)
        else:
            try:
                _authorized(runtime, runtime.store.one("execution_attempts", attempt_id), request)
            except ACPError as exc:
                reported = {"reported": reported, "authorization_error": str(exc)}
                outcome = "REJECTED" if occurred is not None else "UNKNOWN"
            _finish(runtime, attempt_id, outcome, reported, actor, occurred)
    return show(runtime, attempt_id)


def recover(runtime, attempt_id, actor):
    require(actor.role in {"human", "controller"}, "Controller recovery authority required")
    with runtime.store.transaction():
        state = show(runtime, attempt_id)
        if state["receipt"] and not state["outcome"]:
            _finish(runtime, attempt_id, "UNKNOWN", {"reason": "Durable receipt without committed outcome; never redispatch", "executor_received": "UNKNOWN"}, actor, None)
    return show(runtime, attempt_id)
