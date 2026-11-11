"""M08 immutable synthetic VMware authority and durable fail-closed facts.

No worker-selected host paths/commands, provider fallback or project writes.
The host driver is separate from canonical intents and receipts.
"""
import json

from . import context, planning
from .domain import canonical_json, digest, identity, now, require

PROFILE = "m08-vmware-synthetic-v1"
SYNTHETIC_STATUS = "M08-SYNTHETIC-PROJECT\n"


def bound_task(runtime, task_id):
    return runtime.db.execute("SELECT * FROM isolation_task_bindings WHERE task_id=?", (task_id,)).fetchone()


def decoded(row):
    require(row is not None, "Unknown isolation identity")
    record = json.loads(row["record_json"])
    require(digest(record) == row["digest"], "Isolation record digest mismatch")
    return record


def source(runtime, plan_id, revision, work_id):
    plan = planning.show(runtime, plan_id, revision)
    require(plan["plan_revision"] == runtime.db.execute("SELECT max(revision) FROM plan_revisions WHERE plan_id=?", (plan_id,)).fetchone()[0], "STALE_AUTHORIZATION")
    require(plan["test_only"] and plan["status"] == "READY_FOR_REVIEW" and not plan["decisions"] and not plan["context_requests"] and not plan["cross_project"], "Only resolved test-only plans supported")
    require(plan["human_assessment"]["state"] == "NONE" and plan["human_assessment"]["evaluated"], "Unresolved Principal assessment")
    works = [w for w in plan["work_items"] if w["work_item_id"] == work_id]
    require(len(works) == 1, "Exact work item required")
    work = works[0]
    from . import dag
    enrolled = dag.enrolled(runtime, plan_id, revision, work_id)
    require(work["primary_project"] == plan["primary_project"] and (not work["dependencies"] or enrolled), "Single primary project and dependency-free fixture or canonical M09 graph required")
    require(work["human_assessment"]["state"] == "NONE" and work["human_assessment"]["evaluated"], "Unresolved work assessment")
    require(work["work_type"] == "documentation" and work["proposed_write_scope"] == ["allowed.txt"] and work["human_approval_required"], "Only explicitly approved synthetic text-write mapping supported")
    require(work["current_read_scope"] == ["STATUS.md"] and "forbidden.txt" in work["forbidden_scope"], "Exact synthetic scope required")
    require(set(work["allowed_operations"]) <= {"inspect_context", "analyze", "synthesize", "propose_edit"} and "propose_edit" in work["allowed_operations"], "Unsupported operation")
    project = runtime.store.one("projects", plan["primary_project"])
    require(project["enabled"], "Project disabled")
    package = context.get(runtime, plan["context_id"])
    require(package["package_digest"] == plan["context_digest"] and package["status"] != "BLOCKED", "Exact context binding required")
    require(package["project"]["project"]["repository_identity"] == project["repository_identity"], "Repository identity changed")
    materials = [m for m in package["materials"] if m["relative_path"] == "STATUS.md"]
    require(len(materials) == 1 and materials[0]["content"] == SYNTHETIC_STATUS, "No real-project material permitted")
    require(runtime.store.one("tasks", plan["task_id"])["state"] in {"NEW", "TRIAGE", "PLANNED"}, "Source task no longer eligible")
    return plan, work, project


def materialize(runtime, plan_id, revision, work_id, template, actor):
    require(actor.role == "human", "Human materialization required; proposal is not authority")
    require(isinstance(template, dict) and template.get("profile") == PROFILE and template.get("sealed") is True, "Explicit sealed template receipt required")
    with runtime.store.transaction():
        plan, work, project = source(runtime, plan_id, revision, work_id)
        require(not runtime.db.execute("SELECT 1 FROM isolation_task_bindings WHERE plan_id=? AND plan_revision=? AND work_item_id=?", (plan_id, revision, work_id)).fetchone(), "Work already bound; no duplicate mapping")
        task_id, binding_id = identity("TASK"), identity("BIND")
        envelope = {"task_revision": 1, "plan_revision": 1, "primary_project": project["id"],
            "repository_identity": project["repository_identity"], "base_commit": plan["observed_head"],
            "context_manifest": {"source": plan["context_id"], "files": ["STATUS.md"]},
            "write_scope": ["allowed.txt"], "forbidden_scope": ["forbidden.txt"],
            "allowed_operations": ["read", "write", "synthetic_fixture"],
            "prohibited_operations": ["network", "host_access", "real_project", "arbitrary_shell"],
            "runtime_profile": PROFILE, "network_capability": "none", "credential_capability": "none",
            "risk_class": "medium", "change_kind": "documentation", "isolation_binding": binding_id,
            "template_digest": digest(template), "acceptance_criteria": [{"id": "synthetic-write",
                "description": "Independent verification of the isolated synthetic text result; not source project mutation",
                "evidence_class": "independent_result", "trust": "independently_verified"}]}
        record = {"id": binding_id, "task_id": task_id, "plan_id": plan_id, "plan_revision": revision,
            "work_item_id": work_id, "plan_digest": plan["plan_digest"], "context_id": plan["context_id"],
            "context_digest": plan["context_digest"], "template": template, "envelope": envelope,
            "created_at": now(), "actor": actor.record(), "real_projects_enabled": False}
        at = now()
        runtime.db.execute("INSERT INTO tasks (id,project_id,title,request,state,created_at,updated_at) VALUES (?,?,?,?,'NEW',?,?)", (task_id, project["id"], "M08 isolated synthetic fixture", work["objective"], at, at))
        runtime._event("task_events", task_id, "CREATED", actor, "M08 mapping is not approval")
        runtime._task_state(runtime.store.one("tasks", task_id), "TRIAGE", actor, "Synthetic immutable mapping")
        runtime.db.execute("UPDATE tasks SET envelope_json=?,plan_revision=1 WHERE id=?", (canonical_json(envelope), task_id))
        runtime._task_state(runtime.store.one("tasks", task_id), "PLANNED", actor, "Separate exact human approval required")
        runtime.db.execute("INSERT INTO isolation_task_bindings VALUES (?,?,?,?,?,?,?)", (binding_id, task_id, plan_id, revision, work_id, canonical_json(record), digest(record)))
    return record


def validate_task(runtime, task):
    record = decoded(bound_task(runtime, task["id"]))
    plan, _, _ = source(runtime, record["plan_id"], record["plan_revision"], record["work_item_id"])
    require(plan["plan_digest"] == record["plan_digest"] and plan["context_digest"] == record["context_digest"], "Immutable source changed")
    require(task["envelope_json"] == canonical_json(record["envelope"]), "Isolation envelope cannot rebind")
    from . import dag
    dag.task_guard(runtime, task['id'])
    from . import review
    enrolled, link = review.task_enrollment(runtime,task['id'])
    if enrolled:
        review.authority(runtime,link['execution_id'],link['work_id'])
    return record


def allocate_guard(runtime, task):
    validate_task(runtime, task)
    previous = runtime.db.execute("SELECT * FROM execution_attempts WHERE task_id=? ORDER BY rowid DESC LIMIT 1", (task["id"],)).fetchone()
    if previous:
        fence = runtime.db.execute("SELECT * FROM isolation_fences WHERE attempt_id=?", (previous["id"],)).fetchone()
        require(fence is not None and previous["fence_evidence_id"] == fence["evidence_id"] and previous["quarantined"], "EXECUTION_OWNERSHIP_UNCERTAIN: NO RETRY")
        decoded(fence)
        require(not runtime.db.execute("SELECT 1 FROM isolation_retries WHERE previous_attempt=?", (previous["id"],)).fetchone(), "Retry already allocated")
        return previous["id"]
    return None


def instance(runtime, attempt_id):
    return decoded(runtime.db.execute("SELECT * FROM isolation_instances WHERE attempt_id=?", (attempt_id,)).fetchone())


def reserve(runtime, attempt_id, host, actor):
    require(actor.role in {"human", "controller"}, "Controller/operator required")
    with runtime.store.transaction():
        from . import dag
        dag.attempt_guard(runtime, attempt_id)
        attempt = runtime.store.one("execution_attempts", attempt_id)
        require(attempt["state"] == "CREATED" and not attempt["quarantined"], "Undispatched attempt required")
        binding = validate_task(runtime, runtime.store.one("tasks", attempt["task_id"]))
        contract = json.loads(attempt["contract_json"])
        require(digest(contract) == attempt["contract_digest"] and canonical_json({k:v for k,v in contract.items() if k != "approval_reference"}) == canonical_json(binding["envelope"]), "Attempt differs from binding")
        runtime._valid_approval(runtime.store.one("approvals", attempt["approval_id"]), binding["envelope"])
        require(not runtime.db.execute("SELECT 1 FROM isolation_instances WHERE attempt_id=?", (attempt_id,)).fetchone(), "Attempt already owns a VM reservation")
        isolation_id = identity("ISO")
        paths = host.reserve_paths(isolation_id)
        record = {"id": isolation_id, "attempt_id": attempt_id, "binding_id": binding["id"],
            "contract_digest": attempt["contract_digest"], "approval_id": attempt["approval_id"],
            "template": binding["template"], "profile": PROFILE, **paths, "created_at": now()}
        runtime.db.execute("INSERT INTO isolation_instances VALUES (?,?,?,?,?,?,?)", (isolation_id, attempt_id, binding["id"], paths["vmx"], paths["workspace"], canonical_json(record), digest(record)))
    return record


def observe(runtime, attempt_id, kind, detail, actor, intent=None):
    require(actor.role in {"human", "controller"}, "Trusted collector required")
    with runtime.store.transaction():
        owned = instance(runtime, attempt_id)
        record = {"id": identity("OBS"), "isolation_id": owned["id"], "attempt_id": attempt_id,
            "kind": kind, "detail": detail, "at": now(), "actor": actor.record()}
        runtime.db.execute("INSERT INTO isolation_observations VALUES (?,?,?,?,?,?)", (record["id"], owned["id"], intent, kind, canonical_json(record), digest(record)))
    return record


def facts(runtime, attempt_id):
    owned = instance(runtime, attempt_id)
    intents = [decoded(r) for r in runtime.db.execute("SELECT * FROM isolation_intents WHERE isolation_id=? ORDER BY rowid", (owned["id"],))]
    observations = [decoded(r) for r in runtime.db.execute("SELECT * FROM isolation_observations WHERE isolation_id=? ORDER BY rowid", (owned["id"],))]
    finished = {r["detail"]["intent_id"] for r in observations if r["kind"] == "OPERATION_COMPLETED"}
    fence = runtime.db.execute("SELECT * FROM isolation_fences WHERE attempt_id=?", (attempt_id,)).fetchone()
    return {"instance": owned, "intents": intents, "observations": observations,
        "pending": [i for i in intents if i["id"] not in finished],
        "fence": decoded(fence) if fence else None, "retry_eligible": bool(fence) and not bool(runtime.db.execute("SELECT 1 FROM isolation_retries WHERE previous_attempt=?", (attempt_id,)).fetchone())}


def operation(runtime, attempt_id, name, host, actor):
    """Persist intent, perform exact driver action once, append separate receipt.

    A crash/failure never silently reissues; canonical pending facts deny retry.
    """
    require(not runtime.db.in_transaction, "Host effects require committed intents")
    require(name in {"clone", "start", "prepare", "probes", "tree", "peers", "stop", "destroy"}, "Closed host operation vocabulary")
    require(actor.role in {"human", "controller"}, "Trusted host operator required")
    with runtime.store.transaction():
        owned = instance(runtime, attempt_id)
        attempt = runtime.store.one("execution_attempts", attempt_id)
        rows = runtime.db.execute("SELECT operation FROM isolation_intents WHERE isolation_id=?", (owned["id"],)).fetchall()
        previous = {r[0] for r in rows}
        require(name not in previous, "Existing intent must reconcile, never repeat")
        require(not facts(runtime, attempt_id)["pending"], "Uncertain host job: NO RETRY / no new operations")
        dependencies = {"clone": set(), "start": {"clone"}, "prepare": {"start"},
            "probes": {"prepare"}, "tree": {"prepare"}, "peers": {"prepare", "tree"}, "stop": {"start"}, "destroy": {"stop"}}
        if name == 'peers':
            from . import dag
            binding = decoded(bound_task(runtime, attempt['task_id']))
            eid = dag.enrolled(runtime, binding['plan_id'], binding['plan_revision'], binding['work_item_id'])
            require(eid and dag.limit(dag.execution(runtime,eid)) >= 2, 'Cross-attempt probe requires explicit M10 parallel profile')
        require(dependencies[name] <= previous, "Lifecycle prerequisite missing")
        if name not in {"stop", "destroy"}:
            from . import dag
            dag.attempt_guard(runtime, attempt_id)
            require("stop" not in previous and not attempt["quarantined"], "Stopped/quarantined VM cannot relaunch")
            binding = validate_task(runtime, runtime.store.one("tasks", attempt["task_id"]))
            runtime._valid_approval(runtime.store.one("approvals", attempt["approval_id"]), binding["envelope"])
            require(attempt["state"] not in {"CANCEL_REQUESTED", "CANCELLED", "LOST", "SUCCEEDED", "FAILED"}, "Attempt not dispatchable")
        if name == "destroy":
            require(facts(runtime, attempt_id)["fence"] is not None, "Destruction requires durable fence")
        intent = {"id": identity("OP"), "isolation_id": owned["id"], "operation": name, "at": now(),
                  "attempt_id": attempt_id, "contract_digest": owned["contract_digest"]}
        runtime.db.execute("INSERT INTO isolation_intents VALUES (?,?,?,?,?)", (intent["id"], owned["id"], name, canonical_json(intent), digest(intent)))
        if name == "start":
            runtime._attempt_state(attempt, "STARTING", actor, "Durable VM launch intent")
    try:
        result = host.perform(name, owned, facts(runtime, attempt_id))
    except BaseException as exc:
        observe(runtime, attempt_id, "OPERATION_UNCERTAIN", {"intent_id": intent["id"], "error": type(exc).__name__}, actor, intent["id"])
        with runtime.store.transaction():
            current = runtime.store.one("execution_attempts", attempt_id)
            if current["state"] not in {"CANCEL_REQUESTED", "LOST", "CANCELLED", "SUCCEEDED", "FAILED"}:
                runtime._attempt_state(current, "LOST", actor, "Host side effect uncertain")
            runtime._hold(current["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")
        raise
    observe(runtime, attempt_id, "OPERATION_COMPLETED", {"intent_id": intent["id"], "operation": name, "result": result}, actor, intent["id"])
    if name == "start":
        with runtime.store.transaction():
            current = runtime.store.one("execution_attempts", attempt_id)
            if current["state"] == "STARTING":
                runtime._attempt_state(current, "RUNNING", actor, "Positive host VM ownership receipt")
    return result


def cancel(runtime, attempt_id, actor):
    require(actor.role in {"human", "controller"}, "Controller/operator required")
    with runtime.store.transaction():
        instance(runtime, attempt_id)
        attempt = runtime.store.one("execution_attempts", attempt_id)
        require(attempt["state"] not in {"SUCCEEDED", "FAILED", "CANCELLED"}, "Terminal attempt")
        runtime._attempt_state(attempt, "CANCEL_REQUESTED", actor, "VM cancellation intent; ACK is not cessation")
        runtime._hold(attempt["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")


def cessation_proof(saved):
    """The identical physical validator for uncertain and terminal M11 fences."""
    require(not saved["pending"] and not saved["fence"], "Host jobs uncertain/already fenced")
    stops = [o for o in saved["observations"] if o["kind"] == "OPERATION_COMPLETED" and o["detail"]["operation"] == "stop"]
    require(len(stops) == 1, "Independent stop observation required")
    proof = stops[0]["detail"]["result"]
    require(proof.get("powered_off") is True and proof.get("same_process_handle_signaled") is True and proof.get("host_jobs_quiescent") is True, "EXECUTION_OWNERSHIP_UNCERTAIN: NO RETRY")
    owned = saved["instance"]
    starts = [o for o in saved["observations"] if o["kind"] == "OPERATION_COMPLETED" and o["detail"]["operation"] == "start"]
    require(len(starts) == 1 and starts[0]['detail']['result'].get('powered_on') is True and all(proof.get(k) == starts[0]["detail"]["result"].get(k) and proof.get(k) is not None for k in ("pid", "creation_filetime")), "VMX creation generation mismatch")
    require(proof.get("vmx") == owned["vmx"] and proof.get("isolation_id") == owned["id"], "Fence identity mismatch")
    return proof, stops[0]


def record_fence(runtime, attempt_id, actor):
    require(actor.role == "controller", "Host fence receipt requires trusted controller")
    with runtime.store.transaction():
        saved = facts(runtime, attempt_id)
        proof, stop = cessation_proof(saved)
        owned = saved['instance']
        attempt = runtime.store.one("execution_attempts", attempt_id)
        terminal = attempt['state'] in {'SUCCEEDED','FAILED'}
        if terminal:
            from . import review
            review.terminal_fence_guard(runtime,attempt_id)
        else:
            require(attempt["state"] in {"CANCEL_REQUESTED", "LOST"}, "Cancellation/uncertainty required for retry fence")
        evidence = runtime._evidence(attempt["task_id"], attempt_id, {"class": "independent_result", "trust": "independently_verified",
            "producer": "ACP VMware host observer", "producer_role": "controller", "collector": "ACP",
            "collection_method": "exact VIX state plus retained VMX process handle", "verification_reference": stop["id"],
            "outcome": "pass", "content": {"fence_kind": "termination", "contract_digest": owned["contract_digest"],
                "protected_resources": owned["workspace"], "explanation": "Exact VM cessation plus completed host jobs", **proof}}, actor)
        record = {"attempt_id": attempt_id, "isolation_id": owned["id"], "evidence_id": evidence, "proof": proof, "at": now()}
        if terminal:
            record['purpose']='semantic-retry'
        runtime.db.execute("INSERT INTO isolation_fences VALUES (?,?,?,?)", (attempt_id, evidence, canonical_json(record), digest(record)))
        runtime.db.execute("UPDATE execution_attempts SET fence_evidence_id=?,quarantined=1 WHERE id=?", (evidence, attempt_id))
        if not terminal:
            runtime._attempt_state(attempt, "CANCELLED", actor, "Independently fenced exact VM; outputs quarantined")
        else:
            runtime._event('attempt_events',attempt_id,'QUARANTINED',actor,'M11 rejected terminal result; terminal history preserved',details={'purpose':'semantic-retry'})
        runtime._event("attempt_events", attempt_id, "FENCED", actor, "Durable VMware fence", details=record)
    return record


def quarantine(runtime, attempt_id, artifact, actor):
    require(actor.role in {"human", "controller"}, "Trusted collector required")
    # Audit bytes/metadata under original identity, never canonical outcome.
    return observe(runtime, attempt_id, "QUARANTINED_OUTPUT", {"artifact": artifact, "acceptance_eligible": False}, actor)


def recover(runtime, attempt_id, actor):
    require(actor.role in {"human", "controller"}, "Trusted controller required")
    saved = facts(runtime, attempt_id)
    # Read committed identities only. No automatic clone/start/stop/retry.
    attempt = runtime.store.one("execution_attempts", attempt_id)
    disposition = "FENCED" if saved["fence"] else "EXECUTION_OWNERSHIP_UNCERTAIN" if saved["pending"] or attempt["state"] in {"CANCEL_REQUESTED", "LOST"} else "HOST_RECONCILIATION_REQUIRED"
    return {**saved, "disposition": disposition, "automatic_retry": False}


def complete(runtime, attempt_id, actor):
    """Accept only host-driver deterministic verification, never worker claims."""
    require(actor.role == "controller", "Trusted independent collector required")
    with runtime.store.transaction():
        from . import dag
        dag.attempt_guard(runtime, attempt_id)
        saved = facts(runtime, attempt_id)
        require(not saved["pending"] and not saved["fence"], "Uncertain/quarantined execution cannot complete")
        attempt = runtime.store.one("execution_attempts", attempt_id)
        require(attempt["state"] == "RUNNING" and not attempt["quarantined"], "Running uncancelled attempt required")
        binding = validate_task(runtime, runtime.store.one("tasks", attempt["task_id"]))
        runtime._valid_approval(runtime.store.one("approvals", attempt["approval_id"]), binding["envelope"])
        completed = {o["detail"]["operation"]: o for o in saved["observations"] if o["kind"] == "OPERATION_COMPLETED"}
        require("probes" in completed and "stop" in completed, "Independent probes and VM cessation required")
        stop = completed["stop"]["detail"]["result"]
        require(stop.get("powered_off") is True and stop.get("same_process_handle_signaled") is True and stop.get("host_jobs_quiescent") is True, "Cessation unverified")
        result = completed["probes"]["detail"]["result"]
        require(result.get("independent_verification") is True and result.get("passed") is True and result.get("attempt_id") == attempt_id, "Worker logs/claims are not independent acceptance evidence")
        evidence = runtime._evidence(attempt["task_id"], attempt_id, {"class": "independent_result", "trust": "independently_verified",
            "producer": "ACP deterministic synthetic verifier", "producer_role": "controller", "collector": "ACP",
            "collection_method": "host-chosen fixed fixture and separate guest/host canary readback",
            "verification_reference": completed["probes"]["id"], "base_commit": binding["envelope"]["base_commit"],
            "outcome": "pass", "content": result}, actor)
        runtime._event("attempt_events", attempt_id, "ISOLATION_VERIFIED", actor, "Independent fixture verification, not DONE", details={"evidence_id": evidence})
        runtime._attempt_state(attempt, "SUCCEEDED", actor, "Isolated synthetic result verified")
        runtime._task_state(runtime.store.one("tasks", attempt["task_id"]), "REVIEW", actor, "Separate explicit acceptance required")
    return evidence


def accept_guard(runtime, task_id, attempt_id, criteria_evidence):
    validate_task(runtime, runtime.store.one("tasks", task_id))
    saved = facts(runtime, attempt_id)
    require(not saved["pending"] and not saved["fence"], "Uncertain/old output cannot satisfy acceptance")
    verified = runtime.db.execute("SELECT details_json FROM attempt_events WHERE attempt_id=? AND kind='ISOLATION_VERIFIED' ORDER BY seq DESC LIMIT 1", (attempt_id,)).fetchone()
    require(verified is not None and criteria_evidence == {"synthetic-write": json.loads(verified[0])["evidence_id"]}, "Exact independent isolation result required")
