"""Advisory canonical planning. Only stored context is read; no worker dispatch."""
import json

from . import awareness, context
from .domain import ACPError, canonical_json, digest, identity, now, require, text
from .read_boundary import relative_name, sensitive

POLICY = "ACP-M05-PLANNING-v1"
OPERATIONS = {"inspect_context": 0, "analyze": 0, "synthesize": 0, "propose_edit": 1,
              "propose_code_change": 2, "propose_architecture": 3, "propose_dependency": 3,
              "propose_destructive_change": 3, "propose_credentials": 3,
              "propose_integration": 3, "propose_deployment": 3}
ANALYSIS_CHECKS = {"source_citations", "decision_maturity", "explain_gap", "surface_contradictions",
                   "label_missing_evidence", "no_unsupported_absence", "context_bounded"}
CODE_CHECKS = {"expected_paths", "expected_repository_state", "tests", "static_checks", "independent_verification"}
HUMAN_STATES = {"NONE", "REQUIRED", "NOT_ASSESSED"}
MATERIAL = {"architecture", "scope", "cross_project_write", "destructive", "credentials", "dependency",
            "production", "cost_security", "semantic_conflict", "business_policy", "policy_exception"}


def shape(value, fields, where):
    require(isinstance(value, dict) and set(value) == set(fields.split()), f"STRUCTURE: {where}")


def sequence(value, where, maximum=64):
    require(isinstance(value, list) and len(value) <= maximum, f"LIST: {where}")
    return value


def prose(value, where):
    require(len(text(value, where)) <= 4096, f"TEXT_LIMIT: {where}")


def path(value):
    result = relative_name(value)
    require(not sensitive(result), "SENSITIVE_SCOPE")
    return result


def covered(name, roots):
    return any(r == "." or name.casefold() == r.casefold() or name.casefold().startswith(r.casefold() + "/") for r in roots)


def validate(raw, inputs):
    """Strict normalized proposal; failures return no canonical plan content."""
    require(isinstance(raw, str) and len(raw.encode("utf-8")) <= 1048576, "RAW_LIMIT")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    p = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ACPError("NONFINITE_JSON")))
    if isinstance(p, dict):
        p.setdefault("evidence_assessments", [])
    shape(p, "goal_interpretation assumptions evidence_gaps evidence_assessments work_items decisions human_assessment", "proposal")
    prose(p["goal_interpretation"], "goal")
    for assumption in sequence(p["assumptions"], "assumptions"):
        prose(assumption, "assumption")
    package = inputs["context_package"]
    primary = inputs["primary_project"]
    known = {v["id"]: v for v in inputs["known_projects"]}
    roots = package["project"]["read_roots"]
    sources = {m["relative_path"]: m for m in package["manifest"] if m["included"]}
    available = set(sources)
    expansions = []
    materials = {m["relative_path"]: m["content"] for m in package["materials"]}
    for assessment in sequence(p["evidence_assessments"], "evidence assessments"):
        shape(assessment, "question state citations decision_maturity", "evidence assessment")
        prose(assessment["question"], "assessment question")
        require(assessment["state"] in {"SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE", "NOT_ASSESSED"}, "EVIDENCE_STATE")
        require(assessment["decision_maturity"] in {"CONFIRMED", "TENTATIVE", "UNCONFIRMED", "REJECTED", "NOT_APPLICABLE", "UNKNOWN"}, "DECISION_MATURITY")
        citations = sequence(assessment["citations"], "citations")
        for citation in citations:
            shape(citation, "path quote", "citation")
            prose(citation["quote"], "quote")
            require(citation["path"] in available and citation["quote"] in materials[citation["path"]], "CITATION_NOT_IN_CONTEXT")
        require(assessment["state"] not in {"SUPPORTED", "CONTRADICTED"} or citations, "ASSESSMENT_NEEDS_EVIDENCE")
        require(assessment["state"] != "CONTRADICTED" or len(citations) >= 2, "CONTRADICTION_NEEDS_BOTH_SIDES")
    for gap in sequence(p["evidence_gaps"], "gaps"):
        shape(gap, "purpose state sources", "gap")
        prose(gap["purpose"], "gap purpose")
        require(gap["state"] in {"INSUFFICIENT_EVIDENCE", "NOT_ASSESSED"}, "MISSING_EVIDENCE_IS_NOT_NEGATIVE")
        require(all(s in available for s in sequence(gap["sources"], "gap sources")), "UNAVAILABLE_CITATION")
    items = sequence(p["work_items"], "work items", 32)
    require(items, "EMPTY_WORK")
    floors, graph = [], []
    for i, w in enumerate(items):
        if isinstance(w, dict):
            w.setdefault("proposed_write_scope", [])
        shape(w, "objective primary_project work_type dependencies required_context current_read_scope proposed_write_scope forbidden_scope allowed_operations execution_risk human_assessment acceptance required_evidence suggested_profile parallel_safe human_approval_required", "work item")
        prose(w["objective"], "objective")
        require(isinstance(w["primary_project"], str) and w["primary_project"] in known and known[w["primary_project"]]["enabled"], "UNKNOWN_PRIMARY_PROJECT")
        require(w["work_type"] in {"analysis", "documentation", "code"}, "WORK_TYPE")
        require(w["suggested_profile"] in {"read_only_analysis", "future_isolated_write"}, "PROFILE")
        require(type(w["parallel_safe"]) is bool and type(w["human_approval_required"]) is bool, "BOOLEAN_REQUIRED")
        deps = sequence(w["dependencies"], "dependencies", 32)
        require(all(type(d) is int and 0 <= d < len(items) and d != i for d in deps) and len(set(deps)) == len(deps), "DEPENDENCY_REFERENCE")
        graph.append(sorted(deps))
        require(not deps or not w["parallel_safe"], "PARALLEL_PREDECESSOR_CONFLICT")
        reads = [path(s) for s in sequence(w["current_read_scope"], "read scope")]
        require(not reads or w["primary_project"] == primary, "CROSS_PROJECT_CONTEXT_UNAVAILABLE")
        require(set(reads) <= available and all(covered(s, roots) for s in reads), "UNAVAILABLE_READ_SCOPE")
        writes = [path(s) for s in sequence(w["proposed_write_scope"], "write scope")]
        forbidden = [path(s) for s in sequence(w["forbidden_scope"], "forbidden scope")]
        w.update(current_read_scope=reads, proposed_write_scope=writes, forbidden_scope=forbidden)
        require(not any(covered(s, forbidden) or covered(f, [s]) for s in writes for f in forbidden), "FORBIDDEN_WRITE_SCOPE")
        contexts = sequence(w["required_context"], "required context")
        require(contexts, "MATERIAL_SOURCE_UNSPECIFIED")
        loaded = set()
        for source in contexts:
            shape(source, "purpose path category approved_read_root already_loaded expansion_required", "required source")
            prose(source["purpose"], "source purpose")
            prose(source["category"], "source category")
            require(type(source["already_loaded"]) is bool and type(source["expansion_required"]) is bool, "BOOLEAN_REQUIRED")
            name = path(source["path"]) if source["path"] is not None else None
            source["path"] = name
            root = source["approved_read_root"]
            if root is not None:
                relative_name(root, root=True)
                require(w["primary_project"] == primary and root in roots and (name is None or covered(name, [root])), "UNAPPROVED_ROOT_CLAIM")
            present = w["primary_project"] == primary and name in available
            require(source["already_loaded"] == present, "CONTEXT_AVAILABILITY_CLAIM")
            require(source["expansion_required"] == (not present), "CONTEXT_EXPANSION_REQUIRED")
            if present:
                require(root is not None and name in reads, "SOURCE_READ_SCOPE_MISMATCH")
                loaded.add(name)
            else:
                expansions.append({"work_index": i, "project": w["primary_project"], **source,
                    "reason": "Required source absent from approved immutable package",
                    "planning_consequence": "Analysis remains unperformed until a new approved package is supplied",
                    "authorization": "REQUEST_ONLY"})
        require(set(reads) == loaded, "UNDECLARED_READ_SOURCE")
        ops = sequence(w["allowed_operations"], "operations")
        require(ops and all(isinstance(op, str) and op in OPERATIONS for op in ops), "UNKNOWN_OPERATION")
        require("propose_code_change" not in ops or w["work_type"] == "code", "CODE_WORK_TYPE_REQUIRED")
        require("propose_edit" not in ops or w["work_type"] in {"documentation", "code"}, "EDIT_WORK_TYPE_REQUIRED")
        floor = max(OPERATIONS[op] for op in ops)
        if writes:
            require(w["work_type"] != "analysis" and w["suggested_profile"] == "future_isolated_write", "WRITE_PROFILE")
            require(any(op.startswith("propose_") for op in ops), "WRITE_OPERATION_REQUIRED")
            floor = max(floor, 2 if w["work_type"] == "code" else 1)
        require(w["execution_risk"] in {"R0", "R1", "R2", "R3"}, "RISK")
        floors.append(max(floor, int(w["execution_risk"][1])))
        criteria = sequence(w["acceptance"], "acceptance")
        checks = set()
        for criterion in criteria:
            shape(criterion, "check observable", "criterion")
            require(criterion["check"] in ANALYSIS_CHECKS | CODE_CHECKS, "ACCEPTANCE_CHECK")
            prose(criterion["observable"], "observable")
            require(len(criterion["observable"].strip()) >= 24 and criterion["observable"].lower() not in {"analyze the project", "works correctly"}, "VAGUE_ACCEPTANCE")
            checks.add(criterion["check"])
        require(ANALYSIS_CHECKS <= checks, "ANALYSIS_PROVENANCE_ACCEPTANCE_REQUIRED")
        evidence = sequence(w["required_evidence"], "required evidence")
        require(set(evidence) <= {"source_citations", "gap_register", "independent_result", "diff", "test_result"} and {"source_citations", "gap_register"} <= set(evidence), "EVIDENCE_REQUIREMENTS")
        if w["work_type"] == "code":
            require(CODE_CHECKS <= checks and {"independent_result", "diff", "test_result"} <= set(evidence), "INDEPENDENT_CODE_VERIFICATION_REQUIRED")
        human(w["human_assessment"], available if w["primary_project"] == primary else set())
    pending = set(range(len(items)))
    order = []
    while pending:
        ready = sorted(i for i in pending if set(graph[i]) <= set(order))
        require(ready, "DEPENDENCY_CYCLE")
        order.extend(ready)
        pending.difference_update(ready)
    human(p["human_assessment"], available)
    decisions = sequence(p["decisions"], "decisions")
    covered_decisions = set()
    for d in decisions:
        shape(d, "category question why source_work_items options consequences reversibility decision_consequence", "decision")
        require(d["category"] in MATERIAL and d["decision_consequence"] in {"MATERIAL", "HIGH"}, "DECISION_CLASSIFICATION")
        for key in ("question", "why", "consequences", "reversibility"):
            prose(d[key], key)
        refs = sequence(d["source_work_items"], "decision sources", 32)
        require(refs and all(type(j) is int and 0 <= j < len(items) for j in refs), "DECISION_REFERENCE")
        covered_decisions.update(refs)
        require(2 <= len(sequence(d["options"], "options", 8)), "BOUNDED_OPTIONS")
        for option in d["options"]:
            prose(option, "option")
    cross = {w["primary_project"] for w in items} != {primary}
    if cross:
        require(any(d["category"] == "cross_project_write" or d["category"] == "scope" for d in decisions), "CROSS_PROJECT_REVIEW_REQUIRED")
        require(any(graph), "CROSS_PROJECT_COORDINATION_REQUIRED")
        if any(w["proposed_write_scope"] for w in items):
            floors = [3] * len(items)
    for i, w in enumerate(items):
        if floors[i] == 3 or w["human_assessment"]["state"] == "REQUIRED":
            require(i in covered_decisions, "MATERIAL_DECISION_REQUIRED")
        if i in covered_decisions:
            require(w["human_assessment"]["state"] == "REQUIRED" and w["human_approval_required"], "DECISION_NOT_AUTHORIZED")
        if w["proposed_write_scope"]:
            require(w["human_approval_required"], "FUTURE_WRITE_UNAUTHORIZED")
    require((p["human_assessment"]["state"] == "REQUIRED") == bool(decisions), "PLAN_HUMAN_ASSESSMENT")
    require(p["human_assessment"]["state"] != "NONE" or all(w["human_assessment"]["state"] == "NONE" for w in items), "HUMAN_NOT_ASSESSED")
    # Unstructured prose is advisory, not accepted factual evidence. No factual
    # absence conclusion is permitted in this planning-only representation.
    rendered = canonical_json(p).casefold()
    require(not any(s in rendered for s in ("no issue exists", "no issues exist", "no problem exists", "no procurement issue", "沒有問題", "無任何問題")), "UNSUPPORTED_ABSENCE_CLAIM")
    return p, {"dependencies": graph, "topological_order": order, "execution_risks": floors,
               "context_requests": expansions, "cross_project": cross,
               "status": "NEEDS_HUMAN" if decisions else "NEEDS_CONTEXT" if expansions else "READY_FOR_REVIEW"}


def human(value, available):
    shape(value, "state evaluated rationale sources", "human assessment")
    require(value["state"] in HUMAN_STATES and type(value["evaluated"]) is bool, "HUMAN_ASSESSMENT")
    prose(value["rationale"], "human rationale")
    refs = sequence(value["sources"], "assessment sources")
    require(all(s in available for s in refs), "UNAVAILABLE_ASSESSMENT_SOURCE")
    require(value["state"] == "NOT_ASSESSED" or value["evaluated"], "RISK_IS_NOT_HUMAN_ASSESSMENT")
    if value["state"] == "NONE":
        require(refs and not any(s in value["rationale"].casefold() for s in ("r0", "read-only", "read only", "低風險")), "RISK_IS_NOT_HUMAN_ASSESSMENT")


def prepare(runtime, task_id, context_id, actor, *, plan_id=None, test_only=False):
    require(actor.role == "human", "Explicit human context selection required")
    task = runtime.store.one("tasks", task_id)
    require(task["state"] in {"NEW", "TRIAGE", "PLANNED", "NEEDS_HUMAN", "BLOCKED"}, "TASK_NOT_PLANNABLE")
    package = context.get(runtime, context_id)
    require(package["status"] in {"READY", "PARTIAL"}, "CONTEXT_BLOCKED")
    require(package["project"]["project"]["id"] == task["project_id"], "CONTEXT_PROJECT_MISMATCH")
    require(package["task_id"] in {None, task_id}, "CONTEXT_TASK_MISMATCH")
    project = runtime.project_show(task["project_id"])
    require(project["enabled"], "PROJECT_DISABLED")
    require(package["project"]["project"]["repository_identity"] == project["repository_identity"], "CONTEXT_IDENTITY_MISMATCH")
    if plan_id:
        require(show(runtime, plan_id)["task_id"] == task_id, "PLAN_TASK_MISMATCH")
    inputs = {"policy": POLICY, "authority": "Principal > ACP policy > authorization > approved context > validated proposal > recommendation > repository data",
              "constraints": ["Planning only", "No tools, no crawling, no authorization, no worker dispatch", "Context expansion is REQUEST_ONLY", "Missing evidence is not negative evidence"],
              "allowed_operations": OPERATIONS, "analysis_checks": sorted(ANALYSIS_CHECKS), "code_checks": sorted(CODE_CHECKS),
              "task_id": task_id, "request": task["request"], "primary_project": task["project_id"],
              "context_package": package, "context_digest": package["package_digest"],
              "known_projects": [{"id": p["id"], "enabled": p["enabled"]} for p in runtime.project_list()],
              "previous_plan_id": plan_id, "test_only": test_only}
    run_id = identity("PRUN")
    with runtime.store.transaction():
        runtime.db.execute("INSERT INTO planning_runs VALUES (?,?,?,?,?,?)", (run_id, task_id, canonical_json(inputs), digest(inputs), canonical_json(actor.record()), now()))
    return {"run_id": run_id, "input": inputs, "input_digest": digest(inputs)}


def run_show(runtime, run_id):
    row = runtime.db.execute("SELECT * FROM planning_runs WHERE id=?", (run_id,)).fetchone()
    require(row is not None, "UNKNOWN_PROVIDER_RUN")
    inputs = json.loads(row["input_json"])
    require(digest(inputs) == row["input_digest"], "INPUT_DIGEST_MISMATCH")
    result = runtime.db.execute("SELECT * FROM planning_results WHERE run_id=?", (run_id,)).fetchone()
    return {"run_id": run_id, "input": inputs, "input_digest": row["input_digest"],
            "created_at": row["created_at"], "result": dict(result) if result else None}


def complete(runtime, run_id, provider, actor):
    """Compatibility entry point; all new invocations use durable M07 facts."""
    from . import provider_runtime
    require(run_show(runtime, run_id)["result"] is None, "PROVIDER_RUN_ALREADY_COMPLETED")
    provider_runtime.enroll(runtime, run_id, provider, actor)
    state = provider_runtime.execute(runtime, run_id, provider, actor)
    if state["result"]:
        return state["result"]
    return {"status": "PROVIDER_FAILED", "certainty": "UNKNOWN", "provider_status": state["state"],
            "errors": ["PROVIDER_OUTCOME_UNKNOWN: reinvocation prohibited"], "plan_id": None}


def finalize(runtime, run_id, raw, metadata, normalized, error, validation_id):
    """Publish only from a persisted M07 validation, atomically and idempotently."""
    run = run_show(runtime, run_id)
    inputs = run["input"]
    with runtime.store.transaction():
        existing = runtime.db.execute("SELECT result_json FROM planning_results WHERE run_id=?", (run_id,)).fetchone()
        if existing:
            return json.loads(existing[0])
        from .provider_runtime import fact
        binding = fact(runtime, "provider_runs", run_id)
        if inputs["previous_plan_id"]:
            require(show(runtime, inputs["previous_plan_id"])["plan_revision"] == binding["previous_plan_revision"], "STALE_PROVIDER_PLAN: held, no automatic rebinding")
        checked_validation = fact(runtime, "provider_validations", run_id)
        require(checked_validation is not None and checked_validation["validation_id"] == validation_id,
                "Durable provider validation required")
        require(canonical_json([raw, metadata, normalized, error]) == canonical_json([
            checked_validation["raw"], checked_validation["metadata"], checked_validation["normalized"], checked_validation["error"]]),
            "Finalization must match immutable validation")
        return _publish(runtime, run_id, inputs, raw, metadata, normalized, error, validation_id)


def _publish(runtime, run_id, inputs, raw, metadata, normalized, error, validation_id):
    # Caller holds SQLite write transaction. Canonical IDs created only here.
    if error:
        result = {"status": "PROVIDER_FAILED" if error.startswith("PROVIDER_FAILURE") else "INVALID", "errors": [error], "plan_id": None}
    else:
        proposal, checked = normalized
        plan_id = inputs["previous_plan_id"] or identity("PLAN")
        revision = runtime.db.execute("SELECT coalesce(max(revision),0)+1 FROM plan_revisions WHERE plan_id=?", (plan_id,)).fetchone()[0]
        ids = [identity("WORK") for _ in proposal["work_items"]]
        items = []
        for i, work in enumerate(proposal["work_items"]):
            items.append({**work, "work_item_id": ids[i], "dependencies": [ids[d] for d in checked["dependencies"][i]],
                          "execution_risk": "R" + str(checked["execution_risks"][i]), "write_authority": "NONE"})
        decisions = [{**d, "decision_id": identity("DEC"), "status": "PENDING", "source_work_items": [ids[i] for i in d["source_work_items"]]} for d in proposal["decisions"]]
        expansions = [{**r, "work_item_id": ids[r["work_index"]]} for r in checked["context_requests"]]
        record = {**proposal, "plan_id": plan_id, "plan_revision": revision, "task_id": inputs["task_id"],
                  "primary_project": inputs["primary_project"], "context_id": inputs["context_package"]["id"],
                  "context_digest": inputs["context_digest"], "observed_head": inputs["context_package"]["repository_state_after"]["head"],
                  "run_id": run_id, "validation_id": validation_id, "created_at": now(), "provider_metadata": metadata,
                  "work_items": items, "decisions": decisions, "context_requests": expansions,
                  "dag": {"topological_order": [ids[i] for i in checked["topological_order"]]},
                  "execution_risk": "R" + str(max(checked["execution_risks"])), "cross_project": checked["cross_project"],
                  "status": checked["status"], "validation_status": "PASS", "execution": "NOT_DISPATCHED",
                  "content_classification": "validated advisory proposal; not verified project findings", "test_only": inputs["test_only"]}
        runtime.db.execute("INSERT INTO plan_revisions VALUES (?,?,?,?,?,?)", (plan_id, revision, inputs["task_id"], run_id, canonical_json(record), digest(record)))
        result = {"status": checked["status"], "errors": [], "plan_id": plan_id, "revision": revision}
    result["validation_id"] = validation_id
    runtime.db.execute("INSERT INTO planning_results VALUES (?,?,?,?,?,?)", (run_id, validation_id, raw, canonical_json(metadata), canonical_json(result), now()))
    return result


def show(runtime, plan_id, revision=None):
    row = runtime.db.execute("SELECT * FROM plan_revisions WHERE plan_id=? AND (? IS NULL OR revision=?) ORDER BY revision DESC LIMIT 1", (plan_id, revision, revision)).fetchone()
    require(row is not None, "UNKNOWN_PLAN_REVISION")
    record = json.loads(row["record_json"])
    require(digest(record) == row["digest"], "PLAN_DIGEST_MISMATCH")
    return {**record, "plan_digest": row["digest"]}


def list_plans(runtime):
    return [dict(r) for r in runtime.db.execute("SELECT plan_id,revision,task_id,run_id,digest FROM plan_revisions ORDER BY plan_id,revision")]


def prepare_resolution(runtime, resolution_id, context_id, actor, *, test_only=False):
    resolution = awareness.resolution_show(runtime, resolution_id)["result"]
    require(resolution["outcome"] == "RESOLVED" and resolution["task_id"], "PROJECT_RESOLUTION_REQUIRED_BEFORE_PROVIDER")
    return prepare(runtime, resolution["task_id"], context_id, actor, test_only=test_only)


def compare(runtime, plan_id, context_id, revision=None):
    record = show(runtime, plan_id, revision)
    package = context.get(runtime, context_id, include_content=False)
    require(package["project"]["project"]["id"] == record["primary_project"], "CONTEXT_PROJECT_MISMATCH")
    return {"plan_id": plan_id, "revision": record["plan_revision"],
            "stale": record["context_digest"] != package["package_digest"] or record["observed_head"] != package["repository_state_after"]["head"],
            "live_repository_checked": False, "reason": "Explicit stored-context comparison only; no filesystem crawl"}
