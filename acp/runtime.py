"""Transactional domain operations. Registry Git commands are strictly read-only."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import subprocess

from .adapters import Outcome, SyntheticAdapter
from .domain import (ACPError, ATTEMPT_EDGES, TASK_EDGES, TERMINAL_ATTEMPTS,
                     UNCERTAIN, VERIFIERS, bounded_read_policy, canonical_json,
                     canonical_path, digest, identity, now, path_key, require, text,
                     timestamp, validate_envelope)
from .store import Store


def decode(row):
    result = dict(row)
    for key in list(result):
        if key.endswith("_json"):
            value = result.pop(key)
            result[key[:-5]] = json.loads(value) if value is not None else None
    return result


class Runtime:
    def __init__(self, data_dir=None, *, existing_only=False):
        self.store = Store(data_dir, existing_only=existing_only)
        self.db = self.store.db

    def close(self):
        self.store.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _event(self, table, record_id, kind, actor, reason, before=None, after=None, details=None):
        text(reason, "reason")
        column = "task_id" if table == "task_events" else "attempt_id"
        self.db.execute(f"INSERT INTO {table} ({column},kind,from_state,to_state,actor_json,reason,details_json,at) VALUES (?,?,?,?,?,?,?,?)",
                        (record_id, kind, before, after, canonical_json(actor.record()), reason, canonical_json(details or {}), now()))

    def project_add(self, project_id, directory, enabled=True):
        require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", project_id)), "Invalid stable project ID")
        path = canonical_path(directory)
        require(not self.store.directory.is_relative_to(path), "State directory must not be inside a registered project")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
        def git(*args):
            try:
                result = subprocess.run(["git", "-C", str(path), "rev-parse", *args], capture_output=True, text=True, encoding="utf-8", timeout=10, env=env)
                return result.stdout.strip() if result.returncode == 0 else None
            except FileNotFoundError as exc:
                raise ACPError("Git is required for registry metadata inspection") from exc
            except subprocess.TimeoutExpired as exc:
                raise ACPError("Git metadata inspection timed out") from exc
        root = git("--show-toplevel")
        git_marker = any((p / ".git").exists() for p in (path, *path.parents))
        require(root is not None or not git_marker, "Git metadata unavailable; refusing to silently downgrade repository identity")
        git_root = str(canonical_path(root)) if root else None
        common = git("--path-format=absolute", "--git-common-dir") if root else None
        require(not root or common, "Git common-directory identity unavailable")
        repository_identity = digest({"kind": "git" if root else "directory", "path": path_key(Path(common).resolve() if common else path)})
        head = git("--verify", "HEAD") if root else None
        contexts = {}
        for name in ("AGENTS.md", "STATUS.md", "README.md", "PROJECT_INSTRUCTIONS.md", "docs/10-decision-log.md"):
            candidate = path / name
            if candidate.is_file() and candidate.resolve().is_relative_to(path):
                contexts[name] = str(candidate.resolve())
        with self.store.transaction():
            existing = self.db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
            if existing:
                require(existing["path_key"] == path_key(path), "Project ID already bound to another path")
                require(existing["repository_identity"] == repository_identity, "Registered repository identity changed")
                require(bool(existing["enabled"]) == enabled, "Registration does not silently change enabled state")
                return decode(existing)
            self.db.execute("INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?)", (project_id, str(path), path_key(path), repository_identity, git_root, head, canonical_json(contexts), int(enabled), now()))
        return self.project_show(project_id)

    def project_show(self, project_id):
        return decode(self.store.one("projects", project_id))

    def project_list(self):
        return [decode(r) for r in self.db.execute("SELECT * FROM projects ORDER BY id")]

    def task_create(self, project_id, title, request, actor):
        text(title, "title")
        text(request, "request")
        with self.store.transaction():
            require(self.store.one("projects", project_id)["enabled"], "Project disabled")
            task_id, at = identity("TASK"), now()
            self.db.execute("INSERT INTO tasks (id,project_id,title,request,state,created_at,updated_at) VALUES (?,?,?,?,'NEW',?,?)", (task_id, project_id, title, request, at, at))
            self._event("task_events", task_id, "CREATED", actor, "Human task intake", after="NEW")
        return self.task_show(task_id)

    def task_list(self):
        return [decode(r) for r in self.db.execute("SELECT * FROM tasks ORDER BY created_at,id")]

    def task_show(self, task_id):
        with self.store.transaction():
            task = decode(self.store.one("tasks", task_id))
            task["attempts"] = [decode(r) for r in self.db.execute("SELECT * FROM execution_attempts WHERE task_id=? ORDER BY created_at,id", (task_id,))]
            task["approvals"] = [decode(r) for r in self.db.execute("SELECT * FROM approvals WHERE task_id=? ORDER BY issued_at,id", (task_id,))]
            task["evidence"] = [decode(r) for r in self.db.execute("SELECT * FROM evidence WHERE task_id=? ORDER BY collected_at,id", (task_id,))]
            return task

    def events(self, task_id):
        self.store.one("tasks", task_id)
        return [decode(r) for r in self.db.execute("SELECT * FROM task_events WHERE task_id=? ORDER BY seq", (task_id,))]

    def attempt_show(self, attempt_id):
        with self.store.transaction():
            result = decode(self.store.one("execution_attempts", attempt_id))
            result["events"] = [decode(r) for r in self.db.execute("SELECT * FROM attempt_events WHERE attempt_id=? ORDER BY seq", (attempt_id,))]
            result["backend_mappings"] = [decode(r) for r in self.db.execute("SELECT * FROM backend_mappings WHERE attempt_id=? ORDER BY created_at,id", (attempt_id,))]
            return result

    def _task_state(self, task, target, actor, reason, details=None, resolving=False):
        require(target in TASK_EDGES, "Unknown canonical task state")
        if resolving:
            require(task["state"] in {"BLOCKED", "NEEDS_HUMAN"} and target == task["resume_state"], "Hold must return to its recorded resume state")
        else:
            require(target in TASK_EDGES[task["state"]], f"Illegal task transition {task['state']} -> {target}")
        held = target in {"BLOCKED", "NEEDS_HUMAN"}
        self.db.execute("UPDATE tasks SET state=?,hold_reason=?,resume_state=?,updated_at=? WHERE id=?", (target, reason if held else None, task["state"] if held else None, now(), task["id"]))
        self._event("task_events", task["id"], "TRANSITION", actor, reason, task["state"], target, details)

    def _hold(self, task_id, actor, reason):
        task = self.store.one("tasks", task_id)
        if task["state"] in {"DONE", "CANCELLED", "FAILED"}:
            return
        if task["state"] in {"BLOCKED", "NEEDS_HUMAN"}:
            self.db.execute("UPDATE tasks SET hold_reason=?,updated_at=? WHERE id=?", (reason, now(), task_id))
            self._event("task_events", task_id, "HOLD_UPDATED", actor, reason, details={"resume_state": task["resume_state"]})
        else:
            self._task_state(task, "BLOCKED", actor, reason)

    def _unresolved(self, task_id):
        return self.db.execute("SELECT * FROM execution_attempts WHERE task_id=? AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED') AND fence_evidence_id IS NULL", (task_id,)).fetchall()

    def transition(self, task_id, target, actor, reason):
        require(actor.role != "worker", "Workers cannot mutate canonical task state")
        require(target not in {"PLANNED", "RUNNING", "DONE"}, "Use plan, attempt creation, or acceptance operation for this transition")
        roles = {
            "TRIAGE": {"human", "planner", "controller"},
            "READY": {"human", "policy", "controller"},
            "REVIEW": VERIFIERS,
            "REWORK": VERIFIERS,
            "FAILED": {"human", "controller"},
            "CANCELLED": {"human", "controller"},
        }
        require(target not in roles or actor.role in roles[target], "Actor role cannot make this transition")
        with self.store.transaction():
            task = self.store.one("tasks", task_id)
            if target == "READY":
                require(task["envelope_json"], "Task has no plan")
                self._find_approval(task)
                require(not self._unresolved(task_id), "Unresolved prior execution ownership")
                if task["state"] == "REWORK":
                    require(actor.role == "human", "Unchanged-plan rework requires a human decision")
            if target == "REVIEW":
                require(not self._unresolved(task_id), "Cannot review with unresolved attempts")
                require(self.db.execute("SELECT 1 FROM execution_attempts WHERE task_id=? AND state='SUCCEEDED' AND quarantined=0", (task_id,)).fetchone(), "No reviewable successful attempt")
            if target in {"CANCELLED", "FAILED"}:
                require(not self._unresolved(task_id), "Active attempts need separate stop/fencing proof")
            self._task_state(task, target, actor, reason)
        return self.task_show(task_id)

    def resolve_hold(self, task_id, actor, reason, retry_ready=False):
        require(actor.role != "worker", "Worker cannot resolve a hold")
        with self.store.transaction():
            task = self.store.one("tasks", task_id)
            if task["state"] == "NEEDS_HUMAN":
                require(actor.role == "human", "Principal resolution required")
            require(not self._unresolved(task_id), "Execution ownership remains unresolved")
            if retry_ready:
                require(task["state"] == "BLOCKED" and task["resume_state"] == "RUNNING", "Retry resolution requires a blocked execution")
                require(actor.role in {"human", "controller"}, "Retry decision requires operator/controller")
                self._find_approval(task)
                self._event("task_events", task_id, "HOLD_RESOLUTION", actor, reason, details={"resume_state": "READY", "retry": True})
                self.db.execute("UPDATE tasks SET resume_state='READY' WHERE id=?", (task_id,))
                task["resume_state"] = "READY"
            if task["resume_state"] in {"READY", "RUNNING", "REVIEW"}:
                self._find_approval(task)
            self._task_state(task, task["resume_state"], actor, reason, resolving=True)
        return self.task_show(task_id)

    def plan(self, task_id, envelope, actor, reason):
        require(actor.role in {"human", "planner", "controller"}, "Planner authority required")
        from .controlled import bound_task
        require(not bound_task(self, task_id), "M06 binding cannot be replanned or retried")
        from . import isolation
        require(not isolation.bound_task(self, task_id), "M08 immutable binding cannot be replanned")
        require(not isinstance(envelope, dict) or ("isolation_binding" not in envelope and not str(envelope.get("runtime_profile", "")).startswith("m08-")), "Use explicit M08 materialization")
        require(not isinstance(envelope, dict) or ("controlled_binding" not in envelope and not str(envelope.get("runtime_profile", "")).startswith("synthetic-")), "Use controlled materialization for M06")
        with self.store.transaction():
            task = self.store.one("tasks", task_id)
            require(task["state"] in {"TRIAGE", "REWORK"}, "Plan requires TRIAGE or REWORK")
            require(not self._unresolved(task_id), "Cannot replan unresolved execution")
            validate_envelope(envelope, task, self.store.one("projects", task["project_id"]))
            require(envelope["plan_revision"] == task["plan_revision"] + 1, "Plan revision must increase by exactly one")
            self.db.execute("UPDATE tasks SET envelope_json=?,plan_revision=? WHERE id=?", (canonical_json(envelope), envelope["plan_revision"], task_id))
            self._task_state(task, "PLANNED", actor, reason, {"envelope": envelope, "digest": digest(envelope)})
        return self.task_show(task_id)

    def approve(self, task_id, kind, actor, expires_at, policy_ref=None):
        require(kind in {"human", "policy"}, "Authorization kind must be human or policy")
        issued = now()
        require(timestamp(expires_at) > timestamp(issued), "Approval expiry must be in the future")
        with self.store.transaction():
            task = self.store.one("tasks", task_id)
            require(task["state"] not in {"DONE", "FAILED", "CANCELLED"} and task["envelope_json"], "No approvable active plan")
            envelope = json.loads(task["envelope_json"])
            from .controlled import bound_task, validate_task
            if bound_task(self, task_id):
                validate_task(self, task)
            require(actor.role == ("human" if kind == "human" else "policy"), "Approval authority does not match kind")
            if kind == "policy":
                text(policy_ref, "policy reference")
                require(bounded_read_policy(envelope), "Policy authorization limited to bounded low-risk reads without privileged capabilities")
            approval_id = identity("APR")
            self.db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,NULL)", (approval_id, task_id, kind, canonical_json(envelope), digest(envelope), canonical_json(actor.record()), policy_ref, issued, timestamp(expires_at).isoformat()))
            self.db.execute("INSERT INTO approval_events (approval_id,kind,actor_json,reason,at) VALUES (?,'ISSUED',?,?,?)", (approval_id, canonical_json(actor.record()), "Concrete envelope authorized", issued))
            self._event("task_events", task_id, "APPROVAL_RECORDED", actor, "Concrete envelope authorized", details={"approval_id": approval_id, "digest": digest(envelope)})
        return decode(self.store.one("approvals", approval_id))

    def _valid_approval(self, approval, envelope):
        require(not approval["revoked_at"], "Approval revoked")
        require(timestamp(approval["expires_at"]) > timestamp(now()), "Approval expired")
        require(approval["envelope_digest"] == digest(envelope) and approval["envelope_json"] == canonical_json(envelope), "Approval envelope mismatch")

    def _find_approval(self, task):
        require(task["envelope_json"], "Task has no envelope")
        from .controlled import bound_task, validate_task
        if bound_task(self, task["id"]):
            validate_task(self, task)
        envelope = json.loads(task["envelope_json"])
        for row in self.db.execute("SELECT * FROM approvals WHERE task_id=? ORDER BY issued_at DESC", (task["id"],)):
            try:
                self._valid_approval(row, envelope)
                return dict(row)
            except ACPError:
                continue
        raise ACPError("No valid authorization for the current envelope")

    def revoke(self, approval_id, actor, reason):
        require(actor.role in {"human", "policy"}, "Revocation authority required")
        with self.store.transaction():
            approval = self.store.one("approvals", approval_id)
            require(actor.role == "human" or approval["kind"] == "policy", "Policy cannot revoke a human approval")
            require(not approval["revoked_at"], "Approval already revoked")
            self.db.execute("UPDATE approvals SET revoked_at=? WHERE id=?", (now(), approval_id))
            self.db.execute("INSERT INTO approval_events (approval_id,kind,actor_json,reason,at) VALUES (?,'REVOKED',?,?,?)", (approval_id, canonical_json(actor.record()), text(reason, "reason"), now()))
            for row in self.db.execute("SELECT * FROM execution_attempts WHERE approval_id=?", (approval_id,)).fetchall():
                if row["state"] not in TERMINAL_ATTEMPTS | {"CANCEL_REQUESTED"}:
                    self._attempt_state(dict(row), "CANCEL_REQUESTED", actor, "Authorization revoked; stop still unconfirmed")
            task = self.store.one("tasks", approval["task_id"])
            if task["state"] in {"READY", "RUNNING", "REVIEW", "BLOCKED", "NEEDS_HUMAN"}:
                self._hold(task["id"], actor, "AUTHORIZATION_REVOKED")
            self._event("task_events", task["id"], "APPROVAL_REVOKED", actor, reason, details={"approval_id": approval_id})
        return decode(self.store.one("approvals", approval_id))

    def attempt_create(self, task_id, approval_id, actor, *, dag_dispatch=None):
        require(actor.role in {"human", "controller"}, "Attempt allocation requires operator/controller")
        with self.store.transaction():
            task = self.store.one("tasks", task_id)
            require(task["state"] == "READY", "Attempt creation requires READY")
            from . import dag
            dag.allocation_guard(self, task_id, dag_dispatch)
            from . import isolation
            retry_previous = isolation.allocate_guard(self, task) if isolation.bound_task(self, task_id) else None
            from .controlled import bound_task, validate_task
            if bound_task(self, task_id):
                validate_task(self, task)
                require(not self.db.execute("SELECT 1 FROM execution_attempts WHERE task_id=?", (task_id,)).fetchone(), "M06 retries are deferred")
            require(not self._unresolved(task_id), "Prior attempt requires termination/fencing before retry")
            project = self.store.one("projects", task["project_id"])
            require(project["enabled"], "Project disabled")
            envelope = json.loads(task["envelope_json"])
            validate_envelope(envelope, task, project)
            approval = self.store.one("approvals", approval_id)
            require(approval["task_id"] == task_id, "Cross-task approval forbidden")
            self._valid_approval(approval, envelope)
            attempt_id, at = identity("ATT"), now()
            contract = {**envelope, "approval_reference": approval_id}
            self.db.execute("INSERT INTO execution_attempts (id,task_id,contract_json,contract_digest,approval_id,idempotency_key,state,created_at,updated_at) VALUES (?,?,?,?,?,?,'CREATED',?,?)", (attempt_id, task_id, canonical_json(contract), digest(contract), approval_id, identity("KEY"), at, at))
            if retry_previous:
                self.db.execute("INSERT INTO isolation_retries VALUES (?,?)", (retry_previous, attempt_id))
            self._event("attempt_events", attempt_id, "CREATED", actor, "Immutable attempt allocated", after="CREATED", details={"contract_digest": digest(contract)})
            self._task_state(task, "RUNNING", actor, "Canonical attempt allocated", {"attempt_id": attempt_id})
        return self.attempt_show(attempt_id)

    def _attempt_state(self, attempt, target, actor, reason, details=None):
        if attempt["state"] == target:
            self._event("attempt_events", attempt["id"], "OBSERVED", actor, reason, attempt["state"], target, details)
            return
        require(target in ATTEMPT_EDGES[attempt["state"]], f"Illegal attempt transition {attempt['state']} -> {target}")
        self.db.execute("UPDATE execution_attempts SET state=?,updated_at=? WHERE id=?", (target, now(), attempt["id"]))
        self._event("attempt_events", attempt["id"], "TRANSITION", actor, reason, attempt["state"], target, details)
        self._event("task_events", attempt["task_id"], "ATTEMPT_OBSERVED", actor, reason, details={"attempt_id": attempt["id"], "state": target})

    def _check_attempt_authorization(self, attempt, actor):
        contract = json.loads(attempt["contract_json"])
        envelope = {k: v for k, v in contract.items() if k != "approval_reference"}
        try:
            self._valid_approval(self.store.one("approvals", attempt["approval_id"]), envelope)
        except ACPError:
            if attempt["state"] not in TERMINAL_ATTEMPTS | {"CANCEL_REQUESTED"}:
                self._attempt_state(attempt, "CANCEL_REQUESTED", actor, "Authorization invalid; stop unconfirmed")
            self._hold(attempt["task_id"], actor, "AUTHORIZATION_INVALID")
            return False
        return True

    def adapter_operation(self, attempt_id, operation, adapter, actor):
        from .controlled import bound_task
        attempt_task = self.store.one("execution_attempts", attempt_id)["task_id"]
        require(not bound_task(self, attempt_task), "M06 attempt cannot use legacy/external adapters")
        from . import isolation
        require(not isolation.bound_task(self, attempt_task), "M08 attempts require the isolated VMware path; no adapter fallback")
        if getattr(adapter, "real_execution", False):
            from .execution import operate
            return operate(self, attempt_id, operation, adapter, actor)
        require(not self.db.execute("SELECT 1 FROM attempt_events WHERE attempt_id=? AND kind='DISPATCH_INTENT'", (attempt_id,)).fetchone(), "Guarded attempt cannot switch to simulation")
        require(type(adapter) is SyntheticAdapter, "M02 permits only its built-in harmless synthetic adapter")
        require(operation in {"submit", "snapshot", "reconcile", "cancel", "collect"}, "Unknown adapter operation")
        require(actor.role in {"human", "controller"}, "Controller/operator authority required")
        with self.store.transaction():
            attempt = self.store.one("execution_attempts", attempt_id)
            require(not attempt["quarantined"], "Quarantined attempt output cannot be accepted or reused")
            if operation == "collect":
                for record in adapter.collect_evidence(attempt["idempotency_key"]):
                    self._evidence(attempt["task_id"], attempt_id, record, actor)
            elif operation == "cancel":
                require(attempt["state"] not in TERMINAL_ATTEMPTS, "Attempt already terminal")
                response = adapter.cancel(attempt["idempotency_key"])
                self._attempt_state(attempt, "CANCEL_REQUESTED", actor, "Cancellation requested, not confirmed", asdict(response))
                self._hold(attempt["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")
            elif self._check_attempt_authorization(attempt, actor):
                require(attempt["state"] not in TERMINAL_ATTEMPTS or operation == "submit", "Terminal attempt cannot resume")
                previous = self.db.execute("SELECT * FROM backend_mappings WHERE attempt_id=? AND backend=?", (attempt_id, adapter.name)).fetchone()
                if operation == "submit" and previous:
                    self._event("attempt_events", attempt_id, "IDEMPOTENT_LOOKUP", actor, "Existing mapping reused; no new submission")
                else:
                    if operation == "submit":
                        require(attempt["state"] == "CREATED", "Unknown submission outcome must reconcile, not resubmit")
                        response = adapter.submit(json.loads(attempt["contract_json"]), attempt["idempotency_key"])
                    else:
                        require(attempt["state"] != "CREATED", "Attempt not submitted")
                        method = adapter.get_snapshot if operation == "snapshot" else adapter.reconcile
                        response = method(attempt["idempotency_key"])
                    observation = asdict(response)
                    self._event("attempt_events", attempt_id, "ADAPTER_OBSERVATION", actor, operation, details=observation)
                    if response.backend_task_id and not previous:
                        self.db.execute("INSERT INTO backend_mappings VALUES (?,?,?,?,?,?,?,?,?)", (identity("MAP"), attempt_id, adapter.name, adapter.version, response.backend_task_id, response.backend_session_id, attempt["idempotency_key"], canonical_json(observation), now()))
                    elif previous and response.backend_task_id:
                        require(previous["backend_task_id"] == response.backend_task_id, "Backend mapping conflict; no silent replacement")
                    if response.outcome == Outcome.UNSUPPORTED:
                        if operation == "submit":
                            self._attempt_state(attempt, "FAILED", actor, "Unsupported capability; no execution dispatched")
                        self._hold(attempt["task_id"], actor, "UNSUPPORTED_CAPABILITY")
                    elif response.outcome == Outcome.UNKNOWN:
                        self._attempt_state(attempt, "LOST", actor, "Execution ownership unknown", observation)
                        self._hold(attempt["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")
                    else:
                        require(response.state is not None, "Adapter omitted normalized state")
                        cancelled = self.db.execute("SELECT 1 FROM attempt_events WHERE attempt_id=? AND to_state='CANCEL_REQUESTED' LIMIT 1", (attempt_id,)).fetchone()
                        if cancelled:
                            self._attempt_state(attempt, "CANCEL_REQUESTED", actor, "Cancellation intent retained; completion is not stop proof", observation)
                            self._hold(attempt["task_id"], actor, "EXECUTION_OWNERSHIP_UNCERTAIN")
                            continue_review = False
                        else:
                            self._attempt_state(attempt, response.state, actor, "Normalized backend observation", observation)
                            continue_review = response.state == "SUCCEEDED"
                        task = self.store.one("tasks", attempt["task_id"])
                        if continue_review and task["state"] == "RUNNING":
                            self._task_state(task, "REVIEW", actor, "Execution completion requires separate ACP acceptance")
        return self.attempt_show(attempt_id)

    def _evidence(self, task_id, attempt_id, record, actor):
        self.store.one("tasks", task_id)
        require(isinstance(record, dict), "Evidence must be a JSON object")
        if attempt_id:
            require(self.store.one("execution_attempts", attempt_id)["task_id"] == task_id, "Cross-task evidence forbidden")
        require(record.get("class") in {"claim", "artifact", "repository_fact", "independent_result"}, "Invalid evidence class")
        require(record.get("trust") in {"unverified", "observed", "independently_verified"}, "Invalid trust")
        for field in ("producer", "collector", "collection_method"):
            text(record.get(field), field)
        require(record.get("producer_role") in VERIFIERS | {"worker"}, "Evidence producer role required")
        require(record.get("outcome") in {"pass", "fail", "unknown"}, "Evidence outcome required")
        require("content" in record or bool(record.get("artifact_reference")), "Evidence content or artifact reference required")
        if record["class"] == "claim" or record["producer_role"] == "worker":
            require(record["trust"] != "independently_verified" and record["class"] != "independent_result", "Worker evidence cannot be promoted to independent evidence")
        if record["class"] == "claim":
            require(record["trust"] == "unverified", "Claims remain unverified")
        if record["class"] == "independent_result" or record["trust"] == "independently_verified":
            require(actor.role in VERIFIERS and record["producer_role"] in VERIFIERS, "Independent verifier provenance required")
            require(record["trust"] == "independently_verified", "Independent result requires independent trust")
            text(record.get("verification_reference"), "verification_reference")
        if "observed_at" in record:
            timestamp(record["observed_at"])
        if "exit_code" in record:
            require(type(record["exit_code"]) is int, "exit_code must be an integer")
        evidence_id, at = identity("EVD"), now()
        retained = {**record, "recorded_by": actor.record()}
        self.db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)", (evidence_id, task_id, attempt_id, record["class"], record["trust"], canonical_json(retained), digest(retained), at))
        self._event("task_events", task_id, "EVIDENCE_ADDED", actor, "Append-only provenance record", details={"evidence_id": evidence_id, "attempt_id": attempt_id})
        return evidence_id

    def evidence_add(self, task_id, attempt_id, record, actor):
        with self.store.transaction():
            evidence_id = self._evidence(task_id, attempt_id, record, actor)
        return decode(self.store.one("evidence", evidence_id))

    def fence(self, attempt_id, evidence_id, actor, reason):
        require(actor.role in VERIFIERS, "Fence verification requires independent authority")
        from .controlled import bound_task
        require(not bound_task(self, self.store.one("execution_attempts", attempt_id)["task_id"]), "M06 does not implement fencing/retries")
        from . import isolation
        require(not isolation.bound_task(self, self.store.one("execution_attempts", attempt_id)["task_id"]), "M08 requires durable host-owned VMware fence receipt")
        with self.store.transaction():
            attempt = self.store.one("execution_attempts", attempt_id)
            require(attempt["state"] in UNCERTAIN and not attempt["fence_evidence_id"], "Fence requires an unresolved, unfenced attempt")
            ev = self.store.one("evidence", evidence_id)
            data = json.loads(ev["record_json"])
            proof = data.get("content", {})
            require(ev["attempt_id"] == attempt_id and ev["class"] == "independent_result" and ev["trust"] == "independently_verified" and data["outcome"] == "pass", "Independent attempt-specific fencing evidence required")
            require(isinstance(proof, dict) and proof.get("fence_kind") in {"termination", "write_revocation", "isolated_environment"}, "Invalid fencing proof kind")
            require(proof.get("contract_digest") == attempt["contract_digest"], "Fencing proof must bind the protected attempt contract")
            text(proof.get("protected_resources"), "protected_resources")
            text(proof.get("explanation"), "fencing explanation")
            if proof["fence_kind"] == "isolated_environment":
                require(proof.get("old_attempt_cannot_affect_new_environment") is True and proof.get("quarantine_outputs") is True, "Isolation and quarantine attestations required; a worktree alone is insufficient")
            self.db.execute("UPDATE execution_attempts SET fence_evidence_id=?,quarantined=1,updated_at=? WHERE id=?", (evidence_id, now(), attempt_id))
            self._event("attempt_events", attempt_id, "FENCED", actor, reason, details={"evidence_id": evidence_id, "proof": proof})
            if proof["fence_kind"] == "termination":
                self._attempt_state(attempt, "CANCELLED", actor, "Independent termination attestation recorded", {"evidence_id": evidence_id})
        return self.attempt_show(attempt_id)

    def accept(self, task_id, attempt_id, criteria_evidence, actor, reason, *, review_decision=None):
        require(actor.role in VERIFIERS, "Independent review authority required")
        from .controlled import bound_task
        require(not bound_task(self, task_id), "M06 synthetic outcome is not task acceptance")
        from . import isolation
        require(isinstance(criteria_evidence, dict), "Criterion-to-evidence object required")
        with self.store.transaction():
            from . import review
            review.accept_guard(self, task_id, attempt_id, review_decision)
            if isolation.bound_task(self, task_id):
                isolation.accept_guard(self, task_id, attempt_id, criteria_evidence)
            task = self.store.one("tasks", task_id)
            require(task["state"] == "REVIEW" and not task["hold_reason"], "Task must be in unblocked REVIEW")
            require(not self._unresolved(task_id), "Unresolved attempts block acceptance")
            attempt = self.store.one("execution_attempts", attempt_id)
            require(attempt["task_id"] == task_id and attempt["state"] == "SUCCEEDED" and not attempt["quarantined"], "Successful non-quarantined attempt required")
            contract = json.loads(attempt["contract_json"])
            envelope = {k: v for k, v in contract.items() if k != "approval_reference"}
            require(canonical_json(envelope) == task["envelope_json"], "Attempt is from a different approved plan")
            guarded = self.db.execute("SELECT 1 FROM attempt_events WHERE attempt_id=? AND kind='DISPATCH_INTENT'", (attempt_id,)).fetchone()
            if guarded:
                checks = [json.loads(row[0]) for row in self.db.execute("SELECT details_json FROM attempt_events WHERE attempt_id=? AND kind='GUARD_VERIFIED' ORDER BY seq", (attempt_id,))]
                require(checks and all(c["pass"] for c in checks), "Mandatory independent execution checks missing or failed")
                require(checks[-1]["evidence_id"] in criteria_evidence.values(), "Review must use latest controller verification")
                from .guarded import repository_facts
                fact = json.loads(self.store.one("evidence", checks[-1]["repository_evidence_id"])["record_json"])["content"]
                current = repository_facts(fact["workspace"], self.store.one("projects", task["project_id"])["path"], contract)
                require(current == fact, "Repository changed since independent verification; verify again")
            self._valid_approval(self.store.one("approvals", attempt["approval_id"]), envelope)
            require(set(criteria_evidence) == {c["id"] for c in envelope["acceptance_criteria"]}, "Every approved criterion must be reviewed exactly once")
            independent_seen = False
            trust_rank = {"unverified": 0, "observed": 1, "independently_verified": 2}
            for criterion in envelope["acceptance_criteria"]:
                ev = self.store.one("evidence", criteria_evidence[criterion["id"]])
                data = json.loads(ev["record_json"])
                require(ev["task_id"] == task_id and ev["attempt_id"] == attempt_id, "Acceptance evidence must belong to this attempt")
                require(ev["class"] == criterion["evidence_class"] and trust_rank[ev["trust"]] >= trust_rank[criterion["trust"]], "Evidence class/trust does not satisfy criterion")
                require(data["outcome"] == "pass", "Failed or unknown evidence cannot satisfy acceptance")
                require(data.get("base_commit") == envelope["base_commit"], "Evidence base binding mismatch")
                if "exit_code" in data:
                    require(data["exit_code"] == 0, "Nonzero verification exit code")
                independent_seen |= ev["class"] == "independent_result" and ev["trust"] == "independently_verified"
            require(envelope["change_kind"] != "executable" or independent_seen, "Executable changes require independent verification")
            self._task_state(task, "DONE", actor, text(reason, "review reason"), {"attempt_id": attempt_id, "criteria_evidence": criteria_evidence, "meaning": "bounded task acceptance only; not integration, merge, release or deployment"})
            from . import dag
            dag.accepted(self, task_id, attempt_id, criteria_evidence, actor)
        return self.task_show(task_id)
