from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from acp.adapters import Outcome, SyntheticAdapter
from acp.domain import ACPError, Actor, AttemptState, windows_path_key
from acp.runtime import Runtime
from acp.store import Store, data_directory, SCHEMA_VERSION

HUMAN = Actor("principal", "human", "test")
CONTROL = Actor("independent-check", "controller", "test")
WORKER = Actor("worker", "worker", "test")
POLICY = Actor("bounded-read-policy", "policy", "test")
ROOT = Path(__file__).resolve().parents[1]


def expiry():
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def envelope(project, kind="documentation"):
    return {"task_revision": 1, "plan_revision": 1, "primary_project": project["id"],
            "repository_identity": project["repository_identity"], "base_commit": project["observed_head"],
            "context_manifest": {"source": "fixture"}, "write_scope": [] if kind == "read_only" else ["allowed.txt"],
            "forbidden_scope": ["forbidden.txt"], "allowed_operations": ["read"] if kind == "read_only" else ["edit"],
            "prohibited_operations": ["deploy", "push"], "runtime_profile": "synthetic", "network_capability": "none",
            "credential_capability": "none", "risk_class": "low", "change_kind": kind,
            "acceptance_criteria": [{"id": "checked", "description": "Independent check", "evidence_class": "independent_result", "trust": "independently_verified"}]}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="acp-m02-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project_path = self.root / "synthetic-project"
        self.project_path.mkdir()
        (self.project_path / "allowed.txt").write_text("unchanged", encoding="utf-8")
        self.r = Runtime(self.root / "state")
        self.addCleanup(self.r.close)
        self.project = self.r.project_add("synthetic", self.project_path)

    def task(self):
        return self.r.task_create("synthetic", "Test", "合成任務", HUMAN)["id"]

    def planned(self, kind="documentation", change=None):
        task = self.task()
        self.r.transition(task, "TRIAGE", HUMAN, "triage")
        plan = envelope(self.project, kind)
        if change:
            change(plan)
        self.r.plan(task, plan, HUMAN, "bounded plan")
        return task

    def attempt(self, scenario=None, kind="documentation", change=None):
        task = self.planned(kind, change)
        approval = self.r.approve(task, "human", HUMAN, expiry())["id"]
        self.r.transition(task, "READY", HUMAN, "approved")
        attempt = self.r.attempt_create(task, approval, HUMAN)["id"]
        if scenario:
            self.r.adapter_operation(attempt, "submit", SyntheticAdapter(scenario), CONTROL)
        return task, attempt, approval

    def evidence(self, task, attempt, **changes):
        record = {"class": "independent_result", "trust": "independently_verified", "producer": "test-verifier", "producer_role": "controller", "collector": "test-controller", "collection_method": "deterministic fixture check", "verification_reference": "test:fixture", "outcome": "pass", "base_commit": self.project["observed_head"], "exit_code": 0, "content": {"synthetic": True}}
        record.update(changes)
        return self.r.evidence_add(task, attempt, record, CONTROL)["id"]

    def fence(self, task, attempt, kind="termination"):
        current = self.r.attempt_show(attempt)
        ev = self.evidence(task, attempt, content={"fence_kind": kind, "contract_digest": current["contract_digest"], "protected_resources": "synthetic only", "explanation": "Explicit test attestation; no real worker", "old_attempt_cannot_affect_new_environment": True, "quarantine_outputs": True})
        return self.r.fence(attempt, ev, CONTROL, "fencing evidence")

    def test_fresh_schema_and_integrity(self):
        for pragma, expected in (("user_version", SCHEMA_VERSION), ("foreign_keys", 1), ("integrity_check", "ok")):
            self.assertEqual(self.r.db.execute("PRAGMA " + pragma).fetchone()[0], expected)

    def test_migration_idempotent(self):
        with Store(self.root / "state") as other:
            self.assertEqual(other.db.execute("SELECT count(*) FROM schema_metadata").fetchone()[0], SCHEMA_VERSION)

    def test_future_version_not_downgraded(self):
        self.r.db.execute("PRAGMA user_version=99")
        with self.assertRaises(ACPError):
            Runtime(self.root / "state")

    def test_unversioned_nonempty_database_rejected(self):
        state = self.root / "unknown"
        state.mkdir()
        db = sqlite3.connect(state / "acp.sqlite3")
        try:
            db.execute("CREATE TABLE unrelated (id INTEGER)")
            db.commit()
        finally:
            db.close()
        with self.assertRaises(ACPError):
            Runtime(state)

    def test_state_directory_boundaries_and_override(self):
        with self.assertRaises(ACPError):
            Runtime(ROOT / "forbidden-state")
        self.assertFalse((ROOT / "forbidden-state").exists())
        with self.assertRaises(ACPError):
            self.r.project_add("contains-state", self.root)
        with patch.dict(os.environ, {"ACP_DATA_DIR": str(self.root / "override")}):
            self.assertEqual(data_directory(), (self.root / "override").resolve())
        with patch.dict(os.environ, {"LOCALAPPDATA": str(self.root / "local")}, clear=True):
            self.assertEqual(data_directory(), (self.root / "local" / "AgentControlPlane").resolve())

    def test_registry_persistence_and_idempotency(self):
        self.assertEqual(self.r.project_add("synthetic", self.project_path / "."), self.project)
        with Runtime(self.root / "state") as other:
            self.assertEqual(other.project_show("synthetic"), self.project)
        self.assertEqual(len(self.r.project_list()), 1)

    def test_registry_identity_cannot_rebind(self):
        other = self.root / "other"
        other.mkdir()
        with self.assertRaises(ACPError):
            self.r.project_add("synthetic", other)
        with self.assertRaises(sqlite3.IntegrityError):
            self.r.project_add("duplicate", self.project_path)

    def test_windows_normalization(self):
        self.assertEqual(windows_path_key("C:/Work/Project/../PROJECT/"), r"c:\work\project")
        self.assertEqual(windows_path_key(r"\\SERVER\Share\A\..\B"), r"\\server\share\b")
        for value in ("C:relative", "relative", r"\without-drive"):
            with self.assertRaises(ACPError):
                windows_path_key(value)

    def test_task_persistence(self):
        task = self.task()
        with Runtime(self.root / "state") as other:
            self.assertEqual(other.task_show(task)["state"], "NEW")
            self.assertEqual(other.task_show(task)["request"], "合成任務")
            self.assertEqual(len(other.events(task)), 1)

    def test_unknown_project_rejected(self):
        with self.assertRaises(ACPError):
            self.r.task_create("unknown", "x", "x", HUMAN)

    def test_disabled_project_blocks_intake(self):
        path = self.root / "disabled-project"
        path.mkdir()
        result = self.r.project_add("disabled", path, enabled=False)
        self.assertEqual(result["enabled"], 0)
        with self.assertRaises(ACPError):
            self.r.task_create("disabled", "test", "test", HUMAN)

    def test_scope_and_context_reject_obvious_external_paths(self):
        for scope in ("../outside", r"C:\outside", r"\\server\share\file", "file:stream"):
            with self.assertRaises(ACPError):
                self.planned(change=lambda p: p.update(write_scope=[scope]))
            with self.assertRaises(ACPError):
                self.planned(change=lambda p: p.update(context_manifest={"files": [scope]}))

    def test_foreign_key_integrity_rejects_orphan_event(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.r.db.execute("INSERT INTO task_events (task_id,kind,actor_json,reason,details_json,at) VALUES ('missing','CREATED','{}','test','{}','now')")

    def test_approval_and_attempt_history_cannot_be_rewritten(self):
        _, _, approval = self.attempt("running")
        for sql in ("UPDATE approval_events SET reason='x'", "DELETE FROM approval_events", "UPDATE attempt_events SET reason='x'", "DELETE FROM attempt_events", "UPDATE approvals SET envelope_json='{}'", "DELETE FROM backend_mappings"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.r.db.execute(sql)

    def test_revised_plan_invalidates_old_approval(self):
        task, attempt, approval = self.attempt("complete")
        self.r.transition(task, "REWORK", HUMAN, "Revise bounded plan")
        plan = envelope(self.project)
        plan["plan_revision"] = 2
        self.r.plan(task, plan, HUMAN, "new plan revision")
        with self.assertRaises(ACPError):
            self.r.transition(task, "READY", HUMAN, "old approval must not apply")
        self.r.approve(task, "human", HUMAN, expiry())
        self.r.transition(task, "READY", HUMAN, "fresh approval")
        with self.assertRaises(ACPError):
            self.r.attempt_create(task, approval, HUMAN)

    def test_legal_transition_audited(self):
        task = self.task()
        self.r.transition(task, "TRIAGE", HUMAN, "explicit triage")
        event = self.r.events(task)[-1]
        self.assertEqual((event["from_state"], event["to_state"]), ("NEW", "TRIAGE"))
        self.assertEqual(event["actor"]["name"], "principal")

    def test_illegal_transition_rolls_back(self):
        task = self.task()
        before = self.r.events(task)
        with self.assertRaises(ACPError):
            self.r.transition(task, "READY", HUMAN, "skip")
        self.assertEqual(self.r.task_show(task)["state"], "NEW")
        self.assertEqual(self.r.events(task), before)

    def test_audit_failure_rolls_back_snapshot(self):
        task = self.task()
        with patch.object(self.r, "_event", side_effect=RuntimeError("audit failed")):
            with self.assertRaises(RuntimeError):
                self.r.transition(task, "TRIAGE", HUMAN, "rollback")
        self.assertEqual(self.r.task_show(task)["state"], "NEW")

    def test_events_are_append_only(self):
        task = self.task()
        for sql in ("UPDATE task_events SET reason='overwrite'", "DELETE FROM task_events"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.r.db.execute(sql)
        self.assertEqual(len(self.r.events(task)), 1)

    def test_authority_roles_and_human_gate(self):
        task = self.task()
        with self.assertRaises(ACPError):
            self.r.transition(task, "TRIAGE", WORKER, "unauthorized")
        self.r.transition(task, "NEEDS_HUMAN", HUMAN, "decision required")
        with self.assertRaises(ACPError):
            self.r.resolve_hold(task, CONTROL, "not principal")
        self.assertEqual(self.r.resolve_hold(task, HUMAN, "decision recorded")["state"], "NEW")

    def test_plan_binding_validation(self):
        task = self.task()
        self.r.transition(task, "TRIAGE", HUMAN, "triage")
        for field, value in (("primary_project", "other"), ("repository_identity", "other"), ("task_revision", 2), ("plan_revision", 2)):
            contract = envelope(self.project)
            contract[field] = value
            with self.assertRaises(ACPError):
                self.r.plan(task, contract, HUMAN, "invalid")
        self.assertEqual(self.r.task_show(task)["state"], "TRIAGE")

    def test_ready_requires_approval(self):
        with self.assertRaises(ACPError):
            self.r.transition(self.planned(), "READY", HUMAN, "unapproved")

    def test_attempt_input_immutable(self):
        _, attempt, _ = self.attempt()
        for field, value in (("contract_json", "{}"), ("contract_digest", "changed"), ("approval_id", "other"), ("idempotency_key", "other")):
            with self.assertRaises(sqlite3.IntegrityError):
                self.r.db.execute(f"UPDATE execution_attempts SET {field}=? WHERE id=?", (value, attempt))
        record = self.r.attempt_show(attempt)
        record["contract"]["write_scope"].append("forbidden.txt")
        self.assertEqual(self.r.attempt_show(attempt)["contract"]["write_scope"], ["allowed.txt"])

    def test_attempt_lifecycle_persistence(self):
        task, attempt, _ = self.attempt("running")
        with Runtime(self.root / "state") as other:
            self.assertEqual(other.attempt_show(attempt)["state"], "RUNNING")
            self.assertEqual(other.task_show(task)["state"], "RUNNING")

    def test_normalized_queue_start_run_sequence(self):
        _, attempt, _ = self.attempt()
        for state in ("QUEUED", "STARTING", "RUNNING", "SUCCEEDED"):
            with self.r.store.transaction():
                self.r._attempt_state(self.r.store.one("execution_attempts", attempt), state, CONTROL, "explicit normalized fixture")
            self.assertEqual(self.r.attempt_show(attempt)["state"], state)
        self.assertEqual([e["to_state"] for e in self.r.attempt_show(attempt)["events"]], ["CREATED", "QUEUED", "STARTING", "RUNNING", "SUCCEEDED"])

    def test_planner_cannot_cancel_task(self):
        task = self.planned()
        self.r.approve(task, "human", HUMAN, expiry())
        self.r.transition(task, "READY", HUMAN, "approved")
        with self.assertRaises(ACPError):
            self.r.transition(task, "CANCELLED", Actor("planner", "planner"), "not cancellation authority")

    def test_backend_success_is_not_done(self):
        task, attempt, _ = self.attempt("complete")
        self.assertEqual(self.r.attempt_show(attempt)["state"], "SUCCEEDED")
        self.assertEqual(self.r.task_show(task)["state"], "REVIEW")
        with self.assertRaises(ACPError):
            self.r.transition(task, "DONE", HUMAN, "skip acceptance")
        with self.r.store.transaction():
            with self.assertRaises(ACPError):
                self.r._attempt_state(self.r.store.one("execution_attempts", attempt), "RUNNING", CONTROL, "illegal")

    def test_mapping_separation_and_idempotency(self):
        task, attempt, _ = self.attempt("complete")
        first = self.r.attempt_show(attempt)["backend_mappings"]
        self.assertTrue(task.startswith("TASK-") and attempt.startswith("ATT-"))
        self.assertTrue(first[0]["backend_task_id"].startswith("demo-"))
        self.r.adapter_operation(attempt, "submit", SyntheticAdapter(), CONTROL)
        self.assertEqual(first, self.r.attempt_show(attempt)["backend_mappings"])
        self.assertNotIn("backend_task_id", [r[1] for r in self.r.db.execute("PRAGMA table_info(tasks)")])

    def test_unknown_reconciliation(self):
        task, attempt, _ = self.attempt("unknown")
        self.assertEqual(self.r.task_show(task)["hold_reason"], "EXECUTION_OWNERSHIP_UNCERTAIN")
        self.assertEqual(self.r.attempt_show(attempt)["state"], "LOST")
        self.r.adapter_operation(attempt, "reconcile", SyntheticAdapter(), CONTROL)
        self.r.resolve_hold(task, HUMAN, "ownership reconciled")
        self.assertEqual(self.r.transition(task, "REVIEW", HUMAN, "review")["state"], "REVIEW")

    def test_unsupported_capability(self):
        task, attempt, _ = self.attempt("unsupported")
        self.assertEqual(self.r.task_show(task)["hold_reason"], "UNSUPPORTED_CAPABILITY")
        self.assertEqual(self.r.attempt_show(attempt)["state"], "FAILED")
        self.assertEqual(SyntheticAdapter().submit({"runtime_profile": "external"}, "key").outcome, Outcome.UNSUPPORTED)

    def test_non_synthetic_adapter_rejected(self):
        _, attempt, _ = self.attempt()
        with self.assertRaises(ACPError):
            self.r.adapter_operation(attempt, "submit", object(), CONTROL)

    def test_cancellation_ack_blocks_retry(self):
        task, attempt, _ = self.attempt("running")
        self.r.adapter_operation(attempt, "cancel", SyntheticAdapter(), CONTROL)
        self.assertEqual(self.r.attempt_show(attempt)["state"], "CANCEL_REQUESTED")
        with self.assertRaises(ACPError):
            self.r.resolve_hold(task, HUMAN, "unsafe retry", retry_ready=True)

    def test_cancel_intent_survives_unknown_then_success(self):
        task, attempt, _ = self.attempt("running")
        for operation, scenario in (("cancel", "complete"), ("reconcile", "unknown"), ("reconcile", "complete")):
            self.r.adapter_operation(attempt, operation, SyntheticAdapter(scenario), CONTROL)
        self.assertEqual(self.r.attempt_show(attempt)["state"], "CANCEL_REQUESTED")
        self.assertEqual(self.r.task_show(task)["state"], "BLOCKED")

    def test_fenced_retry_allocates_distinct_attempt(self):
        task, attempt, approval = self.attempt("unknown")
        self.fence(task, attempt)
        self.r.resolve_hold(task, HUMAN, "confirmed stop permits retry", retry_ready=True)
        new = self.r.attempt_create(task, approval, HUMAN)
        self.assertNotEqual(new["id"], attempt)
        self.assertEqual(self.r.attempt_show(attempt)["state"], "CANCELLED")
        self.assertEqual(len(self.r.task_show(task)["attempts"]), 2)

    def test_isolation_fence_quarantines_output(self):
        task, attempt, approval = self.attempt("unknown")
        self.fence(task, attempt, "isolated_environment")
        self.assertEqual(self.r.attempt_show(attempt)["state"], "LOST")
        with self.assertRaises(ACPError):
            self.r.adapter_operation(attempt, "reconcile", SyntheticAdapter(), CONTROL)
        self.r.resolve_hold(task, HUMAN, "isolated retry attested", retry_ready=True)
        self.r.attempt_create(task, approval, HUMAN)

    def test_bad_fence_binding_rejected(self):
        task, attempt, _ = self.attempt("unknown")
        ev = self.evidence(task, attempt, content={"fence_kind": "termination", "contract_digest": "wrong", "protected_resources": "x", "explanation": "x"})
        with self.assertRaises(ACPError):
            self.r.fence(attempt, ev, HUMAN, "bad proof")

    def test_approval_revocation(self):
        task, attempt, approval = self.attempt("running")
        self.r.revoke(approval, HUMAN, "withdrawn")
        self.assertEqual(self.r.attempt_show(attempt)["state"], "CANCEL_REQUESTED")
        self.assertEqual(self.r.task_show(task)["state"], "BLOCKED")
        self.assertEqual(self.r.db.execute("SELECT count(*) FROM approval_events").fetchone()[0], 2)

    def test_expiry_prevents_dispatch_or_acceptance(self):
        task, attempt, _ = self.attempt("running")
        with patch("acp.runtime.now", return_value="2099-01-01T00:00:00+00:00"):
            self.r.adapter_operation(attempt, "reconcile", SyntheticAdapter(), CONTROL)
        self.assertEqual(self.r.attempt_show(attempt)["state"], "CANCEL_REQUESTED")
        self.assertEqual(self.r.task_show(task)["hold_reason"], "AUTHORIZATION_INVALID")
        for invalid in ("2020-01-01T00:00:00Z", "2099-01-01", "invalid"):
            with self.assertRaises(ACPError):
                self.r.approve(task, "human", HUMAN, invalid)

    def test_policy_only_bounded_nonprivileged_reads(self):
        self.r.approve(self.planned("read_only"), "policy", POLICY, expiry(), "policy:bounded")
        for field, value in (("network_capability", "internet"), ("credential_capability", "secrets"), ("allowed_operations", ["read_external_repository"]), ("risk_class", "high"), ("write_scope", ["x"])):
            task = self.planned("read_only", lambda p: p.update({field: value}))
            with self.assertRaises(ACPError):
                self.r.approve(task, "policy", POLICY, expiry(), "policy:bounded")

    def test_cross_task_approval_forbidden(self):
        _, _, approval = self.attempt()
        task = self.planned()
        self.r.approve(task, "human", HUMAN, expiry())
        self.r.transition(task, "READY", HUMAN, "ready")
        with self.assertRaises(ACPError):
            self.r.attempt_create(task, approval, HUMAN)

    def test_evidence_immutable_with_provenance(self):
        task, attempt, _ = self.attempt("complete")
        ev = self.evidence(task, attempt)
        for sql in ("UPDATE evidence SET digest='x'", "DELETE FROM evidence"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.r.db.execute(sql)
        record = self.r.task_show(task)["evidence"][0]
        self.assertEqual(record["id"], ev)
        self.assertEqual(record["record"]["producer"], "test-verifier")

    def test_worker_claim_never_independent(self):
        task, attempt, _ = self.attempt("complete")
        with self.assertRaises(ACPError):
            self.evidence(task, attempt, producer_role="worker")
        self.r.adapter_operation(attempt, "collect", SyntheticAdapter(), CONTROL)
        ev = self.r.task_show(task)["evidence"][0]
        self.assertEqual((ev["class"], ev["trust"]), ("claim", "unverified"))

    def test_missing_failed_or_cross_attempt_evidence_prevents_done(self):
        task, attempt, _ = self.attempt("complete")
        failed = self.evidence(task, attempt, outcome="fail")
        other, other_attempt, _ = self.attempt("complete")
        wrong = self.evidence(other, other_attempt)
        for mapping in ({}, {"checked": failed}, {"checked": wrong}):
            with self.assertRaises(ACPError):
                self.r.accept(task, attempt, mapping, HUMAN, "must reject")
        self.assertEqual(self.r.task_show(task)["state"], "REVIEW")

    def test_independent_acceptance_is_terminal_not_merge(self):
        task, attempt, _ = self.attempt("complete", "executable")
        ev = self.evidence(task, attempt)
        self.assertEqual(self.r.accept(task, attempt, {"checked": ev}, HUMAN, "independent review")["state"], "DONE")
        self.assertIn("not integration", self.r.events(task)[-1]["details"]["meaning"])
        with self.assertRaises(ACPError):
            self.r.transition(task, "TRIAGE", HUMAN, "implicit reopen")

    def test_executable_change_requires_independent_verification(self):
        def weak(plan):
            plan["acceptance_criteria"][0].update(evidence_class="claim", trust="unverified")
        task, attempt, _ = self.attempt("complete", "executable", weak)
        record = SyntheticAdapter().collect_evidence("key")[0]
        record.update(outcome="pass", base_commit=None)
        ev = self.r.evidence_add(task, attempt, record, HUMAN)["id"]
        with self.assertRaises(ACPError):
            self.r.accept(task, attempt, {"checked": ev}, HUMAN, "claim insufficient")

    def test_revoked_approval_blocks_done(self):
        task, attempt, approval = self.attempt("complete")
        ev = self.evidence(task, attempt)
        self.r.revoke(approval, HUMAN, "revoked before review")
        with self.assertRaises(ACPError):
            self.r.accept(task, attempt, {"checked": ev}, HUMAN, "not authorized")

    def test_synthetic_adapter_no_process_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("No process permitted")):
            adapter = SyntheticAdapter()
            result = adapter.submit({"runtime_profile": "synthetic"}, "stable-key")
            self.assertEqual(result.state, AttemptState.SUCCEEDED)
            self.assertEqual(result.backend_task_id, adapter.reconcile("stable-key").backend_task_id)
            self.assertEqual(adapter.cancel("stable-key").state, AttemptState.CANCEL_REQUESTED)

    def test_registered_project_not_modified(self):
        before = {str(p): p.read_bytes() for p in self.project_path.rglob("*") if p.is_file()}
        self.attempt("complete")
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.project_path.rglob("*") if p.is_file()})

    def test_all_records_survive_independent_instances(self):
        task, attempt, _ = self.attempt("complete")
        self.evidence(task, attempt)
        with Runtime(self.root / "state") as other:
            self.assertEqual(other.task_show(task), self.r.task_show(task))
            self.assertEqual(other.events(task), self.r.events(task))
            self.assertEqual(other.attempt_show(attempt), self.r.attempt_show(attempt))


class ProcessAndGitTests(unittest.TestCase):
    def test_full_cli_flow_across_independent_processes(self):
        with tempfile.TemporaryDirectory(prefix="acp-m02-process-") as directory:
            root = Path(directory)
            project = root / "repo"
            project.mkdir()
            def call(*args, expected=0):
                result = subprocess.run([sys.executable, "-B", "-m", "acp", "--data-dir", str(root / "state"), *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=20)
                self.assertEqual(result.returncode, expected, result.stderr)
                return json.loads(result.stdout if expected == 0 else result.stderr)
            self.assertEqual(call("init")["schema_version"], SCHEMA_VERSION)
            registered = call("project", "add", "--id", "demo", "--path", str(project))
            self.assertEqual(len(call("project", "list")), 1)
            task = call("task", "create", "--project", "demo", "--title", "Test", "--request", "跨程序合成測試")["id"]
            call("task", "transition", task, "TRIAGE", "--reason", "triage")
            contract = root / "envelope.json"
            contract.write_text(json.dumps(envelope(registered)), encoding="utf-8")
            call("task", "plan", task, "--file", str(contract), "--reason", "bounded plan")
            approval = call("approval", "record", "--task", task, "--kind", "human", "--expires", expiry())["id"]
            call("task", "transition", task, "READY", "--reason", "approved")
            attempt = call("attempt", "create", "--task", task, "--approval", approval)["id"]
            call("attempt", "submit", attempt)
            call("attempt", "collect", attempt)
            snapshot = call("task", "show", task)
            history = call("task", "events", task)
            self.assertEqual(snapshot["state"], "REVIEW")
            self.assertEqual(len(snapshot["evidence"]), 1)
            self.assertEqual(snapshot, call("task", "show", task))
            self.assertEqual(history, call("task", "events", task))
            self.assertIn("error", call("task", "transition", task, "DONE", "--reason", "invalid", expected=2))

    def test_git_registration_reads_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix="acp-m02-git-") as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            def git(*args):
                return subprocess.run(["git", "-c", "core.hooksPath=" + str(root / "no-hooks"), "-c", "init.templateDir=", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()
            git("init", "-b", "main")
            (repo / "README.md").write_text("synthetic", encoding="utf-8")
            git("add", "README.md")
            git("-c", "user.name=ACP Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture")
            def snapshot():
                return {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in repo.rglob("*") if p.is_file()}
            before = snapshot()
            with Runtime(root / "state") as runtime:
                project = runtime.project_add("git-fixture", repo)
                self.assertEqual(project["observed_head"], git("rev-parse", "HEAD"))
                self.assertEqual(project["git_root"], str(repo.resolve()))
                self.assertIn("README.md", project["context"])
                self.assertEqual(before, snapshot())
                with self.assertRaises(ACPError):
                    Runtime(repo / "forbidden-state")


if __name__ == "__main__":
    unittest.main()
