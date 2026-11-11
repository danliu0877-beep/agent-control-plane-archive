"""M06 synthetic lifecycle only. Child processes are test controllers, not workers."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from acp import context, controlled, planning
from acp.adapters import SyntheticAdapter
from acp.decision_provider import SyntheticDecisionProvider
from acp.domain import ACPError, Actor, canonical_json
from acp.runtime import Runtime
from acp.store import SCHEMA_VERSION
from tests.test_planning import fixture, material

HUMAN = Actor("principal", "human", "test")
CONTROL = Actor("controller", "controller", "test")
ROOT = Path(__file__).resolve().parents[1]


class ControlledTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="acp-m06-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "STATUS.md").write_text("Status: synthetic read only.\n", encoding="utf-8")
        self.r = Runtime(self.root / "state")
        self.addCleanup(lambda: self.r.close())
        self.r.project_add("demo", self.repo)
        self.task = self.r.task_create("demo", "fixture", "Synthetic inspection", HUMAN)["id"]
        self.ctx = context.load(self.r, "demo", HUMAN)["id"]
        self.plan = self.make_plan()

    def make_plan(self, change=None, revise=None, test_only=True):
        proposal = fixture()
        assessment = {"state": "NONE", "evaluated": True, "rationale": "The supplied fixture defines no business choice; this inspection reports material identifiers without resolving project decisions.", "sources": ["STATUS.md"]}
        proposal["human_assessment"] = assessment
        proposal["work_items"][0]["human_assessment"] = copy.deepcopy(assessment)
        if change:
            change(proposal)
        run = planning.prepare(self.r, self.task, self.ctx, HUMAN, plan_id=revise, test_only=test_only)
        if test_only:
            provider = SyntheticDecisionProvider(json.dumps(proposal), testing=True)
        else:
            from acp.decision_provider import SubmittedDecisionProvider
            provider = SubmittedDecisionProvider(json.dumps(proposal), "manual", "not-live", "manual")
        result = planning.complete(self.r, run["run_id"], provider, HUMAN)
        self.assertNotEqual(result["status"], "INVALID", result)
        return planning.show(self.r, result["plan_id"])

    def bind(self, executor="synthetic-inspect-v1", plan=None):
        p = plan or self.plan
        return controlled.materialize(self.r, p["plan_id"], p["plan_revision"], p["work_items"][0]["work_item_id"], executor, HUMAN)

    def allocate(self, executor="synthetic-inspect-v1", plan=None):
        binding = self.bind(executor, plan)
        task = binding["binding"]["task_id"]
        approval = self.r.approve(task, "human", HUMAN, "2099-01-01T00:00:00+00:00")
        self.r.transition(task, "READY", HUMAN, "exact binding approved")
        attempt = self.r.attempt_create(task, approval["id"], HUMAN)
        state = controlled.show(self.r, attempt["id"])
        return state, approval

    def execute(self, state, executor=None, request=None):
        return controlled.execute(self.r, state["attempt_id"], state["request"] if request is None else request,
                                  CONTROL, executor=executor or state["request"]["runtime_profile"])

    def test_authorized_binding_succeeds_without_plan_mutation(self):
        state, approval = self.allocate()
        result = self.execute(state)
        self.assertEqual(result["outcome"]["outcome"], "SUCCEEDED")
        self.assertEqual(result["lifecycle"], "OUTCOME_RECORDED")
        self.assertEqual(result["request"]["approval_reference"], approval["id"])
        self.assertEqual(self.r.task_show(state["task_id"])["state"], "REVIEW")
        self.assertEqual(planning.show(self.r, self.plan["plan_id"]), self.plan)
        self.assertEqual(self.r.task_show(self.task)["state"], "NEW")
        self.assertFalse(result["isolation_validated"])
        self.assertFalse(result["external_side_effects_enabled"])

    def test_wrong_revision_and_work_rejected(self):
        for revision, work in ((2, self.plan["work_items"][0]["work_item_id"]), (1, "WORK-forged")):
            with self.assertRaises(ACPError):
                controlled.materialize(self.r, self.plan["plan_id"], revision, work, "synthetic-inspect-v1", HUMAN)
        self.assertEqual(self.r.db.execute("SELECT count(*) FROM execution_bindings").fetchone()[0], 0)

    def test_request_cannot_substitute_any_authorization_field(self):
        state, _ = self.allocate()
        mutations = {"controlled_binding": "other", "binding_digest": "wrong", "plan_revision": 2,
                     "allowed_operations": ["shell"], "write_scope": ["*"], "context_manifest": {"files": ["secret.txt"]},
                     "approval_reference": "APR-forged", "primary_project": "other", "network_capability": "internet",
                     "credential_capability": "secrets", "runtime_profile": "real", "extra": "unknown"}
        with patch.object(controlled, "_invoke") as invoke:
            for field, value in mutations.items():
                with self.subTest(field=field):
                    request = copy.deepcopy(state["request"])
                    request[field] = value
                    with self.assertRaises(ACPError):
                        self.execute(state, request=request)
            invoke.assert_not_called()
        self.assertIsNone(controlled.show(self.r, state["attempt_id"])["receipt"])

    def test_missing_and_cross_task_approval_rejected(self):
        binding = self.bind()
        task = binding["binding"]["task_id"]
        with self.assertRaises(ACPError):
            self.r.transition(task, "READY", HUMAN, "no approval")
        with self.assertRaises(ACPError):
            self.r.attempt_create(task, "missing", HUMAN)
        _, approval = self.allocate()
        other = self.bind(plan=self.make_plan())["binding"]["task_id"]
        self.r.approve(other, "human", HUMAN, expires_at="2099-01-01T00:00:00+00:00")
        self.r.transition(other, "READY", HUMAN, "separately approved")
        with self.assertRaises(ACPError):
            self.r.attempt_create(other, approval["id"], HUMAN)

    def test_stale_source_fails_closed_without_rebinding(self):
        state, _ = self.allocate()
        self.make_plan(revise=self.plan["plan_id"])
        result = self.execute(state)
        self.assertEqual(result["outcome"]["outcome"], "REJECTED")
        self.assertIsNone(result["receipt"])
        self.assertFalse(result["evidence"]["content"]["execution_occurred"])
        self.assertEqual(result["request"], state["request"])

    def test_revoked_and_expired_approval_fail_closed(self):
        state, approval = self.allocate()
        self.r.revoke(approval["id"], HUMAN, "withdrawn")
        self.assertEqual(self.execute(state)["outcome"]["outcome"], "REJECTED")

    def test_expired_approval_before_dispatch(self):
        state, _ = self.allocate()
        with patch("acp.runtime.now", return_value="2100-01-01T00:00:00+00:00"):
            self.assertEqual(self.execute(state)["outcome"]["outcome"], "REJECTED")

    def test_receipt_visible_in_other_connection_before_invocation(self):
        state, _ = self.allocate()
        invoke = controlled._invoke
        def observed(executor, request, payload):
            self.assertFalse(self.r.db.in_transaction)
            with Runtime(self.root / "state") as other:
                saved = controlled.show(other, state["attempt_id"])
                self.assertIsNotNone(saved["receipt"])
                self.assertEqual(saved["lifecycle"], "DISPATCHED")
                self.assertEqual(saved["receipt"]["record"]["request"], request)
                self.assertEqual(saved["receipt"]["record"]["payload"], payload)
            return invoke(executor, request, payload)
        with patch.object(controlled, "_invoke", side_effect=observed):
            self.assertEqual(self.execute(state)["outcome"]["outcome"], "SUCCEEDED")

    def test_failed_and_rejected_executor_outcomes_auditable(self):
        for executor, expected in (("synthetic-fail-v1", "FAILED"), ("synthetic-reject-v1", "REJECTED")):
            p = self.make_plan()
            state, _ = self.allocate(executor, p)
            result = self.execute(state)
            self.assertEqual(result["outcome"]["outcome"], expected)
            self.assertEqual(result["evidence"]["content"]["reported"]["outcome"], expected)
            self.assertEqual(result["outcome"]["record"]["certainty"], "KNOWN")

    def test_exception_is_unknown_not_failed(self):
        state, _ = self.allocate()
        with patch.object(controlled, "_invoke", side_effect=RuntimeError("uncertain")):
            result = self.execute(state)
        self.assertEqual(result["outcome"]["outcome"], "UNKNOWN")
        self.assertIsNone(result["outcome"]["record"]["execution_occurred"])
        self.assertEqual(self.r.attempt_show(state["attempt_id"])["state"], "LOST")

    def test_immutable_evidence_and_records(self):
        state, _ = self.allocate()
        self.execute(state)
        for table in ("execution_bindings", "execution_receipts", "execution_dispatches", "execution_outcomes", "evidence"):
            for sql in (f"DELETE FROM {table}", f"UPDATE {table} SET id='forged'"):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.r.db.execute(sql)
        self.assertIsNotNone(controlled.show(self.r, state["attempt_id"])["evidence"])

    def test_materialization_idempotent_and_no_rebinding(self):
        first = self.bind()
        self.assertEqual(first, self.bind())
        with self.assertRaises(ACPError):
            self.bind("synthetic-fail-v1")
        with self.assertRaises(ACPError):
            self.r.plan(first["binding"]["task_id"], first["envelope"], HUMAN, "replace")

    def test_duplicate_execute_never_invokes_twice(self):
        state, _ = self.allocate()
        first = self.execute(state)
        with patch.object(controlled, "_invoke") as invoke:
            second = self.execute(state)
            invoke.assert_not_called()
        self.assertEqual(first, second)

    def test_crash_before_receipt_rolls_back_and_does_not_dispatch(self):
        state, _ = self.allocate()
        with patch.object(self.r, "_attempt_state", side_effect=KeyboardInterrupt), patch.object(controlled, "_invoke") as invoke:
            with self.assertRaises(KeyboardInterrupt):
                self.execute(state)
            invoke.assert_not_called()
        result = controlled.recover(self.r, state["attempt_id"], CONTROL)
        self.assertEqual(result["lifecycle"], "AUTHORIZED")
        self.assertIsNone(result["receipt"])

    def test_crash_after_receipt_is_unknown_no_redispatch(self):
        state, _ = self.allocate()
        with patch.object(controlled, "_mark_dispatch", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.execute(state)
        self.assertEqual(controlled.show(self.r, state["attempt_id"])["lifecycle"], "RECEIPT_PERSISTED")
        with patch.object(controlled, "_invoke") as invoke:
            self.execute(state)  # Merely reads receipt; recovery must be explicit.
            result = controlled.recover(self.r, state["attempt_id"], CONTROL)
            invoke.assert_not_called()
        self.assertEqual(result["outcome"]["outcome"], "UNKNOWN")

    def test_crash_during_outcome_rolls_back_evidence_and_recovers_unknown(self):
        state, _ = self.allocate()
        original = self.r._event
        def fail(table, record_id, kind, *args, **kwargs):
            if kind == "OUTCOME_RECORDED":
                raise KeyboardInterrupt
            return original(table, record_id, kind, *args, **kwargs)
        with patch.object(self.r, "_event", side_effect=fail):
            with self.assertRaises(KeyboardInterrupt):
                self.execute(state)
        self.assertEqual(self.r.db.execute("SELECT count(*) FROM evidence WHERE attempt_id=?", (state["attempt_id"],)).fetchone()[0], 0)
        self.assertIsNone(controlled.show(self.r, state["attempt_id"])["outcome"])
        self.assertEqual(controlled.recover(self.r, state["attempt_id"], CONTROL)["outcome"]["outcome"], "UNKNOWN")

    def test_no_real_executor_or_implicit_fallback(self):
        state, _ = self.allocate()
        with patch.object(controlled, "_invoke") as invoke:
            for executor in ("kandev", "shell", "network", None, object()):
                with self.assertRaises(ACPError):
                    self.execute(state, executor=executor if executor is not None else "missing")
            invoke.assert_not_called()
        with self.assertRaises(ACPError):
            self.bind("kandev")

    def test_legacy_adapter_acceptance_and_fence_cannot_bypass(self):
        state, _ = self.allocate()
        with self.assertRaises(ACPError):
            self.r.adapter_operation(state["attempt_id"], "submit", SyntheticAdapter(), CONTROL)
        from acp.execution import operate
        with self.assertRaises(ACPError):
            operate(self.r, state["attempt_id"], "submit", object(), CONTROL)
        self.execute(state)
        with self.assertRaises(ACPError):
            self.r.accept(state["task_id"], state["attempt_id"], {}, HUMAN, "cannot accept")
        with self.assertRaises(ACPError):
            self.r.fence(state["attempt_id"], "any", HUMAN, "no fencing")

    def test_pending_decisions_unassessed_and_real_plan_denied(self):
        for change, test_only in ((material, True), (lambda p: p.update(human_assessment={"state": "NOT_ASSESSED", "evaluated": False, "rationale": "not evaluated", "sources": []}), True), (None, False)):
            p = self.make_plan(change, test_only=test_only)
            with self.assertRaises(ACPError):
                self.bind(plan=p)

    def test_worker_cannot_materialize_or_dispatch(self):
        state, _ = self.allocate()
        worker = Actor("worker", "worker", "test")
        with self.assertRaises(ACPError):
            controlled.materialize(self.r, self.plan["plan_id"], 1, self.plan["work_items"][0]["work_item_id"], "synthetic-inspect-v1", worker)
        with self.assertRaises(ACPError):
            controlled.execute(self.r, state["attempt_id"], state["request"], worker, executor="synthetic-inspect-v1")

    def test_prior_attempt_preserved_and_retry_forbidden(self):
        first, _ = self.allocate()
        before = self.execute(first)
        p = self.make_plan()
        second, _ = self.allocate(plan=p)
        self.execute(second)
        self.assertNotEqual(first["attempt_id"], second["attempt_id"])
        self.assertEqual(controlled.show(self.r, first["attempt_id"]), before)
        with self.assertRaises(ACPError):
            self.r.transition(first["task_id"], "REWORK", HUMAN, "attempt retry")
            self.r.plan(first["task_id"], first["request"], HUMAN, "retry")

    def test_parallel_or_unknown_prior_execution_denied(self):
        first, _ = self.allocate()
        second, _ = self.allocate(plan=self.make_plan())
        with patch.object(controlled, "_mark_dispatch", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.execute(first)
        with self.assertRaisesRegex(ACPError, "Parallel"):
            self.execute(second)
        controlled.recover(self.r, first["attempt_id"], CONTROL)
        with self.assertRaisesRegex(ACPError, "uncertain"):
            self.execute(second)

    def test_no_source_filesystem_network_or_subprocess_during_execution(self):
        state, _ = self.allocate()
        with patch("subprocess.run", side_effect=AssertionError), patch("socket.socket", side_effect=AssertionError), patch("builtins.open", side_effect=AssertionError), patch.object(Path, "read_text", side_effect=AssertionError), patch.object(Path, "write_text", side_effect=AssertionError):
            self.assertEqual(self.execute(state)["outcome"]["outcome"], "SUCCEEDED")
        self.assertEqual((self.repo / "STATUS.md").read_text(encoding="utf-8"), "Status: synthetic read only.\n")

    def test_restart_readback_from_fresh_cli_process(self):
        state, _ = self.allocate()
        result = self.execute(state)
        command = [sys.executable, "-B", "-m", "acp", "--data-dir", str(self.root / "state"), "controlled", "show", state["attempt_id"]]
        child = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), result)

    def test_actual_process_death_after_receipt(self):
        state, _ = self.allocate()
        code = """import os,sys
from acp.runtime import Runtime
from acp import controlled
from acp.domain import Actor
with Runtime(sys.argv[1]) as r:
 s=controlled.show(r,sys.argv[2])
 controlled._mark_dispatch=lambda *a: os._exit(67)
 controlled.execute(r,s['attempt_id'],s['request'],Actor('fixture','controller','test'),executor='synthetic-inspect-v1')
"""
        child = subprocess.run([sys.executable, "-B", "-c", code, str(self.root / "state"), state["attempt_id"]], cwd=ROOT, capture_output=True)
        self.assertEqual(child.returncode, 67, child.stderr)
        result = controlled.recover(self.r, state["attempt_id"], CONTROL)
        self.assertEqual(result["outcome"]["outcome"], "UNKNOWN")
        self.assertIsNone(result["dispatch"])

    def test_revocation_after_receipt_prevents_invocation(self):
        state, approval = self.allocate()
        mark = controlled._mark_dispatch
        def revoked(*args):
            self.r.revoke(approval["id"], HUMAN, "at dispatch boundary")
            return mark(*args)
        with patch.object(controlled, "_mark_dispatch", side_effect=revoked), patch.object(controlled, "_invoke") as invoke:
            result = self.execute(state)
            invoke.assert_not_called()
        self.assertEqual(result["outcome"]["outcome"], "REJECTED")
        self.assertFalse(result["outcome"]["record"]["execution_occurred"])

    def test_revocation_during_invocation_retains_report_without_acceptance(self):
        state, approval = self.allocate()
        invoke = controlled._invoke
        def revoked(*args):
            response = invoke(*args)
            self.r.revoke(approval["id"], HUMAN, "during synthetic call")
            return response
        with patch.object(controlled, "_invoke", side_effect=revoked):
            result = self.execute(state)
        self.assertEqual(result["outcome"]["outcome"], "REJECTED")
        self.assertEqual(result["evidence"]["content"]["reported"]["reported"]["outcome"], "SUCCEEDED")

    def test_recovery_race_quarantines_late_output(self):
        state, _ = self.allocate()
        invoke = controlled._invoke
        def recovered(*args):
            controlled.recover(self.r, state["attempt_id"], CONTROL)
            return invoke(*args)
        with patch.object(controlled, "_invoke", side_effect=recovered):
            result = self.execute(state)
        self.assertEqual(result["outcome"]["outcome"], "UNKNOWN")
        rows = self.r.db.execute("SELECT record_json FROM evidence WHERE attempt_id=?", (state["attempt_id"],)).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertTrue(json.loads(rows[-1][0])["content"]["quarantined"])

    def test_sqlite_full_durability_and_integrity(self):
        self.assertEqual(self.r.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.r.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.r.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_policy_approval_remains_bounded_and_separate(self):
        binding = self.bind()
        task = binding["binding"]["task_id"]
        approval = self.r.approve(task, "policy", Actor("policy", "policy", "test"), "2099-01-01T00:00:00+00:00", "bounded-synthetic-read-v1")
        self.assertEqual(approval["envelope"]["binding_digest"], binding["binding_digest"])
        self.assertEqual(planning.show(self.r, self.plan["plan_id"])["work_items"][0]["write_authority"], "NONE")

    def test_disabled_project_rejects(self):
        state, _ = self.allocate()
        self.r.db.execute("UPDATE projects SET enabled=0 WHERE id='demo'")
        self.assertEqual(self.execute(state)["outcome"]["outcome"], "REJECTED")

    def test_v3_migration_preserves_planning_and_legacy_history(self):
        # Construct a v3 fixture by removing later schema additions in this
        # temporary test database. Never touches operator/canonical runtime data.
        original_plan = planning.show(self.r, self.plan["plan_id"])
        before = {name: [tuple(row) for row in self.r.db.execute("SELECT * FROM " + name)]
                  for name in ("tasks", "task_events", "planning_runs", "planning_results", "plan_revisions", "context_loads", "context_blobs")}
        self.r.close()
        with sqlite3.connect(self.root / "state" / "acp.sqlite3") as db:
            from tests.schema_fixture import drop_dag
            drop_dag(db)
            for name in ("isolation_retries", "isolation_fences", "isolation_observations", "isolation_intents", "isolation_instances", "isolation_task_bindings"):
                db.execute("DROP TABLE " + name)
            for name in ("provider_observations", "provider_validations", "provider_responses", "provider_invocations", "provider_dispatches", "provider_requests", "provider_runs"):
                db.execute("DROP TABLE " + name)
            for name in ("execution_bindings", "execution_receipts", "execution_dispatches", "execution_outcomes"):
                db.execute("DROP TABLE " + name)
            trigger = db.execute("SELECT sql FROM sqlite_master WHERE name='schema_metadata_delete'").fetchone()[0]
            db.execute("DROP TRIGGER schema_metadata_delete")
            db.execute("DELETE FROM schema_metadata WHERE version>=4")
            db.execute(trigger)
            db.execute("PRAGMA user_version=3")
        db.close()
        self.r = Runtime(self.root / "state")
        self.assertEqual(self.r.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        for name, rows in before.items():
            self.assertEqual([tuple(row) for row in self.r.db.execute("SELECT * FROM " + name)], rows)
        self.assertEqual(planning.show(self.r, self.plan["plan_id"]), original_plan)
        self.assertEqual(self.r.db.execute("PRAGMA foreign_key_check").fetchall(), [])
        with self.assertRaises(sqlite3.IntegrityError):
            self.r.db.execute("DELETE FROM planning_results")

    def test_cli_execution_across_independent_processes(self):
        def cli(*args):
            result = subprocess.run([sys.executable, "-B", "-m", "acp", "--data-dir", str(self.root / "state"), *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        binding = cli("controlled", "materialize", "--plan", self.plan["plan_id"], "--revision", "1", "--work", self.plan["work_items"][0]["work_item_id"], "--executor", "synthetic-inspect-v1")
        task = binding["binding"]["task_id"]
        approval = cli("approval", "record", "--task", task, "--kind", "human", "--expires", "2099-01-01T00:00:00+00:00")
        cli("task", "transition", task, "READY", "--reason", "explicit fixture approval")
        attempt = cli("attempt", "create", "--task", task, "--approval", approval["id"])
        state = cli("controlled", "show", attempt["id"])
        request_file = self.root / "request.json"
        request_file.write_text(canonical_json(state["request"]), encoding="utf-8")
        result = cli("controlled", "execute", attempt["id"], "--request", str(request_file), "--executor", "synthetic-inspect-v1")
        self.assertEqual(result["outcome"]["outcome"], "SUCCEEDED")
        self.assertEqual(cli("controlled", "recover", attempt["id"]), result)
        self.assertEqual(cli("controlled", "show", attempt["id"]), result)

    def test_actual_process_death_before_receipt_commit(self):
        state, _ = self.allocate()
        code = """import os,sys
from acp.runtime import Runtime
from acp import controlled
from acp.domain import Actor
with Runtime(sys.argv[1]) as r:
 s=controlled.show(r,sys.argv[2])
 r._attempt_state=lambda *a,**k: os._exit(68)
 controlled.execute(r,s['attempt_id'],s['request'],Actor('fixture','controller','test'),executor='synthetic-inspect-v1')
"""
        child = subprocess.run([sys.executable, "-B", "-c", code, str(self.root / "state"), state["attempt_id"]], cwd=ROOT, capture_output=True)
        self.assertEqual(child.returncode, 68, child.stderr)
        result = controlled.recover(self.r, state["attempt_id"], CONTROL)
        self.assertEqual(result["lifecycle"], "AUTHORIZED")
        self.assertIsNone(result["receipt"])
        self.assertIsNone(result["dispatch"])

    def test_actual_process_death_after_outcome_commit(self):
        state, _ = self.allocate()
        code = """import os,sys
from acp.runtime import Runtime
from acp import controlled
from acp.domain import Actor
with Runtime(sys.argv[1]) as r:
 s=controlled.show(r,sys.argv[2])
 controlled.execute(r,s['attempt_id'],s['request'],Actor('fixture','controller','test'),executor='synthetic-inspect-v1')
 os._exit(69)
"""
        child = subprocess.run([sys.executable, "-B", "-c", code, str(self.root / "state"), state["attempt_id"]], cwd=ROOT, capture_output=True)
        self.assertEqual(child.returncode, 69, child.stderr)
        result = controlled.recover(self.r, state["attempt_id"], CONTROL)
        self.assertEqual(result["outcome"]["outcome"], "SUCCEEDED")
        self.assertIsNotNone(result["evidence"])

    def test_forbidden_read_scope_rejected(self):
        plan = self.make_plan(lambda p: p["work_items"][0].update(forbidden_scope=["STATUS.md"]))
        with self.assertRaisesRegex(ACPError, "forbidden"):
            self.bind(plan=plan)

    def test_dependent_work_item_rejected(self):
        def change(p):
            child = copy.deepcopy(p["work_items"][0])
            child.update(dependencies=[0], parallel_safe=False)
            p["work_items"].append(child)
        plan = self.make_plan(change)
        with self.assertRaisesRegex(ACPError, "Dependency"):
            controlled.materialize(self.r, plan["plan_id"], 1, plan["work_items"][1]["work_item_id"], "synthetic-inspect-v1", HUMAN)

    def test_receipt_persistence_error_no_invocation_or_fallback(self):
        state, _ = self.allocate()
        with patch.object(self.r, "_attempt_state", side_effect=sqlite3.OperationalError("simulated disk failure")), patch.object(controlled, "_invoke") as invoke:
            with self.assertRaises(sqlite3.OperationalError):
                self.execute(state)
            invoke.assert_not_called()
        self.assertIsNone(controlled.show(self.r, state["attempt_id"])["receipt"])

    def test_malformed_output_is_unknown(self):
        state, _ = self.allocate()
        with patch.object(controlled, "_invoke", return_value={"outcome": "invented"}):
            result = self.execute(state)
        self.assertEqual(result["outcome"]["outcome"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
