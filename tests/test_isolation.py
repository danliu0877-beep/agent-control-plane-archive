"""M08 canonical fault tests. Fake host is explicit TEST ONLY, not fallback.

These tests establish SQLite/control semantics, never real VM confinement.
"""
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

from acp import context, isolation, planning
from acp.adapters import SyntheticAdapter
from acp.decision_provider import SyntheticDecisionProvider
from acp.domain import ACPError, Actor
from acp.runtime import Runtime
from tests.test_planning import fixture

HUMAN = Actor("principal", "human", "test")
CONTROL = Actor("controller", "controller", "test")
WORKER = Actor("worker", "worker", "test")
TEMPLATE = {"profile": isolation.PROFILE, "sealed": True, "test_only": True}


class TestOnlyHost:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.bad_stop = False

    def reserve_paths(self, isolation_id):
        return {"vmx": f"test-only/{isolation_id}/vm.vmx", "workspace": f"test-only/{isolation_id}"}

    def perform(self, name, owned, saved):
        self.calls.append((name, owned["id"]))
        if name == self.fail:
            raise TimeoutError("fault injected")
        if name == "start":
            return {"powered_on": True, "pid": 42, "creation_filetime": 987654321}
        if name == "stop":
            return {"vmx": owned["vmx"], "isolation_id": owned["id"], "pid": 42,
                "creation_filetime": 987654321, "powered_off": True,
                "same_process_handle_signaled": not self.bad_stop, "host_jobs_quiescent": True}
        if name == "probes":
            return {"independent_verification": True, "passed": True, "attempt_id": owned["attempt_id"]}
        return {"test_only": True}


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="acp-m08-canonical-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / "fixture"
        self.project.mkdir()
        (self.project / "STATUS.md").write_text(isolation.SYNTHETIC_STATUS, newline="\n")
        self.r = Runtime(self.root / "state")
        self.addCleanup(lambda: self.r.close())
        self.r.project_add("demo", self.project)
        self.task = self.r.task_create("demo", "fixture", "M08 synthetic", HUMAN)["id"]
        self.ctx = context.load(self.r, "demo", HUMAN)["id"]
        proposal = fixture()
        assessment = {"state": "NONE", "evaluated": True, "rationale": "No business decision is resolved by this disposable synthetic fixture", "sources": ["STATUS.md"]}
        proposal["human_assessment"] = copy.deepcopy(assessment)
        work = proposal["work_items"][0]
        work.update(work_type="documentation", proposed_write_scope=["allowed.txt"], forbidden_scope=["forbidden.txt"],
            allowed_operations=["inspect_context", "analyze", "propose_edit"], execution_risk="R1",
            human_assessment=assessment, human_approval_required=True, suggested_profile="future_isolated_write")
        self.proposal = proposal
        self.plan = self.make_plan()
        self.host = TestOnlyHost()

    def make_plan(self):
        run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)
        result = planning.complete(self.r, run["run_id"], SyntheticDecisionProvider(json.dumps(self.proposal), testing=True), HUMAN)
        self.assertNotEqual(result["status"], "INVALID", result)
        return planning.show(self.r, result["plan_id"])

    def bind(self):
        return isolation.materialize(self.r, self.plan["plan_id"], self.plan["plan_revision"], self.plan["work_items"][0]["work_item_id"], TEMPLATE, HUMAN)

    def allocate(self):
        binding = self.bind()
        task = binding["task_id"]
        approval = self.r.approve(task, "human", HUMAN, "2099-01-01T00:00:00+00:00")
        self.r.transition(task, "READY", HUMAN, "Exact synthetic approval")
        attempt = self.r.attempt_create(task, approval["id"], CONTROL)
        isolation.reserve(self.r, attempt["id"], self.host, CONTROL)
        return attempt, approval

    def running(self):
        attempt, approval = self.allocate()
        for operation in ("clone", "start", "prepare", "tree"):
            isolation.operation(self.r, attempt["id"], operation, self.host, CONTROL)
        return attempt, approval

    def fenced(self):
        attempt, approval = self.running()
        isolation.cancel(self.r, attempt["id"], CONTROL)
        isolation.operation(self.r, attempt["id"], "stop", self.host, CONTROL)
        isolation.record_fence(self.r, attempt["id"], CONTROL)
        return attempt, approval

    def reopen(self):
        self.r.close()
        self.r = Runtime(self.root / "state")

    def test_plan_proposal_never_grants_write_or_mutates_validity(self):
        before = copy.deepcopy(self.plan)
        binding = self.bind()
        self.assertEqual(planning.show(self.r, self.plan["plan_id"]), before)
        self.assertEqual(before["work_items"][0]["write_authority"], "NONE")
        self.assertEqual(self.r.task_show(binding["task_id"])["state"], "PLANNED")
        with self.assertRaises(ACPError):
            self.r.transition(binding["task_id"], "READY", CONTROL, "No approval")

    def test_canonical_flow_review_not_done(self):
        attempt, _ = self.allocate()
        for op in ("clone", "start", "prepare", "probes", "stop"):
            isolation.operation(self.r, attempt["id"], op, self.host, CONTROL)
        evidence = isolation.complete(self.r, attempt["id"], CONTROL)
        self.assertEqual(self.r.task_show(attempt["task_id"])["state"], "REVIEW")
        with self.assertRaises(ACPError):
            self.r.accept(attempt["task_id"], attempt["id"], {"synthetic-write": "other"}, HUMAN, "wrong")
        self.r.accept(attempt["task_id"], attempt["id"], {"synthetic-write": evidence}, HUMAN, "Synthetic bounded result only")
        self.assertEqual(self.r.task_show(attempt["task_id"])["state"], "DONE")

    def test_worker_cannot_materialize_reserve_observe_cancel_fence(self):
        with self.assertRaises(ACPError):
            isolation.materialize(self.r, self.plan["plan_id"], 1, self.plan["work_items"][0]["work_item_id"], TEMPLATE, WORKER)
        attempt, _ = self.allocate()
        for call in (lambda: isolation.reserve(self.r, attempt["id"], self.host, WORKER),
            lambda: isolation.observe(self.r, attempt["id"], "fake", {}, WORKER),
            lambda: isolation.operation(self.r, attempt["id"], "clone", self.host, WORKER),
            lambda: isolation.cancel(self.r, attempt["id"], WORKER),
            lambda: isolation.record_fence(self.r, attempt["id"], WORKER)):
            with self.assertRaises(ACPError):
                call()

    def test_duplicate_binding_and_vm_reservation_denied(self):
        attempt, _ = self.allocate()
        with self.assertRaises(ACPError):
            self.bind()
        with self.assertRaises(ACPError):
            isolation.reserve(self.r, attempt["id"], self.host, CONTROL)

    def test_closed_operation_and_lifecycle(self):
        attempt, _ = self.allocate()
        for op in ("shell", "network", "start", "destroy", "probes"):
            with self.assertRaises(ACPError):
                isolation.operation(self.r, attempt["id"], op, self.host, CONTROL)
        self.assertFalse(self.host.calls)

    def test_legacy_adapter_and_replan_and_generic_fence_denied(self):
        attempt, _ = self.allocate()
        with self.assertRaises(ACPError):
            self.r.adapter_operation(attempt["id"], "submit", SyntheticAdapter(), CONTROL)
        with self.assertRaises(ACPError):
            self.r.plan(attempt["task_id"], {}, HUMAN, "try replacing binding")
        with self.assertRaises(ACPError):
            self.r.fence(attempt["id"], "fake", CONTROL, "try generic attestation")

    def test_cancel_ack_never_fences_or_allows_retry(self):
        attempt, _ = self.running()
        isolation.cancel(self.r, attempt["id"], CONTROL)
        isolation.observe(self.r, attempt["id"], "CANCEL_ACKNOWLEDGED", {"backend_claim": True}, CONTROL)
        with self.assertRaises(ACPError):
            isolation.record_fence(self.r, attempt["id"], CONTROL)
        with self.assertRaises(ACPError):
            self.r.resolve_hold(attempt["task_id"], CONTROL, "unsafe retry", retry_ready=True)
        self.assertFalse(isolation.facts(self.r, attempt["id"])["retry_eligible"])

    def test_false_off_or_cli_success_without_handle_is_not_fence(self):
        attempt, _ = self.running()
        isolation.cancel(self.r, attempt["id"], CONTROL)
        self.host.bad_stop = True
        isolation.operation(self.r, attempt["id"], "stop", self.host, CONTROL)
        with self.assertRaises(ACPError):
            isolation.record_fence(self.r, attempt["id"], CONTROL)

    def test_unknown_action_is_auditable_and_never_reissued(self):
        attempt, _ = self.allocate()
        self.host.fail = "clone"
        with self.assertRaises(TimeoutError):
            isolation.operation(self.r, attempt["id"], "clone", self.host, CONTROL)
        self.reopen()
        recovered = isolation.recover(self.r, attempt["id"], CONTROL)
        self.assertEqual(recovered["disposition"], "EXECUTION_OWNERSHIP_UNCERTAIN")
        self.assertFalse(recovered["automatic_retry"])
        self.assertEqual(len(recovered["pending"]), 1)
        with self.assertRaises(ACPError):
            isolation.operation(self.r, attempt["id"], "clone", self.host, CONTROL)
        self.assertEqual(len(self.host.calls), 1)

    def test_restart_running_uncertain_fenced_and_candidate(self):
        attempt, approval = self.running()
        original = isolation.instance(self.r, attempt["id"])
        self.reopen()
        self.assertEqual(isolation.instance(self.r, attempt["id"]), original)
        self.assertEqual(isolation.recover(self.r, attempt["id"], CONTROL)["disposition"], "HOST_RECONCILIATION_REQUIRED")
        isolation.cancel(self.r, attempt["id"], CONTROL)
        self.reopen()
        self.assertFalse(isolation.recover(self.r, attempt["id"], CONTROL)["retry_eligible"])
        isolation.operation(self.r, attempt["id"], "stop", self.host, CONTROL)
        isolation.record_fence(self.r, attempt["id"], CONTROL)
        self.reopen()
        self.assertEqual(isolation.recover(self.r, attempt["id"], CONTROL)["disposition"], "FENCED")
        self.r.resolve_hold(attempt["task_id"], CONTROL, "proven fence", retry_ready=True)
        retry = self.r.attempt_create(attempt["task_id"], approval["id"], CONTROL)
        isolated_retry = isolation.reserve(self.r, retry["id"], self.host, CONTROL)
        self.assertNotEqual(original["workspace"], isolated_retry["workspace"])
        self.reopen()
        self.assertEqual(self.r.db.execute("SELECT count(*) FROM isolation_retries").fetchone()[0], 1)
        self.assertFalse(isolation.facts(self.r, attempt["id"])["retry_eligible"])
        with self.assertRaises(ACPError):
            self.r.attempt_create(attempt["task_id"], approval["id"], CONTROL)

    def test_late_output_remains_old_and_cannot_accept_retry(self):
        old, approval = self.fenced()
        self.r.resolve_hold(old["task_id"], CONTROL, "fenced", retry_ready=True)
        new = self.r.attempt_create(old["task_id"], approval["id"], CONTROL)
        isolation.reserve(self.r, new["id"], self.host, CONTROL)
        receipt = isolation.quarantine(self.r, old["id"], {"bytes": "LATE OLD OUTPUT"}, CONTROL)
        self.assertEqual(receipt["attempt_id"], old["id"])
        self.assertFalse(receipt["detail"]["acceptance_eligible"])
        with self.assertRaises(ACPError):
            isolation.complete(self.r, old["id"], CONTROL)
        self.assertEqual(self.r.attempt_show(new["id"])["state"], "CREATED")

    def test_append_only_and_identity_constraints(self):
        attempt, _ = self.allocate()
        for table in ("isolation_task_bindings", "isolation_instances"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.r.db.execute(f"DELETE FROM {table}")
        with self.assertRaises(sqlite3.IntegrityError):
            self.r.db.execute("UPDATE isolation_instances SET vmx_path='other'")

    def test_fence_receipt_missing_generation_denies(self):
        attempt, _ = self.running()
        isolation.cancel(self.r, attempt["id"], CONTROL)
        original = self.host.perform
        def bad(name, owned, saved):
            record = original(name, owned, saved)
            if name == "stop":
                record["creation_filetime"] += 1
            return record
        self.host.perform = bad
        isolation.operation(self.r, attempt["id"], "stop", self.host, CONTROL)
        with self.assertRaises(ACPError):
            isolation.record_fence(self.r, attempt["id"], CONTROL)

    def test_two_fresh_controllers_allocate_at_most_one_retry(self):
        attempt, approval = self.fenced()
        self.r.resolve_hold(attempt["task_id"], CONTROL, "fenced", retry_ready=True)
        code = "from acp.runtime import Runtime; from acp.domain import Actor; import sys; r=Runtime(sys.argv[1]); print(r.attempt_create(sys.argv[2],sys.argv[3],Actor('controller','controller','test'))['id']); r.close()"
        command = [sys.executable, "-B", "-c", code, str(self.root / "state"), attempt["task_id"], approval["id"]]
        workers = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=Path(__file__).resolve().parents[1]) for _ in range(2)]
        for process in workers:
            process.communicate(timeout=30)
        self.assertEqual(sum(p.returncode == 0 for p in workers), 1)
        self.assertEqual(self.r.db.execute("SELECT count(*) FROM isolation_retries").fetchone()[0], 1)

    def test_profile_and_scope_and_real_material_fail_closed(self):
        for change in (lambda p: p["work_items"][0].update(proposed_write_scope=["other.txt"]),
                       lambda p: p["work_items"][0].update(work_type="analysis", proposed_write_scope=[], allowed_operations=["inspect_context"], suggested_profile="read_only_analysis", human_approval_required=False)):
            original = copy.deepcopy(self.proposal)
            change(self.proposal)
            self.plan = self.make_plan()
            with self.assertRaises(ACPError):
                self.bind()
            self.proposal = original
        self.plan = self.make_plan()
        bad = {**TEMPLATE, "profile": "other"}
        with self.assertRaises(ACPError):
            isolation.materialize(self.r, self.plan["plan_id"], 1, self.plan["work_items"][0]["work_item_id"], bad, HUMAN)

    def test_revocation_blocks_dispatch_but_not_required_stop(self):
        attempt, approval = self.running()
        self.r.revoke(approval["id"], HUMAN, "Synthetic cancellation test")
        with self.assertRaises(ACPError):
            isolation.operation(self.r, attempt["id"], "probes", self.host, CONTROL)
        isolation.operation(self.r, attempt["id"], "stop", self.host, CONTROL)
        isolation.record_fence(self.r, attempt["id"], CONTROL)
        with self.assertRaises(ACPError):
            self.r.resolve_hold(attempt["task_id"], CONTROL, "revoked approval cannot retry", retry_ready=True)

    def test_v5_migration_preserves_every_prior_row(self):
        tables = [r[0] for r in self.r.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'isolation_%' AND name NOT LIKE 'dag_%' AND name NOT IN ('sqlite_sequence','schema_metadata')")]
        original = {name: [tuple(r) for r in self.r.db.execute('SELECT * FROM "' + name + '"')] for name in tables}
        self.r.close()
        with sqlite3.connect(self.root / "state/acp.sqlite3") as db:
            from tests.schema_fixture import drop_dag
            drop_dag(db)
            for name in ("isolation_retries", "isolation_fences", "isolation_observations", "isolation_intents", "isolation_instances", "isolation_task_bindings"):
                db.execute("DROP TABLE " + name)
            trigger = db.execute("SELECT sql FROM sqlite_master WHERE name='schema_metadata_delete'").fetchone()[0]
            db.execute("DROP TRIGGER schema_metadata_delete")
            db.execute("DELETE FROM schema_metadata WHERE version>=6")
            db.execute(trigger)
            db.execute("PRAGMA user_version=5")
        db.close()
        self.r = Runtime(self.root / "state")
        for name, rows in original.items():
            self.assertEqual([tuple(r) for r in self.r.db.execute('SELECT * FROM "' + name + '"')], rows)
        self.assertEqual(self.r.db.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(self.r.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        from acp.store import SCHEMA_VERSION
        self.assertEqual(self.r.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    @unittest.skipUnless(os.name == "nt", "NTFS junction test requires Windows")
    def test_actual_ntfs_junction_cannot_be_host_authority(self):
        from acp import vmware_host
        target = self.root / "canary"
        target.mkdir()
        (target / "canary.txt").write_text("synthetic canary")
        link = self.root / "junction"
        command = "New-Item -ItemType Junction -Path '" + str(link).replace("'", "''") + "' -Target '" + str(target).replace("'", "''") + "' | Out-Null"
        result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(link.is_junction())
        with patch.object(vmware_host, "ROOT", self.root):
            with self.assertRaises(ACPError):
                vmware_host.no_reparse(link / "canary.txt")
        self.assertEqual((target / "canary.txt").read_text(), "synthetic canary")

    def test_stop_crash_window_is_uncertain_not_retried(self):
        attempt, _ = self.running()
        isolation.cancel(self.r, attempt["id"], CONTROL)
        self.host.fail = "stop"
        with self.assertRaises(TimeoutError):
            isolation.operation(self.r, attempt["id"], "stop", self.host, CONTROL)
        self.reopen()
        self.assertEqual(isolation.recover(self.r, attempt["id"], CONTROL)["disposition"], "EXECUTION_OWNERSHIP_UNCERTAIN")
        with self.assertRaises(ACPError):
            isolation.record_fence(self.r, attempt["id"], CONTROL)
        with self.assertRaises(ACPError):
            self.r.resolve_hold(attempt["task_id"], CONTROL, "unsafe", retry_ready=True)


if __name__ == "__main__":
    unittest.main()
