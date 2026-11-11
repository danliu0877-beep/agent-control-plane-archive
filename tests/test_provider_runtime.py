"""Synthetic providers and actual disposable controller crashes. No live I/O."""
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

from acp import context, planning, provider_runtime as pr
from acp.decision_provider import ProviderOutput, SubmittedDecisionProvider, SyntheticDecisionProvider
from acp.domain import ACPError, Actor, canonical_json, digest
from acp.runtime import Runtime
from tests.test_planning import fixture

HUMAN = Actor("principal", "human", "test")
ROOT = Path(__file__).resolve().parents[1]


class FixtureProvider:
    def __init__(self, counter, raw=None, reconcile=True):
        self.counter, self.raw, self.lookup = Path(counter), raw or json.dumps(fixture()), reconcile
        self.calls = self.retrievals = 0

    def durable_profile(self):
        return {"adapter": "fixture-v1", "provider": "fixture", "model": "fixture", "reasoning": "deterministic",
                "external": False, "reconcile": self.lookup, "idempotency": False, "raw_kind": "proposal"}

    def invoke_durable(self, receipt):
        self.calls += 1
        with self.counter.open("a", encoding="utf-8") as out:
            out.write(receipt["request_digest"] + "\n")
        metadata = {"provider": "fixture", "model": "fixture", "reasoning": "deterministic", "response_id": "remote-test-id"}
        binding = {k: receipt[k] for k in ("provider_run_id", "request_digest", "correlation_key")}
        # Disposable provider-side test storage, never an ACP canonical fallback.
        self.counter.with_suffix(".response.json").write_text(json.dumps({"raw": self.raw, "metadata": metadata, "binding": binding}), encoding="utf-8")
        return ProviderOutput(self.raw, metadata)

    def reconcile(self, receipt):
        self.retrievals += 1
        stored = self.counter.with_suffix(".response.json")
        if not stored.exists():
            return None
        saved = json.loads(stored.read_text(encoding="utf-8"))
        return ProviderOutput(saved["raw"], saved["metadata"]), saved["binding"]


class ProviderRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="acp-m07-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        repo = self.root / "repo"; repo.mkdir()
        (repo / "STATUS.md").write_text("Synthetic evidence remains incomplete.\n", encoding="utf-8")
        self.r = Runtime(self.root / "state")
        self.addCleanup(lambda: self.r.close())
        self.r.project_add("demo", repo)
        self.task = self.r.task_create("demo", "fixture", "Inspect synthetic material", HUMAN)["id"]
        self.ctx = context.load(self.r, "demo", HUMAN)["id"]
        self.run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
        self.p = FixtureProvider(self.root / "calls.txt")
        pr.enroll(self.r, self.run, self.p, HUMAN)

    def state(self):
        return pr.show(self.r, self.run)

    def calls(self):
        return len(self.p.counter.read_text().splitlines()) if self.p.counter.exists() else 0

    def receipt_only(self):
        pr.request(self.r, self.run, self.p, HUMAN)
        pr._dispatch(self.r, self.run, HUMAN)
        request = self.state()["request"]
        out = self.p.invoke_durable(request)
        pr.receive(self.r, self.run, out.raw, out.metadata, HUMAN)

    def child(self, code, *args):
        return subprocess.run([sys.executable, "-B", "-c", code, str(self.root / "state"), self.run, str(self.p.counter), *args], cwd=ROOT, capture_output=True, text=True)

    def test_ids_context_and_request_binding(self):
        state = self.state()
        self.assertTrue(state["provider_run_id"].startswith("PRUN-"))
        self.assertTrue(state["run"]["correlation_key"].startswith("PCORR-"))
        self.assertEqual(state["run"]["context_id"], self.ctx)
        req = pr.request(self.r, self.run, self.p, HUMAN)
        self.assertEqual(req["request_digest"], digest(req["wire_request"]))
        self.assertEqual(req["input"]["context_digest"], state["run"]["context_digest"])
        for table in ("provider_runs", "provider_requests"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.r.db.execute("UPDATE " + table + " SET digest='forged'")

    def test_exact_profile_no_rebinding(self):
        self.p.lookup = False
        with self.assertRaises(ACPError):
            pr.enroll(self.r, self.run, self.p, HUMAN)
        with self.assertRaises(ACPError):
            pr.execute(self.r, self.run, self.p, HUMAN)
        self.assertEqual(self.calls(), 0)

    def test_receipt_and_intent_committed_before_provider(self):
        original = self.p.invoke_durable
        def probe(receipt):
            with Runtime(self.root / "state") as second:
                self.assertEqual(pr.show(second, self.run)["request"], receipt)
                self.assertIsNotNone(pr.show(second, self.run)["dispatch"])
                self.assertIsNotNone(pr.show(second, self.run)["invocation"])
            return original(receipt)
        with patch.object(self.p, "invoke_durable", side_effect=probe):
            self.assertEqual(pr.execute(self.r, self.run, self.p, HUMAN)["state"], "PLAN_REVISION_FINALIZED")

    def test_raw_receipt_committed_before_validation(self):
        original = planning.validate
        def probe(raw, inputs):
            second = sqlite3.connect(self.root / "state" / "acp.sqlite3")
            try:
                receipt = json.loads(second.execute("SELECT record_json FROM provider_responses WHERE run_id=?", (self.run,)).fetchone()[0])
                self.assertEqual(receipt["raw"]["data"], raw)
            finally:
                second.close()
            return original(raw, inputs)
        with patch.object(planning, "validate", side_effect=probe):
            pr.execute(self.r, self.run, self.p, HUMAN)

    def test_timeout_unknown_no_retry_or_fallback(self):
        with patch.object(self.p, "invoke_durable", side_effect=TimeoutError), patch.object(SyntheticDecisionProvider, "propose", side_effect=AssertionError):
            first = pr.execute(self.r, self.run, self.p, HUMAN)
            second = pr.execute(self.r, self.run, self.p, HUMAN)
        self.assertEqual(first["state"], "PROVIDER_OUTCOME_UNKNOWN")
        self.assertEqual(second["state"], first["state"])
        self.assertIsNone(second["response"])
        self.assertEqual(planning.list_plans(self.r), [])

    def test_no_reconciliation_stays_unknown(self):
        # Separate run with explicitly unsupported lookup capability.
        run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
        provider = FixtureProvider(self.p.counter, reconcile=False)
        pr.enroll(self.r, run, provider, HUMAN)
        with patch.object(provider, "invoke_durable", side_effect=TimeoutError):
            pr.execute(self.r, run, provider, HUMAN)
        with patch.object(provider, "reconcile", side_effect=AssertionError):
            self.assertEqual(pr.recover(self.r, run, HUMAN, provider)["state"], "PROVIDER_OUTCOME_UNKNOWN")

    def test_exact_reconciliation_recovers_without_invocation(self):
        pr.request(self.r, self.run, self.p, HUMAN); pr._dispatch(self.r, self.run, HUMAN)
        self.p.invoke_durable(self.state()["request"]) # remote response exists; local receipt lost
        state = pr.recover(self.r, self.run, HUMAN, self.p)
        self.assertEqual(state["response"]["source"], "recovered")
        self.assertEqual(state["state"], "PLAN_REVISION_FINALIZED")
        self.assertEqual((self.p.calls, self.p.retrievals), (1, 1))

    def test_wrong_recovery_identity_audited(self):
        pr.request(self.r, self.run, self.p, HUMAN); pr._dispatch(self.r, self.run, HUMAN)
        self.p.invoke_durable(self.state()["request"])
        output, binding = self.p.reconcile(self.state()["request"])
        for key in binding:
            wrong = {**binding, key: "wrong"}
            with self.assertRaises(ACPError):
                pr.receive(self.r, self.run, output.raw, output.metadata, HUMAN, source="recovered", binding=wrong)
        self.assertIsNone(self.state()["response"])
        self.assertEqual(len(self.state()["observations"]), 3)

    def test_duplicate_and_conflicting_response(self):
        self.receipt_only()
        before = self.state()["response"]
        pr.receive(self.r, self.run, self.p.raw, before["metadata"], HUMAN)
        with self.assertRaises(ACPError):
            pr.receive(self.r, self.run, "conflicting raw", before["metadata"], HUMAN)
        with self.assertRaises(ACPError):
            pr.receive(self.r, self.run, self.p.raw, {**before["metadata"], "response_id": "another-native-response"}, HUMAN)
        self.assertEqual(self.state()["response"], before)
        self.assertEqual(self.state()["observations"][-1]["kind"], "CONFLICTING_RESPONSE")
        self.assertEqual(len(self.state()["observations"]), 2)

    def test_malformed_and_semantic_rejection_retained(self):
        for raw in ("{broken-json", json.dumps({**fixture(), "plan_id": "provider-forged"})):
            run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
            provider = FixtureProvider(self.p.counter, raw)
            pr.enroll(self.r, run, provider, HUMAN)
            state = pr.execute(self.r, run, provider, HUMAN)
            self.assertEqual(state["result"]["status"], "INVALID")
            self.assertEqual(state["response"]["raw"]["data"], raw)
            self.assertTrue(state["validation"]["error"])
            self.assertIsNone(state["result"]["plan_id"])
        self.assertEqual(planning.list_plans(self.r), [])

    def test_provider_native_identity_is_metadata_only(self):
        state = pr.execute(self.r, self.run, self.p, HUMAN)
        plan = planning.show(self.r, state["result"]["plan_id"])
        self.assertNotEqual(plan["plan_id"], "remote-test-id")
        self.assertEqual(plan["provider_metadata"]["observations"]["response_id"], "remote-test-id")
        self.assertNotIn("response_id", plan)

    def test_recovery_reuses_response_and_validation_ids(self):
        self.receipt_only()
        with patch.object(self.p, "invoke_durable", side_effect=AssertionError):
            one = pr.recover(self.r, self.run, HUMAN)
            two = pr.recover(self.r, self.run, HUMAN)
        self.assertEqual(one, two)
        self.assertEqual(len(planning.list_plans(self.r)), 1)
        self.assertEqual(self.calls(), 1)

    def test_actual_crash_windows_A_to_F(self):
        stages = {"A": ("provider_requests", False), "B": ("_dispatch", True), "C": ("_started", True),
                  "D": ("receive", True), "E": ("finalize", True), "F": ("planning.finalize", True)}
        for stage in stages:
            with self.subTest(stage=stage):
                run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
                provider = FixtureProvider(self.root / (stage + "-calls.txt"))
                pr.enroll(self.r, run, provider, HUMAN)
                code = '''import os,sys
from unittest.mock import patch
from acp.runtime import Runtime
from acp import provider_runtime as pr,planning
from tests.test_provider_runtime import FixtureProvider,HUMAN
stage=sys.argv[4]
with Runtime(sys.argv[1]) as r:
 p=FixtureProvider(sys.argv[3])
 if stage=='A':
  original=pr._put
  def fail(*args,**kw):
   original(*args,**kw)
   if args[1]=='provider_requests': os._exit(73)
  hook=patch.object(pr,'_put',side_effect=fail)
 else:
  target,name=(planning,'finalize') if stage=='F' else (pr,{'B':'_dispatch','C':'_started','D':'receive','E':'finalize'}[stage])
  hook=patch.object(target,name,side_effect=lambda *a,**k:os._exit(73))
 with hook: pr.execute(r,sys.argv[2],p,HUMAN)
'''
                proc = subprocess.run([sys.executable, "-B", "-c", code, str(self.root / "state"), run, str(provider.counter), stage], cwd=ROOT, capture_output=True)
                self.assertEqual(proc.returncode, 73, proc.stderr)
                state = pr.show(self.r, run)
                count = len(provider.counter.read_text().splitlines()) if provider.counter.exists() else 0
                self.assertEqual(count, int(stage in {"D", "E", "F"}))
                if stage == "A":
                    self.assertIsNone(state["request"]); self.assertIsNone(state["dispatch"])
                elif stage == "B":
                    self.assertEqual(state["state"], "REQUEST_RECEIPT_PERSISTED")
                    continued = pr.recover(self.r, run, HUMAN, provider)
                    self.assertEqual(continued["provider_run_id"], run)
                    self.assertEqual(continued["state"], "PLAN_REVISION_FINALIZED")
                elif stage in {"C", "D"}:
                    self.assertEqual(pr.recover(self.r, run, HUMAN)["state"], "PROVIDER_OUTCOME_UNKNOWN")
                    self.assertIsNone(state["result"])
                else:
                    self.assertIsNotNone(state["response"])
                    self.assertEqual(state["validation"] is not None, stage == "F")
                    recovered = pr.recover(self.r, run, HUMAN)
                    self.assertEqual(recovered["state"], "PLAN_REVISION_FINALIZED")
                    self.assertEqual(len(provider.counter.read_text().splitlines()), 1)

    def test_concurrent_execution_one_provider_call(self):
        code = '''import sys
from acp.runtime import Runtime
from acp import provider_runtime as pr
from tests.test_provider_runtime import FixtureProvider,HUMAN
with Runtime(sys.argv[1]) as r: pr.execute(r,sys.argv[2],FixtureProvider(sys.argv[3]),HUMAN)
'''
        args = [sys.executable, "-B", "-c", code, str(self.root / "state"), self.run, str(self.p.counter)]
        children = [subprocess.Popen(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        for child in children:
            stdout, stderr = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(self.calls(), 1)
        self.assertEqual(len(planning.list_plans(self.r)), 1)

    def test_concurrent_recovery_and_finalization(self):
        self.receipt_only()
        code = '''import sys
from acp.runtime import Runtime
from acp import provider_runtime as pr
from tests.test_provider_runtime import HUMAN
with Runtime(sys.argv[1]) as r: print(pr.recover(r,sys.argv[2],HUMAN)['result']['plan_id'])
'''
        args = [sys.executable, "-B", "-c", code, str(self.root / "state"), self.run]
        children = [subprocess.Popen(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        ids = []
        for child in children:
            stdout, stderr = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, stderr); ids.append(stdout)
        self.assertEqual(ids[0], ids[1]); self.assertEqual(len(planning.list_plans(self.r)), 1)
        self.assertEqual(self.calls(), 1)

    def test_storage_failure_each_fact_boundary(self):
        for table in ("provider_requests", "provider_dispatches", "provider_responses", "provider_validations"):
            run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
            provider = FixtureProvider(self.root / (table + "-calls.txt"))
            pr.enroll(self.r, run, provider, HUMAN)
            original = pr._put
            def fail(r, name, *args):
                if name == table: raise sqlite3.OperationalError("simulated persistence failure")
                return original(r, name, *args)
            with patch.object(pr, "_put", side_effect=fail), self.assertRaises(sqlite3.OperationalError):
                pr.execute(self.r, run, provider, HUMAN)
            self.assertIsNone(pr.show(self.r, run)["result"])
            self.assertEqual(provider.calls, int(table in {"provider_responses", "provider_validations"}))

    def test_finalization_failure_rolls_back_plan_and_audit(self):
        self.receipt_only(); pr._validation(self.r, self.run, HUMAN)
        original = planning._publish
        def fail(*args):
            original(*args)
            raise sqlite3.OperationalError("after inserts before commit")
        with patch.object(planning, "_publish", side_effect=fail), self.assertRaises(sqlite3.OperationalError):
            pr.finalize(self.r, self.run, HUMAN)
        self.assertEqual(planning.list_plans(self.r), [])
        self.assertIsNone(self.state()["result"])
        self.assertEqual(pr.recover(self.r, self.run, HUMAN)["state"], "PLAN_REVISION_FINALIZED")

    def test_cli_restart_readback_and_submission(self):
        def cli(*args):
            proc = subprocess.run([sys.executable, "-B", "-m", "acp", "--data-dir", str(self.root / "state"), "provider", *args], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(proc.stdout)
        self.assertEqual(cli("show", self.run), self.state())
        run = planning.prepare(self.r, self.task, self.ctx, HUMAN)["run_id"]
        proposal = self.root / "proposal.json"; proposal.write_text(json.dumps(fixture()), encoding="utf-8")
        cli("create", "--run", run, "--provider", "submitted", "--model", "fixture", "--reasoning", "manual", "--proposal", str(proposal))
        proposal.unlink() # continuation uses SQLite request, not original import path
        state = cli("execute", run)
        self.assertEqual(state["state"], "PLAN_REVISION_FINALIZED")
        self.assertEqual(cli("recover", run), state)
        self.assertEqual(cli("response", run), state["response"])

    def test_m06_migration_preserves_prior_history_and_settings(self):
        # Build populated legacy/M06 history first, then remove ONLY v5 additions
        # from this disposable database to construct an exact v4 fixture.
        legacy = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
        planning.complete(self.r, legacy, SyntheticDecisionProvider(json.dumps(fixture()), testing=True), HUMAN)
        from acp import controlled
        approved = fixture()
        assessment = {"state": "NONE", "evaluated": True, "rationale": "This fixture only inspects material identifiers; no business choice is resolved.", "sources": ["STATUS.md"]}
        approved["human_assessment"] = assessment; approved["work_items"][0]["human_assessment"] = assessment
        m06run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
        result = planning.complete(self.r, m06run, SyntheticDecisionProvider(json.dumps(approved), testing=True), HUMAN)
        plan = planning.show(self.r, result["plan_id"])
        child = controlled.materialize(self.r, plan["plan_id"], 1, plan["work_items"][0]["work_item_id"], "synthetic-inspect-v1", HUMAN)["binding"]["task_id"]
        approval = self.r.approve(child, "human", HUMAN, "2099-01-01T00:00:00+00:00")
        self.r.transition(child, "READY", HUMAN, "fixture approved")
        attempt = self.r.attempt_create(child, approval["id"], HUMAN)["id"]
        controlled.execute(self.r, attempt, controlled.show(self.r, attempt)["request"], HUMAN, executor="synthetic-inspect-v1")
        before = {name: [tuple(row) for row in self.r.db.execute("SELECT * FROM " + name)] for name in (
            "tasks", "task_events", "planning_runs", "planning_results", "plan_revisions", "context_loads", "context_blobs", "execution_bindings", "execution_receipts", "execution_dispatches", "execution_outcomes", "execution_attempts", "evidence", "approvals")}
        self.r.close()
        db = sqlite3.connect(self.root / "state" / "acp.sqlite3")
        with db:
            from tests.schema_fixture import drop_dag
            drop_dag(db)
            for name in ("isolation_retries", "isolation_fences", "isolation_observations", "isolation_intents", "isolation_instances", "isolation_task_bindings"):
                db.execute("DROP TABLE " + name)
            for name in ("provider_observations", "provider_validations", "provider_responses", "provider_invocations", "provider_dispatches", "provider_requests", "provider_runs"):
                db.execute("DROP TABLE " + name)
            trigger = db.execute("SELECT sql FROM sqlite_master WHERE name='schema_metadata_delete'").fetchone()[0]
            db.execute("DROP TRIGGER schema_metadata_delete"); db.execute("DELETE FROM schema_metadata WHERE version>=5")
            db.execute(trigger); db.execute("PRAGMA user_version=4")
        db.close(); self.r = Runtime(self.root / "state")
        for name, values in before.items():
            self.assertEqual([tuple(row) for row in self.r.db.execute("SELECT * FROM " + name)], values)
        from acp.store import SCHEMA_VERSION
        self.assertEqual(self.r.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        self.assertEqual(self.r.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.r.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.r.db.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(self.r.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_all_provider_records_append_only(self):
        pr.execute(self.r, self.run, self.p, HUMAN)
        with self.r.store.transaction(): pr._observe(self.r, self.run, HUMAN, "TEST_OBSERVATION")
        for table in pr.TABLES:
            for action in ("UPDATE " + table + " SET digest='forged'", "DELETE FROM " + table):
                with self.assertRaises(sqlite3.IntegrityError): self.r.db.execute(action)

    def test_actual_crash_after_final_commit_same_identity(self):
        code = '''import os,sys
from unittest.mock import patch
from acp.runtime import Runtime
from acp import planning,provider_runtime as pr
from tests.test_provider_runtime import FixtureProvider,HUMAN
with Runtime(sys.argv[1]) as r:
 original=planning.finalize
 def die(*args):
  original(*args)
  os._exit(74)
 with patch.object(planning,'finalize',side_effect=die): pr.execute(r,sys.argv[2],FixtureProvider(sys.argv[3]),HUMAN)
'''
        proc = self.child(code)
        self.assertEqual(proc.returncode, 74, proc.stderr)
        before = self.state()
        after = pr.recover(self.r, self.run, HUMAN)
        self.assertEqual(before, after)
        self.assertEqual(self.calls(), 1)

    def test_stale_revision_finalization_held(self):
        first = pr.execute(self.r, self.run, self.p, HUMAN)["result"]
        runs = [planning.prepare(self.r, self.task, self.ctx, HUMAN, plan_id=first["plan_id"], test_only=True)["run_id"] for _ in range(2)]
        for run in runs: pr.enroll(self.r, run, self.p, HUMAN)
        pr.execute(self.r, runs[0], self.p, HUMAN)
        with self.assertRaisesRegex(ACPError, "STALE_PROVIDER_PLAN"):
            pr.execute(self.r, runs[1], self.p, HUMAN)
        self.assertIsNotNone(pr.show(self.r, runs[1])["response"])
        self.assertIsNotNone(pr.show(self.r, runs[1])["validation"])
        self.assertIsNone(pr.show(self.r, runs[1])["result"])

    def test_validator_version_mismatch_held(self):
        self.receipt_only(); pr._validation(self.r, self.run, HUMAN)
        with patch.object(planning, "POLICY", "different-version"), self.assertRaisesRegex(ACPError, "Validator version"):
            pr.finalize(self.r, self.run, HUMAN)
        self.assertIsNone(self.state()["result"])

    def test_profile_capabilities_closed_and_explicit(self):
        for key, value in (("reconcile", "yes"), ("idempotency", 1), ("raw_kind", "arbitrary-decoder")):
            selected = self.p.durable_profile(); selected[key] = value
            with patch.object(self.p, "durable_profile", return_value=selected), self.assertRaises(ACPError):
                pr.profile(self.p)

    def test_input_and_request_digest_corruption_denied(self):
        original = planning.run_show
        def corrupt(*args):
            value = original(*args); value["input_digest"] = "different"
            return value
        with patch.object(planning, "run_show", side_effect=corrupt), self.assertRaises(ACPError):
            pr.request(self.r, self.run, self.p, HUMAN)
        self.assertEqual(self.calls(), 0)
        pr.request(self.r, self.run, self.p, HUMAN)
        # Digest check protects readback even if a database owner bypasses triggers.
        self.r.db.execute("DROP TRIGGER provider_requests_update")
        self.r.db.execute("UPDATE provider_requests SET digest='corrupt'")
        with self.assertRaisesRegex(ACPError, "digest mismatch"):
            pr.execute(self.r, self.run, self.p, HUMAN)
        self.assertEqual(self.calls(), 0)

    def test_recovery_no_filesystem_network_or_new_context(self):
        self.receipt_only()
        with patch("builtins.open", side_effect=AssertionError), patch("socket.socket", side_effect=AssertionError), patch("subprocess.run", side_effect=AssertionError), patch.object(context, "load", side_effect=AssertionError):
            self.assertEqual(pr.recover(self.r, self.run, HUMAN)["state"], "PLAN_REVISION_FINALIZED")

    def test_openai_raw_bytes_receipted_before_envelope_decode(self):
        from acp.openai_decision import OpenAIResponsesDecisionProvider
        from unittest.mock import MagicMock
        provider = OpenAIResponsesDecisionProvider("fixture-model", "medium", allow_remote=True)
        run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
        pr.enroll(self.r, run, provider, HUMAN)
        raw = b'{"status":"incomplete","id":"native-only"}'
        opener = MagicMock(); opener.return_value.open.return_value.__enter__.return_value.read.return_value = raw
        with patch.dict("os.environ", {"OPENAI_API_KEY": "synthetic-fixture"}), patch("urllib.request.build_opener", opener):
            state = pr.execute(self.r, run, provider, HUMAN)
        self.assertEqual(pr._decode(state["response"]["raw"]), raw)
        self.assertEqual(state["result"]["status"], "PROVIDER_FAILED")
        self.assertIsNone(state["result"]["plan_id"])
        self.assertNotIn("synthetic-fixture", canonical_json(state))

    def test_known_configuration_error_before_dispatch(self):
        from acp.openai_decision import OpenAIResponsesDecisionProvider
        provider = OpenAIResponsesDecisionProvider(allow_remote=True)
        run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
        pr.enroll(self.r, run, provider, HUMAN)
        with patch.dict("os.environ", {}, clear=True), patch("urllib.request.build_opener", side_effect=AssertionError):
            state = pr.execute(self.r, run, provider, HUMAN)
        self.assertIsNone(state["dispatch"])
        self.assertIsNone(state["response"])
        self.assertEqual(state["result"]["status"], "PROVIDER_FAILED")
        self.assertIn("NO_API_KEY", state["validation"]["error"])

    def test_actual_crash_inside_finalization_transaction(self):
        self.receipt_only(); pr._validation(self.r, self.run, HUMAN)
        code = '''import os,sys
from unittest.mock import patch
from acp.runtime import Runtime
from acp import planning,provider_runtime as pr
from tests.test_provider_runtime import HUMAN
with Runtime(sys.argv[1]) as r:
 original=planning._publish
 def die(*args):
  original(*args)
  os._exit(75)
 with patch.object(planning,'_publish',side_effect=die): pr.finalize(r,sys.argv[2],HUMAN)
'''
        proc = self.child(code)
        self.assertEqual(proc.returncode, 75, proc.stderr)
        self.assertIsNone(self.state()["result"])
        self.assertEqual(planning.list_plans(self.r), [])
        self.assertIsNotNone(self.state()["validation"])
        self.assertEqual(pr.recover(self.r, self.run, HUMAN)["state"], "PLAN_REVISION_FINALIZED")

    def test_reconciliation_requires_actual_provider_side_record(self):
        pr.request(self.r, self.run, self.p, HUMAN); pr._dispatch(self.r, self.run, HUMAN)
        state = pr.recover(self.r, self.run, HUMAN, self.p)
        self.assertEqual(state["state"], "PROVIDER_OUTCOME_UNKNOWN")
        self.assertIsNone(state["response"])
        self.assertEqual(self.calls(), 0)

    def test_reconciliation_cross_process_exact_retrieval(self):
        pr.request(self.r, self.run, self.p, HUMAN); pr._dispatch(self.r, self.run, HUMAN)
        self.p.invoke_durable(self.state()["request"])
        code = '''import sys,json
from acp.runtime import Runtime
from acp import provider_runtime as pr
from tests.test_provider_runtime import FixtureProvider,HUMAN
with Runtime(sys.argv[1]) as r: print(json.dumps(pr.recover(r,sys.argv[2],HUMAN,FixtureProvider(sys.argv[3]))))
'''
        proc = self.child(code); self.assertEqual(proc.returncode, 0, proc.stderr)
        state = json.loads(proc.stdout)
        self.assertEqual(state["response"]["source"], "recovered")
        self.assertEqual(state["response"]["request_digest"], state["request"]["request_digest"])
        self.assertEqual(self.calls(), 1)

    def test_missing_dispatch_blocks_unsolicited_response(self):
        pr.request(self.r, self.run, self.p, HUMAN)
        with self.assertRaises(ACPError):
            pr.receive(self.r, self.run, self.p.raw, {}, HUMAN)
        self.assertIsNone(self.state()["response"])

    def test_worker_role_cannot_control_provider(self):
        worker = Actor("worker", "worker", "test")
        for operation in (
            lambda: pr.enroll(self.r, self.run, self.p, worker),
            lambda: pr.execute(self.r, self.run, self.p, worker),
            lambda: pr.recover(self.r, self.run, worker)):
            with self.assertRaises(ACPError): operation()
        self.assertEqual(self.calls(), 0)

    def test_commit_failure_before_and_after_acknowledgement(self):
        real = self.r.db
        for table in ("provider_requests", "provider_dispatches", "provider_responses", "provider_validations", "planning_results"):
            for committed in (False, True):
                with self.subTest(table=table, committed=committed):
                    run = planning.prepare(self.r, self.task, self.ctx, HUMAN, test_only=True)["run_id"]
                    provider = FixtureProvider(self.root / (table + str(committed) + "-calls.txt"))
                    pr.enroll(self.r, run, provider, HUMAN)
                    class CommitFault:
                        armed = False
                        def __getattr__(self, key): return getattr(real, key)
                        def execute(self, sql, *args):
                            if sql.startswith("INSERT INTO " + table + " "):
                                self.armed = True
                            if sql == "COMMIT" and self.armed:
                                self.armed = False
                                if committed: real.execute(sql, *args)
                                raise sqlite3.OperationalError("simulated uncertain commit acknowledgement")
                            return real.execute(sql, *args)
                    proxy = CommitFault()
                    with patch.object(self.r, "db", proxy), patch.object(self.r.store, "db", proxy), self.assertRaises(sqlite3.OperationalError):
                        pr.execute(self.r, run, provider, HUMAN)
                    exists = real.execute("SELECT 1 FROM " + table + " WHERE run_id=?", (run,)).fetchone()
                    self.assertEqual(exists is not None, committed)
                    self.assertEqual(provider.calls, int(table in {"provider_responses", "provider_validations", "planning_results"}))
                    if table == "provider_dispatches":
                        self.assertEqual(pr.recover(self.r, run, HUMAN)["state"], "PROVIDER_OUTCOME_UNKNOWN" if committed else "REQUEST_RECEIPT_PERSISTED")

    def test_cli_explicit_test_only_plan(self):
        proc = subprocess.run([sys.executable, "-B", "-m", "acp", "--data-dir", str(self.root / "state"), "plan", "prepare", "--task", self.task, "--context", self.ctx, "--test-only"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["input"]["test_only"])


if __name__ == "__main__":
    unittest.main()
