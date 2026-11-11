"""No server or worker needed. Independent tests for external dispatch boundaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from acp.adapters import Observation, Outcome, SyntheticAdapter
from acp.domain import ACPError, AttemptState
from acp.guarded import check_paths, scope_path
from acp.kandev import KandevAdapter, Transport
from acp.runtime import Runtime
from tests.test_runtime import HUMAN, CONTROL, envelope, expiry


class FakeAdapter:
    real_execution = True
    name = "opaque-backend"
    version = "external-version"
    adapter_version = "1"
    binding = "fixed-config"
    config = {"limitations": ["no isolation"]}

    def __init__(self):
        self.submissions = 0
        self.state = AttemptState.RUNNING
        self.lost_response = False

    def prepare(self, contract, project):
        pass

    def submit(self, contract, key):
        self.submissions += 1
        if self.lost_response:
            raise OSError("lost response AFTER submission")
        return self.reconcile(key)

    def reconcile(self, key):
        return Observation(Outcome.OK, self.state, "opaque-task", "opaque-session")

    def cancel(self, key):
        return Observation(Outcome.OK, AttemptState.CANCEL_REQUESTED, detail={"acknowledged": True})


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "repo").mkdir()
        self.runtime = Runtime(self.root / "state")
        self.addCleanup(lambda: self.runtime.close())
        project = self.runtime.project_add("fixture", self.root / "repo")
        self.task = self.runtime.task_create("fixture", "test", "synthetic", HUMAN)["id"]
        self.runtime.transition(self.task, "TRIAGE", HUMAN, "test")
        self.runtime.plan(self.task, envelope(project), HUMAN, "test")
        self.approval = self.runtime.approve(self.task, "human", HUMAN, expiry())["id"]
        self.runtime.transition(self.task, "READY", HUMAN, "test")
        self.attempt = self.runtime.attempt_create(self.task, self.approval, HUMAN)["id"]
        self.adapter = FakeAdapter()

    def op(self, name):
        return self.runtime.adapter_operation(self.attempt, name, self.adapter, CONTROL)

    def test_duplicate_submit_queries_not_creates(self):
        self.op("submit")
        result = self.op("submit")
        self.assertEqual(self.adapter.submissions, 1)
        self.assertEqual(result["backend_mappings"][0]["backend_task_id"], "opaque-task")
        self.assertTrue(result["id"].startswith("ATT-"))

    def test_lost_response_recovers_without_resubmit(self):
        self.adapter.lost_response = True
        self.assertEqual(self.op("submit")["state"], "LOST")
        self.assertEqual(self.runtime.task_show(self.task)["state"], "BLOCKED")
        self.op("submit")
        self.assertEqual(self.adapter.submissions, 1)
        self.assertEqual(self.runtime.attempt_show(self.attempt)["state"], "RUNNING")

    def test_restart_retains_intent_and_mapping(self):
        self.op("submit")
        self.runtime.close()
        self.runtime = Runtime(self.root / "state")
        self.op("submit")
        self.assertEqual(self.adapter.submissions, 1)
        self.assertEqual(len(self.runtime.task_list()), 1)

    def test_crash_intent_without_mapping_does_not_resubmit(self):
        self.adapter.submit = lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.op("submit")
        self.assertEqual(self.runtime.attempt_show(self.attempt)["state"], "QUEUED")
        self.op("submit")
        self.assertEqual(self.adapter.submissions, 0)

    def test_backend_success_is_only_review(self):
        self.adapter.state = AttemptState.SUCCEEDED
        self.op("submit")
        self.assertEqual(self.runtime.task_show(self.task)["state"], "REVIEW")
        with self.assertRaisesRegex(ACPError, "Mandatory independent"):
            self.runtime.accept(self.task, self.attempt, {}, HUMAN, "cannot bypass")

    def test_cancellation_ack_cannot_fence_or_retry(self):
        self.op("submit")
        result = self.op("cancel")
        self.assertEqual(result["state"], "CANCEL_REQUESTED")
        self.assertIsNone(result["fence_evidence_id"])
        self.op("reconcile")
        with self.assertRaises(ACPError):
            self.runtime.resolve_hold(self.task, HUMAN, "retry", retry_ready=True)

    def test_revoked_approval_no_dispatch(self):
        self.runtime.revoke(self.approval, HUMAN, "withdrawn")
        self.op("submit")
        self.assertEqual(self.adapter.submissions, 0)

    def test_expired_approval_no_dispatch(self):
        with patch("acp.runtime.now", return_value="2099-01-01T00:00:00+00:00"):
            self.op("submit")
        self.assertEqual(self.adapter.submissions, 0)

    def test_config_rebinding_rejected(self):
        self.op("submit")
        self.adapter.binding = "different-endpoint"
        with self.assertRaisesRegex(ACPError, "configuration"):
            self.op("reconcile")

    def test_synthetic_cannot_complete_real_attempt(self):
        self.op("submit")
        with self.assertRaisesRegex(ACPError, "switch to simulation"):
            self.runtime.adapter_operation(self.attempt, "submit", SyntheticAdapter(), CONTROL)

    def test_contract_update_forbidden(self):
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            self.runtime.db.execute("UPDATE execution_attempts SET contract_json='{}' WHERE id=?", (self.attempt,))

    def test_unsupported_admission_records_explicit_hold(self):
        self.adapter.prepare = lambda *_: (_ for _ in ()).throw(ACPError("UNSUPPORTED_CAPABILITY: sandbox"))
        self.assertEqual(self.op("submit")["state"], "FAILED")
        self.assertEqual(self.runtime.task_show(self.task)["hold_reason"], "UNSUPPORTED_CAPABILITY")
        self.assertEqual(self.adapter.submissions, 0)

    def test_missing_authorization_prevents_allocation(self):
        with self.assertRaises(ACPError):
            self.runtime.attempt_create(self.task, "missing", HUMAN)


class AdapterBoundaryTests(unittest.TestCase):
    def test_native_states_are_normalized_not_task_states(self):
        for native, expected in [("RUNNING", AttemptState.RUNNING), ("STARTING", AttemptState.STARTING), ("COMPLETED", AttemptState.SUCCEEDED)]:
            self.assertEqual(KandevAdapter.normalize({}, {"state": native}), (Outcome.OK, expected))
        self.assertEqual(KandevAdapter.normalize({"state": "COMPLETED"}, {"state": "WAITING_FOR_INPUT"})[1], AttemptState.SUCCEEDED)

    def test_cancelled_and_unknown_fail_closed(self):
        for state in ("CANCELLED", "FAILED", "ALIEN"):
            self.assertEqual(KandevAdapter.normalize({}, {"state": state})[0], Outcome.UNKNOWN)

    def test_mcp_notifications_are_not_responses(self):
        raw = 'data: {"jsonrpc":"2.0","method":"notice"}\n\ndata: {"id":2,"result":{"ok":true}}\n'
        self.assertEqual(Transport.rpc_result(raw, 2), {"ok": True})

    def test_remote_endpoints_rejected(self):
        for endpoint in ("http://example.com:1234", "http://127.0.0.1:12/other", "http://user:pass@127.0.0.1:12"):
            with self.assertRaises(ACPError):
                Transport(endpoint)

    def test_malformed_and_forbidden_paths(self):
        for path in ("../x", "C:\\x", ".git/config", "x/./y", "x.", "x//y", "*.py"):
            with self.assertRaises(ACPError):
                scope_path(path)
        with tempfile.TemporaryDirectory() as root:
            self.assertFalse(check_paths(Path(root), ["src/a.py"], ["src"], ["src/no.py"]))
            self.assertTrue(check_paths(Path(root), ["SRC/no.py", "outside.py"], ["src"], ["src/no.py"]))


class RepositoryGuardTests(unittest.TestCase):
    def setUp(self):
        import subprocess
        from acp.domain import digest, path_key
        from acp.guarded import git
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / ".acp-synthetic").write_text("DISPOSABLE ACP M03\n")
        (self.repo / "allowed.txt").write_text("before")
        (self.repo / "forbidden.txt").write_text("before")
        for args in (["init"], ["add", "."], ["-c", "user.name=test", "-c", "user.email=test@invalid", "commit", "-m", "fixture"]):
            subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)
        common = Path(git(self.repo, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
        self.project = {"path": str(self.repo), "id": "fixture", "enabled": 1,
                        "repository_identity": digest({"kind": "git", "path": path_key(common)}),
                        "observed_head": git(self.repo, "rev-parse", "HEAD")}
        self.contract = envelope(self.project)
        self.contract.update(allowed_operations=["write"], verification={"fixture": True}, limitations_acknowledged=["not sandboxed"])
        self.config = {"synthetic_root": str(self.root), "repositories": [str(self.repo)], "disposable_only": True,
                       "profile_name": "synthetic", "limitations": ["not sandboxed"], "verification": {"fixture": True}}

    def test_exact_clean_synthetic_admission(self):
        from acp.guarded import admit
        self.assertEqual(admit(self.contract, self.project, self.config), str(self.repo))

    def test_repository_base_scope_and_capability_rejections(self):
        from copy import deepcopy
        from acp.guarded import admit
        for updates in ({"repository_identity": "wrong"}, {"base_commit": "0" * 40}, {"primary_project": "unknown"},
                        {"allowed_operations": ["deploy"]}, {"write_scope": ["../other"]}, {"runtime_profile": "full-access"},
                        {"required_capabilities": ["windows_os_sandbox"]}, {"limitations_acknowledged": []},
                        {"verification": {"changed": True}}, {"write_scope": ["forbidden.txt"]}):
            with self.subTest(updates=updates), self.assertRaises(ACPError):
                admit({**deepcopy(self.contract), **updates}, self.project, self.config)

    def test_scope_detector_includes_untracked_and_forbidden(self):
        from acp.guarded import repository_facts
        (self.repo / "allowed.txt").write_text("after")
        facts = repository_facts(self.repo, self.repo, self.contract)
        self.assertTrue(facts["pass"])
        self.assertEqual(facts["changed_files"], ["allowed.txt"])
        (self.repo / "forbidden.txt").write_text("after")
        (self.repo / "extra.txt").write_text("after")
        facts = repository_facts(self.repo, self.repo, self.contract)
        self.assertFalse(facts["pass"])
        self.assertEqual({v["path"] for v in facts["violations"]}, {"forbidden.txt", "extra.txt"})

    def test_ignored_files_cannot_hide_scope_drift(self):
        from acp.guarded import repository_facts
        (self.repo / ".gitignore").write_text("hidden.txt\n")
        (self.repo / "hidden.txt").write_text("hidden")
        self.assertIn("hidden.txt", repository_facts(self.repo, self.repo, self.contract)["changed_files"])

    def verification_case(self, content):
        import hashlib
        import sys
        script = self.root / "verifier.py"
        script.write_text("import pathlib,sys\nprint('independent check')\nsys.exit(0 if (pathlib.Path(sys.argv[1])/'allowed.txt').read_text() == 'pass' else 1)\n")
        runtime = Runtime(self.root / "state")
        self.addCleanup(runtime.close)
        project = runtime.project_add("fixture", self.repo)
        task = runtime.task_create("fixture", "verify", "synthetic", HUMAN)["id"]
        runtime.transition(task, "TRIAGE", HUMAN, "test")
        contract = envelope(project, "executable")
        contract["verification"] = {"python": sys.executable, "script": str(script), "sha256": hashlib.sha256(script.read_bytes()).hexdigest()}
        runtime.plan(task, contract, HUMAN, "test")
        approval = runtime.approve(task, "human", HUMAN, expiry())["id"]
        runtime.transition(task, "READY", HUMAN, "test")
        attempt = runtime.attempt_create(task, approval, HUMAN)["id"]
        adapter = FakeAdapter()
        adapter.state = AttemptState.SUCCEEDED
        adapter.workspace = lambda _: self.repo
        runtime.adapter_operation(attempt, "submit", adapter, CONTROL)
        (self.repo / "allowed.txt").write_text(content)
        result = runtime.adapter_operation(attempt, "verify", adapter, CONTROL)
        return runtime, task, attempt, result

    def test_independent_verifier_evidence_and_acceptance(self):
        runtime, task, attempt, result = self.verification_case("pass")
        self.assertTrue(result["pass"])
        # Equal collection timestamps may sort by opaque ID, not insertion order.
        record = next(e for e in runtime.task_show(task)["evidence"]
                      if e["id"] == result["verification_evidence_id"])
        self.assertEqual(record["class"], "independent_result")
        self.assertEqual(record["record"]["exit_code"], 0)
        self.assertEqual(runtime.accept(task, attempt, {"checked": result["verification_evidence_id"]}, HUMAN, "verified")["state"], "DONE")

    def test_independent_failure_blocks_acceptance(self):
        runtime, task, attempt, result = self.verification_case("fail")
        self.assertFalse(result["pass"])
        self.assertEqual(runtime.task_show(task)["state"], "BLOCKED")
        with self.assertRaises(ACPError):
            runtime.accept(task, attempt, {"checked": result["verification_evidence_id"]}, HUMAN, "cannot accept")

    def test_stale_repository_verification_rejected(self):
        runtime, task, attempt, result = self.verification_case("pass")
        (self.repo / "allowed.txt").write_text("changed after verification")
        with self.assertRaisesRegex(ACPError, "changed since"):
            runtime.accept(task, attempt, {"checked": result["verification_evidence_id"]}, HUMAN, "cannot accept stale facts")


if __name__ == "__main__":
    unittest.main()
