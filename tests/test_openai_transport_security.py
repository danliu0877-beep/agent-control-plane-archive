"""Synthetic-only credential reflection regressions; no network or real keys."""
import base64
import io
import json
import os
from pathlib import Path
import tempfile
import traceback
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from acp import context, planning, provider_runtime as pr
from acp.domain import ACPError, Actor, canonical_json
from acp.openai_decision import OpenAIResponsesDecisionProvider
from acp.runtime import Runtime
from tests.test_planning import fixture

HUMAN = Actor("principal", "human", "test")
KEY = "synthetic-reflection-credential-DO-NOT-USE"


class OpenAITransportSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="acp-transport-security-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        repo = self.root / "repo"
        repo.mkdir()
        (repo / "STATUS.md").write_text("Synthetic evidence.\n")
        self.r = Runtime(self.root / "state")
        self.addCleanup(self.r.close)
        self.r.project_add("demo", repo)
        task = self.r.task_create("demo", "fixture", "Inspect synthetic material", HUMAN)["id"]
        ctx = context.load(self.r, "demo", HUMAN)["id"]
        self.run = planning.prepare(self.r, task, ctx, HUMAN, test_only=True)["run_id"]
        self.provider = OpenAIResponsesDecisionProvider("fixture-model", allow_remote=True)
        pr.enroll(self.r, self.run, self.provider, HUMAN)
        self.env = patch.dict(os.environ, {"OPENAI_API_KEY": KEY})
        self.env.start()
        self.addCleanup(self.env.stop)

    def assert_no_credential(self, state):
        for content in (canonical_json(state), "\n".join(self.r.db.iterdump())):
            self.assertNotIn(KEY, content)
            self.assertNotIn(base64.b64encode(KEY.encode()).decode(), content)
        if state["response"]:
            self.assertNotIn(KEY.encode(), pr._decode(state["response"]["raw"]))
        # Check actual SQLite/WAL bytes as well as decoded logical records.
        for path in (self.root / "state").glob("acp.sqlite3*"):
            self.assertNotIn(KEY.encode(), path.read_bytes())

    def test_http_rejection_discards_body_reason_headers_and_retains_status(self):
        body = MagicMock(wraps=io.BytesIO(("invalid key " + KEY).encode()))
        error = urllib.error.HTTPError("https://api.openai.com/" + KEY, 401, KEY,
                                       {"Authorization": "Bearer " + KEY}, body)
        opener = MagicMock()
        opener.open.side_effect = error
        with patch("urllib.request.build_opener", return_value=opener):
            first = pr.execute(self.r, self.run, self.provider, HUMAN)
            second = pr.execute(self.r, self.run, self.provider, HUMAN)
        body.read.assert_not_called()
        body.close.assert_called_once()
        opener.open.assert_called_once()
        self.assertEqual(first, second)
        self.assertEqual(first["state"], "REJECTED")
        self.assertEqual(first["response"]["metadata"]["http_status"], 401)
        self.assertEqual(first["response"]["metadata"]["body_omitted"], "http_error")
        self.assertEqual(pr._decode(first["response"]["raw"]), b"")
        self.assertEqual(first["validation"]["raw"], "")
        self.assert_no_credential(first)

    def test_untrusted_http_status_and_close_error_are_not_retained(self):
        error = urllib.error.HTTPError("https://api.openai.com/", KEY, KEY, {}, None)
        with patch.object(error, "close", side_effect=RuntimeError(KEY)), patch(
                "urllib.request.build_opener", side_effect=error):
            state = pr.execute(self.r, self.run, self.provider, HUMAN)
        self.assertEqual(state["response"]["metadata"]["http_status"], 400)
        self.assert_no_credential(state)

    def test_setup_and_transport_errors_have_no_sensitive_exception_chain(self):
        for target in ("urllib.request.Request", "urllib.request.build_opener"):
            with self.subTest(target=target), patch(target, side_effect=ValueError(KEY)):
                try:
                    self.provider.propose({})
                except ACPError as exc:
                    self.assertEqual(str(exc), "PROVIDER_TRANSPORT_OUTCOME_UNKNOWN")
                    self.assertIsNone(exc.__context__)
                    self.assertIsNone(exc.__cause__)
                    self.assertNotIn(KEY, "".join(traceback.format_exception(exc)))
                else:
                    self.fail("Expected sanitized transport failure")
        opener = MagicMock()
        opener.open.side_effect = urllib.error.URLError(KEY)
        with patch("urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(ACPError, "PROVIDER_TRANSPORT_OUTCOME_UNKNOWN") as caught:
                self.provider.propose({})
        self.assertIsNone(caught.exception.__context__)

    def test_active_caller_exception_is_not_attached_to_transport_or_decode_error(self):
        errors = (ValueError(KEY), urllib.error.HTTPError("https://api.openai.com/", 401, KEY, {}, None))
        for error in errors:
            with self.subTest(error=type(error).__name__), patch(
                    "urllib.request.build_opener", side_effect=error):
                try:
                    raise RuntimeError(KEY)
                except RuntimeError:
                    try:
                        self.provider.propose({})
                    except ACPError as exc:
                        self.assertIsNone(exc.__context__)
                        self.assertIsNone(exc.__cause__)
                        self.assertNotIn(KEY, str(exc))
                        self.assertNotIn(KEY, repr(exc))
                        self.assertNotIn(KEY, "".join(traceback.format_exception(exc)))
                    else:
                        self.fail("Expected sanitized failure")

    def test_timeout_unknown_no_receipt_or_reinvocation(self):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.side_effect = TimeoutError(KEY)
        with patch("urllib.request.build_opener", return_value=opener):
            first = pr.execute(self.r, self.run, self.provider, HUMAN)
            second = pr.execute(self.r, self.run, self.provider, HUMAN)
        opener.open.assert_called_once()
        for state in (first, second):
            self.assertEqual(state["state"], "PROVIDER_OUTCOME_UNKNOWN")
            self.assertIsNone(state["response"])
            self.assertIsNone(state["validation"])
            self.assertFalse(state["automatic_reinvocation_allowed"])
            self.assert_no_credential(state)

    def test_setup_error_is_unknown_and_never_reinvoked(self):
        with patch("urllib.request.Request", side_effect=ValueError(KEY)) as request:
            first = pr.execute(self.r, self.run, self.provider, HUMAN)
            second = pr.execute(self.r, self.run, self.provider, HUMAN)
        request.assert_called_once()
        for state in (first, second):
            self.assertEqual(state["state"], "PROVIDER_OUTCOME_UNKNOWN")
            self.assertIsNone(state["response"])
            self.assert_no_credential(state)

    def test_json_escaped_active_key_is_omitted(self):
        key = KEY + '\"\\suffix-\u96ea'
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = json.dumps({"error": key}).encode()
        with patch.dict(os.environ, {"OPENAI_API_KEY": key}), patch(
                "urllib.request.build_opener", return_value=opener):
            output = self.provider.invoke_durable({"wire_request": {}})
        self.assertEqual(output.raw, b"")
        self.assertEqual(output.metadata["body_omitted"], "credential_reflection")

    def test_surrogate_key_encoding_failure_has_no_exception_chain(self):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = b"{}"
        with patch("acp.openai_decision.os.environ.get", return_value=KEY + "\ud800"), patch(
                "urllib.request.build_opener", return_value=opener):
            try:
                self.provider.invoke_durable({"wire_request": {}})
            except ACPError as exc:
                self.assertEqual(str(exc), "PROVIDER_TRANSPORT_OUTCOME_UNKNOWN")
                self.assertIsNone(exc.__context__)
                self.assertIsNone(exc.__cause__)
                self.assertNotIn(KEY, "".join(traceback.format_exception(exc)))
            else:
                self.fail("Expected sanitized encoding failure")

    def test_successful_envelope_keeps_exact_bytes(self):
        raw = json.dumps({"status": "completed", "output": [{"type": "message", "content": [
            {"type": "output_text", "text": json.dumps(fixture())}]}]}).encode()
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = raw
        with patch("urllib.request.build_opener", return_value=opener):
            state = pr.execute(self.r, self.run, self.provider, HUMAN)
        self.assertEqual(pr._decode(state["response"]["raw"]), raw)
        self.assertEqual(state["state"], "PLAN_REVISION_FINALIZED")
        self.assert_no_credential(state)

    def test_success_status_with_reflected_key_is_rejected_without_raw_body(self):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"status": "incomplete", "error": "Bearer " + KEY}).encode()
        with patch("urllib.request.build_opener", return_value=opener):
            state = pr.execute(self.r, self.run, self.provider, HUMAN)
        self.assertEqual(state["state"], "REJECTED")
        self.assertEqual(state["response"]["metadata"]["body_omitted"], "credential_reflection")
        self.assert_no_credential(state)


if __name__ == "__main__":
    unittest.main()
