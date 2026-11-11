"""Pinned external Kandev integration; native types stay in this module."""

import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from .adapters import Observation, Outcome
from .domain import AttemptState, canonical_json, digest, require
from .guarded import admit


LIMITATIONS = ["sibling_read_isolation", "windows_os_sandbox", "credential_isolation",
              "network_isolation", "forbidden_path_prevention", "cancellation_fencing"]


class Transport:
    def __init__(self, endpoint):
        parsed = urllib.parse.urlsplit(endpoint)
        require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port
                and not parsed.username and not parsed.password and parsed.path in {"", "/"}
                and not parsed.query and not parsed.fragment, "M03 requires explicit loopback endpoint")
        self.endpoint = endpoint.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, body=None, headers=None):
        request = urllib.request.Request(self.endpoint + path,
            data=canonical_json(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", **(headers or {})})
        with self.opener.open(request, timeout=45) as response:
            return response.read().decode("utf-8"), response.headers

    def get(self, path):
        raw, _ = self.request(path)
        return json.loads(raw)

    @staticmethod
    def rpc_result(raw, request_id):
        # Streamable HTTP may emit notifications before the matching response.
        lines = [line[6:] for line in raw.splitlines() if line.startswith("data: ")]
        objects = [json.loads(line) for line in lines] if lines else [json.loads(raw)]
        result = next((obj for obj in objects if obj.get("id") == request_id), None)
        require(result is not None and "error" not in result, "MCP request failed")
        return result["result"]

    def call(self, name, arguments):
        headers = {"Accept": "application/json, text/event-stream"}
        raw, response_headers = self.request("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "acp-m03", "version": "1"}}}, headers)
        self.rpc_result(raw, 1)
        headers["Mcp-Session-Id"] = response_headers["Mcp-Session-Id"]
        raw, _ = self.request("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}, headers)
        result = self.rpc_result(raw, 2)
        require(not result.get("isError"), "Backend tool rejected request: " + str(result))
        if result.get("structuredContent"):
            return result["structuredContent"]
        return json.loads("\n".join(c["text"] for c in result["content"] if c["type"] == "text"))

    def cancel(self, session_id):
        script = Path(__file__).with_name("kandev_cancel.mjs")
        result = subprocess.run(["node", str(script), self.endpoint.replace("http:", "ws:") + "/ws", session_id],
            capture_output=True, text=True, encoding="utf-8", timeout=55)
        require(result.returncode == 0, "Cancellation transport unavailable")
        return json.loads(result.stdout)


class KandevAdapter:
    name = "kandev"
    adapter_version = "1"
    real_execution = True

    def __init__(self, config, transport=None):
        self.config = config
        require(config["backend_version"] == "0.95.0" and config["codex_acp_version"] == "1.12.0", "Unsupported pinned runtime")
        require(config["limitations"] == LIMITATIONS, "Capability limitations must remain visible")
        self.version = config["backend_version"]
        self.binding = digest(config)
        self.transport = transport or Transport(config["endpoint"])
        self.contract = None

    def bind_context(self, contract, project):
        self.contract, self.project = contract, project

    def prepare(self, contract, project):
        self.contract, self.project = contract, project
        admit(contract, project, self.config)
        agents = self.transport.get("/api/v1/agents")["agents"]
        profiles = [p for a in agents if a["name"] == "codex-acp" for p in a["profiles"]]
        profile = next((p for p in profiles if p["id"] == self.config["agent_profile_id"]), {})
        mode = "read-only" if contract["change_kind"] == "read_only" else "agent"
        require(profile.get("mode") == mode and profile.get("model") == "gpt-6-astra"
                and profile.get("require_exact_model") is True and not profile.get("auto_approve")
                and profile.get("config_options", {}).get("reasoning_effort") == "medium"
                and profile.get("config_options", {}).get("fast-mode") == "off"
                and not profile.get("cli_flags") and not profile.get("cli_passthrough"), "UNSUPPORTED_CAPABILITY: unsafe backend profile")

    def submit(self, contract, idempotency_key):
        require(self.contract == contract, "Adapter requires guarded preparation")
        prompt = ("Disposable ACP synthetic task. Do not use network, credentials, external paths, delegation, "
                  "or commit/merge/deploy. Only operate in this assigned worktree. Stop after the requested edit.\n"
                  "Approved immutable contract:\n" + canonical_json(contract) + "\nInstruction:\n" + contract["worker_instruction"])
        result = self.transport.call("create_task_kandev", {
            "title": "ACP " + idempotency_key[:48], "local_path": self.project["path"],
            "base_branch": contract["base_commit"], "external_id": idempotency_key,
            "workspace_id": self.config["workspace_id"], "workflow_id": self.config["workflow_id"],
            "agent_profile_id": self.config["agent_profile_id"], "executor_profile_id": self.config["executor_profile_id"],
            "start_agent": True, "autopilot": False, "prompt": prompt})
        return Observation(Outcome.OK, AttemptState.QUEUED, result["id"], detail={"creation": result, "binding": self.binding})

    def lookup(self, key):
        path = "/api/v1/workspaces/" + urllib.parse.quote(self.config["workspace_id"], safe="") + "/tasks/by-external-id?external_id=" + urllib.parse.quote(key, safe="")
        result = self.transport.get(path)
        task = result.get("task", result)
        require(task.get("external_id") == key, "Backend external identity mismatch")
        return task

    @staticmethod
    def normalize(task, session):
        native = session.get("state", "")
        # A cancelled native session is NOT proof of terminated descendants.
        if native == "CANCELLED" or task.get("state") == "CANCELLED":
            return Outcome.UNKNOWN, None
        if native in {"RUNNING", "STARTING", "CREATED"}:
            return Outcome.OK, {"RUNNING": AttemptState.RUNNING, "STARTING": AttemptState.STARTING, "CREATED": AttemptState.QUEUED}[native]
        if native == "WAITING_FOR_INPUT" and task.get("state") in {"REVIEW", "COMPLETED"}:
            return Outcome.OK, AttemptState.SUCCEEDED
        if native == "COMPLETED":
            return Outcome.OK, AttemptState.SUCCEEDED
        # Even a FAILED backend might retain mutation authority: fail closed.
        return Outcome.UNKNOWN, None

    def get_snapshot(self, key):
        task = self.lookup(key)
        sessions = self.transport.get("/api/v1/tasks/" + task["id"] + "/sessions")["sessions"]
        if len(sessions) != 1:
            return Observation(Outcome.UNKNOWN, backend_task_id=task["id"], detail={"reason": "Expected exactly one session", "sessions": sessions})
        session = sessions[0]
        if self.contract and (session.get("base_commit_sha") != self.contract["base_commit"]
                or session.get("agent_profile_id") != self.config["agent_profile_id"]
                or session.get("executor_profile_id") != self.config["executor_profile_id"]):
            return Observation(Outcome.UNKNOWN, backend_task_id=task["id"], backend_session_id=session["id"], detail={"reason": "Execution binding mismatch", "session": session})
        outcome, state = self.normalize(task, session)
        return Observation(outcome, state, task["id"], session["id"], {"task": task, "session": session, "workspace_id": self.config["workspace_id"], "limitations": LIMITATIONS})

    def reconcile(self, key):
        return self.get_snapshot(key)

    def cancel(self, key):
        snapshot = self.get_snapshot(key)
        require(snapshot.backend_session_id, "No unambiguous session to cancel")
        result = self.transport.cancel(snapshot.backend_session_id)
        return Observation(Outcome.OK, AttemptState.CANCEL_REQUESTED, snapshot.backend_task_id, snapshot.backend_session_id,
                           {"acknowledgement": result, "stopped": False, "fenced": False})

    def collect_evidence(self, key):
        task = self.lookup(key)
        conversation = self.transport.call("get_task_conversation_kandev", {"task_id": task["id"], "limit": 100, "sort": "desc"})
        records = [{"class": "artifact", "trust": "observed", "producer": "kandev", "producer_role": "worker",
                 "collector": "ACP", "collection_method": "external conversation snapshot (bounded; not complete log)",
                 "outcome": "unknown", "content": conversation}]
        for message in conversation.get("messages", []):
            if message.get("author_type") == "agent" and message.get("type") == "message":
                records.append({"class": "claim", "trust": "unverified", "producer": "Codex worker", "producer_role": "worker", "collector": "ACP",
                    "collection_method": "backend-provided worker prose", "outcome": "unknown", "content": message})
        return records

    def inspect_cancellation(self, key):
        workspace = self.workspace(key)
        from .processes import inspect_candidates
        result = inspect_candidates()
        return {"class": "artifact", "trust": "observed", "producer": "ACP process inspector", "producer_role": "controller",
                "collector": "ACP", "collection_method": "read-only Windows Toolhelp32 process metadata snapshot",
                "outcome": "unknown", "content": {"workspace": str(workspace), "inspection": result, "termination_proven": False, "fenced": False}}

    def workspace(self, key):
        task = self.lookup(key)
        environment = self.transport.get("/api/v1/tasks/" + task["id"] + "/environment")
        require(environment.get("executor_type") == "worktree" and len(environment.get("repos", [])) == 1, "Expected single worktree environment")
        path = Path(environment["repos"][0]["worktree_path"]).resolve(strict=True)
        require(path.is_relative_to(Path(self.config["worktree_root"]).resolve(strict=True)), "Backend workspace outside disposable task root")
        return path
