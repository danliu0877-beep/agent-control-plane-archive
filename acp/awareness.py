"""Deterministic project metadata, resolution and pre-task intake. No LLM/backend."""
import json
import re
import unicodedata

from .domain import canonical_json, identity, now, require, text
from .read_boundary import relative_name


def profile(runtime, project_id):
    project = runtime.project_show(project_id)
    result = {"name": project_id, "aliases": [], "terms": [],
              "governance_files": ["AGENTS.md", "PROJECT_INSTRUCTIONS.md"], "status_file": "STATUS.md",
              "decision_files": ["docs/10-decision-log.md"], "context_files": ["README.md"],
              "context_roots": [], "read_roots": ["."], "revision": 0}
    row = runtime.db.execute("SELECT revision,metadata_json FROM project_profiles WHERE project_id=? ORDER BY revision DESC LIMIT 1", (project_id,)).fetchone()
    if row:
        result.update(json.loads(row["metadata_json"]))
        result["revision"] = row["revision"]
    return {**result, "project": project}


def configure(runtime, project_id, changes, actor):
    require(actor.role == "human", "Registry context boundary changes require human authority")
    require(isinstance(changes, dict), "Metadata object required")
    allowed = {"name", "aliases", "terms", "governance_files", "status_file", "decision_files", "context_files", "context_roots", "read_roots", "enabled"}
    require(set(changes) <= allowed, "Unknown metadata field")
    with runtime.store.transaction():
        current = profile(runtime, project_id)
        metadata = {k: v for k, v in current.items() if k not in {"project", "revision"}}
        metadata.update({k: v for k, v in changes.items() if k != "enabled"})
        require(len(text(metadata["name"], "name")) <= 256, "Metadata name exceeds limit")
        for key in ("aliases", "terms", "governance_files", "decision_files", "context_files", "context_roots", "read_roots"):
            values = metadata[key]
            require(isinstance(values, list) and len(values) <= 64, "Metadata list exceeds limit")
            for value in values:
                require(len(text(value, key)) <= 256, "Metadata value exceeds limit")
                if key not in {"aliases", "terms"}:
                    relative_name(value, root=key.endswith("roots"))
        if metadata["status_file"] is not None:
            relative_name(metadata["status_file"])
        require(metadata["read_roots"], "At least one approved read root required")
        if "enabled" in changes:
            require(type(changes["enabled"]) is bool, "enabled must be boolean")
            runtime.db.execute("UPDATE projects SET enabled=? WHERE id=?", (int(changes["enabled"]), project_id))
        metadata["enabled"] = bool(changes.get("enabled", current["project"]["enabled"]))
        runtime.db.execute("INSERT INTO project_profiles VALUES (?,?,?,?,?)", (project_id, current["revision"] + 1,
            canonical_json(metadata), canonical_json(actor.record()), now()))
    return profile(runtime, project_id)


def normalize(value):
    return unicodedata.normalize("NFKC", value).casefold().replace("\\", "/")


def matches(request, signal):
    signal = normalize(signal)
    if not signal:
        return False
    # ASCII identifiers need token boundaries; CJK phrases may be embedded in prose.
    prefix = r"(?<![a-z0-9_])" if signal[0].isascii() and signal[0].isalnum() else ""
    suffix = r"(?![a-z0-9_])" if signal[-1].isascii() and signal[-1].isalnum() else ""
    return re.search(prefix + re.escape(signal) + suffix, request) is not None


def resolve(runtime, request, explicit=None):
    text(request, "request")
    require(len(request.encode("utf-8")) <= 32768, "Intake request too large")
    request_key = normalize(request)
    candidates, disabled = [], []
    for project in runtime.project_list():
        metadata = profile(runtime, project["id"])
        signals = []
        if explicit is not None:
            if explicit == project["id"]:
                signals.append({"kind": "explicit_project_id", "value": explicit, "weight": 100})
        else:
            for kind, values, weight in (("project_id", [project["id"]], 100), ("name", [metadata["name"]], 90),
                ("alias", metadata["aliases"], 80), ("path", [project["path"]], 100), ("terminology", metadata["terms"], 60)):
                for value in values:
                    if matches(request_key, value):
                        signals.append({"kind": kind, "value": value, "weight": weight})
        if signals:
            item = {"project_id": project["id"], "score": max(s["weight"] for s in signals), "signals": signals, "profile_revision": metadata["revision"]}
            (candidates if project["enabled"] else disabled).append(item)
    candidates.sort(key=lambda c: (-c["score"], c["project_id"]))
    outcome = "RESOLVED" if len(candidates) == 1 else "AMBIGUOUS" if candidates else "UNRESOLVED"
    return {"outcome": outcome, "primary_project": candidates[0]["project_id"] if outcome == "RESOLVED" else None,
            "candidate_project_ids": [c["project_id"] for c in candidates], "candidates": candidates, "disabled_matches": disabled,
            "human_required": outcome != "RESOLVED", "intake_state": "NEW" if outcome == "RESOLVED" else "NEEDS_HUMAN" if outcome == "AMBIGUOUS" else "UNRESOLVED",
            "strategy": "deterministic exact signals; every positive candidate remains plausible; scores are not probabilities",
            "explicit_project": explicit}


def intake(runtime, request, actor, explicit=None, create=True):
    require(actor.role != "worker", "Worker cannot perform canonical intake")
    with runtime.store.transaction():
        result = resolve(runtime, request, explicit)
        resolution_id, task_id, at = identity("RES"), None, now()
        if create and result["outcome"] == "RESOLVED":
            task_id = identity("TASK")
            runtime.db.execute("INSERT INTO tasks (id,project_id,title,request,state,created_at,updated_at) VALUES (?,?,?,?,'NEW',?,?)",
                (task_id, result["primary_project"], request[:120], request, at, at))
            runtime._event("task_events", task_id, "CREATED", actor, "Deterministic project intake; no plan or execution authority", after="NEW", details={"resolution_id": resolution_id})
        result.update(resolution_id=resolution_id, task_id=task_id)
        runtime.db.execute("INSERT INTO resolutions VALUES (?,?,?,?,?,?)", (resolution_id, request, canonical_json(result), task_id, canonical_json(actor.record()), at))
    return result


def resolution_show(runtime, resolution_id):
    row = runtime.db.execute("SELECT * FROM resolutions WHERE id=?", (resolution_id,)).fetchone()
    require(row is not None, "Unknown resolution ID")
    return {"request": row["request"], "result": json.loads(row["result_json"]), "actor": json.loads(row["actor_json"]), "at": row["at"]}
