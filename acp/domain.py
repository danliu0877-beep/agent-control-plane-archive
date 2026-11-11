"""Canonical values and validation; no backend-native lifecycle names."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import uuid


class ACPError(ValueError):
    """An explicit, fail-closed domain or input error."""


class TaskState(StrEnum):
    NEW = "NEW"
    TRIAGE = "TRIAGE"
    PLANNED = "PLANNED"
    READY = "READY"
    RUNNING = "RUNNING"
    REVIEW = "REVIEW"
    REWORK = "REWORK"
    NEEDS_HUMAN = "NEEDS_HUMAN"
    BLOCKED = "BLOCKED"
    DONE = "DONE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AttemptState(StrEnum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    LOST = "LOST"


TASK_EDGES = {
    "NEW": {"TRIAGE", "NEEDS_HUMAN"},
    "TRIAGE": {"PLANNED", "NEEDS_HUMAN", "BLOCKED"},
    "PLANNED": {"READY", "NEEDS_HUMAN", "BLOCKED"},
    "READY": {"RUNNING", "NEEDS_HUMAN", "BLOCKED", "CANCELLED"},
    "RUNNING": {"REVIEW", "BLOCKED", "FAILED", "NEEDS_HUMAN", "CANCELLED"},
    "REVIEW": {"DONE", "REWORK", "NEEDS_HUMAN", "BLOCKED", "FAILED"},
    "REWORK": {"PLANNED", "READY", "NEEDS_HUMAN", "BLOCKED"},
    "BLOCKED": set(), "NEEDS_HUMAN": set(),
    "DONE": set(), "FAILED": set(), "CANCELLED": set(),
}
ATTEMPT_EDGES = {
    "CREATED": {"QUEUED", "STARTING", "RUNNING", "SUCCEEDED", "FAILED", "LOST", "CANCEL_REQUESTED"},
    "QUEUED": {"STARTING", "RUNNING", "SUCCEEDED", "FAILED", "LOST", "CANCEL_REQUESTED"},
    "STARTING": {"RUNNING", "SUCCEEDED", "FAILED", "LOST", "CANCEL_REQUESTED"},
    "RUNNING": {"SUCCEEDED", "FAILED", "LOST", "CANCEL_REQUESTED"},
    "LOST": {"QUEUED", "STARTING", "RUNNING", "SUCCEEDED", "FAILED", "CANCEL_REQUESTED", "CANCELLED"},
    "CANCEL_REQUESTED": {"LOST", "CANCELLED"},
    "SUCCEEDED": set(), "FAILED": set(), "CANCELLED": set(),
}
TERMINAL_ATTEMPTS = {"SUCCEEDED", "FAILED", "CANCELLED"}
UNCERTAIN = {"LOST", "CANCEL_REQUESTED"}
VERIFIERS = {"controller", "reviewer", "human", "ci"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ACPError("Expected an ISO-8601 timestamp with timezone") from exc


def canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise ACPError("Value must be finite JSON") from exc


def digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def identity(prefix):
    return f"{prefix}-{uuid.uuid4()}"


def require(condition, message):
    if not condition:
        raise ACPError(message)


def text(value, name):
    require(isinstance(value, str) and bool(value.strip()), f"{name} must be nonempty text")
    return value


@dataclass(frozen=True)
class Actor:
    name: str
    role: str = "human"
    source: str = "local-cli"

    def __post_init__(self):
        text(self.name, "actor")
        text(self.source, "source")
        require(self.role in {"human", "planner", "policy", "controller", "reviewer", "worker", "ci"}, "Invalid actor role")

    def record(self):
        return {"name": self.name, "role": self.role, "source": self.source}


def windows_path_key(value):
    """Lexical Windows comparison only; filesystem resolution is separate."""
    value = text(value, "path")
    require(ntpath.isabs(value) and bool(ntpath.splitdrive(value)[0]), "Windows path must be fully qualified")
    return ntpath.normcase(ntpath.normpath(value))


def path_key(path):
    return windows_path_key(str(path)) if os.name == "nt" else str(path)


def canonical_path(value):
    try:
        result = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ACPError(f"Cannot resolve project directory: {value}") from exc
    require(result.is_dir(), "Project path must be a directory")
    return result


def relative_scope(value):
    """Reject obvious host/parent paths; not a sandbox or glob evaluator."""
    parts = value.replace("\\", "/").split("/")
    require(not ntpath.isabs(value) and not ntpath.splitdrive(value)[0]
            and ".." not in parts and ":" not in value and "\x00" not in value,
            "Scope/context paths must stay lexically relative to the primary project")


def validate_envelope(envelope, task, project):
    require(isinstance(envelope, dict), "Envelope must be a JSON object")
    required = {"task_revision", "plan_revision", "primary_project", "repository_identity", "base_commit", "context_manifest", "write_scope", "forbidden_scope", "allowed_operations", "prohibited_operations", "runtime_profile", "network_capability", "credential_capability", "risk_class", "change_kind", "acceptance_criteria"}
    require(required <= envelope.keys(), f"Missing envelope fields: {sorted(required - envelope.keys())}")
    require(type(envelope["task_revision"]) is int and envelope["task_revision"] == task["revision"], "Task revision mismatch")
    require(type(envelope["plan_revision"]) is int and envelope["plan_revision"] > 0, "Invalid plan revision")
    require(envelope["primary_project"] == task["project_id"], "Primary project mismatch")
    require(envelope["repository_identity"] == project["repository_identity"], "Repository identity mismatch")
    if project["git_root"]:
        require(isinstance(envelope["base_commit"], str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", envelope["base_commit"]), "Git base must be an exact full SHA")
    else:
        require(envelope["base_commit"] is None, "Non-Git project base must be null")
    require(isinstance(envelope["context_manifest"], dict), "context_manifest must be an object")
    manifest = envelope["context_manifest"]
    require(set(manifest) <= {"source", "files"}, "M02 context manifest supports source and relative files only")
    require(isinstance(manifest.get("files", []), list), "Context files must be a list")
    for value in manifest.get("files", []):
        relative_scope(text(value, "context file"))
    for key in ("write_scope", "forbidden_scope", "allowed_operations", "prohibited_operations"):
        require(isinstance(envelope[key], list) and all(isinstance(v, str) and v.strip() for v in envelope[key]), f"{key} must be a text list")
    for value in envelope["write_scope"] + envelope["forbidden_scope"]:
        relative_scope(value)
    require(not set(envelope["write_scope"]) & set(envelope["forbidden_scope"]), "Identical allowed and forbidden paths are contradictory")
    for key in ("runtime_profile", "network_capability", "credential_capability"):
        text(envelope[key], key)
    require(envelope["risk_class"] in {"low", "medium", "high"}, "Invalid risk class")
    require(envelope["change_kind"] in {"read_only", "documentation", "executable"}, "Invalid change kind")
    require(not set(envelope["allowed_operations"]) & set(envelope["prohibited_operations"]), "Contradictory operations")
    criteria = envelope["acceptance_criteria"]
    require(isinstance(criteria, list) and bool(criteria), "At least one acceptance criterion required")
    seen = set()
    for criterion in criteria:
        require(isinstance(criterion, dict), "Criterion must be an object")
        key = text(criterion.get("id"), "criterion id")
        require(key not in seen, "Duplicate criterion id")
        seen.add(key)
        text(criterion.get("description"), "criterion description")
        require(criterion.get("evidence_class") in {"claim", "artifact", "repository_fact", "independent_result"}, "Invalid criterion evidence class")
        require(criterion.get("trust") in {"unverified", "observed", "independently_verified"}, "Invalid criterion trust")
    canonical_json(envelope)


def bounded_read_policy(envelope):
    return (envelope["change_kind"] == "read_only" and not envelope["write_scope"]
            and envelope["risk_class"] == "low" and envelope["network_capability"] == "none"
            and envelope["credential_capability"] == "none"
            and bool(envelope["allowed_operations"])
            and set(envelope["allowed_operations"]) <= {"read", "inspect_metadata"})
