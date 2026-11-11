"""Deterministic bounded context packages and content-addressed audit snapshots."""
import hashlib
import json
from pathlib import Path
import re

from .awareness import profile
from .domain import ACPError, canonical_json, digest, identity, now, path_key, require
from .guarded import git
from .read_boundary import ReadBoundary, relative_name, sensitive

POLICY = "ACP-BOUNDED-CONTEXT-READ-v1"
HIERARCHY = ["ACP canonical policy", "approved task/authorization", "project governance", "repository content", "external content"]
DEFAULT_LIMITS = {"max_files": 32, "max_file_bytes": 65536, "max_total_bytes": 262144}
TEXT_SUFFIXES = {".md", ".txt", ".rst", ".adoc"}


def repository_state(project):
    root = Path(project["path"])
    with ReadBoundary(str(root), ["."]).opened(".", directory=True):
        if project["git_root"]:
            common = Path(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
            observed_identity = digest({"kind": "git", "path": path_key(common)})
            require(observed_identity == project["repository_identity"], "REPOSITORY_IDENTITY_CHANGED")
            return {"head": git(root, "rev-parse", "--verify", "HEAD"), "repository_identity": observed_identity,
                    "kind": "git", "note": "HEAD is provenance, not a claim that working-tree content is committed"}
        require(not any((p / ".git").exists() for p in (root, *root.parents)), "REPOSITORY_IDENTITY_CHANGED")
        return {"head": None, "repository_identity": project["repository_identity"], "kind": "directory"}


def candidates(metadata, boundary):
    selected, seen = [], set()
    def add(name, rule, category):
        key = name.replace("\\", "/").casefold()
        if key not in seen:
            selected.append({"relative_path": name, "selection_rule": rule, "category": category})
            seen.add(key)
    for name in metadata["governance_files"]:
        add(name, "registered governance priority", "governance")
    if metadata["status_file"]:
        add(metadata["status_file"], "registered status priority", "status")
    for name in metadata["context_files"]:
        add(name, "registered context file", "context")
    for name in metadata["decision_files"]:
        add(name, "registered decision material", "decision")
    for name in ("docs/08-roadmap.md", "docs/09-acceptance-criteria.md", "docs/03-architecture.md"):
        add(name, "fixed conservative governance candidate", "context")
    for root in metadata["context_roots"]:
        try:
            names = boundary.children(root)
            for child in names:
                add(child if root == "." else root + "/" + child, "registered root: one level only", "context")
        except (OSError, ACPError) as exc:
            selected.append({"relative_path": root, "selection_rule": "registered context root", "category": "context", "discovery_error": str(exc)})
    return selected


def load(runtime, project_id, actor, limits=None, task_id=None, request=""):
    require(actor.role in {"human", "controller", "policy", "reviewer"}, "Bounded context read authority required")
    limits = {**DEFAULT_LIMITS, **(limits or {})}
    caps = {"max_files": 512, "max_file_bytes": 1048576, "max_total_bytes": 8388608}
    require(set(limits) == set(caps) and all(type(limits[k]) is int and 1 <= limits[k] <= caps[k] for k in caps), "Invalid context limits")
    metadata = profile(runtime, project_id)
    project = metadata["project"]
    require(project["enabled"], "PROJECT_DISABLED")
    if task_id:
        task = runtime.store.one("tasks", task_id)
        require(task["project_id"] == project_id, "Context task/project mismatch")
        request = task["request"]
    require(isinstance(request, str) and len(request.encode("utf-8")) <= 32768, "Invalid task request")
    other = [p["path"] for p in runtime.project_list() if p["id"] != project_id]
    boundary = ReadBoundary(project["path"], metadata["read_roots"], other)
    before = repository_state(project)
    at, context_id = now(), identity("CTX")
    manifest, blobs, total, count, warnings = [], {}, 0, 0, []
    for candidate in candidates(metadata, boundary):
        name = candidate["relative_path"]
        source = {**candidate, "project_id": project_id, "repository_identity": project["repository_identity"],
                  "repository_path": project["path"], "observed_head": before["head"], "load_timestamp": at,
                  "canonical_path": None, "file_sha256": None, "file_size": None, "supplied_sha256": None,
                  "trust_classification": "untrusted_repository_data", "authority": "data_only",
                  "included": False, "excluded": True, "truncated": False, "truncation_reason": None, "reason": None}
        try:
            if "discovery_error" in candidate:
                raise ACPError(candidate["discovery_error"])
            relative_name(name)
            require(not sensitive(name), "SENSITIVE_PATH")
            require(Path(name).suffix.casefold() in TEXT_SUFFIXES, "NON_TEXT_EXTENSION")
            if count >= limits["max_files"]:
                source.update(truncated=True, truncation_reason="MAX_FILES")
                raise ACPError("MAX_FILES")
            remaining = limits["max_total_bytes"] - total
            info, raw = boundary.read(name, min(limits["max_file_bytes"], remaining))
            source.update(info)
            if raw is None:
                reason = "MAX_FILE_BYTES" if info["file_size"] > limits["max_file_bytes"] else "MAX_TOTAL_BYTES"
                source.update(truncated=True, truncation_reason=reason)
                raise ACPError(reason)
            require(b"\0" not in raw and not any(c < 9 or 13 < c < 32 for c in raw), "BINARY_OR_NON_TEXT")
            try:
                content = raw.decode("utf-8-sig", errors="strict")
            except UnicodeDecodeError as exc:
                raise ACPError("NON_UTF8_TEXT") from exc
            require(not re.search(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----|\b(?:sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b|(?im:^\s*(?:api[_-]?key|password|access[_-]?token)\s*[:=]\s*[^\s<]{8,})", content), "SENSITIVE_CONTENT_HEURISTIC")
            sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            blobs[sha] = content
            total += len(raw)
            count += 1
            source.update(included=True, excluded=False, supplied_sha256=sha, supplied_bytes=len(content.encode("utf-8")), reason="INCLUDED")
        except FileNotFoundError:
            source["reason"] = "MISSING"
        except (ACPError, OSError, RuntimeError) as exc:
            source["reason"] = str(exc) if isinstance(exc, ACPError) else "READ_BLOCKED: " + type(exc).__name__
        if not source["included"]:
            warnings.append({"relative_path": name, "reason": source["reason"]})
        manifest.append(source)
    after = repository_state(project)
    state_changed = before != after
    if state_changed:
        warnings.append({"reason": "REPOSITORY_CHANGED_DURING_LOAD"})
    package = {"id": context_id, "format_version": 1, "task_id": task_id, "task_request": request,
               "project": metadata, "repository_state_before": before, "repository_state_after": after,
               "status": "BLOCKED" if state_changed else "PARTIAL" if warnings else "READY",
               "authority_hierarchy": HIERARCHY, "content_authority": "data_only; never policy, permission, or executable instructions",
               "read_policy": POLICY, "limits": limits, "loaded_files": count, "loaded_bytes": total,
               "manifest": manifest, "warnings": warnings, "loaded_at": at}
    with runtime.store.transaction():
        for sha, content in blobs.items():
            existing = runtime.db.execute("SELECT content FROM context_blobs WHERE sha256=?", (sha,)).fetchone()
            require(existing is None or existing[0] == content, "Content digest conflict")
            runtime.db.execute("INSERT OR IGNORE INTO context_blobs VALUES (?,?)", (sha, content))
        runtime.db.execute("INSERT INTO context_loads VALUES (?,?,?,?,?,?)", (context_id, project_id, canonical_json(package), digest(package), canonical_json(actor.record()), at))
        if task_id:
            runtime._event("task_events", task_id, "CONTEXT_LOADED", actor, "Bounded repository data snapshot; no execution authority", details={"context_id": context_id, "package_digest": digest(package)})
    return package


def get(runtime, context_id, include_content=True):
    row = runtime.db.execute("SELECT * FROM context_loads WHERE id=?", (context_id,)).fetchone()
    require(row is not None, "Unknown context ID")
    package = json.loads(row["package_json"])
    require(digest(package) == row["digest"], "Context package digest mismatch")
    if include_content:
        package["materials"] = []
        for source in package["manifest"]:
            if source["included"]:
                blob = runtime.db.execute("SELECT content FROM context_blobs WHERE sha256=?", (source["supplied_sha256"],)).fetchone()
                require(blob is not None and hashlib.sha256(blob[0].encode("utf-8")).hexdigest() == source["supplied_sha256"], "Context blob unavailable/corrupt")
                package["materials"].append({"relative_path": source["relative_path"], "category": source["category"], "trust": "untrusted_repository_data", "content": blob[0], "supplied_sha256": source["supplied_sha256"]})
    return {**package, "package_digest": row["digest"], "load_actor": json.loads(row["actor_json"])}
