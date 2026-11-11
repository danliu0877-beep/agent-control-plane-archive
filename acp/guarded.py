"""Backend-independent synthetic admission and independent repository inspection.

These are detection/admission controls, NEVER an OS security boundary.
"""

import hashlib
import os
from pathlib import Path
import subprocess

from .domain import ACPError, digest, path_key, relative_scope, require


def git(path, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(["git", "-c", "core.hooksPath=NUL", "-C", str(path), *args],
                            capture_output=True, timeout=20, env=env)
    require(result.returncode == 0, "Repository inspection failed: " + result.stderr.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "strict").rstrip("\r\n")


def scope_path(value):
    relative_scope(value)
    parts = value.replace("\\", "/").split("/")
    reserved = {"con", "prn", "aux", "nul", *("com" + str(i) for i in range(1, 10)), *("lpt" + str(i) for i in range(1, 10))}
    require(all(p and p.casefold() not in {".", "..", ".git"} and p == p.rstrip(" .")
                and p.split(".")[0].casefold() not in reserved for p in parts), "Noncanonical scope path")
    require(not any(c in value for c in "*?[]"), "M03 supports literal paths/subtrees only, not globs")
    return "/".join(parts).casefold()


def covered(path, scopes):
    return any(path == s or path.startswith(s + "/") for s in scopes)


def check_paths(root, names, allowed, forbidden):
    allowed, forbidden = [scope_path(p) for p in allowed], [scope_path(p) for p in forbidden]
    violations = []
    for name in names:
        try:
            key = scope_path(name)
            require((root / name).resolve().is_relative_to(root.resolve()), "Path escapes workspace")
            require(covered(key, allowed) and not covered(key, forbidden), "Path outside approved scope")
        except (ACPError, OSError, RuntimeError) as exc:
            violations.append({"path": name, "reason": str(exc)})
    return violations


def admit(contract, project, config):
    """Config is explicit operator attestation of disposable roots, not discovery."""
    root = Path(config["synthetic_root"]).resolve(strict=True)
    repo = Path(project["path"]).resolve(strict=True)
    require(config.get("disposable_only") is True, "Disposable-only profile required")
    require(repo != root and repo.is_relative_to(root), "Repository outside disposable root")
    require(str(repo) in config["repositories"], "Repository absent from explicit synthetic allowlist")
    require(not (root / ".git").exists(), "Synthetic root cannot be a Git checkout")
    require((repo / ".acp-synthetic").read_text(encoding="utf-8").strip() == "DISPOSABLE ACP M03", "Missing synthetic marker")
    require(project["enabled"] and project["id"] == contract["primary_project"], "Unknown/disabled primary project")
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
    require(digest({"kind": "git", "path": path_key(common)}) == contract["repository_identity"] == project["repository_identity"], "Repository identity mismatch")
    require(git(repo, "rev-parse", "HEAD") == contract["base_commit"], "Base commit mismatch")
    require(not git(repo, "status", "--porcelain", "--untracked-files=all"), "Synthetic input repository must be clean")
    require(contract["runtime_profile"] == config["profile_name"], "UNSUPPORTED_CAPABILITY: runtime profile")
    require(contract["risk_class"] == "low", "UNSUPPORTED_CAPABILITY: only low-risk disposable work")
    require(contract["network_capability"] == "none" and contract["credential_capability"] == "none", "UNSUPPORTED_CAPABILITY: privileged operations")
    require(set(contract["allowed_operations"]) <= {"read", "write", "test", "inspect_metadata"}, "Forbidden operation requested")
    require(not contract["write_scope"] or "write" in contract["allowed_operations"], "Write scope requires authorized write operation")
    require(contract["change_kind"] != "read_only" or not contract["write_scope"], "Read-only contract cannot authorize writes")
    require(not set(contract["allowed_operations"]) & set(contract["prohibited_operations"]), "Contradictory operations")
    require(not contract.get("required_capabilities"), "UNSUPPORTED_CAPABILITY: isolation/fencing not provided")
    require(contract.get("limitations_acknowledged") == config["limitations"], "Capability limitations must be explicitly approved")
    for value in contract["write_scope"] + contract["forbidden_scope"]:
        scope_path(value)
        require((repo / value).resolve().is_relative_to(repo), "Scope escapes synthetic repository")
    require(not check_paths(repo, contract["write_scope"], contract["write_scope"], contract["forbidden_scope"]), "Forbidden write scope")
    require(contract.get("verification") == config["verification"], "Verification configuration not authorized")
    require(any(c["evidence_class"] == "independent_result" and c["trust"] == "independently_verified" for c in contract["acceptance_criteria"]), "Independent verification criterion required")
    return str(repo)


def repository_facts(workspace, repo, contract):
    workspace, repo = Path(workspace).resolve(strict=True), Path(repo).resolve(strict=True)
    require(git(workspace, "rev-parse", "--path-format=absolute", "--git-common-dir") == git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"), "Output repository mismatch")
    base = contract["base_commit"]
    head = git(workspace, "rev-parse", "HEAD")
    actual_base = git(workspace, "merge-base", base, head)
    changed = set(filter(None, git(workspace, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, "--").split("\0")))
    changed.update(filter(None, git(workspace, "ls-files", "--others", "--exclude-standard", "-z").split("\0")))
    # Include ignored files too: .gitignore must not hide a forbidden write.
    changed.update(filter(None, git(workspace, "ls-files", "--others", "--ignored", "--exclude-standard", "-z").split("\0")))
    violations = check_paths(workspace, sorted(changed), contract["write_scope"], contract["forbidden_scope"])
    return {"workspace": str(workspace), "expected_base": base, "actual_base": actual_base, "head": head,
            "changed_files": sorted(changed), "violations": violations,
            "status": git(workspace, "status", "--porcelain=v1", "--untracked-files=all"),
            "diff_stat": git(workspace, "diff", "--no-ext-diff", "--no-textconv", "--stat", base, "--"),
            "diff_digest": digest(git(workspace, "diff", "--no-ext-diff", "--no-textconv", "--binary", base, "--")),
            "files": {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in changed if (workspace / p).is_file() and (workspace / p).resolve().is_relative_to(workspace)},
            "pass": actual_base == base and not violations}
