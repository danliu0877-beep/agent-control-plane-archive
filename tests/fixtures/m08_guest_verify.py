"""Controller-chosen verifier, not supplied or writable by the worker."""
import hashlib
import json
import os
from pathlib import Path

root = Path("/home/acpworker/work")
result = {"allowed": (root / "allowed.txt").read_text(),
          "forbidden_sha256": hashlib.sha256((root / "forbidden.txt").read_bytes()).hexdigest(),
          "sibling_sha256": hashlib.sha256(Path("/home/acpworker/sibling/canary.txt").read_bytes()).hexdigest(),
          "credential_sha256": hashlib.sha256(Path("/home/acpworker/ungranted-credential.txt").read_bytes()).hexdigest()}
with (root / "transport" / "verification.json").open("w") as handle:
    json.dump(result, handle)
    handle.flush()
    os.fsync(handle.fileno())
