"""Trusted bounded copy-out preparation; outside worker Landlock grants.

Host chooses exact files. No guest-selected host destination or executable.
"""
import json
import os
from pathlib import Path
import stat
import sys

FILES = {"probes.json", "launcher.json", "approved-output.txt", "processes.json",
         "grandchild.json", "ticks.txt", "late.txt", "peer.json", "semantic.json"}
name = sys.argv[1]
if name not in FILES:
    raise SystemExit("Unknown output")
root = Path("/home/acpworker/work")
fd = os.open(root / "output" / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
        raise SystemExit("Non-regular/oversized export rejected")
    data = os.read(fd, 65537)
    if len(data) > 65536:
        raise SystemExit("Export byte limit exceeded")
finally:
    os.close(fd)
# This directory and script have no worker write grant. The source remains
# untrusted; host must independently parse and verify the snapshot bytes.
(root / "transport" / name).write_bytes(data)
