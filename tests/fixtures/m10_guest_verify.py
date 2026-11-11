"""Trusted independent readback, staged outside worker writable directories."""
import hashlib
import json
import os
from pathlib import Path
import time

root=Path('/home/acpworker/work')
data=json.loads((root/'input/attempt-fixtures.json').read_text())
paths={'input':'input/input-marker.txt','workspace':'scratch/workspace-marker.txt',
       'output':'output/attempt-marker.txt','credential':'input/credential-marker.txt',
       'environment':'input/environment-marker.txt'}
actual={k:(root/p).read_text() for k,p in paths.items()}
assert actual == data['markers']
report={'attempt_id':data['attempt_id'],'hashes':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in actual.items()}}
tree=json.loads((root/'output/processes.json').read_text())
grandchild=json.loads((root/'output/grandchild.json').read_text())
pids=[tree['parent'],tree['child'],grandchild['grandchild']]
for pid in pids:
    os.kill(pid,0)
    assert data['attempt_id'].encode() in Path('/proc/'+str(pid)+'/cmdline').read_bytes()
report['active_tree_pids']=pids
report['observed_at_unix']=time.time()
(root/'transport/peer-verification.json').write_text(json.dumps(report))
