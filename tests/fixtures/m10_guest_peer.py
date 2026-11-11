"""Fixed cross-attempt probe under the unchanged M08 Landlock/seccomp launcher."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path('/home/acpworker/work')
PATHS={'input':'input/input-marker.txt','workspace':'scratch/workspace-marker.txt',
       'output':'output/attempt-marker.txt','credential':'input/credential-marker.txt',
       'environment':'input/environment-marker.txt'}


def run(attempt):
    own = json.loads((ROOT/'input/attempt-fixtures.json').read_text())
    targets = json.loads((ROOT/'input/peer-targets.json').read_text())
    assert own['attempt_id'] == attempt and targets['attempt_id'] == attempt
    rows = []
    for target in targets['peers']:
        assert target['attempt_id'] != attempt
        # The identical guest pathname must resolve to THIS VM's data, never
        # the other VM's same pathname. Independent host readback corroborates.
        own_hashes = {k:hashlib.sha256(v.encode()).hexdigest() for k,v in own['markers'].items()}
        assert all((ROOT/PATHS[k]).read_text()==v for k,v in own['markers'].items())
        assert all(own_hashes[k] != target['hashes'][k] for k in own_hashes)
        assert not any(v in json.dumps(dict(os.environ)) for v in own['markers'].values())
        denied=[]
        for path in target['probe_paths']:
            for op in ('read','write'):
                try:
                    if op == 'read':
                        value=Path(path).read_bytes()
                    else:
                        value=Path(path).write_text('CROSS-ATTEMPT-WRITE '+attempt)
                    denied.append({'path':path,'operation':op,'denied':False,'size':len(str(value))})
                except OSError as exc:
                    denied.append({'path':path,'operation':op,'denied':True,'errno':exc.errno})
        assert all(x['denied'] for x in denied)
        rows.append({'peer':target['attempt_id'],'own_hashes':own_hashes,'not_peer_namespace':True,'operations':denied})
    (ROOT/'output/peer.json').write_text(json.dumps({'attempt_id':attempt,'peers':rows,'environment_keys':sorted(os.environ)}))
