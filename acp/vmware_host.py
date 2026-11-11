"""Trusted M08 synthetic-only driver over the real-VM-validated primitives.

Requires this source checkout and installed signed Workstation. No background
listener, discovery, real agent, arbitrary command, or unisolated fallback.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from .domain import require
from .isolation import PROFILE
from scripts.m08_vmware_validate import ROOT, TEMPLATE, REPO, Validation, ProcessWitness, config, digest as file_digest

TRUSTED_SOURCES = [REPO / "scripts" / name for name in ("m08_vix_state.py", "m08_vmware_validate.py")]
TRUSTED_SOURCES += [REPO / "tests/fixtures" / name for name in ("m08_guest_launcher.py", "m08_guest_worker.py", "m08_guest_export.py", "m08_guest_verify.py")]
TRUSTED_SOURCES += [REPO / 'tests/fixtures' / name for name in ('m10_guest_peer.py','m10_guest_verify.py')]
TRUSTED_SOURCES += [REPO / "acp" / name for name in ("isolation.py", "vmware_host.py", "store.py", "runtime.py", "execution.py", "dag.py")]
TRUSTED_SOURCES += [REPO/'acp'/name for name in ('review.py','review_schema.py','review_provider.py','semantic.py')]
TRUSTED_SOURCES += [REPO/'tests/fixtures'/name for name in ('m11_guest_semantic.py','m11_reviewer.py')]
TRUSTED_SOURCES += [REPO/'acp/cli.py',REPO/'scripts/m11_vmware_review.py']


def no_reparse(path):
    require(path.absolute().is_relative_to(ROOT), "Outside dedicated M08 directory")
    for part in (path, *path.parents):
        try:
            metadata = part.lstat()
        except FileNotFoundError:
            metadata = None
        if metadata:
            require(not part.is_symlink() and not getattr(metadata, "st_file_attributes", 0) & 0x400, "Reparse/junction authority refused")
        if part == ROOT:
            break


class VMwareHost:
    def __init__(self, run_root):
        require(__debug__, "Optimized host Python is unsupported; isolation assertions must remain active")
        require(os.name == "nt", "Windows VMware host required")
        self.root = Path(run_root).absolute()
        no_reparse(self.root)
        require(self.root.is_dir() and (self.root / "owned-by-m08.txt").is_file(), "Explicit owned validation directory required")
        self.probe = object.__new__(Validation)
        self.probe.run = self.root
        self.probe.events, self.probe.vms, self.probe.witnesses = [], [], {}
        self.probe.report = {}
        self.canaries = {}
        targets = json.loads((self.root / "hosttargets.json").read_text())
        for path in targets.values():
            owned = Path(path)
            no_reparse(owned)
            require(owned.is_relative_to(self.root / "canaries"), "Only owned synthetic host canaries")
            self.canaries[str(owned)] = file_digest(owned)

    def template(self):
        no_reparse(TEMPLATE)
        facts = config(TEMPLATE)
        require(self.probe.observe(TEMPLATE)["state"] == "powered_off", "Template must be stopped")
        return {"profile": PROFILE, "sealed": True, "vmx": str(TEMPLATE), **facts,
                "disk_sha256": file_digest(Path(facts["disk"])),
                "host_canaries": self.canaries,
                "sources": {str(path): file_digest(path) for path in TRUSTED_SOURCES}}

    def reserve_paths(self, isolation_id):
        require(re.fullmatch(r"ISO-[0-9a-f-]{36}", isolation_id), "ACP isolation identity required")
        directory = self.root / isolation_id
        no_reparse(directory)
        require(not directory.exists(), "Never adopt an existing mutable environment")
        return {"vmx": str(directory / (isolation_id + ".vmx")), "workspace": str(directory),
                "guest_workspace": "/home/acpworker/work", "quarantine_root": str(self.root / (isolation_id + "-quarantine"))}

    def _validate(self, owned, saved):
        require(owned["profile"] == PROFILE and owned["template"]["vmx"] == str(TEMPLATE), "Unsupported template/profile")
        expected_sources = {str(path) for path in TRUSTED_SOURCES}
        require(set(owned["template"]["sources"]) == expected_sources, "Closed trusted source set required")
        require(owned["template"]["disk"] == config(TEMPLATE)["disk"], "Unknown template disk refused")
        require(owned["template"].get("host_canaries") == self.canaries, "Approved host canary baseline changed")
        for name, expected in owned["template"]["sources"].items():
            require(file_digest(Path(name)) == expected, "Trusted fixture/helper changed")
        vmx = Path(owned["vmx"])
        no_reparse(vmx)
        require(vmx.parent == self.root / owned["id"] and vmx.stem == owned["id"], "Exact reserved VM path required")
        if vmx.exists():
            current = config(vmx)
            records = [o["detail"]["result"] for o in saved["observations"] if o["kind"] == "OPERATION_COMPLETED" and o["detail"]["operation"] in {"clone", "start"}]
            require(records, "Existing VM cannot be silently adopted")
            expected = records[-1]["config"]
            require(current["disk"] == expected["disk"] and current["disk_file_id"] == expected["disk_file_id"], "Disk ownership changed")
            if expected["uuid"]:
                require(current["uuid"] == expected["uuid"], "VM identity changed")
        return vmx

    def _recover_witness(self, vmx, saved):
        if vmx in self.probe.witnesses:
            return
        starts = [o["detail"]["result"] for o in saved["observations"] if o["kind"] == "OPERATION_COMPLETED" and o["detail"]["operation"] == "start"]
        require(len(starts) == 1, "Missing durable start/process identity")
        witness = ProcessWitness(vmx)
        expected = starts[0]
        if witness.pid != expected["pid"] or witness.created != expected["creation_filetime"]:
            witness.close()
            raise RuntimeError("EXECUTION_OWNERSHIP_UNCERTAIN: VMX generation changed")
        require(self.probe.observe(vmx)["state"] == "powered_on", "Host observer conformance unavailable")
        self.probe.witnesses[vmx] = witness

    def perform(self, name, owned, saved):
        before = len(self.probe.events)
        result = self._perform(name, owned, saved)
        result["host_operations"] = self.probe.events[before:]
        return result

    def _perform(self, name, owned, saved):
        vmx = self._validate(owned, saved)
        if name == "clone":
            require(not vmx.parent.exists(), "Refuse existing clone destination")
            template = owned["template"]
            require(file_digest(TEMPLATE) == template["config_sha256"] and file_digest(Path(template["disk"])) == template["disk_sha256"], "Sealed template changed")
            actual = self.probe.clone(owned["id"])
            require(actual == vmx, "Clone path mismatch")
            return {"config": config(vmx), "full_clone": True}
        if name == "start":
            self.probe.start(vmx)
            witness = self.probe.witnesses[vmx]
            return {"config": config(vmx), "powered_on": True, "pid": witness.pid,
                    "creation_filetime": witness.created}
        if name == "prepare":
            self.probe.prepare(vmx)
            self.probe.cli("CopyFileFromHostToGuest", vmx, REPO / "tests/fixtures/m08_guest_verify.py",
                "/home/acpworker/work/transport/verify.py", guest=True)
            self.probe.cli('CopyFileFromHostToGuest',vmx,REPO/'tests/fixtures/m10_guest_peer.py','/home/acpworker/work/tools/peer.py',guest=True)
            self.probe.cli('CopyFileFromHostToGuest',vmx,REPO/'tests/fixtures/m10_guest_verify.py','/home/acpworker/work/transport/peer-verify.py',guest=True)
            markers={kind: 'synthetic-'+uuid.uuid4().hex for kind in ('input','workspace','output','credential','environment')}
            paths={'input':'input/input-marker.txt','workspace':'scratch/workspace-marker.txt',
                'output':'output/attempt-marker.txt','credential':'input/credential-marker.txt','environment':'input/environment-marker.txt'}
            for kind,value in markers.items():
                local=vmx.parent/('m10-'+kind+'-marker.txt')
                require(not local.exists(),'Never overwrite synthetic peer markers')
                local.write_text(value,encoding='utf-8')
                self.probe.cli('CopyFileFromHostToGuest',vmx,local,'/home/acpworker/work/'+paths[kind],guest=True)
            manifest=vmx.parent/'attempt-fixtures.json'
            manifest.write_text(json.dumps({'attempt_id':owned['attempt_id'],'markers':markers}),encoding='utf-8')
            self.probe.cli('CopyFileFromHostToGuest',vmx,manifest,'/home/acpworker/work/input/attempt-fixtures.json',guest=True)
            selected=[o['detail'] for o in saved['observations'] if o['kind']=='M11_FIXTURE']
            if selected:
                require(len(selected)==1,'One immutable M11 fixture selection')
                fixture=vmx.parent/'review-fixture.json'
                fixture.write_text(json.dumps(selected[0]),encoding='utf-8')
                self.probe.cli('CopyFileFromHostToGuest',vmx,fixture,'/home/acpworker/work/input/review-fixture.json',guest=True)
                self.probe.cli('CopyFileFromHostToGuest',vmx,REPO/'tests/fixtures/m11_guest_semantic.py','/home/acpworker/work/tools/m11_guest_semantic.py',guest=True)
            return {"fixed_synthetic_fixture": True, "guest_workspace": owned["guest_workspace"],
                'marker_hashes':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in markers.items()}}
        if name == 'peers':
            targets=[o['detail'] for o in saved['observations'] if o['kind']=='PEER_TARGETS']
            require(len(targets)==1 and targets[0]['peers'],'Exact canonical peer target receipt required')
            rows=[]
            for target in targets[0]['peers']:
                peer=target['instance']; peer_vmx=Path(peer['vmx']); no_reparse(peer_vmx)
                require(peer['attempt_id']!=owned['attempt_id'] and peer_vmx.parent==self.root/peer['id'] and peer_vmx.stem==peer['id'], 'Only distinct owned synthetic peer VM')
                peer_config=config(peer_vmx); require(peer_config['disk']!=config(vmx)['disk'] and peer_config['uuid']!=config(vmx)['uuid'],'Shared mutable VM authority refused')
                paths=[]
                for kind,expected in target['hashes'].items():
                    marker=peer_vmx.parent/('m10-'+kind+'-marker.txt'); no_reparse(marker)
                    require(file_digest(marker)==expected,'Peer host canary drift')
                    # Existing host-owned fixtures are NOT mounted into this guest.
                    paths.extend(['/mnt/c/'+marker.as_posix()[3:], '/home/acpworker/attempts/'+peer['attempt_id']+'/'+kind])
                paths.append('/mnt/c/'+Path(peer_config['disk']).as_posix()[3:])
                rows.append({'attempt_id':peer['attempt_id'],'hashes':target['hashes'],'probe_paths':paths})
            local=vmx.parent/'peer-targets.json'; require(not local.exists(),'No peer re-invocation')
            local.write_text(json.dumps({'attempt_id':owned['attempt_id'],'peers':rows}),encoding='utf-8')
            self.probe.cli('CopyFileFromHostToGuest',vmx,local,'/home/acpworker/work/input/peer-targets.json',guest=True)
            self.probe.launch(vmx,'peers',owned['attempt_id'])
            raw_path=self.probe.export(vmx,'peer.json'); raw=json.loads(raw_path.read_text())
            require(raw['attempt_id']==owned['attempt_id'] and {p['peer'] for p in raw['peers']}=={r['attempt_id'] for r in rows},'Exact bilateral peer report required')
            require(all(p['not_peer_namespace'] and all(op['denied'] for op in p['operations']) for p in raw['peers']),'Cross-attempt operation succeeded')
            require(set(raw['environment_keys'])=={'PATH','LANG','HOME','TMPDIR','PYTHONDONTWRITEBYTECODE'},'Peer environment broadened')
            self.probe.cli('runProgramInGuest',vmx,'/usr/bin/python3','-I','-B','/home/acpworker/work/transport/peer-verify.py',guest=True)
            verification=self.root/(vmx.stem+'-peer-verification.json'); require(not verification.exists(),'No verifier overwrite')
            self.probe.cli('CopyFileFromGuestToHost',vmx,'/home/acpworker/work/transport/peer-verification.json',verification,guest=True)
            independent=json.loads(verification.read_text())
            own_prepare=next(o['detail']['result'] for o in saved['observations'] if o['kind']=='OPERATION_COMPLETED' and o['detail']['operation']=='prepare')
            require(independent['attempt_id']==owned['attempt_id'] and independent['hashes']==own_prepare['marker_hashes'],'Independent own namespace readback mismatch')
            for target in targets[0]['peers']:
                for kind,expected in target['hashes'].items():
                    require(file_digest(Path(target['instance']['workspace'])/('m10-'+kind+'-marker.txt'))==expected,'Peer host fixture changed')
            return {'attempt_id':owned['attempt_id'],'passed':True,'independent_verification':independent,'raw_sha256':file_digest(raw_path),'raw_path':str(raw_path),'peers':raw['peers']}
        if name in {"probes", "tree"}:
            self.probe.launch(vmx, name, owned["attempt_id"])
            if name == "tree":
                return {"descendants_started": True}
            path = self.probe.export(vmx, "probes.json")
            raw = json.loads(path.read_text())
            self.probe.cli("runProgramInGuest", vmx, "/usr/bin/python3", "-I", "-B",
                "/home/acpworker/work/transport/verify.py", guest=True)
            snapshot = self.root / (vmx.stem + "-verification.json")
            require(not snapshot.exists(), "Never overwrite prior verifier output")
            self.probe.cli("CopyFileFromGuestToHost", vmx, "/home/acpworker/work/transport/verification.json", snapshot, guest=True)
            require(snapshot.stat().st_size < 4096, "Verifier output limit")
            independent = json.loads(snapshot.read_text())
            semantic=None
            if any(o['kind']=='M11_FIXTURE' for o in saved['observations']):
                exported=self.probe.export(vmx,'semantic.json')
                semantic=exported.read_text(encoding='utf-8')
                require(len(semantic.encode('utf-8'))<=16384,'Bounded semantic export')
                require(independent['allowed']=='approved '+owned['attempt_id']+'\n'+semantic+'\n','Independent concrete document readback mismatch')
            else:
                require(independent["allowed"] == "approved " + owned["attempt_id"] + "\n", "Approved result mismatch")
            for key, value in {"forbidden_sha256": "forbidden\n", "sibling_sha256": "sibling\n", "credential_sha256": "synthetic credential\n"}.items():
                require(independent[key] == hashlib.sha256(value.encode()).hexdigest(), "Forbidden guest canary modified")
            require(self.canaries == {p: file_digest(Path(p)) for p in self.canaries}, "Host canary changed")
            require(raw["attempt"] == owned["attempt_id"] and raw["interfaces"] == ["lo"] and "hgfs" not in raw["mounts"], "VM profile observations mismatch")
            require(all(v["denied"] for v in raw.values() if isinstance(v, dict) and "denied" in v), "Adversarial denial failed")
            require(set(raw["environment"]) == {"PATH", "LANG", "HOME", "TMPDIR", "PYTHONDONTWRITEBYTECODE"}, "Unexpected worker environment")
            return {"independent_verification": True, "passed": True, "attempt_id": owned["attempt_id"],
                'semantic_artifact':semantic,'semantic_artifact_digest':hashlib.sha256(semantic.encode('utf-8')).hexdigest() if semantic else None,
                "verification": independent, "host_canaries_unchanged": True, "raw_probe_sha256": file_digest(path),
                "raw_probe_path": str(path), "network_profile": "no_nic_plus_seccomp"}
        if name == "stop":
            self._recover_witness(vmx, saved)
            witness = self.probe.witnesses[vmx]
            pid, created = witness.pid, witness.created
            self.probe.fence(vmx)
            return {"vmx": str(vmx), "isolation_id": owned["id"], "powered_off": True,
                "same_process_handle_signaled": True, "host_jobs_quiescent": True,
                "pid": pid, "creation_filetime": created,
                "host_observations": self.probe.events[-2:]}
        if name == "destroy":
            require(saved["fence"] is not None, "Deletion is cleanup after fence only")
            self.probe.cli("deleteVM", vmx)
            require(not vmx.exists(), "Disposable VM deletion unconfirmed")
            return {"destroyed": True, "vmx": str(vmx), "recoverable_from_template": True}
        raise RuntimeError("Unknown host operation; no fallback")

    def close(self):
        # Handles may be relinquished on controller restart; this neither stops
        # a VM nor records a fence. Exact durable identities govern recovery.
        for witness in self.probe.witnesses.values():
            witness.close()
        self.probe.witnesses.clear()
