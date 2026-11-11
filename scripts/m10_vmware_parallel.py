"""Manual synthetic M10 wave on real independent M08 full clones. No service."""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

REPO=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(REPO))
from acp import context, dag, isolation, planning
from acp.decision_provider import SyntheticDecisionProvider
from acp.domain import ACPError
from acp.runtime import Runtime
from acp.vmware_host import VMwareHost, ROOT
from tests.test_dag import proposal_for
from tests.test_isolation import HUMAN, CONTROL


def start_claim(root, dispatch):
    with Runtime(root/'canonical-state') as r:
        host=VMwareHost(root)
        try:
            attempt=dag.allocate(r,dispatch,CONTROL)['id']
            isolation.reserve(r,attempt,host,CONTROL)
            for name in ('clone','start','prepare','tree'):
                isolation.operation(r,attempt,name,host,CONTROL)
            return {'dispatch_id':dispatch,'attempt_id':attempt,'facts':isolation.facts(r,attempt)}
        finally:
            host.close()  # Relinquishing a handle is not a stop/fence.


def finish(r,eid,step,host):
    attempt=step['attempt_id']
    for name in ('probes','stop'):
        isolation.operation(r,attempt,name,host,CONTROL)
    evidence=isolation.complete(r,attempt,CONTROL)
    step.update(evidence_id=evidence,stopped_facts=isolation.facts(r,attempt),review=dag.refresh(r,eid,CONTROL))
    return evidence


def main():
    if not __debug__ or not os.environ.get('ACP_M08_GUEST_PASSWORD'):
        raise RuntimeError('Normal Python and disposable guest-only test credential required')
    root=ROOT/('m10-parallel-'+uuid.uuid4().hex); root.mkdir()
    (root/'owned-by-m08.txt').write_text('M10 synthetic parallel evidence only\n')
    canaries={}
    for category in ('sibling','profile','credentials'):
        directory=root/'canaries'/category; directory.mkdir(parents=True)
        target=directory/'canary.txt'; target.write_text('synthetic '+category,newline='\n'); canaries[category]=str(target)
    (root/'hosttargets.json').write_text(json.dumps(canaries))
    project=root/'synthetic-project'; project.mkdir()
    (project/'STATUS.md').write_text(isolation.SYNTHETIC_STATUS,newline='\n')
    r,host=Runtime(root/'canonical-state'),VMwareHost(root)
    report={'root':str(root),'sqlite':str(r.store.path),'result':'NOT PASSED','real_project':False,'production_credentials':False,'real_agent':False}
    try:
        r.project_add('demo',project)
        task=r.task_create('demo','Parallel','Synthetic A -> B,C,D -> E',HUMAN)['id']
        ctx=context.load(r,'demo',HUMAN)['id']
        run=planning.prepare(r,task,ctx,HUMAN,test_only=True)
        result=planning.complete(r,run['run_id'],SyntheticDecisionProvider(json.dumps(proposal_for([[],[0],[0],[0],[1,2,3]])),testing=True),HUMAN)
        plan=planning.show(r,result['plan_id']); works=[w['work_item_id'] for w in plan['work_items']]
        eid=dag.create(r,plan['plan_id'],1,HUMAN,max_parallel=2)['id']; dag.materialize(r,eid,CONTROL)
        report.update(execution_id=eid,works=works,initial=dag.show(r,eid))
        template=host.template()
        for work in works:
            b=dag.bind(r,eid,work,template,HUMAN)
            r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00'); r.transition(b['task_id'],'READY',HUMAN,'Exact synthetic approval')
        first=dag.execute_next(r,eid,host,CONTROL)
        dag.accept(r,eid,first['dispatch']['work_id'],{'synthetic-write':first['evidence_id']},HUMAN)
        report['first']=first
        wave=dag.claim_wave(r,eid,CONTROL)
        assert [d['work_id'] for d in wave] == works[1:3]
        code="import sys,json; from pathlib import Path; from scripts.m10_vmware_parallel import start_claim; print(json.dumps(start_claim(Path(sys.argv[1]),sys.argv[2])))"
        children=[subprocess.Popen([sys.executable,'-B','-c',code,str(root),d['id']],cwd=REPO,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for d in wave]
        outputs=[p.communicate(timeout=240) for p in children]
        assert all(p.returncode==0 for p in children),[o[1].decode(errors='replace') for o in outputs]
        running=[json.loads(o[0]) for o in outputs]
        state=dag.recover(r,eid,CONTROL)
        assert len(state['slots'])==2 and state['available_capacity']==0 and state['ready']==[works[3]]
        identities=[next(o['detail']['result']['config'] for o in s['facts']['observations'] if o['kind']=='OPERATION_COMPLETED' and o['detail']['operation']=='start') for s in running]
        assert identities[0]['uuid']!=identities[1]['uuid'] and identities[0]['disk_file_id']!=identities[1]['disk_file_id'] and identities[0]['disk']!=identities[1]['disk']
        observations=[host.probe.observe(Path(s['facts']['instance']['vmx'])) for s in running]
        assert all(o['state']=='powered_on' for o in observations)
        report.update(concurrent_vms=2,concurrent_state=state,identities=identities,positive_on=observations)
        # Canonical immutable target metadata precedes each fixed peer operation.
        for current,peer in ((running[0],running[1]),(running[1],running[0])):
            prep=next(o['detail']['result'] for o in peer['facts']['observations'] if o['kind']=='OPERATION_COMPLETED' and o['detail']['operation']=='prepare')
            isolation.observe(r,current['attempt_id'],'PEER_TARGETS',{'peers':[{'instance':peer['facts']['instance'],'hashes':prep['marker_hashes']}]},CONTROL)
        report['cross_attempt']=[isolation.operation(r,s['attempt_id'],'peers',host,CONTROL) for s in running]
        assert all(p['passed'] and len(p['independent_verification']['active_tree_pids'])==3 for p in report['cross_attempt'])
        # C completes first while B remains positively owned/running.
        evidence=finish(r,eid,running[1],host)
        assert dag.show(r,eid)['available_capacity']==0
        assert next(n['state'] for n in dag.show(r,eid)['nodes'] if n['work_id']==works[4])=='WAITING_DEPENDENCY'
        dag.accept(r,eid,works[2],{'synthetic-write':evidence},HUMAN)
        report['after_c_acceptance']=dag.recover(r,eid,CONTROL)
        assert report['after_c_acceptance']['available_capacity']==1
        middle=dag.execute_next(r,eid,host,CONTROL)
        assert middle['dispatch']['work_id']==works[3]
        dag.accept(r,eid,works[3],{'synthetic-write':middle['evidence_id']},HUMAN)
        assert dag.show(r,eid)['ready']==[]
        evidence=finish(r,eid,running[0],host)
        dag.accept(r,eid,works[1],{'synthetic-write':evidence},HUMAN)
        assert dag.recover(r,eid,CONTROL)['ready']==[works[4]]
        last=dag.execute_next(r,eid,host,CONTROL)
        dag.accept(r,eid,works[4],{'synthetic-write':last['evidence_id']},HUMAN)
        r.close(); r=Runtime(root/'canonical-state')
        final=dag.recover(r,eid,CONTROL)
        assert final['state']=='COMPLETE' and final['available_capacity']==2 and not final['slots'] and not final['plan_accepted']
        report.update(result='PASS',parallel_steps=running,middle=middle,last=last,final=final,
            integrity=r.db.execute('PRAGMA integrity_check').fetchone()[0],foreign_keys=[tuple(x) for x in r.db.execute('PRAGMA foreign_key_check')],completion_order='C,D,B,E')
    except BaseException as exc:
        report['error']=str(exc)
        # Stop only exact owned test VMs diagnostically. Never fabricate a fence
        # or make UNKNOWN eligible by cleanup success.
        for row in r.db.execute('SELECT vmx_path FROM isolation_instances').fetchall():
            vmx=Path(row['vmx_path'])
            if vmx.is_relative_to(root) and vmx.exists():
                try: host.probe.cli('stop',vmx,'hard',allow_failure=True)
                except Exception: pass
        raise
    finally:
        host.close(); r.close()
        path=root/'parallel-report.json'; path.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'report':str(path),'result':report['result'],'error':report.get('error')}))


if __name__=='__main__':
    main()
