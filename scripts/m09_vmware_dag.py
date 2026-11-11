"""Explicit real M09->M08 synthetic DAG composition, never project execution.

Only the already provisioned disposable M08 guest credential is used. No new
backend, network, service, arbitrary commands, credentials or VM substrate.
"""
import json
import os
from pathlib import Path
import sys
import uuid

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from acp import context, dag, isolation, planning
from acp.decision_provider import SyntheticDecisionProvider
from acp.domain import ACPError
from acp.runtime import Runtime
from acp.vmware_host import VMwareHost, ROOT
from tests.test_dag import proposal_for
from tests.test_isolation import HUMAN, CONTROL


def main():
    if not __debug__ or not os.environ.get('ACP_M08_GUEST_PASSWORD'):
        raise RuntimeError('Normal Python and explicit disposable guest credential required')
    root = ROOT / ('m09-dag-' + uuid.uuid4().hex)
    root.mkdir()
    (root / 'owned-by-m08.txt').write_text('M09 synthetic VMware composition only\n')
    canaries = {}
    for category in ('sibling','profile','credentials'):
        directory = root / 'canaries' / category; directory.mkdir(parents=True)
        target = directory / 'canary.txt'; target.write_text('synthetic ' + category, newline='\n')
        canaries[category] = str(target)
    (root / 'hosttargets.json').write_text(json.dumps(canaries))
    repo = root / 'synthetic-project'; repo.mkdir()
    (repo / 'STATUS.md').write_text(isolation.SYNTHETIC_STATUS, newline='\n')
    r, host = Runtime(root/'canonical-state'), VMwareHost(root)
    report = {'root':str(root),'sqlite':str(r.store.path),'real_project':False,'real_agent':False,'production_credentials':False,'parallel_workers':False}
    active = None
    try:
        r.project_add('demo',repo)
        source = r.task_create('demo','DAG','M09 synthetic linear VMware composition',HUMAN)['id']
        ctx = context.load(r,'demo',HUMAN)['id']
        run = planning.prepare(r,source,ctx,HUMAN,test_only=True)
        proposal = proposal_for([[],[0]])
        result = planning.complete(r,run['run_id'],SyntheticDecisionProvider(json.dumps(proposal),testing=True),HUMAN)
        plan = planning.show(r,result['plan_id'])
        eid = dag.create(r,plan['plan_id'],1,HUMAN)['id']
        report['execution_id'] = eid
        dag.materialize(r,eid,CONTROL)
        template = host.template()
        for work in plan['work_items']:
            binding = dag.bind(r,eid,work['work_item_id'],template,HUMAN)
            r.approve(binding['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00')
            r.transition(binding['task_id'],'READY',HUMAN,'Separate exact synthetic approval')
        report['initial'] = dag.show(r,eid)
        assert len(report['initial']['ready']) == 1
        report['steps'] = []
        for expected in plan['work_items']:
            # execute_next cannot resume UNKNOWN: claim fails if a slot exists.
            step = dag.execute_next(r,eid,host,CONTROL)
            active = step['attempt_id']
            assert step['dispatch']['work_id'] == expected['work_item_id']
            reviewed = dag.show(r,eid)
            assert not reviewed['ready'] and reviewed['active_dispatch']
            try:
                dag.claim(r,eid,CONTROL)
                raise AssertionError('Second work escaped REVIEW gate')
            except ACPError:
                step['review_blocks_next'] = True
            receipt = isolation.facts(r,step['attempt_id'])
            step['vm_receipt'] = receipt
            stop = next(o['detail']['result'] for o in receipt['observations'] if o['kind']=='OPERATION_COMPLETED' and o['detail']['operation']=='stop')
            assert stop['powered_off'] and stop['same_process_handle_signaled'] and stop['host_jobs_quiescent']
            active = None
            dag.accept(r,eid,expected['work_item_id'],{'synthetic-write':step['evidence_id']},HUMAN)
            r.close(); r = Runtime(root/'canonical-state')
            step['after_restart'] = dag.recover(r,eid,CONTROL)
            report['steps'].append(step)
        final = dag.show(r,eid)
        assert final['state']=='COMPLETE' and not final['plan_accepted'] and not final['active_dispatch']
        assert r.db.execute('SELECT count(*) FROM dag_acceptances').fetchone()[0]==2
        instances = [s['vm_receipt']['instance'] for s in report['steps']]
        assert instances[0]['workspace'] != instances[1]['workspace']
        configs = [next(o['detail']['result']['config'] for o in s['vm_receipt']['observations'] if o['kind']=='OPERATION_COMPLETED' and o['detail']['operation']=='start') for s in report['steps']]
        assert configs[0]['uuid'] != configs[1]['uuid'] and configs[0]['disk_file_id'] != configs[1]['disk_file_id']
        report.update(result='PASS',final=final,distinct_vm_disk=True,integrity=r.db.execute('PRAGMA integrity_check').fetchone()[0])
    except BaseException as exc:
        report.update(result='NOT PASSED',error=str(exc))
        # Only this run's exact owned VM may be stopped diagnostically. No fence
        # is synthesized from cleanup acknowledgement; UNKNOWN is retained.
        row = r.db.execute('SELECT a.attempt_id FROM dag_slots s JOIN dag_allocations a ON a.dispatch_id=s.dispatch_id').fetchone()
        if row:
            try:
                owned = isolation.instance(r,row['attempt_id'])
                vmx = Path(owned['vmx'])
                if vmx.exists():
                    host.probe.cli('stop',vmx,'hard')
                    report['diagnostic_cleanup_stop_requested'] = True
            except Exception as cleanup:
                report['cleanup_error'] = type(cleanup).__name__
        raise
    finally:
        host.close(); r.close()
        path = root/'dag-report.json'
        path.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'report':str(path),'result':report.get('result'),'error':report.get('error')}))


if __name__ == '__main__':
    main()
