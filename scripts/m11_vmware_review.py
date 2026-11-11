"""Owned real synthetic M11 loop, fresh VMware retry and independent review."""
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

REPO=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(REPO))
from acp import context,dag,isolation,planning,review
from acp.decision_provider import SyntheticDecisionProvider
from acp.domain import require
from acp.domain import ACPError
from acp.runtime import Runtime
from acp.vmware_host import VMwareHost,ROOT,TRUSTED_SOURCES
from tests.test_dag import proposal_for
from tests.test_isolation import HUMAN,CONTROL


def main():
    require(__debug__ and os.environ.get('ACP_M08_GUEST_PASSWORD'),'Normal Python and separate disposable guest-only test credential required')
    root=ROOT/('m11-review-'+uuid.uuid4().hex);root.mkdir()
    (root/'owned-by-m08.txt').write_text('M11 synthetic review evidence only\n',encoding='utf-8')
    canaries={}
    for category in ('sibling','profile','credentials'):
        directory=root/'canaries'/category;directory.mkdir(parents=True)
        target=directory/'canary.txt';target.write_text('synthetic '+category,encoding='utf-8');canaries[category]=str(target)
    (root/'hosttargets.json').write_text(json.dumps(canaries),encoding='utf-8')
    project=root/'synthetic-project';project.mkdir();(project/'STATUS.md').write_text(isolation.SYNTHETIC_STATUS,encoding='utf-8',newline='\n')
    report={'root':str(root),'result':'NOT PASSED','real_project':False,'real_agent':False,'production_credentials':False,'live_provider':'NOT_DEMONSTRATED','steps':[]}
    r=Runtime(root/'canonical-state');host=VMwareHost(root)
    try:
        r.project_add('demo',project);task=r.task_create('demo','M11 review','Synthetic defect -> fresh correction -> dependent',HUMAN)['id']
        ctx=context.load(r,'demo',HUMAN)['id'];run=planning.prepare(r,task,ctx,HUMAN,test_only=True)
        result=planning.complete(r,run['run_id'],SyntheticDecisionProvider(json.dumps(proposal_for([[],[0]])),testing=True),HUMAN)
        plan=planning.show(r,result['plan_id']);works=[w['work_item_id'] for w in plan['work_items']]
        eid=dag.create(r,plan['plan_id'],1,HUMAN,max_parallel=2)['id'];dag.materialize(r,eid,CONTROL)
        template=host.template()
        for wid in works:
            b=dag.bind(r,eid,wid,template,HUMAN);r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00');r.transition(b['task_id'],'READY',HUMAN,'Exact M11 synthetic approval')
        enrolled=review.enroll(r,eid,{w:review.criteria(r,eid,w) for w in works},HUMAN,max_semantic_retries=1,expires_at='2099-01-01T00:00:00+00:00')
        report.update(execution_id=eid,works=works,enrollment=enrolled,source_seal=template['sources'],sqlite=str(r.store.path))
        for _ in range(16):
            step=review.step(r,eid,host,CONTROL,initial_defect_work=works[0]);report['steps'].append(step)
            if step['action']=='COMPLETE':break
            require(step['action'] not in {'HELD','WAIT_UNKNOWN_REVIEW'},'Unexpected held autonomous synthetic loop')
        final=dag.recover(r,eid,CONTROL);require(final['state']=='COMPLETE','Bounded loop incomplete')
        attempts=[dict(x) for x in r.db.execute('SELECT a.id,a.state,a.quarantined,i.vmx_path,i.workspace_path FROM execution_attempts a JOIN isolation_instances i ON i.attempt_id=a.id ORDER BY a.rowid')]
        require(len(attempts)==3 and len({x['vmx_path'] for x in attempts})==3 and len({x['workspace_path'] for x in attempts})==3,'Three fresh isolated synthetic workers required')
        require(attempts[0]['state']=='SUCCEEDED' and attempts[0]['quarantined']==1,'Terminal rejected history preserved')
        facts=[isolation.facts(r,x['id']) for x in attempts]
        identities=[next(o['detail']['result']['config'] for o in f['observations'] if o['kind']=='OPERATION_COMPLETED' and o['detail']['operation']=='start') for f in facts]
        require(len({x['uuid'] for x in identities})==3 and len({x['disk_file_id'] for x in identities})==3,'Fresh VM/disk authority required')
        require(r.db.execute('SELECT count(*) FROM review_retries').fetchone()[0]==1,'Exactly one reserved semantic retry')
        require(not final['slots'] and not final['plan_accepted'],'Execution acceptance distinct from plan/merge')
        stopped=[host.probe.observe(Path(x['vmx_path'])) for x in attempts]
        require(all(o['state']=='powered_off' for o in stopped),'Independent final powered-off readback')
        require(template['sources']=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in TRUSTED_SOURCES},'Final source seal changed')
        report.update(attempts=attempts,physical_facts=facts,vm_identities=identities,final_powered_off=stopped,
            final=final,review_records=[review.show(r,x[0]) for x in r.db.execute('SELECT id FROM review_runs ORDER BY rowid')],
            integrity=r.db.execute('PRAGMA integrity_check').fetchone()[0],foreign_keys=[tuple(x) for x in r.db.execute('PRAGMA foreign_key_check')])
        old_run=report['review_records'][0]['run'];new_run=report['review_records'][1]['run']
        report['late_old_output']=isolation.quarantine(r,attempts[0]['id'],{'artifact_digest':next(m['record']['content']['artifact_digest'] for m in old_run['manifest'] if m['record'].get('content',{}).get('validator_version'))},CONTROL)
        try:review.prepare(r,eid,works[0],attempts[1]['id'],[m['id'] for m in old_run['manifest']],CONTROL)
        except ACPError as exc:report['old_evidence_rejected']=str(exc)
        else:raise RuntimeError('Old evidence admitted as fresh successor evidence')
        # A real stopped accepted worker cannot acquire retry authority even if human asks a new verdict.
        try:isolation.record_fence(r,attempts[1]['id'],CONTROL)
        except ValueError as exc:report['accepted_retry_blocked']=str(exc)
        else:raise RuntimeError('Accepted physical worker was allowed to fence for retry')
        # Separate enrolled real fixture: no semantic budget, durable Principal hold.
        fault_task=r.task_create('demo','M11 budget hold','Real synthetic bounded exhaustion',HUMAN)['id']
        prepared=planning.prepare(r,fault_task,ctx,HUMAN,test_only=True)
        fault_result=planning.complete(r,prepared['run_id'],SyntheticDecisionProvider(json.dumps(proposal_for([[],[0]])),testing=True),HUMAN)
        fault_plan=planning.show(r,fault_result['plan_id']);fault_works=[w['work_item_id'] for w in fault_plan['work_items']]
        fault_eid=dag.create(r,fault_plan['plan_id'],1,HUMAN)['id'];dag.materialize(r,fault_eid,CONTROL)
        for wid in fault_works:
            b=dag.bind(r,fault_eid,wid,template,HUMAN);r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00');r.transition(b['task_id'],'READY',HUMAN,'Exact exhaustion fixture approval')
        review.enroll(r,fault_eid,{w:review.criteria(r,fault_eid,w) for w in fault_works},HUMAN,max_semantic_retries=0,expires_at='2099-01-01T00:00:00+00:00')
        held_steps=[review.step(r,fault_eid,host,CONTROL,initial_defect_work=fault_works[0]) for _ in range(3)]
        held=dag.recover(r,fault_eid,CONTROL)
        require(held['state']=='NEEDS_HUMAN' and not held['slots'] and [n['state'] for n in held['nodes']]==['NEEDS_HUMAN','WAITING_DEPENDENCY'],'Exhaustion must not unlock dependency')
        fault_attempt=held_steps[0]['attempt_id'];fault_facts=isolation.facts(r,fault_attempt)
        require(fault_facts['fence'] and r.store.one('execution_attempts',fault_attempt)['state']=='SUCCEEDED','Full terminal fence preserves rejected history')
        taskid=r.store.one('execution_attempts',fault_attempt)['task_id']
        try:r.resolve_hold(taskid,CONTROL,'No controller bypass of Principal exhaustion')
        except ACPError:pass
        else:raise RuntimeError('Controller resolved reserved human gate')
        report['real_exhaustion']={'execution_id':fault_eid,'steps':held_steps,'state':held,'facts':fault_facts,'powered_off':host.probe.observe(Path(fault_facts['instance']['vmx']))}
        # Preserve all old M08 observer-fault tests under the changed source by
        # exercising exact failure in another enrolled disposable execution.
        unknown_task=r.task_create('demo','M11 UNKNOWN','Real synthetic observer failure',HUMAN)['id']
        prepared=planning.prepare(r,unknown_task,ctx,HUMAN,test_only=True)
        unknown_result=planning.complete(r,prepared['run_id'],SyntheticDecisionProvider(json.dumps(proposal_for([[],[0]])),testing=True),HUMAN)
        unknown_plan=planning.show(r,unknown_result['plan_id']);unknown_works=[w['work_item_id'] for w in unknown_plan['work_items']]
        unknown_eid=dag.create(r,unknown_plan['plan_id'],1,HUMAN)['id'];dag.materialize(r,unknown_eid,CONTROL)
        for wid in unknown_works:
            b=dag.bind(r,unknown_eid,wid,template,HUMAN);r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00');r.transition(b['task_id'],'READY',HUMAN,'Exact unknown fixture approval')
        review.enroll(r,unknown_eid,{w:review.criteria(r,unknown_eid,w) for w in unknown_works},HUMAN,max_semantic_retries=1,expires_at='2099-01-01T00:00:00+00:00')
        dispatch=dag.claim(r,unknown_eid,CONTROL);unknown=dag.allocate(r,dispatch['id'],CONTROL)['id']
        isolation.reserve(r,unknown,host,CONTROL);review.select_fixture(r,unknown,CONTROL)
        for op in ('clone','start','prepare','tree'):isolation.operation(r,unknown,op,host,CONTROL)
        isolation.cancel(r,unknown,CONTROL)
        original_observer=host.probe.observe
        def unavailable(vmx):raise RuntimeError('INJECTED exact positive state observer unavailable')
        host.probe.observe=unavailable
        try:
            try:isolation.operation(r,unknown,'stop',host,CONTROL)
            except RuntimeError:pass
            else:raise RuntimeError('Unknown observer was accepted')
        finally:host.probe.observe=original_observer
        unknown_facts=isolation.facts(r,unknown);unknown_state=dag.recover(r,unknown_eid,CONTROL)
        for action in (lambda:isolation.record_fence(r,unknown,CONTROL),lambda:review.execution_failure(r,unknown_eid,unknown_works[0],unknown,CONTROL),lambda:dag.claim(r,unknown_eid,CONTROL)):
            try:action()
            except ACPError:pass
            else:raise RuntimeError('UNKNOWN allowed retry/new physical authority')
        vmx=Path(unknown_facts['instance']['vmx']);diagnostic=original_observer(vmx)
        require(diagnostic['state']=='powered_off' and host.probe.witnesses[vmx].ceased(),'Diagnostic exact stopped readback')
        require(unknown_facts['pending'] and not unknown_facts['fence'] and len(unknown_state['slots'])==1,'UNKNOWN slot must remain occupied without invented fence')
        report['real_unknown']={'execution_id':unknown_eid,'attempt_id':unknown,'state':unknown_state,'facts':unknown_facts,'diagnostic_powered_off':diagnostic,'same_process_handle_signaled':True,'canonical_retry':'DENIED'}
        require(template['sources']=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in TRUSTED_SOURCES},'Final source seal changed')
        all_instances=[isolation.instance(r,x[0]) for x in r.db.execute('SELECT attempt_id FROM isolation_instances ORDER BY rowid')]
        all_stopped=[host.probe.observe(Path(x['vmx'])) for x in all_instances]
        require(len(all_instances)==5 and all(x['state']=='powered_off' for x in all_stopped),'Final five exact VM states required')
        report.update(all_instances=all_instances,all_final_powered_off=all_stopped,
            final_attempt_count=r.db.execute('SELECT count(*) FROM execution_attempts').fetchone()[0],
            final_retry_count=r.db.execute('SELECT count(*) FROM review_retries').fetchone()[0],
            final_review_count=r.db.execute('SELECT count(*) FROM review_runs').fetchone()[0],
            final_integrity=r.db.execute('PRAGMA integrity_check').fetchone()[0],
            final_foreign_keys=[tuple(x) for x in r.db.execute('PRAGMA foreign_key_check')])
        require(report['final_integrity']=='ok' and not report['final_foreign_keys'],'Final canonical integrity/FKs required')
        report['result']='PASS'
    except BaseException as exc:
        report['error']=type(exc).__name__+': '+str(exc)
        # Diagnostic shutdown only; pending uncertainty remains canonical.
        for row in r.db.execute('SELECT vmx_path FROM isolation_instances'):
            vmx=Path(row[0])
            if vmx.is_relative_to(root) and vmx.exists():
                try:host.probe.cli('stop',vmx,'hard',allow_failure=True)
                except Exception:pass
        raise
    finally:
        host.close();r.close();path=root/'review-report.json';path.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'report':str(path),'result':report['result'],'error':report.get('error')}))


if __name__=='__main__':main()
