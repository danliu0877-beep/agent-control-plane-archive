"""Retained M12 TEST-ONLY seeded operator demo. No actual VM/worker launch."""
import argparse
import json
from pathlib import Path

from acp import awareness, board_read, dag, isolation, review
from acp.review_provider import SyntheticReviewProvider
from acp.domain import digest
from tests.test_board import BoardTests
from tests.test_isolation import CONTROL, HUMAN


def populate(t):
    awareness.configure(t.r,'demo',{'name':'M12 TEST-ONLY synthetic demo — VM receipts simulated'},HUMAN)
    t.enrolled([[],[],[0,1]],budget=1,capacity=2)
    happy=t.e
    wave=dag.claim_wave(t.r,t.e,CONTROL)
    active=[]
    for index,intent in enumerate(wave):
        a=dag.allocate(t.r,intent['id'],CONTROL)['id']
        isolation.reserve(t.r,a,t.host,CONTROL);review.select_fixture(t.r,a,CONTROL,defect=index==0)
        for op in ('clone','start','prepare'):isolation.operation(t.r,a,op,t.host,CONTROL)
        active.append((intent,a))
    dag.refresh(t.r,t.e,CONTROL)
    concurrent=board_read.snapshot(t.r)
    assert concurrent['counts']['RUNNING']==2
    rejected=None
    for intent,a in active:
        for op in ('probes','stop'):isolation.operation(t.r,a,op,t.host,CONTROL)
        ev=isolation.complete(t.r,a,CONTROL)
        sem=review.collect(t.r,t.e,intent['work_id'],a,CONTROL)
        run=review.prepare(t.r,t.e,intent['work_id'],a,[ev,sem],CONTROL)
        result=review.execute(t.r,run['id'],SyntheticReviewProvider(testing=True),CONTROL)
        if result['outcome']=='REWORK_REQUIRED':rejected=(a,run)
    a,run=rejected
    isolation.record_fence(t.r,a,CONTROL)
    review.retry(t.r,run['id'],t.correction(run),CONTROL)
    _,_,_,_,fresh=t.finish();review.execute(t.r,fresh['id'],SyntheticReviewProvider(testing=True),CONTROL)
    _,_,_,_,child=t.finish();review.execute(t.r,child['id'],SyntheticReviewProvider(testing=True),CONTROL)
    assert dag.show(t.r,happy)['state']=='COMPLETE'
    assert not dag.show(t.r,happy)['plan_accepted']
    t.enrolled([[],[0]],budget=0)
    exhausted=t.e
    _,a,_,_,run=t.finish(True);review.execute(t.r,run['id'],SyntheticReviewProvider(testing=True),CONTROL)
    isolation.record_fence(t.r,a,CONTROL);review.retry(t.r,run['id'],t.correction(run),CONTROL)
    t.enrolled([[],[0]],capacity=2)
    unknown=t.e
    i=dag.claim(t.r,t.e,CONTROL);a=dag.allocate(t.r,i['id'],CONTROL)['id']
    isolation.reserve(t.r,a,t.host,CONTROL)
    for op in ('clone','start','prepare'):isolation.operation(t.r,a,op,t.host,CONTROL)
    isolation.cancel(t.r,a,CONTROL);dag.refresh(t.r,t.e,CONTROL)
    # Separate review UNKNOWN and two active branches remain populated for restart.
    t.enrolled([[],[]],capacity=2)
    reviewing=t.e
    _,_,_,_,run=t.finish();review.dispatch(t.r,run['id'],CONTROL)
    i=dag.claim(t.r,t.e,CONTROL);a=dag.allocate(t.r,i['id'],CONTROL)['id']
    isolation.reserve(t.r,a,t.host,CONTROL);review.select_fixture(t.r,a,CONTROL)
    for op in ('clone','start','prepare'):isolation.operation(t.r,a,op,t.host,CONTROL)
    dag.refresh(t.r,t.e,CONTROL)
    snapshot=board_read.snapshot(t.r)
    assert snapshot['counts']['DONE / ACCEPTED']==3
    assert snapshot['counts']['NEEDS_HUMAN']==1
    assert snapshot['counts']['BLOCKED']>=2
    assert snapshot['counts']['RUNNING']==1
    return {'happy':happy,'exhausted':exhausted,'unknown':unknown,'reviewing':reviewing,
            'concurrent_counts':concurrent['counts'],'final_counts':snapshot['counts'],
            'snapshot_digest':digest(snapshot),'two_concurrent_branches':True,
            'no_implicit_plan_acceptance':all(not p['plan_accepted'] for p in snapshot['plans']),
            'test_only':'Seeded canonical semantics; fake host receipts, NOT physical M08 evidence'},snapshot


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,help='New owned directory outside Git checkouts')
    args=parser.parse_args()
    output=Path(args.output).resolve()
    from acp.store import data_directory
    data_directory(output)
    assert not output.exists(),'Refuse overwrite: output must be a new directory'
    output.mkdir(parents=True)
    t=BoardTests()
    t.root=output
    project=output/'project';project.mkdir()
    (project/'STATUS.md').write_text(isolation.SYNTHETIC_STATUS,encoding='utf-8',newline='\n')
    from acp import context
    from acp.runtime import Runtime
    t.r=Runtime(output/'state')
    t.r.project_add('demo',project)
    t.task=t.r.task_create('demo','DAG','Synthetic only',HUMAN)['id']
    t.ctx=context.load(t.r,'demo',HUMAN)['id']
    try:
        report,snapshot=populate(t)
        with Runtime(output/'state') as fresh:
            assert board_read.snapshot(fresh)==snapshot
            report['restart_readback']='PASS: exact snapshot and canonical fingerprint'
        (output/'demo-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'data_dir':str(output/'state'),**report},indent=2))
    finally:t.r.close()


if __name__=='__main__':main()
