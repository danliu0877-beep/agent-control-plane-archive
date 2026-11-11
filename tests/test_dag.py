"""Synthetic canonical tests. Fake M08 observations are never VM evidence."""
import copy
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from acp import context, dag, isolation, planning
from acp.decision_provider import SyntheticDecisionProvider
from acp.domain import ACPError
from acp.runtime import Runtime
from tests.test_isolation import HUMAN, CONTROL, WORKER, TEMPLATE, TestOnlyHost
from tests.test_planning import fixture

ROOT = Path(__file__).resolve().parents[1]


def proposal_for(parents):
    p = fixture()
    assessment = {'state': 'NONE', 'evaluated': True, 'rationale': 'Disposable synthetic documentation fixture only', 'sources': ['STATUS.md']}
    p['human_assessment'] = copy.deepcopy(assessment)
    base = p['work_items'][0]
    base.update(work_type='documentation', proposed_write_scope=['allowed.txt'], forbidden_scope=['forbidden.txt'],
        allowed_operations=['inspect_context','analyze','propose_edit'], execution_risk='R1',
        human_assessment=assessment, human_approval_required=True, suggested_profile='future_isolated_write', parallel_safe=False)
    p['work_items'] = [{**copy.deepcopy(base), 'objective': 'Synthetic node ' + str(i), 'dependencies': dependencies} for i, dependencies in enumerate(parents)]
    return p


class DAGTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='acp-m09-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        project = self.root / 'project'; project.mkdir()
        (project / 'STATUS.md').write_text(isolation.SYNTHETIC_STATUS, newline='\n')
        self.r = Runtime(self.root / 'state')
        self.addCleanup(lambda: self.r.close())
        self.r.project_add('demo', project)
        self.task = self.r.task_create('demo','DAG','Synthetic only',HUMAN)['id']
        self.ctx = context.load(self.r,'demo',HUMAN)['id']
        self.host = TestOnlyHost()

    def graph(self, parents, *, bind=True, materialize=True):
        run = planning.prepare(self.r,self.task,self.ctx,HUMAN,test_only=True)
        result = planning.complete(self.r,run['run_id'],SyntheticDecisionProvider(json.dumps(proposal_for(parents)),testing=True),HUMAN)
        self.assertEqual(result['status'],'READY_FOR_REVIEW',result)
        self.plan = planning.show(self.r,result['plan_id'])
        self.e = dag.create(self.r,self.plan['plan_id'],self.plan['plan_revision'],HUMAN)['id']
        if materialize:
            dag.materialize(self.r,self.e,CONTROL)
        self.works = [w['work_item_id'] for w in self.plan['work_items']]
        self.links = {}
        if bind:
            for wid in self.works:
                b = dag.bind(self.r,self.e,wid,TEMPLATE,HUMAN)
                a = self.r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00')
                self.r.transition(b['task_id'],'READY',HUMAN,'Separate exact approval')
                self.links[wid] = (b,a)
        return dag.show(self.r,self.e)

    def states(self):
        s = dag.refresh(self.r,self.e,CONTROL)
        return [next(n['state'] for n in s['nodes'] if n['work_id']==wid) for wid in self.works]

    def review(self):
        intent = dag.claim(self.r,self.e,CONTROL)
        attempt = dag.allocate(self.r,intent['id'],CONTROL)['id']
        isolation.reserve(self.r,attempt,self.host,CONTROL)
        for op in ('clone','start','prepare','probes','stop'):
            isolation.operation(self.r,attempt,op,self.host,CONTROL)
        evidence = isolation.complete(self.r,attempt,CONTROL)
        dag.refresh(self.r,self.e,CONTROL)
        return intent,attempt,{'synthetic-write': evidence}

    def accept_next(self):
        intent,attempt,evidence = self.review()
        dag.accept(self.r,self.e,intent['work_id'],evidence,HUMAN)
        return intent,attempt,evidence

    def fresh(self):
        code = "from acp.runtime import Runtime; from acp import dag; from acp.domain import Actor; import sys,json; r=Runtime(sys.argv[1]); print(json.dumps(dag.recover(r,sys.argv[2],Actor('fresh','controller','test')))); r.close()"
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),self.e],cwd=ROOT,capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr)
        result = json.loads(p.stdout)
        self.assertEqual(result['execution']['id'],self.e)
        return result

    def race(self, expression):
        code = "from acp.runtime import Runtime; from acp import dag; from acp.domain import Actor; import sys,json; r=Runtime(sys.argv[1]); a=Actor('race','controller','test'); h=Actor('principal','human','test'); print(json.dumps(" + expression + ")); r.close()"
        processes = [subprocess.Popen([sys.executable,'-B','-c',code,str(self.root/'state'),self.e],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        outputs = [p.communicate(timeout=30) for p in processes]
        return [(p.returncode,o[0].decode(),o[1].decode()) for p,o in zip(processes,outputs)]

    def test_linear_review_not_acceptance_and_plan_not_implicitly_accepted(self):
        self.graph([[],[0],[1]])
        self.assertEqual(self.states(),['READY','WAITING_DEPENDENCY','WAITING_DEPENDENCY'])
        i,a,e = self.review()
        self.assertEqual(self.states(),['REVIEW','WAITING_DEPENDENCY','WAITING_DEPENDENCY'])
        self.assertEqual(self.fresh()['ready'],[])
        dag.accept(self.r,self.e,i['work_id'],e,HUMAN)
        self.assertEqual(self.states(),['ACCEPTED','READY','WAITING_DEPENDENCY'])
        self.accept_next(); self.accept_next()
        s = self.fresh()
        self.assertEqual(s['state'],'COMPLETE'); self.assertFalse(s['plan_accepted'])
        dag.accept_plan(self.r,self.e,HUMAN)
        self.assertTrue(self.fresh()['plan_accepted'])

    def test_fan_out_fan_in_and_single_slot(self):
        self.graph([[],[0],[0],[1,2]])
        self.accept_next()
        self.assertEqual(self.states(),['ACCEPTED','READY','READY','WAITING_DEPENDENCY'])
        intent,_,e = self.review()
        with self.assertRaisesRegex(ACPError,'authority'): dag.claim(self.r,self.e,CONTROL)
        dag.accept(self.r,self.e,intent['work_id'],e,HUMAN)
        self.assertEqual(self.states(),['ACCEPTED','ACCEPTED','READY','WAITING_DEPENDENCY'])
        self.accept_next()
        self.assertEqual(self.states(),['ACCEPTED','ACCEPTED','ACCEPTED','READY'])
        self.accept_next(); self.assertEqual(self.fresh()['state'],'COMPLETE')

    def test_independent_roots_stable_order(self):
        self.graph([[],[],[0],[1]])
        before = dag.show(self.r,self.e)['ready']
        self.assertEqual(before,self.works[:2])
        self.assertEqual(before,self.fresh()['ready'])
        self.accept_next()
        self.assertEqual(self.states(),['ACCEPTED','READY','READY','WAITING_DEPENDENCY'])
        self.assertEqual(dag.claim(self.r,self.e,CONTROL)['work_id'],self.works[1])

    def test_failure_exact_cause_and_sibling_not_blocked(self):
        self.graph([[],[0],[1],[]])
        dag.disposition(self.r,self.e,self.works[0],'FAILED','Principal rejected bounded work',HUMAN)
        self.assertEqual(self.states(),['FAILED','BLOCKED','BLOCKED','READY'])
        self.assertEqual(self.fresh()['state'],'BLOCKED')
        self.accept_next()
        self.assertEqual(self.states(),['FAILED','BLOCKED','BLOCKED','ACCEPTED'])
        self.assertIn(self.works[0],json.dumps(dag.show(self.r,self.e)['causes']))

    def test_mixed_human_gate_restart_and_resolution(self):
        self.graph([[],[],[],[1,2]])
        self.accept_next()
        dag.disposition(self.r,self.e,self.works[1],'HUMAN_GATE','Architecture decision for Principal',HUMAN)
        self.assertEqual(self.states(),['ACCEPTED','NEEDS_HUMAN','READY','WAITING_DEPENDENCY'])
        self.assertEqual(self.fresh()['ready'],[self.works[2]])
        self.accept_next(); self.assertEqual(self.fresh()['state'],'NEEDS_HUMAN')
        with self.assertRaises(ACPError): dag.disposition(self.r,self.e,self.works[1],'HUMAN_RESOLVED','not human',CONTROL)
        dag.disposition(self.r,self.e,self.works[1],'HUMAN_RESOLVED','Approved exact existing bounded semantics',HUMAN)
        self.accept_next(); self.accept_next()
        self.assertEqual(self.fresh()['state'],'COMPLETE')

    def test_creation_materialization_mapping_idempotency_and_immutable(self):
        self.graph([[],[0]])
        before = {t:self.r.db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in ('tasks','approvals','dag_nodes','dag_edges','isolation_task_bindings')}
        self.assertEqual(dag.create(self.r,self.plan['plan_id'],1,HUMAN)['id'],self.e)
        dag.materialize(self.r,self.e,CONTROL); self.fresh()
        for wid in self.works: dag.bind(self.r,self.e,wid,TEMPLATE,HUMAN)
        self.assertEqual(before,{t:self.r.db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in before})
        for table in ('dag_executions','dag_edges','dag_links','dag_dispatches','dag_allocations','dag_acceptances','dag_facts','dag_plan_acceptances'):
            with self.subTest(table=table),self.assertRaises(sqlite3.IntegrityError): self.r.db.execute('DELETE FROM '+table) if self.r.db.execute('SELECT count(*) FROM '+table).fetchone()[0] else self.r.db.execute('UPDATE dag_nodes SET ordinal=ordinal+1')

    def test_direct_attempt_and_waiting_child_and_legacy_bypass_denied(self):
        self.graph([[],[0]])
        for wid in self.works:
            b,a = self.links[wid]
            with self.assertRaisesRegex(ACPError,'authority'): self.r.attempt_create(b['task_id'],a['id'],CONTROL)
        i = dag.claim(self.r,self.e,CONTROL)
        child,approval = self.links[self.works[1]]
        with self.assertRaises(ACPError): self.r.attempt_create(child['task_id'],approval['id'],CONTROL)
        with self.assertRaises(ACPError): dag.execute_next(self.r,self.e,self.host,CONTROL)
        a = dag.allocate(self.r,i['id'],CONTROL)
        self.assertEqual(a['id'],dag.allocate(self.r,i['id'],CONTROL)['id'])
        with self.assertRaises(ACPError): self.r.attempt_create(i['task_id'],i['approval_id'],CONTROL)

    def test_unknown_vm_ownership_blocks_descendants_and_new_claim(self):
        self.graph([[],[0],[]])
        i = dag.claim(self.r,self.e,CONTROL); a = dag.allocate(self.r,i['id'],CONTROL)['id']
        isolation.reserve(self.r,a,self.host,CONTROL)
        isolation.operation(self.r,a,'clone',self.host,CONTROL)
        self.host.fail = 'start'
        with self.assertRaises(TimeoutError): isolation.operation(self.r,a,'start',self.host,CONTROL)
        s = self.fresh()
        self.assertIn('EXECUTION_OWNERSHIP_UNCERTAIN',json.dumps(s))
        self.assertEqual(self.states(),['DISPATCHED','WAITING_DEPENDENCY','READY'])
        with self.assertRaises(ACPError): dag.claim(self.r,self.e,CONTROL)
        with self.assertRaises(ACPError): dag.disposition(self.r,self.e,self.works[0],'FAILED','Cannot release uncertain ownership',HUMAN)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM execution_attempts').fetchone()[0],1)

    def test_fenced_work_cannot_scheduler_retry_or_satisfy_dependency(self):
        self.graph([[],[0],[]])
        i = dag.claim(self.r,self.e,CONTROL); a = dag.allocate(self.r,i['id'],CONTROL)['id']
        isolation.reserve(self.r,a,self.host,CONTROL)
        for op in ('clone','start','prepare'): isolation.operation(self.r,a,op,self.host,CONTROL)
        isolation.cancel(self.r,a,CONTROL)
        isolation.operation(self.r,a,'stop',self.host,CONTROL); isolation.record_fence(self.r,a,CONTROL)
        self.assertEqual(next(n['state'] for n in self.fresh()['nodes'] if n['work_id']==self.works[1]),'WAITING_DEPENDENCY')
        self.r.resolve_hold(i['task_id'],CONTROL,'M08 proven fence',retry_ready=True)
        with self.assertRaises(ACPError): self.r.attempt_create(i['task_id'],i['approval_id'],CONTROL)
        dag.disposition(self.r,self.e,self.works[0],'CANCELLED','Fenced cancellation; no DAG retry',HUMAN)
        self.assertEqual(self.states(),['CANCELLED','BLOCKED','READY'])

    def test_acceptance_transaction_rolls_back_task_node_and_unlock(self):
        self.graph([[],[0]])
        i,a,e = self.review()
        with patch.object(dag,'_evaluate',side_effect=RuntimeError('propagation crash')):
            with self.assertRaises(RuntimeError): dag.accept(self.r,self.e,i['work_id'],e,HUMAN)
        self.assertEqual(self.r.task_show(i['task_id'])['state'],'REVIEW')
        self.assertEqual(self.states(),['REVIEW','WAITING_DEPENDENCY'])
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_acceptances').fetchone()[0],0)
        dag.accept(self.r,self.e,i['work_id'],e,HUMAN)
        dag.accept(self.r,self.e,i['work_id'],e,HUMAN)
        self.assertEqual(self.fresh()['ready'],[self.works[1]])

    def test_competing_materialization_claim_allocation_acceptance_finalization(self):
        self.graph([[],[],[0,1]],bind=False)
        results = self.race('dag.materialize(r,sys.argv[2],a)')
        self.assertTrue(all(p[0]==0 for p in results),results)
        for wid in self.works:
            b = dag.bind(self.r,self.e,wid,TEMPLATE,HUMAN)
            self.r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00'); self.r.transition(b['task_id'],'READY',HUMAN,'approved')
        results = self.race('dag.claim(r,sys.argv[2],a)')
        self.assertEqual(sum(p[0]==0 for p in results),1,results)
        intent = json.loads(next(p[1] for p in results if p[0]==0))
        results = self.race('dag.allocate(r,'+repr(intent['id'])+',a)')
        self.assertTrue(all(p[0]==0 for p in results),results)
        self.assertEqual(len({json.loads(p[1])['id'] for p in results}),1)
        a = json.loads(results[0][1])['id']
        isolation.reserve(self.r,a,self.host,CONTROL)
        for op in ('clone','start','prepare','probes','stop'): isolation.operation(self.r,a,op,self.host,CONTROL)
        evidence = isolation.complete(self.r,a,CONTROL)
        results = self.race('dag.accept(r,sys.argv[2],'+repr(intent['work_id'])+','+repr({'synthetic-write':evidence})+',h)')
        self.assertTrue(all(p[0]==0 for p in results),results)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_acceptances').fetchone()[0],1)
        self.accept_next(); self.accept_next()
        results = self.race('dag.accept_plan(r,sys.argv[2],h)')
        self.assertTrue(all(p[0]==0 for p in results),results)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_plan_acceptances').fetchone()[0],1)

    def test_real_process_death_during_materialization_and_dispatch_windows(self):
        self.graph([[],[0]],bind=False,materialize=False)
        # Fresh execution creation survives without graph; process death during
        # graph inserts rolls all of them back, preserving the original PEX.
        self.assertEqual(self.fresh()['ready'],[self.works[0]])
        # Separate fresh unmaterialized execution for an actual mid-insert death.
        run = planning.prepare(self.r,self.task,self.ctx,HUMAN,test_only=True)
        result = planning.complete(self.r,run['run_id'],SyntheticDecisionProvider(json.dumps(proposal_for([[],[0]])),testing=True),HUMAN)
        self.plan = planning.show(self.r,result['plan_id'])
        self.e = dag.create(self.r,self.plan['plan_id'],1,HUMAN)['id']
        self.works = [w['work_item_id'] for w in self.plan['work_items']]
        code = "import os,sys; from acp.runtime import Runtime; from acp import dag; from acp.domain import Actor; r=Runtime(sys.argv[1]); dag._evaluate=lambda *a:os._exit(73); dag.materialize(r,sys.argv[2],Actor('c','controller','test'))"
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),self.e],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,73); self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_nodes WHERE execution_id=?',(self.e,)).fetchone()[0],0)
        self.assertEqual(self.fresh()['ready'],[self.works[0]])
        for wid in self.works:
            b = dag.bind(self.r,self.e,wid,TEMPLATE,HUMAN); self.r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00'); self.r.transition(b['task_id'],'READY',HUMAN,'approved')
        code = "import os,sys; from acp.runtime import Runtime; from acp import dag; from acp.domain import Actor; r=Runtime(sys.argv[1]); dag.claim(r,sys.argv[2],Actor('c','controller','test')); os._exit(74)"
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),self.e],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,74)
        s = self.fresh(); self.assertIsNotNone(s['active_dispatch']); self.assertEqual(s['ready'],[])
        with self.assertRaises(ACPError): dag.claim(self.r,self.e,CONTROL)
        code = "import os,sys; from acp.runtime import Runtime; from acp import dag; from acp.domain import Actor; r=Runtime(sys.argv[1]); original=r.attempt_create; r.attempt_create=lambda *args,**kw:(original(*args,**kw),os._exit(75))[0]; dag.allocate(r,sys.argv[2],Actor('c','controller','test'))"
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),s['active_dispatch']],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,75); self.assertEqual(self.r.db.execute('SELECT count(*) FROM execution_attempts').fetchone()[0],0)
        self.fresh()
        attempt = dag.allocate(self.r,s['active_dispatch'],CONTROL)['id']
        self.fresh(); self.assertEqual(dag.allocate(self.r,s['active_dispatch'],CONTROL)['id'],attempt)

    def test_invalid_policy_actor_and_prior_standalone_authority(self):
        self.graph([[]],bind=False)
        with self.assertRaises(ACPError): dag.claim(self.r,self.e,WORKER)
        with patch.object(dag,'POLICY','unknown'),self.assertRaises(ACPError): dag.show(self.r,self.e)
        with self.assertRaises(ACPError): dag.accept_plan(self.r,self.e,HUMAN)
        self.assertEqual(self.plan['work_items'][0]['write_authority'],'NONE')

    def test_v6_migration_preserves_rows(self):
        self.graph([[],[0]])
        tables = [r[0] for r in self.r.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'dag_%' AND name NOT IN ('schema_metadata','sqlite_sequence')")]
        before = {t:[tuple(r) for r in self.r.db.execute('SELECT * FROM '+t)] for t in tables}
        self.r.close()
        db = sqlite3.connect(self.root/'state/acp.sqlite3')
        from tests.schema_fixture import drop_dag
        with db:
            drop_dag(db)
            trigger = db.execute("SELECT sql FROM sqlite_master WHERE name='schema_metadata_delete'").fetchone()[0]
            db.execute('DROP TRIGGER schema_metadata_delete'); db.execute('DELETE FROM schema_metadata WHERE version>=7'); db.execute(trigger); db.execute('PRAGMA user_version=6')
        db.close(); self.r = Runtime(self.root/'state')
        self.assertEqual(before,{t:[tuple(r) for r in self.r.db.execute('SELECT * FROM '+t)] for t in tables})
        self.assertEqual(self.r.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
        self.assertEqual(self.r.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_process_death_after_reservation_and_during_invocation(self):
        self.graph([[],[0]])
        i = dag.claim(self.r,self.e,CONTROL); a = dag.allocate(self.r,i['id'],CONTROL)['id']
        code = "import os,sys; from acp.runtime import Runtime; from acp import isolation; from tests.test_isolation import TestOnlyHost,CONTROL; r=Runtime(sys.argv[1]); isolation.reserve(r,sys.argv[2],TestOnlyHost(),CONTROL); os._exit(76)"
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),a],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,76)
        self.fresh()
        with self.assertRaises(ACPError): isolation.reserve(self.r,a,self.host,CONTROL)
        code = "import os,sys; from pathlib import Path; from acp.runtime import Runtime; from acp import isolation; from tests.test_isolation import TestOnlyHost,CONTROL; r=Runtime(sys.argv[1]); h=TestOnlyHost(); h.perform=lambda *args:(Path(sys.argv[3]).write_text('one invocation'),os._exit(77))[0]; isolation.operation(r,sys.argv[2],'clone',h,CONTROL)"
        marker = self.root/'calls.txt'
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),a,str(marker)],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,77); self.assertEqual(marker.read_text(),'one invocation')
        self.assertIn('EXECUTION_OWNERSHIP_UNCERTAIN',json.dumps(self.fresh()))
        with self.assertRaises(ACPError): isolation.operation(self.r,a,'clone',self.host,CONTROL)
        with self.assertRaises(ACPError): dag.claim(self.r,self.e,CONTROL)
        self.assertEqual(self.host.calls,[])

    def test_actual_process_death_during_acceptance_and_after_commit(self):
        self.graph([[],[0]])
        i,a,e = self.review()
        code = "import os,sys,json; from acp.runtime import Runtime; from acp import dag; from tests.test_isolation import HUMAN; r=Runtime(sys.argv[1]); dag._evaluate=lambda *args:os._exit(78); dag.accept(r,sys.argv[2],sys.argv[3],json.loads(sys.argv[4]),HUMAN)"
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),self.e,i['work_id'],json.dumps(e)],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,78); self.assertEqual(self.r.task_show(i['task_id'])['state'],'REVIEW')
        self.assertEqual(self.fresh()['ready'],[])
        code = "import os,sys,json; from acp.runtime import Runtime; from acp import dag; from tests.test_isolation import HUMAN; r=Runtime(sys.argv[1]); dag.accept(r,sys.argv[2],sys.argv[3],json.loads(sys.argv[4]),HUMAN); os._exit(79)"
        p = subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state'),self.e,i['work_id'],json.dumps(e)],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,79); self.assertEqual(self.fresh()['ready'],[self.works[1]])
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_acceptances').fetchone()[0],1)

    def test_materialization_binding_and_nested_transaction_failure_atomic(self):
        self.graph([[],[0]],bind=False)
        original = isolation.materialize
        def crash(*args):
            original(*args)
            raise RuntimeError('after child task mapping before DAG receipt')
        with patch.object(isolation,'materialize',side_effect=crash),self.assertRaises(RuntimeError):
            dag.bind(self.r,self.e,self.works[0],TEMPLATE,HUMAN)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM isolation_task_bindings').fetchone()[0],0)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM tasks').fetchone()[0],1)
        dag.bind(self.r,self.e,self.works[0],TEMPLATE,HUMAN)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM isolation_task_bindings').fetchone()[0],1)

    def test_worker_claim_and_bad_evidence_never_unlock(self):
        self.graph([[],[0]])
        i,a,e = self.review()
        ev = self.r.evidence_add(i['task_id'],a,{'class':'claim','trust':'unverified','producer':'worker','producer_role':'worker','collector':'ACP test collector','collection_method':'Unverified worker claim','outcome':'pass','content':{'success':True}},WORKER)['id']
        with self.assertRaises(ACPError): dag.accept(self.r,self.e,i['work_id'],{'synthetic-write':ev},HUMAN)
        with self.assertRaises(ACPError): dag.accept(self.r,self.e,i['work_id'],e,WORKER)
        self.assertEqual(self.states(),['REVIEW','WAITING_DEPENDENCY'])
        # Direct existing acceptance API cannot skip propagation.
        self.r.accept(i['task_id'],a,e,HUMAN,'Exact independent verification')
        self.assertEqual(self.fresh()['ready'],[self.works[1]])

    def test_revoked_and_superseded_authority_and_no_m06_fallback(self):
        self.graph([[],[0]])
        b,approval = self.links[self.works[0]]
        self.r.revoke(approval['id'],HUMAN,'Revoked exact scope')
        self.assertEqual(self.states(),['NEEDS_HUMAN','WAITING_DEPENDENCY'])
        with self.assertRaises(ACPError): dag.claim(self.r,self.e,CONTROL)
        from acp import controlled
        with self.assertRaisesRegex(ACPError,'M08 isolation'): controlled.materialize(self.r,self.plan['plan_id'],1,self.works[0],'synthetic-inspect-v1',HUMAN)

    def test_gate_while_running_preserves_slot_and_shutdown_authority(self):
        self.graph([[],[]])
        i = dag.claim(self.r,self.e,CONTROL); a = dag.allocate(self.r,i['id'],CONTROL)['id']
        isolation.reserve(self.r,a,self.host,CONTROL)
        for op in ('clone','start','prepare'): isolation.operation(self.r,a,op,self.host,CONTROL)
        dag.disposition(self.r,self.e,i['work_id'],'HUMAN_GATE','Scope decision',HUMAN)
        self.assertEqual(self.fresh()['state'],'NEEDS_HUMAN')
        self.assertIsNotNone(self.fresh()['active_dispatch'])
        with self.assertRaises(ACPError): dag.claim(self.r,self.e,CONTROL)
        with self.assertRaises(ACPError): isolation.operation(self.r,a,'probes',self.host,CONTROL)
        isolation.cancel(self.r,a,CONTROL); isolation.operation(self.r,a,'stop',self.host,CONTROL); isolation.record_fence(self.r,a,CONTROL)
        dag.disposition(self.r,self.e,i['work_id'],'CANCELLED','Exact fenced cancellation',HUMAN)
        self.assertEqual(self.states(),['CANCELLED','READY'])

    def test_competing_creation_and_next_dispatch(self):
        self.graph([[],[],[0,1]])
        results = self.race('dag.create(r,'+repr(self.plan['plan_id'])+',1,a)')
        self.assertTrue(all(p[0]==0 for p in results),results)
        self.assertEqual({json.loads(p[1])['id'] for p in results},{self.e})
        self.accept_next()
        results = self.race('dag.claim(r,sys.argv[2],a)')
        self.assertEqual(sum(p[0]==0 for p in results),1,results)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_slots').fetchone()[0],1)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_dispatches').fetchone()[0],2)

    def test_superseded_revision_never_rebinds_or_dispatches(self):
        self.graph([[],[0]])
        run = planning.prepare(self.r,self.task,self.ctx,HUMAN,plan_id=self.plan['plan_id'],test_only=True)
        result = planning.complete(self.r,run['run_id'],SyntheticDecisionProvider(json.dumps(proposal_for([[],[0]])),testing=True),HUMAN)
        self.assertEqual(result['revision'],2)
        with self.assertRaisesRegex(ACPError,'STALE'): dag.claim(self.r,self.e,CONTROL)
        self.assertEqual(dag.show(self.r,self.e)['execution']['revision'],1)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_dispatches').fetchone()[0],0)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM execution_attempts').fetchone()[0],0)
