"""M10 bounded SQLite authority tests; fake hosts are test-only observations."""
import json
import sqlite3
import subprocess
import sys
from unittest.mock import patch

from acp import dag, isolation
from acp.domain import canonical_json, digest
from acp.domain import ACPError
from acp.runtime import Runtime
from tests import test_dag as fixture_module
from tests.test_dag import ROOT
from tests.test_isolation import HUMAN, CONTROL, TEMPLATE, TestOnlyHost


class ParallelTests(fixture_module.DAGTests):
    # Reuse fixture helpers, not inherited M09 test duplication.
    def graph(self, parents, *, bind=True, materialize=True):
        with patch.object(dag,'DEFAULT_PARALLEL',2):
            return super().graph(parents,bind=bind,materialize=materialize)

    def start(self, intent, *, run=True):
        a = dag.allocate(self.r,intent['id'],CONTROL)['id']
        isolation.reserve(self.r,a,self.host,CONTROL)
        if run:
            for op in ('clone','start','prepare'): isolation.operation(self.r,a,op,self.host,CONTROL)
        return a

    def finish(self, intent, attempt, *, accept=True):
        for op in ('probes','stop'): isolation.operation(self.r,attempt,op,self.host,CONTROL)
        evidence = isolation.complete(self.r,attempt,CONTROL)
        dag.refresh(self.r,self.e,CONTROL)
        if accept: dag.accept(self.r,self.e,intent['work_id'],{'synthetic-write':evidence},HUMAN)
        return evidence

    def test_policy_is_immutable_and_default_does_not_rebind(self):
        self.graph([[],[],[]])
        self.assertEqual(self.fresh()['capacity'],2)
        with patch.object(dag,'DEFAULT_PARALLEL',4):
            self.assertEqual(dag.create(self.r,self.plan['plan_id'],1,HUMAN)['concurrency']['max_parallel'],2)
        with self.assertRaises(ACPError): dag.create(self.r,self.plan['plan_id'],1,HUMAN,max_parallel=3)
        for bad in (0,5,True,1.5,'2'):
            with self.assertRaises(ACPError): dag.create(self.r,self.plan['plan_id'],1,HUMAN,max_parallel=bad)

    def test_wave_backpressure_and_review_retains_capacity(self):
        self.graph([[],[],[],[],[]])
        self.assertEqual(self.fresh()['available_capacity'],2)
        wave = dag.claim_wave(self.r,self.e,CONTROL)
        self.assertEqual([d['work_id'] for d in wave],self.works[:2])
        self.assertEqual([d['available_before'] for d in wave],[2,1])
        self.assertEqual(len(self.fresh()['ready']),3)
        self.assertEqual(dag.claim_wave(self.r,self.e,CONTROL),[])
        a = self.start(wave[0]); self.start(wave[1])
        evidence = self.finish(wave[0],a,accept=False)
        state = self.fresh(); self.assertEqual(state['available_capacity'],0)
        self.assertEqual({n['state'] for n in state['nodes']},{'REVIEW','RUNNING','READY'})
        dag.accept(self.r,self.e,wave[0]['work_id'],{'synthetic-write':evidence},HUMAN)
        next_wave = dag.claim_wave(self.r,self.e,CONTROL)
        self.assertEqual([d['work_id'] for d in next_wave],[self.works[2]])
        self.assertEqual(self.fresh()['available_capacity'],0)

    def test_both_completion_orders_fan_in_converge(self):
        outcomes=[]
        for reverse in (False,True):
            self.graph([[],[0],[0],[1,2]])
            self.accept_next()
            wave = dag.claim_wave(self.r,self.e,CONTROL)
            attempts = {d['id']:self.start(d) for d in wave}
            self.assertEqual(self.fresh()['available_capacity'],0)
            order = list(reversed(wave)) if reverse else wave
            e = self.finish(order[0],attempts[order[0]['id']],accept=False)
            self.assertEqual(next(n['state'] for n in self.fresh()['nodes'] if n['work_id']==self.works[3]),'WAITING_DEPENDENCY')
            dag.accept(self.r,self.e,order[0]['work_id'],{'synthetic-write':e},HUMAN)
            self.assertEqual(next(n['state'] for n in self.fresh()['nodes'] if n['work_id']==self.works[3]),'WAITING_DEPENDENCY')
            self.finish(order[1],attempts[order[1]['id']])
            self.assertEqual(self.fresh()['ready'],[self.works[3]])
            self.accept_next(); outcomes.append((self.fresh()['state'],self.states()))
        self.assertEqual(outcomes[0],outcomes[1])
        self.assertEqual(outcomes[0],('COMPLETE',['ACCEPTED']*4))

    def test_partial_failure_retains_acceptance_and_exact_branches(self):
        self.graph([[],[],[0],[1],[0,1],[]])
        wave=dag.claim_wave(self.r,self.e,CONTROL)
        attempts=[self.start(d) for d in wave]
        self.finish(wave[0],attempts[0])
        isolation.cancel(self.r,attempts[1],CONTROL)
        isolation.operation(self.r,attempts[1],'stop',self.host,CONTROL)
        isolation.record_fence(self.r,attempts[1],CONTROL)
        dag.disposition(self.r,self.e,wave[1]['work_id'],'FAILED','Independent rejected fixture, exact cessation proven',HUMAN)
        self.assertEqual(self.states(),['ACCEPTED','FAILED','READY','BLOCKED','BLOCKED','READY'])
        self.assertEqual(self.fresh()['state'],'BLOCKED')
        wave=dag.claim_wave(self.r,self.e,CONTROL)
        self.assertEqual([d['work_id'] for d in wave],[w for w in self.plan['dag']['topological_order'] if w in {self.works[2],self.works[5]}])

    def test_human_gate_does_not_serialize_independent_work(self):
        self.graph([[],[],[],[0]])
        wave=dag.claim_wave(self.r,self.e,CONTROL)
        attempts=[self.start(d) for d in wave]
        dag.disposition(self.r,self.e,wave[0]['work_id'],'HUMAN_GATE','Principal architecture judgement',HUMAN)
        self.assertEqual(self.fresh()['state'],'ACTIVE')
        self.finish(wave[1],attempts[1])
        next_claim=dag.claim(self.r,self.e,CONTROL)
        self.assertEqual(next_claim['work_id'],self.works[2])
        self.assertEqual(self.fresh()['available_capacity'],0)
        self.assertEqual(self.states(),['NEEDS_HUMAN','ACCEPTED','DISPATCHED','WAITING_DEPENDENCY'])

    def test_unknown_retains_exact_slot_while_sibling_can_progress(self):
        self.graph([[],[],[],[0]])
        wave=dag.claim_wave(self.r,self.e,CONTROL)
        a=self.start(wave[0],run=False)
        isolation.operation(self.r,a,'clone',self.host,CONTROL); self.host.fail='start'
        with self.assertRaises(TimeoutError): isolation.operation(self.r,a,'start',self.host,CONTROL)
        self.host.fail=None
        b=self.start(wave[1]); self.finish(wave[1],b)
        state=self.fresh(); self.assertEqual(state['available_capacity'],1)
        self.assertIn('EXECUTION_OWNERSHIP_UNCERTAIN',json.dumps(state))
        self.assertEqual(dag.claim(self.r,self.e,CONTROL)['work_id'],self.works[2])
        with self.assertRaises(ACPError): dag.claim(self.r,self.e,CONTROL)
        self.assertEqual(self.fresh()['available_capacity'],0)
        with self.assertRaises(sqlite3.IntegrityError): self.r.db.execute('DELETE FROM dag_slots WHERE dispatch_id=?',(wave[0]['id'],))

    def test_ack_denied_fence_releases_only_its_slot_once(self):
        self.graph([[],[],[]])
        wave=dag.claim_wave(self.r,self.e,CONTROL); a,b=[self.start(d) for d in wave]
        isolation.cancel(self.r,a,CONTROL)
        isolation.observe(self.r,a,'CANCEL_ACKNOWLEDGED',{'not_cessation':True},CONTROL)
        self.assertEqual(self.fresh()['available_capacity'],0)
        with self.assertRaises(sqlite3.IntegrityError): self.r.db.execute('DELETE FROM dag_slots WHERE dispatch_id=?',(wave[0]['id'],))
        isolation.operation(self.r,a,'stop',self.host,CONTROL); isolation.record_fence(self.r,a,CONTROL)
        state=self.fresh(); self.assertEqual(state['available_capacity'],1)
        self.assertEqual(state['active_dispatches'],[wave[1]['id']])
        self.assertEqual(self.r.db.execute("SELECT count(*) FROM dag_facts WHERE kind='SLOT_RELEASED_FENCED'").fetchone()[0],1)
        self.fresh(); self.assertEqual(self.r.db.execute("SELECT count(*) FROM dag_facts WHERE kind='SLOT_RELEASED_FENCED'").fetchone()[0],1)
        self.assertEqual(dag.claim(self.r,self.e,CONTROL)['work_id'],self.works[2])
        with self.assertRaises(ACPError): dag.allocate(self.r,wave[0]['id'],CONTROL)

    def test_four_competing_controllers_cannot_exceed_capacity(self):
        self.graph([[],[],[],[],[]])
        code="from acp.runtime import Runtime; from acp import dag; from tests.test_isolation import CONTROL; import sys,json; r=Runtime(sys.argv[1]); print(json.dumps(dag.claim(r,sys.argv[2],CONTROL))); r.close()"
        ps=[subprocess.Popen([sys.executable,'-B','-c',code,str(self.root/'state'),self.e],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(4)]
        outputs=[p.communicate(timeout=30) for p in ps]
        self.assertEqual(sum(p.returncode==0 for p in ps),2,outputs)
        claims=[json.loads(o[0]) for p,o in zip(ps,outputs) if p.returncode==0]
        self.assertEqual({d['work_id'] for d in claims},set(self.works[:2]))
        self.assertEqual({d['slot_no'] for d in claims},{1,2})
        for d in claims:
            results=self.race('dag.allocate(r,'+repr(d['id'])+',a)')
            self.assertTrue(all(p[0]==0 for p in results),results)
            self.assertEqual(len({json.loads(p[1])['id'] for p in results}),1)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM execution_attempts').fetchone()[0],2)
        self.assertEqual(self.fresh()['available_capacity'],0)

    def test_sql_constraints_block_overcapacity_and_reassignment(self):
        self.graph([[],[],[]]); claims=dag.claim_wave(self.r,self.e,CONTROL)
        with self.assertRaises(sqlite3.IntegrityError): self.r.db.execute('UPDATE dag_slots SET slot_no=3')
        # Even direct trusted SQL cannot create capacity beyond sealed policy.
        with self.assertRaises(sqlite3.IntegrityError): self.r.db.execute('INSERT INTO dag_slots VALUES (?,?,3)',(self.e,claims[0]['id']))
        self.assertEqual(self.fresh()['available_capacity'],0)

    def test_competing_vm_reservation_invocation_and_fence_release(self):
        self.graph([[],[],[]]); wave=dag.claim_wave(self.r,self.e,CONTROL)
        a=dag.allocate(self.r,wave[0]['id'],CONTROL)['id']; dag.allocate(self.r,wave[1]['id'],CONTROL)
        code="from acp.runtime import Runtime; from acp import isolation; from tests.test_isolation import TestOnlyHost,CONTROL; import sys; r=Runtime(sys.argv[1]); print(isolation.reserve(r,sys.argv[2],TestOnlyHost(),CONTROL)['id']); r.close()"
        ps=[subprocess.Popen([sys.executable,'-B','-c',code,str(self.root/'state'),a],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        outputs=[p.communicate(timeout=30) for p in ps]
        self.assertEqual(sum(p.returncode==0 for p in ps),1,outputs)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM isolation_instances').fetchone()[0],1)
        code="""from pathlib import Path
from acp.runtime import Runtime
from acp import isolation
from tests.test_isolation import TestOnlyHost,CONTROL
import sys
r=Runtime(sys.argv[1]); h=TestOnlyHost()
def once(*args):
 with Path(sys.argv[3]).open('x') as f: f.write('one')
 return {'test_only':True}
h.perform=once
isolation.operation(r,sys.argv[2],'clone',h,CONTROL)
r.close()
"""
        marker=self.root/'one-clone.txt'
        ps=[subprocess.Popen([sys.executable,'-B','-c',code,str(self.root/'state'),a,str(marker)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        outputs=[p.communicate(timeout=30) for p in ps]
        self.assertEqual(sum(p.returncode==0 for p in ps),1,outputs); self.assertEqual(marker.read_text(),'one')
        for op in ('start','prepare'): isolation.operation(self.r,a,op,self.host,CONTROL)
        isolation.cancel(self.r,a,CONTROL); isolation.operation(self.r,a,'stop',self.host,CONTROL); isolation.record_fence(self.r,a,CONTROL)
        results=self.race('dag.refresh(r,sys.argv[2],a)')
        self.assertTrue(all(p[0]==0 for p in results),results)
        self.assertEqual(self.fresh()['available_capacity'],1)
        self.assertEqual(self.r.db.execute("SELECT count(*) FROM dag_facts WHERE kind='SLOT_RELEASED_FENCED'").fetchone()[0],1)

    def test_competing_acceptances_unlock_and_finalization(self):
        self.graph([[],[],[0,1]])
        wave=dag.claim_wave(self.r,self.e,CONTROL); attempts=[self.start(d) for d in wave]
        evidence=[self.finish(d,a,accept=False) for d,a in zip(wave,attempts)]
        commands=[]
        for d,e in zip(wave,evidence):
            code="from acp.runtime import Runtime; from acp import dag; from tests.test_isolation import HUMAN; import sys; r=Runtime(sys.argv[1]); dag.accept(r,sys.argv[2],sys.argv[3],{'synthetic-write':sys.argv[4]},HUMAN); r.close()"
            commands.append([sys.executable,'-B','-c',code,str(self.root/'state'),self.e,d['work_id'],e])
        ps=[subprocess.Popen(c,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for c in commands]
        outputs=[p.communicate(timeout=30) for p in ps]
        self.assertTrue(all(p.returncode==0 for p in ps),outputs)
        self.assertEqual(self.fresh()['ready'],[self.works[2]])
        i,a,e=self.review()
        code="from acp.runtime import Runtime; from acp import dag; from tests.test_isolation import HUMAN; import sys; r=Runtime(sys.argv[1]); dag.accept(r,sys.argv[2],sys.argv[3],{'synthetic-write':sys.argv[4]},HUMAN); r.close()"
        accept=subprocess.Popen([sys.executable,'-B','-c',code,str(self.root/'state'),self.e,i['work_id'],e['synthetic-write']],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        races=self.race('dag.accept_plan(r,sys.argv[2],h)')
        output=accept.communicate(timeout=30); self.assertEqual(accept.returncode,0,output)
        self.assertEqual(self.fresh()['state'],'COMPLETE')
        self.race('dag.accept_plan(r,sys.argv[2],h)')
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_plan_acceptances').fetchone()[0],1)
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM dag_acceptances').fetchone()[0],3)

    def test_active_legacy_v7_migration_preserves_authority(self):
        with patch.object(dag,'DEFAULT_PARALLEL',1):
            fixture_module.DAGTests.graph(self,[[],[0]])
        i=dag.claim(self.r,self.e,CONTROL); a=dag.allocate(self.r,i['id'],CONTROL)['id']
        isolation.reserve(self.r,a,self.host,CONTROL)
        # Construct exact old two-column slot schema in this disposable fixture.
        self.r.close(); db=sqlite3.connect(self.root/'state/acp.sqlite3')
        with db:
            from tests.schema_fixture import drop_review
            drop_review(db,keep_dag=True)
            data=json.loads(db.execute('SELECT record_json FROM dag_executions WHERE id=?',(self.e,)).fetchone()[0]); del data['concurrency']
            trigger=db.execute("SELECT sql FROM sqlite_master WHERE name='dag_executions_update'").fetchone()[0]
            db.execute('DROP TRIGGER dag_executions_update'); db.execute('UPDATE dag_executions SET record_json=?,digest=? WHERE id=?',(canonical_json(data),digest(data),self.e)); db.execute(trigger)
            slots=db.execute('SELECT execution_id,dispatch_id FROM dag_slots').fetchall()
            db.execute('DROP TABLE dag_slots'); db.execute('CREATE TABLE dag_slots (execution_id TEXT PRIMARY KEY REFERENCES dag_executions(id),dispatch_id TEXT UNIQUE NOT NULL REFERENCES dag_dispatches(id))')
            db.executemany('INSERT INTO dag_slots VALUES (?,?)',slots)
            trigger=db.execute("SELECT sql FROM sqlite_master WHERE name='schema_metadata_delete'").fetchone()[0]
            db.execute('DROP TRIGGER schema_metadata_delete'); db.execute('DELETE FROM schema_metadata WHERE version>=8'); db.execute(trigger); db.execute('PRAGMA user_version=7')
        before={t:[tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in ('dag_executions','dag_nodes','dag_edges','dag_dispatches','dag_allocations','dag_facts','execution_attempts','isolation_instances')}; db.close()
        self.r=Runtime(self.root/'state')
        self.assertEqual(before,{t:[tuple(r) for r in self.r.db.execute('SELECT '+('id,execution_id,work_id,record_json,digest' if t=='dag_dispatches' else '*')+' FROM '+t)] for t in before})
        self.assertEqual([tuple(r) for r in self.r.db.execute('SELECT execution_id,dispatch_id FROM dag_slots')],slots)
        with patch.object(dag,'DEFAULT_PARALLEL',4):
            self.assertEqual(self.fresh()['capacity'],1); self.assertEqual(self.fresh()['available_capacity'],0)
        self.assertEqual(self.r.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_unapproved_ready_does_not_block_authorized_eligible_order(self):
        self.graph([[],[],[]],bind=False)
        # Root A is merely logically READY; B/C have exact separate grants.
        for wid in self.works[1:]:
            b=dag.bind(self.r,self.e,wid,TEMPLATE,HUMAN)
            self.r.approve(b['task_id'],'human',HUMAN,'2099-01-01T00:00:00+00:00')
            self.r.transition(b['task_id'],'READY',HUMAN,'Exact synthetic grant')
        wave=dag.claim_wave(self.r,self.e,CONTROL)
        self.assertEqual([d['work_id'] for d in wave],self.works[1:])
        self.assertEqual(self.fresh()['ready'],[self.works[0]])
        self.assertEqual(wave[0]['skipped_ready'],[{'work_id':self.works[0],'reason':'UNMAPPED'}])
        self.assertEqual(self.r.db.execute('SELECT count(*) FROM execution_attempts').fetchone()[0],0)


# Do not rerun inherited M09 tests under a different policy and pretend that
# represents unchanged single-dispatch regression. Original tests run normally.
for _name in dir(fixture_module.DAGTests):
    if _name.startswith('test_'):
        setattr(ParallelTests,_name,None)
