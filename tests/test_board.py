"""M12 deterministic operator/control proofs. Fake VM facts are test-only."""
import ast
import http.client
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from acp import awareness, board_commands as commands, board_read, dag, isolation, review
from acp.board import ASSETS, BoardServer
from acp.domain import ACPError
from acp.runtime import Runtime
from acp.review_provider import SyntheticReviewProvider
from tests.test_review import ReviewTests
from tests.test_isolation import HUMAN, CONTROL


class BoardTests(unittest.TestCase):
    setUp=ReviewTests.setUp
    graph=ReviewTests.graph
    states=ReviewTests.states
    enrolled=ReviewTests.enrolled
    finish=ReviewTests.finish
    raw=ReviewTests.raw
    decision=ReviewTests.decision
    correction=ReviewTests.correction

    def snap(self):return board_read.snapshot(self.r)

    def run_command(self,action,payload):
        return commands.execute(self.r,action,payload,board_read.version(self.r))

    def test_empty_registry_safe_boundary(self):
        s=self.snap()
        self.assertEqual(s['projects'][0]['id'],'demo')
        self.assertNotIn('path',s['projects'][0])
        self.assertIn('NOT DEMONSTRATED',s['provider_status']['real'])
        self.assertIn('no-NIC',s['capability'])

    def test_read_projection_does_not_mutate_or_grant(self):
        self.enrolled([[],[0]])
        before=board_read.version(self.r)
        for _ in range(3):s=self.snap();commands.available(self.r)
        self.assertEqual(before,board_read.version(self.r))
        self.assertEqual(s['counts']['READY / QUEUED'],1)
        self.assertEqual(s['counts']['WAITING'],1)
        self.assertFalse(s['plans'][0]['plan_accepted'])

    def test_reviewer_pass_is_not_canonical_acceptance(self):
        self.enrolled();_,_,_,_,run=self.finish()
        self.raw(run);review.validate(self.r,run['id'],CONTROL)
        v=self.snap()['plans'][0]['nodes'][0]['reviews'][0]
        self.assertEqual(v['reviewer_verdict'],'PASS');self.assertEqual(v['acp_decision'],'NOT_DECIDED')
        self.assertEqual(self.snap()['counts']['DONE / ACCEPTED'],0)
        review.finalize(self.r,run['id'],CONTROL)
        self.assertEqual(self.snap()['counts']['DONE / ACCEPTED'],1)
        self.assertFalse(self.snap()['plans'][0]['plan_accepted'])

    def test_full_criteria_and_metadata_view(self):
        self.enrolled();_,_,_,_,run=self.finish();self.decision(run)
        r=self.snap()['plans'][0]['nodes'][0]['reviews'][0]
        self.assertEqual(len(r['criteria']),8);self.assertEqual(len(r['coverage']),8)
        self.assertEqual({c['level'] for c in r['criteria']},{'source','execution'})
        self.assertEqual(r['acp_decision'],'ACCEPTED')

    def test_named_gate_and_exact_canonical_resolution(self):
        self.graph([[],[0]])
        dag.disposition(self.r,self.e,self.works[0],'HUMAN_GATE','Architecture judgement',HUMAN)
        self.assertEqual(self.snap()['counts']['NEEDS_HUMAN'],1)
        self.assertEqual(self.snap()['needs_human'][0]['remaining_blocked'],[1])
        result=self.run_command('resolve_gate',{'execution':self.e,'work':self.works[0],'reason':'Principal resolved named architecture choice'})
        self.assertEqual(result['applied'],'resolve_gate')
        self.assertEqual(dag.show(self.r,self.e)['nodes'][0]['state'],'READY')

    def test_planning_assessment_not_resolvable_as_named_gate(self):
        self.graph([[]])
        with self.assertRaises(ACPError):self.run_command('resolve_gate',{'execution':self.e,'work':self.works[0],'reason':'invented gate'})

    def test_stale_state_rejected_without_overwrite(self):
        self.graph([[]]);version=board_read.version(self.r)
        dag.disposition(self.r,self.e,self.works[0],'HUMAN_GATE','New canonical decision',HUMAN)
        with self.assertRaisesRegex(ACPError,'STALE_STATE'):
            commands.execute(self.r,'cancel_work',{'execution':self.e,'work':self.works[0],'reason':'old button'},version)
        self.assertEqual(dag.show(self.r,self.e)['nodes'][0]['state'],'NEEDS_HUMAN')

    def test_unknown_worker_prominent_retained_capacity_no_retry_or_cancel(self):
        self.enrolled();intent=dag.claim(self.r,self.e,CONTROL);a=dag.allocate(self.r,intent['id'],CONTROL)['id']
        isolation.reserve(self.r,a,self.host,CONTROL)
        for op in ('clone','start','prepare'):isolation.operation(self.r,a,op,self.host,CONTROL)
        isolation.cancel(self.r,a,CONTROL);dag.refresh(self.r,self.e,CONTROL)
        n=self.snap()['plans'][0]['nodes'][0]
        self.assertTrue(n['unknown']);self.assertTrue(n['capacity_reserved'])
        self.assertEqual(n['display_state'],'BLOCKED / UNKNOWN')
        self.assertIn('Retry is prohibited',n['explanation'])
        self.assertFalse(any(c['action']=='cancel_work' for c in commands.available(self.r)))
        with self.assertRaises(ACPError):self.run_command('cancel_work',{'execution':self.e,'work':self.works[0],'reason':'ACK is not proof'})

    def test_unknown_review_is_not_spinner_or_available_capacity(self):
        self.enrolled();_,_,_,_,run=self.finish();review.dispatch(self.r,run['id'],CONTROL)
        n=self.snap()['plans'][0]['nodes'][0]
        self.assertTrue(n['unknown']);self.assertTrue(n['review_capacity_reserved'])
        self.assertEqual(n['reviews'][0]['state'],'REVIEW_PROVIDER_OUTCOME_UNKNOWN')

    def test_retry_lineage_keeps_failed_generation_and_fence(self):
        self.enrolled();_,a,_,_,run=self.finish(True);self.decision(run)
        isolation.record_fence(self.r,a,CONTROL);review.retry(self.r,run['id'],self.correction(run),CONTROL)
        _,b,_,_,next_run=self.finish();self.decision(next_run)
        p=self.snap()['plans'][0];n=p['nodes'][0]
        self.assertEqual([g['generation'] for g in n['generations']],[0,1])
        self.assertNotEqual(a,b);self.assertTrue(n['generations'][0]['quarantined'])
        self.assertTrue(n['generations'][0]['fence']);self.assertEqual(n['retry_count'],1)
        self.assertEqual([v['acp_decision'] for v in n['reviews']],['REWORK_REQUIRED','ACCEPTED'])
        self.assertIn('RETRY_AUTHORIZED',[v['kind'] for v in p['timeline']])

    def test_exhausted_human_packet_counters(self):
        self.enrolled(budget=0);_,a,_,_,run=self.finish(True);self.decision(run)
        isolation.record_fence(self.r,a,CONTROL);review.retry(self.r,run['id'],self.correction(run),CONTROL)
        s=self.snap();self.assertEqual(s['counts']['NEEDS_HUMAN'],1)
        self.assertIn('RETRY_EXHAUSTED',s['needs_human'][0]['reason'])
        self.assertEqual(s['needs_human'][0]['retry_budget'],0)

    def test_audit_is_reconstructible_after_fresh_process_restart(self):
        self.enrolled();_,_,_,_,run=self.finish();self.decision(run)
        expected=self.snap()
        code='import json,sys;from acp.runtime import Runtime;from acp.board_read import snapshot;\nwith Runtime(sys.argv[1]) as r: print(json.dumps(snapshot(r),sort_keys=True))'
        p=subprocess.run([sys.executable,'-B','-c',code,str(self.root/'state')],capture_output=True,text=True,encoding='utf-8',timeout=30)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout),expected)

    def test_explicit_plan_acceptance_separate_from_complete(self):
        self.enrolled();_,_,_,_,run=self.finish();self.decision(run)
        self.assertFalse(self.snap()['plans'][0]['plan_accepted'])
        self.run_command('accept_plan',{'execution':self.e})
        self.assertTrue(self.snap()['plans'][0]['plan_accepted'])

    def test_premature_plan_acceptance_unavailable(self):
        self.graph([[]])
        with self.assertRaises(ACPError):self.run_command('accept_plan',{'execution':self.e})

    def test_reject_cancel_map_to_domain_and_block_children(self):
        self.graph([[],[0]])
        with patch.object(dag,'disposition',wraps=dag.disposition) as call:
            self.run_command('reject_work',{'execution':self.e,'work':self.works[0],'reason':'Principal rejects bounded work'})
            self.assertEqual(call.call_args.args[3],'FAILED')
        self.assertEqual([n['state'] for n in dag.show(self.r,self.e)['nodes']],['FAILED','BLOCKED'])

    def test_delegation_revocation_visible_and_immutable(self):
        self.enrolled()
        self.run_command('revoke_review',{'execution':self.e,'reason':'Principal pauses delegation'})
        with self.assertRaises(ACPError):review.authority(self.r,self.e,self.works[0])
        self.assertFalse(any(c['action']=='revoke_review' for c in commands.available(self.r)))

    def test_enroll_exact_mapping_and_original_scope(self):
        self.graph([[]])
        action=next(c for c in commands.available(self.r) if c['action']=='enroll_review')
        payload={**action['payload'],'budget':1,'expires_at':'2099-01-01T00:00:00+00:00'}
        self.run_command('enroll_review',payload)
        self.assertEqual(review.enrollment(self.r,self.e)['delegation']['scope'],['allowed.txt'])

    def test_invalid_mapping_does_not_delegate(self):
        self.graph([[]])
        with self.assertRaises(ACPError):self.run_command('enroll_review',{'execution':self.e,'mapping':{},'budget':2,'expires_at':'2099-01-01T00:00:00+00:00'})
        self.assertIsNone(review.enrollment(self.r,self.e))

    def test_intake_ambiguous_and_unresolved_do_not_guess(self):
        for text in ('unknown project goal','demo and other goal'):
            if 'other' in text:
                project=self.root/'other';project.mkdir();self.r.project_add('other',project)
            before=len(self.r.task_list())
            result=self.run_command('intake',{'request':text,'project':''})
            self.assertIn(result['outcome'],{'AMBIGUOUS','UNRESOLVED'})
            self.assertEqual(len(self.r.task_list()),before)
        self.assertEqual(len(self.snap()['resolutions']),2)

    def test_natural_language_context_prepare_no_provider_execution(self):
        result=self.run_command('intake',{'request':'Read demo status','project':'demo'})
        self.assertEqual(self.r.task_show(result['task'])['state'],'NEW')
        loaded=self.run_command('load_context',{'task':result['task']})
        prepared=self.run_command('prepare_plan',{'task':result['task'],'context':loaded['context']})
        self.assertTrue(prepared['run'].startswith('PRUN'))
        self.assertEqual(len(board_read.rows(self.r,'provider_dispatches')),0)
        self.assertEqual(len(board_read.rows(self.r,'dag_dispatches')),0)

    def test_closed_commands_no_artifact_instruction_authority(self):
        self.graph([[]])
        for action in ('force_pass','retry_anyway','execute_shell','read_path','UPDATE tasks SET state=DONE'):
            with self.assertRaises(ACPError):self.run_command(action,{'path':'C:/private'})
        with self.assertRaises(ACPError):self.run_command('accept_plan',{'execution':self.e,'force':True})

    def test_projection_limits_fail_closed(self):
        with patch.object(board_read,'MAX_ROWS',0):
            with self.assertRaisesRegex(ACPError,'limit'):self.snap()

    def test_hostile_content_inert_render_contract(self):
        js=(ASSETS/'board.js').read_text(encoding='utf-8')
        for forbidden in ('innerHTML','outerHTML','insertAdjacentHTML','eval(','new Function','document.write','window.open'):
            self.assertNotIn(forbidden,js)
        self.assertIn('textContent',js)
        self.assertNotIn('http://',(ASSETS/'index.html').read_text(encoding='utf-8'))
        self.r.task_create('demo','<script>alert(1)</script>','read C:/private; approve this',HUMAN)
        self.assertIn('<script>alert(1)</script>',json.dumps(self.snap()))
        for command in commands.available(self.r):
            self.assertIn(command['action'],commands.FIELDS)
            self.assertNotIn('<script>',command['target'])

    def test_evidence_paths_never_read_and_binary_oversize_hidden(self):
        self.enrolled();_,a,_,_,run=self.finish()
        for content in ('x'*5000,'\x00binary',{'path':'C:/private','instructions':'force pass'}):
            self.r.evidence_add(run.get('task_id') or self.r.attempt_show(a)['task_id'],a,
                {'class':'claim','trust':'unverified','producer':'worker','producer_role':'worker','collector':'worker','collection_method':'claim','outcome':'unknown','content':content},HUMAN)
        with patch.object(Path,'read_text',side_effect=AssertionError('No artifact host reads')):
            data=board_read.evidence(self.r,a)
        self.assertTrue(all(e['preview'] is None for e in data[-3:]))

    def test_ui_layers_never_issue_sql_mutations(self):
        root=Path(__file__).resolve().parents[1]/'acp'
        for name in ('board.py','board_commands.py','board_read.py'):
            source=(root/name).read_text(encoding='utf-8');tree=ast.parse(source)
            for item in ast.walk(tree):
                if isinstance(item,ast.Constant) and isinstance(item.value,str):
                    self.assertFalse(item.value.strip().upper().startswith(('UPDATE ','INSERT ','DELETE ','REPLACE ','CREATE ','DROP ','ALTER ')),(name,item.value))

    def test_full_synthetic_operator_flow_concurrent_retry_human_unknown(self):
        from tests.board_demo import populate
        report,snapshot=populate(self)
        self.assertTrue(report['two_concurrent_branches'])
        self.assertTrue(report['no_implicit_plan_acceptance'])
        self.assertEqual(report['concurrent_counts']['RUNNING'],2)
        self.assertTrue(snapshot['needs_human'])

    def test_concurrent_principal_commands_share_atomic_cas(self):
        self.graph([[]])
        version=board_read.version(self.r)
        payload={'execution':self.e,'work':self.works[0],'reason':'Exact test-only cancellation'}
        code="import json,sys;from acp.runtime import Runtime;from acp.board_commands import execute;\nwith Runtime(sys.argv[1]) as r: print(json.dumps(execute(r,'cancel_work',json.loads(sys.argv[2]),sys.argv[3])))"
        processes=[subprocess.Popen([sys.executable,'-B','-c',code,str(self.root/'state'),json.dumps(payload),version],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        results=[(p,p.communicate(timeout=30)) for p in processes]
        self.assertEqual(sorted(p.returncode for p,_ in results),[0,1])
        self.assertIn('STALE_STATE',next(err.decode() for p,(_,err) in results if p.returncode))
        self.assertEqual(len([x for x in board_read.rows(self.r,'dag_facts') if x['kind']=='CANCELLED']),1)

    def test_existing_only_store_never_creates_or_migrates(self):
        with self.assertRaises(Exception):Runtime(self.root/'absent',existing_only=True)
        self.assertFalse((self.root/'absent').exists())
        with patch.object(type(self.r.store),'_migrate',side_effect=AssertionError('UI startup must not migrate')):
            with Runtime(self.root/'state',existing_only=True) as fresh:
                self.assertEqual(board_read.version(fresh),board_read.version(self.r))

    def test_unmaterialized_plan_dag_visible_without_mutation(self):
        self.graph([[],[0]],bind=False,materialize=False)
        before=board_read.version(self.r)
        p=self.snap()['plans'][0]
        self.assertEqual([n['state'] for n in p['nodes']],['UNMATERIALIZED','UNMATERIALIZED'])
        self.assertEqual(before,board_read.version(self.r))

    def test_standalone_legacy_task_states_are_not_hidden(self):
        from tests.test_runtime import envelope
        task=self.r.task_create('demo','Standalone legacy work','Synthetic only',HUMAN)['id']
        self.r.transition(task,'NEEDS_HUMAN',HUMAN,'Principal choice')
        s=self.snap();self.assertEqual(s['counts']['NEEDS_HUMAN'],1)
        self.assertTrue(any(t['id']==task for t in s['tasks']))
        active=self.r.task_create('demo','Standalone running work','Synthetic only',HUMAN)['id']
        self.r.transition(active,'TRIAGE',HUMAN,'Synthetic triage')
        self.r.plan(active,envelope(self.r.project_show('demo')),HUMAN,'Synthetic approved contract')
        approval=self.r.approve(active,'human',HUMAN,'2099-01-01T00:00:00+00:00')['id']
        self.r.transition(active,'READY',HUMAN,'Approved')
        attempt=self.r.attempt_create(active,approval,HUMAN)['id']
        from acp.adapters import SyntheticAdapter
        self.r.adapter_operation(attempt,'submit',SyntheticAdapter('running'),CONTROL)
        s=self.snap();self.assertEqual(s['counts']['RUNNING'],1)
        self.assertEqual(next(t['attempt_state'] for t in s['tasks'] if t['id']==active),'RUNNING')


class HTTPBoardTests(BoardTests):
    # Do not inherit/duplicate projection tests; discovery filters below.
    def server(self):
        server=BoardServer(self.root/'state',0)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        self.port=server.server_address[1];self.http=server
        status,headers,page=self.request('GET','/')
        self.cookie=headers['Set-Cookie'].split(';')[0]
        status,_,data=self.request('GET','/api/session',headers={'Cookie':self.cookie})
        self.csrf=json.loads(data)['csrf']
        return server

    def request(self,method,path,value=None,headers=None):
        h={'Host':f'127.0.0.1:{self.port}',**(headers or {})}
        if value is not None:h.update({'Content-Type':'application/json','Origin':f'http://127.0.0.1:{self.port}','X-ACP-CSRF':getattr(self,'csrf',''),'Cookie':getattr(self,'cookie','')})
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        conn.request(method,path,body=json.dumps(value) if value is not None else None,headers=h)
        response=conn.getresponse();result=(response.status,dict(response.getheaders()),response.read());conn.close();return result

    def test_http_loopback_and_security_headers(self):
        self.server();status,h,page=self.request('GET','/')
        self.assertEqual(status,200);self.assertIn("frame-ancestors 'none'",h['Content-Security-Policy'])
        self.assertIn('HttpOnly',h['Set-Cookie']);self.assertIn('SameSite=Strict',h['Set-Cookie'])
        with self.assertRaises(ACPError):BoardServer(self.root/'state',0,host='0.0.0.0')

    def test_http_no_get_mutation_or_path_reads(self):
        self.server()
        for path in ('/api/command','/api/confirm','/../../private','/api/evidence?path=C:/private'):
            self.assertEqual(self.request('GET',path,headers={'Cookie':self.cookie})[0],404)

    def test_http_csrf_origin_host_and_session_rejection(self):
        self.server();value={'action':'intake','payload':{'request':'demo goal','project':'demo'},'version':board_read.version(self.r)}
        # request helper deliberately supplies valid defaults only when value provided.
        for field,bad in (('Origin','http://evil.test'),('Host','evil.test'),('X-ACP-CSRF','bad'),('Cookie','')):
            headers={'Host':f'127.0.0.1:{self.port}','Content-Type':'application/json','Origin':f'http://127.0.0.1:{self.port}','X-ACP-CSRF':self.csrf,'Cookie':self.cookie,field:bad}
            c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5);c.request('POST','/api/confirm',json.dumps(value),headers)
            r=c.getresponse();self.assertEqual(r.status,403);r.read();c.close()

    def test_http_confirmation_once_and_stale_rejection(self):
        self.graph([[]]);self.server()
        value={'action':'cancel_work','payload':{'execution':self.e,'work':self.works[0],'reason':'Deliberate cancel'},'version':board_read.version(self.r)}
        status,_,data=self.request('POST','/api/confirm',value);self.assertEqual(status,200)
        token=json.loads(data)['confirmation'];self.assertEqual(dag.show(self.r,self.e)['nodes'][0]['state'],'READY')
        dag.disposition(self.r,self.e,self.works[0],'HUMAN_GATE','Newer Principal decision',HUMAN)
        status,_,data=self.request('POST','/api/command',{'confirmation':token})
        self.assertEqual(status,409);self.assertFalse(json.loads(data)['applied'])
        self.assertEqual(self.request('POST','/api/command',{'confirmation':token})[0],403)

    def test_http_mutation_success_and_restart_no_authority(self):
        self.enrolled();_,_,_,_,run=self.finish();self.decision(run);self.server()
        before=board_read.version(self.r)
        for _ in range(2):self.assertEqual(self.request('GET','/api/state',headers={'Cookie':self.cookie})[0],200)
        self.assertEqual(before,board_read.version(self.r))
        value={'action':'accept_plan','payload':{'execution':self.e},'version':before}
        status,_,data=self.request('POST','/api/confirm',value);self.assertEqual(status,200)
        self.assertIn('current_state',json.loads(data)['packet'])
        self.assertEqual(self.request('POST','/api/command',{'confirmation':json.loads(data)['confirmation']})[0],200)
        self.assertTrue(dag.show(self.r,self.e)['plan_accepted'])
        after=board_read.version(self.r)
        with BoardServer(self.root/'state',0):pass
        self.assertEqual(after,board_read.version(self.r))

    def test_http_storage_unavailable_not_stale_green(self):
        self.server()
        with patch.object(self.http,'runtime',side_effect=sqlite_error()):
            status,_,data=self.request('GET','/api/state',headers={'Cookie':self.cookie})
        self.assertEqual(status,503);self.assertIn('unavailable',json.loads(data)['error'])

    def test_http_no_implicit_database_initialization(self):
        with self.assertRaises(ACPError):BoardServer(self.root/'missing-state',0)
        self.assertFalse((self.root/'missing-state'/'acp.sqlite3').exists())

    def test_http_confirmation_session_bound_and_expired(self):
        self.server()
        value={'action':'intake','payload':{'request':'demo synthetic goal','project':'demo'},'version':board_read.version(self.r)}
        status,_,data=self.request('POST','/api/confirm',value);self.assertEqual(status,200)
        token=json.loads(data)['confirmation']
        old_cookie,old_csrf=self.cookie,self.csrf
        sid,session=self.http.new_session();self.cookie='acp_board='+sid;self.csrf=session['csrf']
        self.assertEqual(self.request('POST','/api/command',{'confirmation':token})[0],403)
        self.cookie,self.csrf=old_cookie,old_csrf
        session=self.http.session(self.cookie);session['confirmations'][token]['expires']=0
        self.assertEqual(self.request('POST','/api/command',{'confirmation':token})[0],403)
        self.assertEqual(len(board_read.rows(self.r,'resolutions')),0)

    def test_http_malformed_duplicate_keys_and_oversize_rejected(self):
        self.server()
        for body in ('{"action":"intake","action":"force_pass"}', 'x'*65537):
            conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
            conn.request('POST','/api/confirm',body,{'Host':f'127.0.0.1:{self.port}','Origin':f'http://127.0.0.1:{self.port}','Content-Type':'application/json','X-ACP-CSRF':self.csrf,'Cookie':self.cookie})
            r=conn.getresponse();self.assertEqual(r.status,403);r.read();conn.close()
        self.assertEqual(len(board_read.rows(self.r,'resolutions')),0)


def sqlite_error():
    import sqlite3
    return sqlite3.OperationalError('synthetic unavailable')


# Keep fixture helpers but avoid duplicated inherited tests in HTTP test class.
def load_tests(loader, tests, pattern):
    suite=unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(BoardTests))
    suite.addTests(HTTPBoardTests(name) for name in HTTPBoardTests.__dict__ if name.startswith('test_http_'))
    return suite
