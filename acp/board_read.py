"""Bounded, read-only Principal projections. No host artifact reads or authority."""
import json
from collections import Counter

from . import awareness, dag, isolation, review
from .domain import digest, require

MAX_ROWS = 5000


def rows(runtime, table):
    # Names originate from SQLite's schema, never browser input.
    names = {r[0] for r in runtime.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    require(table in names and table.replace('_', '').isalnum(), 'Unknown projection table')
    result = [dict(r) for r in runtime.db.execute(f'SELECT * FROM "{table}" LIMIT ?', (MAX_ROWS + 1,))]
    require(len(result) <= MAX_ROWS, 'Control Board projection limit exceeded; use scoped CLI')
    return result


def version(runtime):
    """Conservative whole-store CAS, including authority and immutable facts."""
    result = {}
    for name, in runtime.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall():
        result[name] = sorted(rows(runtime, name), key=lambda r: json.dumps(r, sort_keys=True))
    return digest(result)


def record(row):
    value = json.loads(row['record_json'])
    require(digest(value) == row['digest'], 'Canonical record digest mismatch')
    return value


def evidence(runtime, attempt_id):
    result = []
    for row in rows(runtime, 'evidence'):
        if row['attempt_id'] != attempt_id:
            continue
        value = record(row)
        content = value.get('content')
        # Only inline text, never paths, URLs, blobs, tools or arbitrary record dumps.
        preview = content if isinstance(content, str) else content.get('artifact') if isinstance(content, dict) else None
        safe = isinstance(preview, str) and len(preview.encode('utf-8')) <= 4096 and not any(ord(c) < 32 and c not in '\n\r\t' for c in preview)
        result.append({'id': row['id'], 'class': row['class'], 'trust': row['trust'],
                       'attempt': attempt_id, 'digest': row['digest'],
                       'collector': value.get('collector'), 'verification': value.get('verification_reference'),
                       'preview': preview if safe else None,
                       'preview_status': 'bounded inert stored text' if safe else 'metadata only: oversized/binary/non-text'})
    return result


def review_view(runtime, row):
    run = record(row)
    detail = review.show(runtime, run['id'])
    last = detail['attempts'][-1]
    validation = last['validation']
    decision = detail['decision']
    return {'id': run['id'], 'work_id': run['work_id'], 'attempt': run['attempt_id'],
            'generation': run['generation'], 'revision': run['revision'],
            'provider': run.get('provider', review.PROVIDER), 'state': last['state'],
            'reviewer_verdict': validation['proposal'].get('verdict') if validation and validation['valid'] else None,
            'coverage': validation.get('coverage') if validation else None,
            'criteria': run['criteria'], 'manifest': [{k: m[k] for k in ('id','digest','class','trust','attempt_id')} for m in run['manifest']],
            'acp_decision': decision['outcome'] if decision else 'NOT_DECIDED',
            'reason': decision['reason'] if decision else None,
            'packet': decision.get('packet') if decision else None}


def explanation(reason):
    text = str(reason)
    if 'UNCERTAIN' in text or 'UNKNOWN' in text:
        return 'ACP cannot prove execution/review has stopped. Capacity remains reserved where held. Retry is prohibited until exact reconciliation/fencing proof exists.'
    if 'EXHAUSTED' in text:
        return 'The approved retry/evidence budget is exhausted. No automatic additional authority is available.'
    if 'DEPENDENCY' in text:
        return 'Required parent WorkItems have not been canonically accepted.'
    return 'ACP stopped at a canonical policy/decision boundary. Review the named reason, criteria and evidence; no force-pass is available.'


def plan_view(runtime, eid):
    state = dag.show(runtime, eid)  # Reading never calls refresh/recover/reserve.
    data = state['execution']
    enrollment = review.enrollment(runtime, eid)
    reviews = [review_view(runtime, x) for x in rows(runtime, 'review_runs') if x['execution_id'] == eid]
    retries = [record(x) for x in rows(runtime, 'review_retries') if x['execution_id'] == eid]
    links = {x['work_id']: x['task_id'] for x in rows(runtime, 'dag_links') if x['execution_id'] == eid}
    nodes = []
    canonical_nodes=state['nodes']
    if not canonical_nodes:
        canonical_nodes=[{'work_id':w['work_item_id'],'ordinal':i,'state':'UNMATERIALIZED','causes':['Graph not yet materialized; no execution authority']} for i,w in enumerate(data['works'])]
    for node, work in zip(canonical_nodes, data['works']):
        wid = node['work_id']
        task_id = links.get(wid)
        task = runtime.task_show(task_id) if task_id else None
        generations = []
        for d in sorted((x for x in rows(runtime, 'dag_dispatches') if x['execution_id'] == eid and x['work_id'] == wid), key=lambda x: x['generation']):
            allocation = next((x for x in rows(runtime, 'dag_allocations') if x['dispatch_id'] == d['id']), None)
            a = runtime.attempt_show(allocation['attempt_id']) if allocation else None
            instance = next((record(x) for x in rows(runtime, 'isolation_instances') if a and x['attempt_id'] == a['id']), None)
            saved = isolation.facts(runtime, a['id']) if instance else None
            pending = [i.get('operation') for i in saved['pending']] if saved else []
            uncertain = bool(a and (a['state'] in {'LOST','CANCEL_REQUESTED'} or pending))
            generations.append({'generation': d['generation'], 'dispatch': d['id'], 'retry': d.get('retry_id'),
                                'attempt': a['id'] if a else None, 'state': a['state'] if a else 'ALLOCATION_UNCERTAIN',
                                'allocated_at': a['created_at'] if a else None,
                                'started': next((o['at'] for o in (saved or {}).get('observations',[]) if o['kind']=='OPERATION_COMPLETED' and o['detail']['operation']=='start'),None),
                                'vm': instance['id'] if instance else None,
                                'fence': a['fence_evidence_id'] if a else None,
                                'quarantined': bool(a and a['quarantined']), 'ownership_uncertain': uncertain,
                                'missing_proof': pending, 'evidence': evidence(runtime, a['id']) if a else []})
        current = generations[-1] if generations else None
        own_reviews = [r for r in reviews if r['work_id'] == wid]
        unknown = bool(current and current['ownership_uncertain']) or any(r['state'] == 'REVIEW_PROVIDER_OUTCOME_UNKNOWN' and r['acp_decision'] == 'NOT_DECIDED' for r in own_reviews)
        reason = task['hold_reason'] if task and task['hold_reason'] else 'REVIEW_PROVIDER_OUTCOME_UNKNOWN' if any(r['state']=='REVIEW_PROVIDER_OUTCOME_UNKNOWN' and r['acp_decision']=='NOT_DECIDED' for r in own_reviews) else node['causes']
        display = 'BLOCKED / UNKNOWN' if unknown else task['state'] if task and task['state'] in {'NEEDS_HUMAN','BLOCKED'} and node['state']!='ACCEPTED' else node['state']
        if display in {'DISPATCHED','RUNNING','REVIEW'} and current and not unknown:
            if current['state'] in {'RUNNING','STARTING'}:display='RUNNING'
            elif task and task['state'] in {'REVIEW','REWORK'}:display='REVIEW'
        for generation in generations:
            for ev in generation['evidence']:
                ev['criterion_mapping'] = [c for rv in own_reviews if rv['attempt']==generation['attempt'] for c,cov in (rv['coverage'] or {}).items() if ev['id'] in cov['evidence']]
        nodes.append({'id': wid, 'ordinal': node['ordinal'], 'objective': work['objective'],
                      'state': node['state'], 'display_state': display,
                      'dependencies': work['dependencies'], 'task': task_id, 'task_state': task['state'] if task else 'UNMAPPED',
                      'human_assessment': work['human_assessment'], 'reason': reason,
                      'explanation': explanation('UNKNOWN' if unknown else reason),
                      'generations': generations, 'reviews': own_reviews,
                      'retry_count': len([r for r in retries if r['work_id'] == wid]),
                      'retry_budget': enrollment['max_semantic_retries'] if enrollment else 0,
                      'capacity_reserved': any(s['dispatch_id'] == (current or {}).get('dispatch') for s in state['slots']),
                      'review_capacity_reserved': bool(unknown and any(s['execution_id'] == eid for s in rows(runtime,'review_slots'))),
                      'unknown': unknown})
    timeline = []
    for x in rows(runtime, 'dag_facts'):
        if x['execution_id'] == eid:
            v = record(x); timeline.append({'at': v['at'], 'kind': v['kind'], 'work': v.get('work_id'), 'detail': v.get('detail')})
    for node in nodes:
        if node['task']:
            for ev in runtime.events(node['task']):
                timeline.append({'at': ev['at'], 'kind': ev['kind'], 'work': node['id'], 'detail': {'reason': ev['reason'], 'from': ev['from_state'], 'to': ev['to_state']}})
        for g in node['generations']:
            for ev in runtime.attempt_show(g['attempt'])['events'] if g['attempt'] else []:
                timeline.append({'at': ev['at'], 'kind': ev['kind'], 'work': node['id'], 'detail': {'reason':ev['reason'],'from':ev['from_state'],'to':ev['to_state']}})
            for row in rows(runtime,'isolation_observations'):
                obs=record(row)
                if obs.get('attempt_id')==g['attempt']:
                    timeline.append({'at':obs['at'],'kind':obs['kind'],'work':node['id'],'detail':{'operation':obs['detail'].get('operation'),'attempt':g['attempt'],'vm':g['vm']}})
            for row in rows(runtime,'isolation_fences'):
                if row['attempt_id']==g['attempt']:
                    fence=record(row);timeline.append({'at':fence['at'],'kind':'VM_FENCED','work':node['id'],'detail':{'attempt':g['attempt'],'evidence':fence['evidence_id']}})
    for r in reviews:
        source = next(record(x) for x in rows(runtime,'review_runs') if x['id'] == r['id'])
        timeline.append({'at': source['created_at'], 'kind':'REVIEW_PREPARED', 'work':r['work_id'], 'detail':{'run':r['id']}})
        decision = next((record(x) for x in rows(runtime,'review_decisions') if x['run_id'] == r['id']), None)
        if decision: timeline.append({'at':decision['at'],'kind':'REVIEW_'+decision['outcome'],'work':r['work_id'],'detail':{'reason':decision['reason']}})
    for retry in retries:
        timeline.append({'at':retry['reserved_at'],'kind':'RETRY_AUTHORIZED','work':retry['work_id'],'detail':{'ordinal':retry['ordinal'],'previous_attempt':retry['previous_attempt']}})
    from . import planning
    source=planning.show(runtime,data['plan_id'],data['revision'])
    return {'id': eid, 'plan_id':data['plan_id'], 'revision':data['revision'], 'project':data['project'],
            'goal':runtime.task_show(source['task_id'])['request'],
            'state':state['state'], 'created':data.get('created_at'), 'provenance':data.get('provenance'),
            'capacity':state['capacity'], 'available_capacity':state['available_capacity'],
            'review_policy':enrollment['policy'] if enrollment else 'Manual; not enrolled',
            'retry_policy':{'budget':enrollment['max_semantic_retries'] if enrollment else 0, 'fencing':'Exact M08 cessation required; UNKNOWN never retry'},
            'enrollment': enrollment['id'] if enrollment else None,
            'plan_accepted':state['plan_accepted'], 'plan_acceptance':'Principal only; COMPLETE is not explicit plan acceptance, merge or deployment',
            'nodes':nodes, 'retries':[{k:r.get(k) for k in ('id','work_id','ordinal','previous_attempt','reserved_at')} for r in retries],
            'timeline': sorted(timeline,key=lambda x:(x['at'],x['kind'],str(x['work']))) }


def snapshot(runtime):
    with runtime.store.transaction():
        plans = sorted((plan_view(runtime, x['id']) for x in rows(runtime, 'dag_executions')),key=lambda p:(p['created'],p['id']))
        tasks = runtime.task_list()
        counts = Counter({'NEEDS_HUMAN':0,'BLOCKED':0,'RUNNING':0,'REVIEW':0,'READY / QUEUED':0,'DONE / ACCEPTED':0,'WAITING':0})
        inbox = []
        for p in plans:
            for n in p['nodes']:
                status = 'BLOCKED' if n['unknown'] else {'ACCEPTED':'DONE / ACCEPTED','READY':'READY / QUEUED','DISPATCHED':'READY / QUEUED','WAITING_DEPENDENCY':'WAITING','FAILED':'BLOCKED','CANCELLED':'BLOCKED'}.get(n['display_state'],n['display_state'])
                counts[status] += 1
                if n['state'] == 'NEEDS_HUMAN' or n['unknown'] or n['task_state'] in {'NEEDS_HUMAN','BLOCKED'}:
                    inbox.append({'execution':p['id'],'project':p['project'],'work':n['id'],'task':n['task'],
                                  'state':n['display_state'],'reason':n['reason'],'summary':n['explanation'],
                                  'packet':n['reviews'][-1]['packet'] if n['reviews'] else None,
                                  'lineage':[{'generation':g['generation'],'state':g['state'],'quarantined':g['quarantined'],'fence':g['fence']} for g in n['generations']],
                                  'reviews':[{'verdict':r['reviewer_verdict'],'acp':r['acp_decision'],'reason':r['reason'],'coverage':r['coverage']} for r in n['reviews']],
                                  'retry_count':n['retry_count'],'retry_budget':n['retry_budget'],
                                  'remaining_blocked':[c['ordinal'] for c in p['nodes'] if n['id'] in c['dependencies'] and c['state']!='ACCEPTED'],
                                  'unknown':n['unknown']})
        mapped = {n['task'] for p in plans for n in p['nodes']}
        standalone=[]
        for t in tasks:
            if t['id'] in mapped:continue
            attempts=[x for x in rows(runtime,'execution_attempts') if x['task_id']==t['id']]
            latest=max(attempts,key=lambda a:(a['created_at'],a['id'])) if attempts else None
            unknown=bool(latest and latest['state'] in {'LOST','CANCEL_REQUESTED'} and not latest['fence_evidence_id'])
            display='BLOCKED / UNKNOWN' if unknown else t['state']
            bucket='BLOCKED' if unknown else {'READY':'READY / QUEUED','DONE':'DONE / ACCEPTED','FAILED':'BLOCKED','CANCELLED':'BLOCKED','REWORK':'REVIEW'}.get(t['state'],t['state'])
            if bucket in counts:counts[bucket]+=1
            standalone.append({'id':t['id'],'project_id':t['project_id'],'title':t['title'],'state':display,
                               'reason':t['hold_reason'],'attempt':latest['id'] if latest else None,
                               'attempt_state':latest['state'] if latest else None,'unknown':unknown,
                               'meaning':'Intake/source or legacy task; not a DAG WorkItem or explicit Plan acceptance'})
            if t['state'] in {'NEEDS_HUMAN','BLOCKED'} or unknown:
                inbox.append({'task':t['id'],'project':t['project_id'],'state':display,'reason':t['hold_reason'],'summary':explanation('UNKNOWN' if unknown else t['hold_reason']),'unknown':unknown})
        resolutions = []
        for row in rows(runtime,'resolutions'):
            v = json.loads(row['result_json'])
            resolutions.append({'id':row['id'],'request':row['request'],'outcome':v['outcome'],'task':row['task_id'],'candidates':v['candidate_project_ids']})
            if v['outcome'] != 'RESOLVED':inbox.append({'resolution':row['id'],'state':v['outcome'],'summary':'Choose an explicit project and submit a new intake; ACP will not guess.','candidates':v['candidate_project_ids']})
        projects=[]
        for project in runtime.project_list():
            metadata=awareness.profile(runtime,project['id'])
            ps=[p for p in plans if p['project']==project['id']]
            gates=[i for i in inbox if i.get('project')==project['id']]
            projects.append({'id':project['id'],'name':metadata['name'],'repository_identity':project['repository_identity'],
                             'resolution_status':'REGISTERED / ENABLED' if project['enabled'] else 'DISABLED',
                             'latest_execution':ps[-1]['id'] if ps else None,'active_work':sum(n['state'] in {'RUNNING','DISPATCHED','REVIEW'} for p in ps for n in p['nodes'])+sum(t['project_id']==project['id'] and t['state'] in {'RUNNING','REVIEW','REWORK','BLOCKED / UNKNOWN'} for t in standalone),
                             'human_gates':len(gates),'health':'ATTENTION' if gates else 'No current gates'})
        proposals=[]
        from . import planning
        for row in rows(runtime,'plan_revisions'):
            plan=planning.show(runtime,row['plan_id'],row['revision'])
            proposals.append({k:plan.get(k) for k in ('plan_id','plan_revision','primary_project','status','goal','work_items','human_assessment','test_only')})
        return {'version':version(runtime),'counts':dict(counts),'projects':projects,'plans':plans,'needs_human':inbox,
                'resolutions':resolutions,'proposals':proposals,
                'tasks':standalone,
                'contexts':[{k:x[k] for k in ('id','project_id')} for x in rows(runtime,'context_loads')],
            'provider_status':{'review':'synthetic/test-only, independent fixture','real':'Live inference NOT DEMONSTRATED; configuration is not certification',
                                   'configured':[{'run':x['id'],**{k:record(x)['profile'].get(k) for k in ('provider','model','reasoning','external')}} for x in rows(runtime,'provider_runs')],
                                   'configuration':'NOT CONFIGURED' if not rows(runtime,'provider_runs') else 'Stored provider runs exist; inspect exact selected profiles',
                                   'unknown_runs':[x['id'] for x in rows(runtime,'provider_dispatches') if not any(r['run_id']==x['run_id'] for r in rows(runtime,'provider_responses'))]},
                'capability':'Local board; VMware headless synthetic worker; no-NIC bounded transport; M08 fencing. No production execution, automatic merge/push/deploy or live-provider certification.'}
