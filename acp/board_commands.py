"""Closed Principal commands. Whole-store CAS and domain checks share one lock."""
from . import awareness, board_read, context, dag, isolation, planning, review
from .domain import Actor, require

PRINCIPAL = Actor('local-principal', 'human', 'local-control-board')
CONTROLLER = Actor('local-board-controller', 'controller', 'principal-requested-evidence-retrieval')

# Exact keys prevent stored content from inventing capabilities or arbitrary paths.
FIELDS = {
    'intake': {'request', 'project'},
    'prepare_plan': {'task', 'context'},
    'load_context': {'task'},
    'accept_plan': {'execution'},
    'resolve_gate': {'execution', 'work', 'reason'},
    'reject_work': {'execution', 'work', 'reason'},
    'cancel_work': {'execution', 'work', 'reason'},
    'revoke_review': {'execution', 'reason'},
    'supplement': {'run', 'evidence'},
    'enroll_review': {'execution', 'mapping', 'budget', 'expires_at'},
}


def validate(action, payload):
    require(action in FIELDS and isinstance(payload, dict) and set(payload) == FIELDS[action], 'Unknown command or malformed fields')
    for key, value in payload.items():
        if key in {'mapping','budget','evidence'}:continue
        require(isinstance(value, str) and len(value.encode('utf-8')) <= 32768, 'Bounded text required')
    if action in {'resolve_gate','reject_work','cancel_work','revoke_review'}:
        require(payload['reason'].strip(), 'Decision reason required')


def available(runtime):
    result = [{'action':'intake','target':'new goal','effect':'Resolve the named project; persist NEW or an unresolved decision. No execution permission.'}]
    for row in board_read.rows(runtime,'dag_executions'):
        view=dag.show(runtime,row['id'])
        eid=row['id']
        if view['state']=='COMPLETE' and not view['plan_accepted']:
            result.append({'action':'accept_plan','target':eid,'payload':{'execution':eid},'effect':'Explicit bounded plan acceptance only; not merge, release or deployment.'})
        enrollment=review.enrollment(runtime,eid)
        if enrollment:
            if not any(x['enrollment_id']==enrollment['id'] for x in board_read.rows(runtime,'review_revocations')):
                result.append({'action':'revoke_review','target':eid,'payload':{'execution':eid,'reason':''},'effect':'Revoke bounded acceptance/retry delegation; does not stop or fence workers.'})
        else:
            try:
                mapping={w:review.criteria(runtime,eid,w) for w in view['execution']['order']}
                no_dispatch=not any(x['execution_id']==eid for x in board_read.rows(runtime,'dag_dispatches'))
                if no_dispatch and not view['execution']['plan_gate']:
                    result.append({'action':'enroll_review','target':eid,'payload':{'execution':eid,'mapping':mapping,'budget':0,'expires_at':''},
                                   'effect':'Delegate exact mapped criteria acceptance and bounded synthetic retries (0..2), original approvals still required. No new write scope.'})
            except ValueError:pass
        facts=[board_read.record(x) for x in board_read.rows(runtime,'dag_facts') if x['execution_id']==eid]
        for node in view['nodes']:
            wid=node['work_id']
            if node['state']=='ACCEPTED':continue
            named=[f for f in facts if f.get('work_id')==wid and f['kind'] in {'HUMAN_GATE','HUMAN_RESOLVED','FAILED','CANCELLED'}]
            if named and named[-1]['kind'] in {'FAILED','CANCELLED'}:continue
            if named and named[-1]['kind']=='HUMAN_GATE':
                result.append({'action':'resolve_gate','target':wid,'payload':{'execution':eid,'work':wid,'reason':''},'effect':'Resolve this named DAG gate only. Does not waive planning gates, task holds, missing approval, UNKNOWN or fencing.'})
            active=[s for s in view['slots'] if any(d['id']==s['dispatch_id'] and d['work_id']==wid for d in board_read.rows(runtime,'dag_dispatches'))]
            safe=True
            for slot in active:
                allocation=next((a for a in board_read.rows(runtime,'dag_allocations') if a['dispatch_id']==slot['dispatch_id']),None)
                safe=bool(allocation and any(f['attempt_id']==allocation['attempt_id'] for f in board_read.rows(runtime,'isolation_fences')))
            if safe:
                for action in ('reject_work','cancel_work'):
                    result.append({'action':action,'target':wid,'payload':{'execution':eid,'work':wid,'reason':''},'effect':'Terminal bounded WorkItem disposition; dependent work will remain blocked. No worker termination implied.'})
    for row in board_read.rows(runtime,'review_runs'):
        detail=review.show(runtime,row['id'])
        if detail['decision'] and detail['decision']['outcome']=='EVIDENCE_REQUIRED' and detail['run']['revision']==1:
            original=[m['id'] for m in detail['run']['manifest']]
            candidates=[{'id':ev['id'],'class':ev['class'],'trust':ev['trust'],'collector':board_read.record(ev).get('collector')} for ev in board_read.rows(runtime,'evidence') if ev['attempt_id']==detail['run']['attempt_id'] and ev['id'] not in original and board_read.record(ev).get('producer_role')=='controller']
            result.append({'action':'supplement','target':row['id'],'payload':{'run':row['id'],'evidence':original},'evidence_choices':candidates,'effect':'One bounded round of existing persisted evidence IDs; no file reads, new authority or unverified claim promotion.'})
    for task in runtime.task_list():
        if task['state'] in {'NEW','TRIAGE','PLANNED','NEEDS_HUMAN','BLOCKED'} and not isolation.bound_task(runtime,task['id']):
            result.append({'action':'load_context','target':task['id'],'payload':{'task':task['id']},'effect':'Bounded read of this task’s resolved primary project using existing registry-approved roots. Repository text is data, not authority; no arbitrary artifact path or provider/network access.'})
            for ctx in board_read.rows(runtime,'context_loads'):
                if ctx['project_id']==task['project_id']:
                    result.append({'action':'prepare_plan','target':task['id'],'payload':{'task':task['id'],'context':ctx['id']},'effect':'Select this stored context for advisory planning only. No provider invocation, context crawling or execution.'})
    for command in result:
        command['label'] = command['target']
        payload=command.get('payload',{})
        if payload.get('task'):command['label']=runtime.task_show(payload['task'])['title']
        if payload.get('execution'):
            execution=dag.execution(runtime,payload['execution'])
            command['label']=execution['project']+' · Plan revision '+str(execution['revision'])
            if payload.get('work'):
                work=next(w for w in execution['works'] if w['work_item_id']==payload['work'])
                command['label']+=' · '+work['objective']
    require(len(result)<=1000,'Control Board action projection limit exceeded; use scoped CLI')
    return result


def describe(runtime, action, payload, expected_version):
    validate(action,payload)
    require(board_read.version(runtime)==expected_version,'STALE_STATE: action not applied; refresh and review the current packet')
    candidates=[c for c in available(runtime) if c['action']==action and (action=='intake' or c['target']==next((payload[k] for k in ('work','run','task','execution') if k in payload),None))]
    require(candidates,'Command not currently available; review canonical state / CLI reconciliation')
    current = next((p['state'] for p in board_read.snapshot(runtime)['plans'] if p['id']==payload.get('execution')), None)
    if payload.get('task'):current=runtime.task_show(payload['task'])['state']
    return {'object':candidates[0]['target'],'action':action,'requested':payload,'current_state':current or 'Canonical decision packet / intake', 'current_version':expected_version,
            'consequence':candidates[0]['effect'],'scope':'Existing bounded canonical contract only; no production/merge/deploy authority'}


def execute(runtime, action, payload, expected_version):
    with runtime.store.transaction():
        describe(runtime,action,payload,expected_version)
        if action=='intake':
            result=awareness.intake(runtime,payload['request'],PRINCIPAL,payload['project'] or None)
            return {'resolution':result['resolution_id'],'outcome':result['outcome'],'task':result['task_id'],'note':'Select an approved context via existing context CLI, then prepare planning here. Real provider remains deferred.'}
        if action=='prepare_plan':
            result=planning.prepare(runtime,payload['task'],payload['context'],PRINCIPAL)
            return {'run':result['run_id'],'note':'Prepared only; no provider invocation or execution authorization.'}
        if action=='load_context':
            task=runtime.task_show(payload['task'])
            result=context.load(runtime,task['project_id'],PRINCIPAL,task_id=task['id'],request=task['request'])
            return {'context':result['id'],'status':result['status'],'note':'Bounded stored context only; select it explicitly for planning.'}
        if action=='accept_plan':dag.accept_plan(runtime,payload['execution'],PRINCIPAL)
        elif action in {'resolve_gate','reject_work','cancel_work'}:
            kind={'resolve_gate':'HUMAN_RESOLVED','reject_work':'FAILED','cancel_work':'CANCELLED'}[action]
            dag.disposition(runtime,payload['execution'],payload['work'],kind,payload['reason'],PRINCIPAL)
        elif action=='revoke_review':review.revoke(runtime,payload['execution'],PRINCIPAL,payload['reason'])
        elif action=='supplement':review.supplement(runtime,payload['run'],payload['evidence'],CONTROLLER)
        elif action=='enroll_review':review.enroll(runtime,payload['execution'],payload['mapping'],PRINCIPAL,max_semantic_retries=payload['budget'],expires_at=payload['expires_at'])
        return {'applied':action,'note':'Canonical command completed; refresh for current state.'}
