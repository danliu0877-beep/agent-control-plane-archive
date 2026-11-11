"""M09 deterministic SQLite DAG control. No worker backend or automatic retry.

Graph/provenance/authority facts are immutable; projections are reconstructible.
An active slot spans claim, execution and REVIEW, not only invocation.
"""
import json

from . import isolation, planning
from .domain import ACPError, canonical_json, digest, identity, now, require

POLICY = 'm09-single-dispatch-v1'
CONCURRENCY_POLICY = 'm10-bounded-parallel-v1'
DEFAULT_PARALLEL = 1


def limit(data):
    policy = data.get('concurrency')
    if policy is None:
        return 1  # Historical M09 immutable records stay single-dispatch.
    require(policy.get('version') == CONCURRENCY_POLICY and type(policy.get('max_parallel')) is int
            and 1 <= policy['max_parallel'] <= 4, 'Unknown concurrency policy')
    return policy['max_parallel']


def _trusted(actor):
    require(actor.role in {'human', 'controller'}, 'DAG controller or Principal required')


def _decode(row):
    require(row is not None, 'Unknown DAG identity')
    data = json.loads(row['record_json'])
    require(digest(data) == row['digest'], 'DAG digest mismatch')
    return data


def execution(runtime, execution_id):
    data = _decode(runtime.db.execute('SELECT * FROM dag_executions WHERE id=?', (execution_id,)).fetchone())
    plan = planning.show(runtime, data['plan_id'], data['revision'])
    require(data['plan_digest'] == plan['plan_digest'] and data['policy'] == POLICY, 'DAG source/policy changed')
    limit(data)
    return data


def _fact(runtime, execution_id, work_id, kind, detail, actor):
    data = {'id': identity('DFACT'), 'execution_id': execution_id, 'work_id': work_id,
            'kind': kind, 'detail': detail, 'actor': actor.record(), 'at': now()}
    runtime.db.execute('INSERT INTO dag_facts VALUES (?,?,?,?,?,?)',
        (data['id'], execution_id, work_id, kind, canonical_json(data), digest(data)))
    return data


def create(runtime, plan_id, revision, actor, *, max_parallel=None):
    _trusted(actor)
    with runtime.store.transaction():
        plan = planning.show(runtime, plan_id, revision)
        require(plan['validation_status'] == 'PASS', 'Validated canonical revision required')
        latest = runtime.db.execute('SELECT max(revision) FROM plan_revisions WHERE plan_id=?', (plan_id,)).fetchone()[0]
        require(latest == revision, 'Superseded plan cannot start')
        existing = runtime.db.execute('SELECT id FROM dag_executions WHERE plan_id=? AND revision=?', (plan_id, revision)).fetchone()
        if existing:
            data = execution(runtime, existing['id'])
            require(max_parallel is None or type(max_parallel) is int and max_parallel == limit(data), 'Concurrency policy is immutable')
            return data
        capacity = DEFAULT_PARALLEL if max_parallel is None else max_parallel
        require(type(capacity) is int and 1 <= capacity <= 4, 'Parallel limit must be integer 1..4')
        require(capacity == 1 or actor.role == 'human', 'Principal selects parallel authority')
        # Preserve canonical order; verify graph rather than repairing it.
        order = plan['dag']['topological_order']
        works = {w['work_item_id']: w for w in plan['work_items']}
        require(len(order) == len(works) == len(plan['work_items']) and set(order) == set(works) and bool(order), 'Invalid canonical graph')
        ranks = {w: i for i, w in enumerate(order)}
        require(all(d in ranks and ranks[d] < ranks[w] for w in order for d in works[w]['dependencies']), 'Invalid canonical dependency order')
        require(not runtime.db.execute('SELECT 1 FROM isolation_task_bindings WHERE plan_id=? AND plan_revision=?', (plan_id, revision)).fetchone(), 'Cannot adopt prior standalone execution authority')
        record = {'id': identity('PEX'), 'project': plan['primary_project'], 'plan_id': plan_id,
            'revision': revision, 'plan_digest': plan['plan_digest'], 'policy': POLICY,
            'concurrency': {'version': CONCURRENCY_POLICY, 'max_parallel': capacity},
            'works': [works[w] for w in order], 'order': order,
            'plan_gate': plan['human_assessment']['state'] != 'NONE' or bool(plan['decisions']) or bool(plan['context_requests']),
            'provenance': actor.record(), 'created_at': now()}
        runtime.db.execute('INSERT INTO dag_executions VALUES (?,?,?,?,?,?)',
            (record['id'], record['project'], plan_id, revision, canonical_json(record), digest(record)))
        runtime.db.execute("INSERT INTO dag_projection VALUES (?,'CREATED','[]')", (record['id'],))
    return record


def materialize(runtime, execution_id, actor):
    _trusted(actor)
    with runtime.store.transaction():
        data = execution(runtime, execution_id)
        existing = runtime.db.execute('SELECT count(*) FROM dag_nodes WHERE execution_id=?', (execution_id,)).fetchone()[0]
        require(existing in {0, len(data['works'])}, 'Partial canonical graph; refuse repair')
        if not existing:
            for ordinal, work in enumerate(data['works']):
                runtime.db.execute("INSERT INTO dag_nodes VALUES (?,?,?,'PENDING','[]')", (execution_id, work['work_item_id'], ordinal))
            for work in data['works']:
                for parent in work['dependencies']:
                    runtime.db.execute('INSERT INTO dag_edges VALUES (?,?,?)', (execution_id, parent, work['work_item_id']))
            _fact(runtime, execution_id, None, 'MATERIALIZED', {'nodes': len(data['works'])}, actor)
        _evaluate(runtime, execution_id, actor)
    return show(runtime, execution_id)


def enrolled(runtime, plan_id, revision, work_id):
    row = runtime.db.execute('SELECT id FROM dag_executions WHERE plan_id=? AND revision=?', (plan_id, revision)).fetchone()
    if row:
        data = execution(runtime, row['id'])
        require(work_id in data['order'] and runtime.db.execute('SELECT 1 FROM dag_nodes WHERE execution_id=? AND work_id=?', (row['id'], work_id)).fetchone(), 'DAG graph must be materialized first')
        return row['id']
    return None


def bind(runtime, execution_id, work_id, template, actor):
    require(actor.role == 'human', 'Exact synthetic mapping requires Principal')
    with runtime.store.transaction():
        data = execution(runtime, execution_id)
        require(work_id in data['order'], 'Work does not belong to execution')
        old = runtime.db.execute('SELECT * FROM dag_links WHERE execution_id=? AND work_id=?', (execution_id, work_id)).fetchone()
        if old:
            binding = isolation.decoded(isolation.bound_task(runtime, old['task_id']))
            require(binding['template'] == template, 'No template rebinding')
            return binding
        binding = isolation.materialize(runtime, data['plan_id'], data['revision'], work_id, template, actor)
        runtime.db.execute('INSERT INTO dag_links VALUES (?,?,?,?)', (execution_id, work_id, binding['task_id'], binding['id']))
        _fact(runtime, execution_id, work_id, 'MAPPED', {'task_id': binding['task_id']}, actor)
    return binding


def task_guard(runtime, task_id):
    binding = isolation.decoded(isolation.bound_task(runtime, task_id))
    eid = enrolled(runtime, binding['plan_id'], binding['plan_revision'], binding['work_item_id'])
    if not eid:
        return
    link = runtime.db.execute('SELECT * FROM dag_links WHERE task_id=?', (task_id,)).fetchone()
    require(link is not None and link['execution_id'] == eid, 'DAG mapping receipt missing')
    dispatch = runtime.db.execute('SELECT d.* FROM dag_slots s JOIN dag_dispatches d ON d.id=s.dispatch_id WHERE s.execution_id=? AND d.work_id=?', (eid, link['work_id'])).fetchone()
    require(dispatch is not None and dispatch['work_id'] == link['work_id'], 'DAG single-dispatch authority required')
    data = execution(runtime, eid)
    require(not data['plan_gate'], 'Principal planning gate unresolved')
    gates = runtime.db.execute("SELECT kind FROM dag_facts WHERE execution_id=? AND work_id=? AND kind IN ('HUMAN_GATE','HUMAN_RESOLVED','FAILED','CANCELLED') ORDER BY rowid DESC LIMIT 1", (eid, link['work_id'])).fetchone()
    require(not gates or gates['kind'] == 'HUMAN_RESOLVED', 'DAG work held or terminal')
    parents = runtime.db.execute('SELECT parent FROM dag_edges WHERE execution_id=? AND child=? ORDER BY parent', (eid, link['work_id'])).fetchall()
    require(all(runtime.db.execute('SELECT 1 FROM dag_acceptances WHERE execution_id=? AND work_id=?', (eid, p['parent'])).fetchone() for p in parents), 'Unsatisfied canonical acceptance dependency')


def _evaluate(runtime, execution_id, actor):
    data = execution(runtime, execution_id)
    # Fencing releases only this physical authority; not acceptance/retry.
    if data.get('concurrency'):
        for row in runtime.db.execute('SELECT s.dispatch_id,d.work_id,a.attempt_id FROM dag_slots s JOIN dag_dispatches d ON d.id=s.dispatch_id JOIN dag_allocations a ON a.dispatch_id=d.id JOIN isolation_fences f ON f.attempt_id=a.attempt_id WHERE s.execution_id=? ORDER BY s.slot_no', (execution_id,)).fetchall():
            saved = isolation.facts(runtime, row['attempt_id'])
            require(not saved['pending'] and saved['fence'], 'Uncertain fence cannot release capacity')
            runtime.db.execute('DELETE FROM dag_slots WHERE dispatch_id=?', (row['dispatch_id'],))
            _fact(runtime, execution_id, row['work_id'], 'SLOT_RELEASED_FENCED', {'dispatch_id': row['dispatch_id'], 'attempt_id': row['attempt_id'], 'fence': saved['fence']['evidence_id']}, actor)
    nodes = runtime.db.execute('SELECT * FROM dag_nodes WHERE execution_id=? ORDER BY ordinal', (execution_id,)).fetchall()
    require(len(nodes) == len(data['works']), 'Graph not materialized')
    expected = {(d, w['work_item_id']) for w in data['works'] for d in w['dependencies']}
    actual = {(r['parent'], r['child']) for r in runtime.db.execute('SELECT * FROM dag_edges WHERE execution_id=?', (execution_id,))}
    require(expected == actual, 'Graph differs from immutable revision')
    accepted = set()
    for row in runtime.db.execute('SELECT * FROM dag_acceptances WHERE execution_id=?', (execution_id,)):
        receipt = _decode(row)
        require(runtime.store.one('tasks', receipt['task_id'])['state'] == 'DONE', 'Acceptance receipt lacks canonical DONE')
        event = runtime.db.execute('SELECT * FROM task_events WHERE seq=?', (receipt['event_seq'],)).fetchone()
        require(event and event['task_id'] == receipt['task_id'] and event['to_state'] == 'DONE' and
                json.loads(event['details_json']).get('criteria_evidence') == receipt['criteria'], 'Acceptance causal evidence mismatch')
        accepted.add(row['work_id'])
    decisions = {}
    for row in runtime.db.execute("SELECT * FROM dag_facts WHERE execution_id=? AND kind IN ('HUMAN_GATE','HUMAN_RESOLVED','FAILED','CANCELLED') ORDER BY rowid", (execution_id,)):
        decisions[row['work_id']] = _decode(row)
    states, causes = {}, {}
    for node, work in zip(nodes, data['works']):
        wid = node['work_id']
        require(wid == work['work_item_id'], 'Canonical node order changed')
        cause = []
        if wid in accepted:
            state = 'ACCEPTED'
        elif wid in decisions and decisions[wid]['kind'] in {'FAILED', 'CANCELLED'}:
            state, cause = decisions[wid]['kind'], [decisions[wid]['id']]
        elif any(states[d] in {'FAILED', 'CANCELLED', 'BLOCKED'} for d in work['dependencies']):
            state = 'BLOCKED'
            cause = [{'dependency': d, 'state': states[d], 'causes': causes[d]} for d in work['dependencies'] if states[d] in {'FAILED', 'CANCELLED', 'BLOCKED'}]
        elif data['plan_gate'] or work['human_assessment']['state'] != 'NONE' or (wid in decisions and decisions[wid]['kind'] == 'HUMAN_GATE'):
            state, cause = 'NEEDS_HUMAN', [decisions[wid]['id']] if wid in decisions else ['CANONICAL_PRINCIPAL_ASSESSMENT']
        elif any(d not in accepted for d in work['dependencies']):
            state, cause = 'WAITING_DEPENDENCY', [d for d in work['dependencies'] if d not in accepted]
        else:
            dispatch = runtime.db.execute('SELECT * FROM dag_dispatches WHERE execution_id=? AND work_id=? ORDER BY generation DESC LIMIT 1', (execution_id, wid)).fetchone()
            state = 'READY'
            if dispatch:
                allocation = runtime.db.execute('SELECT attempt_id FROM dag_allocations WHERE dispatch_id=?', (dispatch['id'],)).fetchone()
                state = 'DISPATCHED'
                if not allocation:
                    cause = ['DISPATCH_INTENT_WITHOUT_ALLOCATION: NO REINVOCATION']
                else:
                    attempt = runtime.store.one('execution_attempts', allocation['attempt_id'])
                    saved = runtime.db.execute('SELECT 1 FROM isolation_instances WHERE attempt_id=?', (attempt['id'],)).fetchone()
                    uncertain = attempt['state'] in {'LOST', 'CANCEL_REQUESTED'} or (saved and bool(isolation.facts(runtime, attempt['id'])['pending']))
                    task = runtime.store.one('tasks', attempt['task_id'])
                    if uncertain:
                        cause = ['EXECUTION_OWNERSHIP_UNCERTAIN: NO RETRY']
                    elif task['state'] == 'REVIEW':
                        state = 'REVIEW'
                    elif task['state']=='REWORK':
                        state,cause='REVIEW',['REWORK_REQUIRED: dependency unsatisfied']
                    elif task['state'] in {'BLOCKED', 'NEEDS_HUMAN'}:
                        state, cause = 'NEEDS_HUMAN', [task['hold_reason']]
                    elif attempt['state'] in {'RUNNING', 'STARTING'}:
                        state = 'RUNNING'
                    elif attempt['state'] == 'CANCELLED':
                        state = 'NEEDS_HUMAN' if data.get('concurrency') else 'DISPATCHED'
                        cause = ['FENCED: EXPLICIT PRINCIPAL DISPOSITION REQUIRED; NO DAG RETRY']
                from . import review
                retry = review.pending_retry(runtime,execution_id,wid)
                if retry and task['state']=='READY':
                    state,cause='READY',[{'retry_id':retry['id'],'generation':retry['ordinal']}]
            else:
                link = runtime.db.execute('SELECT task_id FROM dag_links WHERE execution_id=? AND work_id=?', (execution_id, wid)).fetchone()
                if link and runtime.store.one('tasks', link['task_id'])['state'] in {'NEEDS_HUMAN', 'BLOCKED'}:
                    state, cause = 'NEEDS_HUMAN', ['TASK_AUTHORIZATION_HOLD']
        states[wid], causes[wid] = state, cause
        if state != node['state'] or canonical_json(cause) != node['cause_json']:
            runtime.db.execute('UPDATE dag_nodes SET state=?,cause_json=? WHERE execution_id=? AND work_id=?', (state, canonical_json(cause), execution_id, wid))
            _fact(runtime, execution_id, wid, 'STATE', {'from': node['state'], 'to': state, 'causes': cause}, actor)
    values = set(states.values())
    terminal = 'COMPLETE' if values == {'ACCEPTED'} else 'ACTIVE'
    if values & {'FAILED', 'CANCELLED', 'BLOCKED'}:
        terminal = 'BLOCKED'
    elif 'NEEDS_HUMAN' in values and not values & {'READY', 'RUNNING', 'REVIEW', 'DISPATCHED'}:
        terminal = 'NEEDS_HUMAN'
    else:
        held = runtime.db.execute('SELECT d.work_id FROM dag_slots s JOIN dag_dispatches d ON d.id=s.dispatch_id WHERE s.execution_id=?', (execution_id,)).fetchall()
        if len(held) >= limit(data) and all(states[r['work_id']] == 'NEEDS_HUMAN' for r in held):
            terminal = 'NEEDS_HUMAN'
    summary = [{'work_id': w, 'state': states[w], 'causes': causes[w]} for w in data['order'] if causes[w]]
    old = runtime.db.execute('SELECT * FROM dag_projection WHERE execution_id=?', (execution_id,)).fetchone()
    if old['state'] != terminal or old['cause_json'] != canonical_json(summary):
        runtime.db.execute('UPDATE dag_projection SET state=?,cause_json=? WHERE execution_id=?', (terminal, canonical_json(summary), execution_id))
        _fact(runtime, execution_id, None, 'PLAN_STATE', {'from': old['state'], 'to': terminal, 'causes': summary}, actor)


def refresh(runtime, execution_id, actor):
    _trusted(actor)
    with runtime.store.transaction():
        _evaluate(runtime, execution_id, actor)
    return show(runtime, execution_id)


def show(runtime, execution_id):
    data = execution(runtime, execution_id)
    nodes = [dict(r) for r in runtime.db.execute('SELECT * FROM dag_nodes WHERE execution_id=? ORDER BY ordinal', (execution_id,))]
    projection = dict(runtime.db.execute('SELECT * FROM dag_projection WHERE execution_id=?', (execution_id,)).fetchone())
    slots = [dict(r) for r in runtime.db.execute('SELECT * FROM dag_slots WHERE execution_id=? ORDER BY slot_no', (execution_id,))]
    return {'execution': data, 'state': projection['state'], 'causes': json.loads(projection['cause_json']),
        'nodes': [{**n, 'causes': json.loads(n['cause_json'])} for n in nodes],
        'ready': [n['work_id'] for n in nodes if n['state'] == 'READY'],
        'active_dispatch': slots[0]['dispatch_id'] if slots else None,
        'active_dispatches': [s['dispatch_id'] for s in slots], 'slots': slots,
        'capacity': limit(data), 'available_capacity': limit(data)-len(slots),
        'plan_accepted': bool(runtime.db.execute('SELECT 1 FROM dag_plan_acceptances WHERE execution_id=?', (execution_id,)).fetchone())}


def _eligible(runtime, execution_id):
    eligible, skipped = [], []
    for node in runtime.db.execute("SELECT * FROM dag_nodes WHERE execution_id=? AND state='READY' ORDER BY ordinal",(execution_id,)):
        link=runtime.db.execute('SELECT * FROM dag_links WHERE execution_id=? AND work_id=?',(execution_id,node['work_id'])).fetchone()
        if link is None:
            skipped.append({'work_id':node['work_id'],'reason':'UNMAPPED'})
            continue
        task=runtime.store.one('tasks',link['task_id'])
        if task['state']!='READY':
            skipped.append({'work_id':node['work_id'],'reason':'CHILD_NOT_AUTHORIZED_READY'})
            continue
        binding=isolation.decoded(isolation.bound_task(runtime,task['id']))
        # Source drift/staleness is not an authorization-selection fallback.
        isolation.source(runtime,binding['plan_id'],binding['plan_revision'],binding['work_item_id'])
        try:
            approval=runtime._find_approval(task)
        except ACPError:
            skipped.append({'work_id':node['work_id'],'reason':'NO_CURRENT_APPROVAL'})
            continue
        eligible.append((node,task,approval))
    return eligible,skipped


def claim(runtime, execution_id, actor):
    _trusted(actor)
    with runtime.store.transaction():
        _evaluate(runtime, execution_id, actor)
        data_policy = execution(runtime, execution_id)
        capacity = limit(data_policy)
        occupied = {r['slot_no'] for r in runtime.db.execute('SELECT slot_no FROM dag_slots WHERE execution_id=?', (execution_id,))}
        require(len(occupied) < capacity, 'Active/UNKNOWN dispatch authority fills capacity; no second claim')
        slot_no = next(n for n in range(1,capacity+1) if n not in occupied)
        eligible,skipped=_eligible(runtime,execution_id)
        require(eligible,'No authorized eligible READY work; exact M08 mapping/approval required')
        ready,task,approval=eligible[0]
        from . import review
        if review.enrollment(runtime,execution_id):
            review.authority(runtime,execution_id,ready['work_id'])
        retry = review.pending_retry(runtime,execution_id,ready['work_id'])
        if retry:
            review.retry_guard(runtime,execution_id,ready['work_id'],retry['id'])
        data = {'id': identity('DDIS'), 'execution_id': execution_id, 'work_id': ready['work_id'],
                'task_id': task['id'], 'approval_id': approval['id'], 'at': now(), 'actor': actor.record(),
                'slot_no': slot_no, 'capacity': capacity, 'available_before': capacity-len(occupied),
                'ordering': 'canonical topological ordinal', 'ordinal': ready['ordinal'],
                'eligible_ready':[n['work_id'] for n,_,_ in eligible], 'skipped_ready':skipped}
        if retry:
            data.update(generation=retry['ordinal'],retry_id=retry['id'],previous_attempt=retry['previous_attempt'])
        runtime.db.execute('INSERT INTO dag_dispatches VALUES (?,?,?,?,?,?,?)', (data['id'], execution_id, ready['work_id'], canonical_json(data), digest(data),retry['ordinal'] if retry else 0,retry['id'] if retry else None))
        runtime.db.execute('INSERT INTO dag_slots VALUES (?,?,?)', (execution_id, data['id'], slot_no))
        _evaluate(runtime, execution_id, actor)
    return data


def claim_wave(runtime, execution_id, actor):
    """Atomic bounded ordered wave; no worker call and no busy loop."""
    _trusted(actor)
    with runtime.store.transaction():
        _evaluate(runtime, execution_id, actor)
        state = show(runtime, execution_id)
        eligible,_=_eligible(runtime,execution_id)
        count = min(state['available_capacity'], len(eligible))
        return [claim(runtime, execution_id, actor) for _ in range(count)]


def allocate(runtime, dispatch_id, actor):
    """Explicit resume of the same intent; allocation+receipt commit atomically."""
    _trusted(actor)
    with runtime.store.transaction():
        intent = _decode(runtime.db.execute('SELECT * FROM dag_dispatches WHERE id=?', (dispatch_id,)).fetchone())
        require(runtime.db.execute('SELECT 1 FROM dag_slots WHERE execution_id=? AND dispatch_id=?', (intent['execution_id'], dispatch_id)).fetchone(), 'Inactive dispatch')
        existing = runtime.db.execute('SELECT attempt_id FROM dag_allocations WHERE dispatch_id=?', (dispatch_id,)).fetchone()
        if existing:
            return runtime.attempt_show(existing['attempt_id'])
        if intent.get('retry_id'):
            from . import review
            review.retry_guard(runtime,intent['execution_id'],intent['work_id'],intent['retry_id'])
        attempt = runtime.attempt_create(intent['task_id'], intent['approval_id'], actor, dag_dispatch=dispatch_id)
        runtime.db.execute('INSERT INTO dag_allocations VALUES (?,?)', (dispatch_id, attempt['id']))
        _evaluate(runtime, intent['execution_id'], actor)
    return attempt


def allocation_guard(runtime, task_id, dispatch_id):
    link = runtime.db.execute('SELECT * FROM dag_links WHERE task_id=?', (task_id,)).fetchone()
    if link:
        task_guard(runtime, task_id)
        dispatch = runtime.db.execute('SELECT s.dispatch_id FROM dag_slots s JOIN dag_dispatches d ON d.id=s.dispatch_id WHERE s.execution_id=? AND d.work_id=?', (link['execution_id'], link['work_id'])).fetchone()
        require(dispatch_id == dispatch['dispatch_id'] and runtime.db.in_transaction, 'Use exact transactional DAG allocation')
        require(not runtime.db.execute('SELECT 1 FROM dag_allocations WHERE dispatch_id=?', (dispatch['dispatch_id'],)).fetchone(), 'DAG attempt already allocated; no independent scheduler retry')


def attempt_guard(runtime, attempt_id):
    attempt = runtime.store.one('execution_attempts', attempt_id)
    link = runtime.db.execute('SELECT * FROM dag_links WHERE task_id=?', (attempt['task_id'],)).fetchone()
    if link:
        task_guard(runtime, attempt['task_id'])
        require(runtime.db.execute('SELECT 1 FROM dag_slots s JOIN dag_allocations a ON a.dispatch_id=s.dispatch_id WHERE s.execution_id=? AND a.attempt_id=?', (link['execution_id'], attempt_id)).fetchone(), 'Exact durable DAG attempt receipt required')


def accepted(runtime, task_id, attempt_id, criteria, actor):
    """Called inside Runtime.accept transaction, including direct API acceptance."""
    link = runtime.db.execute('SELECT * FROM dag_links WHERE task_id=?', (task_id,)).fetchone()
    if not link:
        return
    task_guard(runtime, task_id)
    slot = runtime.db.execute('SELECT s.dispatch_id FROM dag_slots s JOIN dag_dispatches d ON d.id=s.dispatch_id WHERE s.execution_id=? AND d.work_id=?', (link['execution_id'], link['work_id'])).fetchone()
    saved = runtime.db.execute('SELECT attempt_id FROM dag_allocations WHERE dispatch_id=?', (slot['dispatch_id'],)).fetchone()
    require(saved is not None and saved['attempt_id'] == attempt_id, 'Exact DAG allocated attempt required')
    event = runtime.db.execute("SELECT seq FROM task_events WHERE task_id=? AND to_state='DONE' ORDER BY seq DESC LIMIT 1", (task_id,)).fetchone()
    data = {'task_id': task_id, 'attempt_id': attempt_id, 'criteria': criteria, 'event_seq': event['seq'], 'actor': actor.record(), 'at': now()}
    runtime.db.execute('INSERT INTO dag_acceptances VALUES (?,?,?,?,?,?)', (link['execution_id'], link['work_id'], attempt_id, event['seq'], canonical_json(data), digest(data)))
    runtime.db.execute('DELETE FROM dag_slots WHERE dispatch_id=?', (slot['dispatch_id'],))
    _fact(runtime, link['execution_id'], link['work_id'], 'SLOT_RELEASED', {'dispatch_id': slot['dispatch_id'], 'acceptance': data}, actor)
    _evaluate(runtime, link['execution_id'], actor)


def accept(runtime, execution_id, work_id, criteria, actor):
    require(actor.role == 'human', 'Explicit Principal acceptance required')
    with runtime.store.transaction():
        old = runtime.db.execute('SELECT * FROM dag_acceptances WHERE execution_id=? AND work_id=?', (execution_id, work_id)).fetchone()
        if old:
            require(_decode(old)['criteria'] == criteria, 'Acceptance cannot rebind evidence')
        else:
            require(actor.role == 'human', 'Explicit Principal acceptance required')
            link = runtime.db.execute('SELECT task_id FROM dag_links WHERE execution_id=? AND work_id=?', (execution_id, work_id)).fetchone()
            require(link is not None, 'Unmapped work')
            slot = runtime.db.execute('SELECT a.attempt_id FROM dag_slots s JOIN dag_dispatches d ON s.dispatch_id=d.id JOIN dag_allocations a ON a.dispatch_id=d.id WHERE s.execution_id=? AND d.work_id=?', (execution_id, work_id)).fetchone()
            require(slot is not None, 'No exact allocation')
            runtime.accept(link['task_id'], slot['attempt_id'], criteria, actor, 'Explicit DAG bounded WorkItem acceptance')
        _evaluate(runtime, execution_id, actor)
    return show(runtime, execution_id)


def disposition(runtime, execution_id, work_id, kind, reason, actor):
    require(actor.role == 'human', 'Explicit Principal disposition required')
    require(kind in {'HUMAN_GATE', 'HUMAN_RESOLVED', 'FAILED', 'CANCELLED'} and isinstance(reason, str) and bool(reason.strip()), 'Exact disposition/reason required')
    with runtime.store.transaction():
        data = execution(runtime, execution_id)
        require(work_id in data['order'], 'Unknown graph work')
        require(not runtime.db.execute('SELECT 1 FROM dag_acceptances WHERE execution_id=? AND work_id=?', (execution_id, work_id)).fetchone(), 'Accepted work immutable')
        old = runtime.db.execute("SELECT kind FROM dag_facts WHERE execution_id=? AND work_id=? AND kind IN ('HUMAN_GATE','HUMAN_RESOLVED','FAILED','CANCELLED') ORDER BY rowid DESC LIMIT 1", (execution_id, work_id)).fetchone()
        require(not old or old['kind'] not in {'FAILED', 'CANCELLED'}, 'Terminal disposition immutable')
        if kind == 'HUMAN_RESOLVED':
            require(old and old['kind'] == 'HUMAN_GATE', 'No explicit gate to resolve; planning gates need a new validated revision')
        active = runtime.db.execute('SELECT d.id,a.attempt_id FROM dag_slots s JOIN dag_dispatches d ON s.dispatch_id=d.id LEFT JOIN dag_allocations a ON a.dispatch_id=d.id WHERE s.execution_id=? AND d.work_id=?', (execution_id, work_id)).fetchone()
        if active and kind in {'FAILED', 'CANCELLED'}:
            require(active['attempt_id'] and isolation.facts(runtime, active['attempt_id'])['fence'], 'UNKNOWN/active ownership cannot release slot')
            runtime.db.execute('DELETE FROM dag_slots WHERE dispatch_id=?', (active['id'],))
        _fact(runtime, execution_id, work_id, kind, {'reason': reason, 'fence_attempt': active['attempt_id'] if active else None}, actor)
        _evaluate(runtime, execution_id, actor)
    return show(runtime, execution_id)


def accept_plan(runtime, execution_id, actor):
    require(actor.role == 'human', 'Plan completion is not Principal acceptance')
    with runtime.store.transaction():
        _evaluate(runtime, execution_id, actor)
        require(show(runtime, execution_id)['state'] == 'COMPLETE', 'All required WorkItems must be accepted')
        if not runtime.db.execute('SELECT 1 FROM dag_plan_acceptances WHERE execution_id=?', (execution_id,)).fetchone():
            data = {'execution_id': execution_id, 'actor': actor.record(), 'at': now(), 'meaning': 'Bounded plan acceptance; not merge/deploy'}
            runtime.db.execute('INSERT INTO dag_plan_acceptances VALUES (?,?,?)', (execution_id, canonical_json(data), digest(data)))
    return show(runtime, execution_id)


def recover(runtime, execution_id, actor):
    # Reconstruct projections from canonical facts only; never invoke/reserve.
    return materialize(runtime, execution_id, actor)


def execute_next(runtime, execution_id, host, actor):
    """Only the existing real M08 driver; no executor plugin/test fallback."""
    from .vmware_host import VMwareHost
    require(type(host) is VMwareHost, 'Exact real M08 VMware driver required')
    require(not runtime.db.in_transaction, 'Host effects require committed intents')
    intent = claim(runtime, execution_id, actor)
    return execute_claim(runtime, intent['id'], host, actor)


def execute_claim(runtime, dispatch_id, host, actor):
    """Execute one exact claimed authority; processes can run different claims."""
    from .vmware_host import VMwareHost
    require(type(host) is VMwareHost and not runtime.db.in_transaction, 'Exact real M08 driver outside transaction required')
    intent = _decode(runtime.db.execute('SELECT * FROM dag_dispatches WHERE id=?',(dispatch_id,)).fetchone())
    attempt = allocate(runtime, intent['id'], actor)
    isolation.reserve(runtime, attempt['id'], host, actor)
    for name in ('clone', 'start', 'prepare', 'probes', 'stop'):
        isolation.operation(runtime, attempt['id'], name, host, actor)
    evidence = isolation.complete(runtime, attempt['id'], actor)
    refresh(runtime, intent['execution_id'], actor)
    return {'dispatch': intent, 'attempt_id': attempt['id'], 'evidence_id': evidence, 'state': 'REVIEW'}
