"""Remove only M09 additions from disposable migration test databases."""


def drop_dag(db):
    drop_review(db)
    for name in ('dag_plan_acceptances','dag_projection','dag_facts','dag_acceptances',
                 'dag_slots','dag_allocations','dag_dispatches','dag_links','dag_edges','dag_nodes','dag_executions'):
        db.execute('DROP TABLE ' + name)


def drop_review(db, *, keep_dag=False):
    """Build historical disposable fixtures; never used on canonical state."""
    db.execute('DROP TRIGGER dag_dispatch_generation')
    db.execute('DROP TRIGGER dag_slots_one_work')
    for name in ('review_slots','review_observations','review_decisions','review_validations',
                 'review_responses','review_invocations','review_dispatches','review_requests',
                 'review_transport_closures','review_attempts','review_collections','review_failures',
                 'review_runs','review_revocations','review_retries','review_enrollments'):
        db.execute('DROP TABLE IF EXISTS '+name)
    if keep_dag:
        db.execute('''CREATE TABLE dag_dispatches_old (
            id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, work_id TEXT NOT NULL,
            record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
            UNIQUE(execution_id,work_id), FOREIGN KEY(execution_id,work_id) REFERENCES dag_nodes(execution_id,work_id))''')
        db.execute('INSERT INTO dag_dispatches_old SELECT id,execution_id,work_id,record_json,digest FROM dag_dispatches')
        db.execute('DROP TABLE dag_dispatches')
        db.execute('PRAGMA legacy_alter_table=ON')
        db.execute('ALTER TABLE dag_dispatches_old RENAME TO dag_dispatches')
        db.execute('PRAGMA legacy_alter_table=OFF')
        for action in ('UPDATE','DELETE'):
            db.execute(f"CREATE TRIGGER dag_dispatches_{action.lower()} BEFORE {action} ON dag_dispatches BEGIN SELECT RAISE(ABORT,'append-only DAG authority'); END")
