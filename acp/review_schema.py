"""M11 transactional migration; historical dispatch JSON/digests are untouched."""
from .domain import now,require


def migrate(db):
    db.execute('''CREATE TABLE review_retries (
        id TEXT PRIMARY KEY, execution_id TEXT NOT NULL REFERENCES dag_executions(id),
        work_id TEXT NOT NULL, previous_attempt TEXT UNIQUE NOT NULL REFERENCES execution_attempts(id),
        ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 2),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
        UNIQUE(execution_id,work_id,ordinal))''')
    db.execute('''CREATE TABLE dag_dispatches_v9 (
        id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, work_id TEXT NOT NULL,
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
        generation INTEGER NOT NULL DEFAULT 0 CHECK(generation>=0), retry_id TEXT UNIQUE,
        UNIQUE(execution_id,work_id,generation),
        FOREIGN KEY(execution_id,work_id) REFERENCES dag_nodes(execution_id,work_id),
        FOREIGN KEY(retry_id) REFERENCES review_retries(id))''')
    db.execute('INSERT INTO dag_dispatches_v9(id,execution_id,work_id,record_json,digest) SELECT * FROM dag_dispatches')
    db.execute('DROP TABLE dag_dispatches')
    db.execute('PRAGMA legacy_alter_table=ON')
    db.execute('ALTER TABLE dag_dispatches_v9 RENAME TO dag_dispatches')
    db.execute('PRAGMA legacy_alter_table=OFF')
    db.execute('''CREATE TABLE review_enrollments (
        id TEXT PRIMARY KEY, execution_id TEXT UNIQUE NOT NULL REFERENCES dag_executions(id),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)''')
    db.execute('''CREATE TABLE review_revocations (
        id TEXT PRIMARY KEY, enrollment_id TEXT UNIQUE NOT NULL REFERENCES review_enrollments(id),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)''')
    db.execute('''CREATE TABLE review_runs (
        id TEXT PRIMARY KEY, execution_id TEXT NOT NULL REFERENCES dag_executions(id),
        work_id TEXT NOT NULL, attempt_id TEXT NOT NULL REFERENCES execution_attempts(id),
        revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2), preparation_key TEXT NOT NULL,
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
        UNIQUE(attempt_id,revision), UNIQUE(attempt_id,preparation_key))''')
    db.execute('''CREATE TABLE review_attempts (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES review_runs(id),
        ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 2),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
        UNIQUE(run_id,ordinal))''')
    for table, parent, reference in (
            ('review_requests','attempt_id','review_attempts'),
            ('review_dispatches','attempt_id','review_attempts'),
            ('review_invocations','attempt_id','review_attempts'),
            ('review_responses','attempt_id','review_attempts'),
            ('review_validations','attempt_id','review_attempts'),
            ('review_transport_closures','attempt_id','review_attempts'),
            ('review_decisions','run_id','review_runs'),
            ('review_collections','attempt_id','execution_attempts')):
        db.execute(f'''CREATE TABLE {table} (
            id TEXT PRIMARY KEY, {parent} TEXT UNIQUE NOT NULL REFERENCES {reference}(id),
            record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)''')
    db.execute('''CREATE TABLE review_failures (
        id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL REFERENCES execution_attempts(id),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)''')
    db.execute('''CREATE TABLE review_observations (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES review_runs(id),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)''')
    db.execute('''CREATE TABLE review_slots (
        execution_id TEXT PRIMARY KEY REFERENCES dag_executions(id),
        attempt_id TEXT UNIQUE NOT NULL REFERENCES review_attempts(id))''')
    for table in ('dag_dispatches','review_enrollments','review_revocations','review_runs',
                  'review_attempts','review_requests','review_dispatches','review_invocations',
                  'review_responses','review_validations','review_decisions','review_observations',
                  'review_retries','review_collections','review_transport_closures','review_failures'):
        for action in ('UPDATE','DELETE'):
            db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'immutable M11 authority'); END")
    db.execute('''CREATE TRIGGER dag_dispatch_generation BEFORE INSERT ON dag_dispatches
        WHEN NEW.generation>0 BEGIN
        SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM review_retries r
          JOIN review_enrollments e ON e.execution_id=r.execution_id
          JOIN dag_dispatches d ON d.execution_id=r.execution_id AND d.work_id=r.work_id AND d.generation=NEW.generation-1
          JOIN dag_allocations a ON a.dispatch_id=d.id AND a.attempt_id=r.previous_attempt
          JOIN isolation_fences f ON f.attempt_id=r.previous_attempt
          WHERE r.id=NEW.retry_id AND r.execution_id=NEW.execution_id AND r.work_id=NEW.work_id AND r.ordinal=NEW.generation)
        THEN RAISE(ABORT,'exact enrolled predecessor retry generation required') END; END''')
    db.execute('''CREATE TRIGGER dag_slots_one_work BEFORE INSERT ON dag_slots BEGIN
        SELECT CASE WHEN EXISTS(SELECT 1 FROM dag_slots s JOIN dag_dispatches d ON d.id=s.dispatch_id
          JOIN dag_dispatches n ON n.id=NEW.dispatch_id
          WHERE d.execution_id=n.execution_id AND d.work_id=n.work_id)
        THEN RAISE(ABORT,'one active work generation required') END; END''')
    db.execute("CREATE TRIGGER review_slots_no_update BEFORE UPDATE ON review_slots BEGIN SELECT RAISE(ABORT,'immutable review capacity'); END")
    db.execute('''CREATE TRIGGER review_slots_binding BEFORE INSERT ON review_slots BEGIN
        SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM review_attempts a JOIN review_runs n ON n.id=a.run_id
        WHERE a.id=NEW.attempt_id AND n.execution_id=NEW.execution_id)
        THEN RAISE(ABORT,'exact review PEX binding required') END; END''')
    db.execute('''CREATE TRIGGER review_slots_release BEFORE DELETE ON review_slots BEGIN
        SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM review_attempts a JOIN review_decisions d ON d.run_id=a.run_id WHERE a.id=OLD.attempt_id)
        AND NOT EXISTS(SELECT 1 FROM review_transport_closures WHERE attempt_id=OLD.attempt_id)
        THEN RAISE(ABORT,'UNKNOWN review retains capacity') END; END''')
    db.execute('INSERT INTO schema_metadata VALUES (9,?)',(now(),))
    db.execute('PRAGMA user_version=9')
    require(not db.execute('PRAGMA foreign_key_check').fetchall(), 'Migration foreign key failure')
