"""Small versioned SQLite store, not a generalized event-sourcing framework."""

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import uuid

from .domain import ACPError, now, require

SCHEMA_VERSION = 9
SCHEMA = [
    "CREATE TABLE schema_metadata (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)",
    """CREATE TABLE projects (
        id TEXT PRIMARY KEY, path TEXT NOT NULL, path_key TEXT NOT NULL UNIQUE,
        repository_identity TEXT NOT NULL, git_root TEXT, observed_head TEXT,
        context_json TEXT NOT NULL CHECK(json_valid(context_json)),
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), created_at TEXT NOT NULL)""",
    """CREATE TABLE tasks (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
        title TEXT NOT NULL, request TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
        state TEXT NOT NULL CHECK(state IN ('NEW','TRIAGE','PLANNED','READY','RUNNING','REVIEW','REWORK','NEEDS_HUMAN','BLOCKED','DONE','FAILED','CANCELLED')),
        plan_revision INTEGER NOT NULL DEFAULT 0, envelope_json TEXT CHECK(json_valid(envelope_json)),
        hold_reason TEXT, resume_state TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE task_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(id),
        kind TEXT NOT NULL, from_state TEXT, to_state TEXT, actor_json TEXT NOT NULL CHECK(json_valid(actor_json)),
        reason TEXT NOT NULL, details_json TEXT NOT NULL CHECK(json_valid(details_json)), at TEXT NOT NULL)""",
    """CREATE TABLE approvals (
        id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id), kind TEXT NOT NULL CHECK(kind IN ('human','policy')),
        envelope_json TEXT NOT NULL CHECK(json_valid(envelope_json)), envelope_digest TEXT NOT NULL,
        authority_json TEXT NOT NULL CHECK(json_valid(authority_json)), policy_ref TEXT,
        issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
        UNIQUE(id,task_id))""",
    """CREATE TABLE approval_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, approval_id TEXT NOT NULL REFERENCES approvals(id),
        kind TEXT NOT NULL, actor_json TEXT NOT NULL CHECK(json_valid(actor_json)), reason TEXT NOT NULL, at TEXT NOT NULL)""",
    """CREATE TABLE execution_attempts (
        id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
        contract_json TEXT NOT NULL CHECK(json_valid(contract_json)), contract_digest TEXT NOT NULL,
        approval_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK(state IN ('CREATED','QUEUED','STARTING','RUNNING','SUCCEEDED','FAILED','CANCEL_REQUESTED','CANCELLED','LOST')),
        fence_evidence_id TEXT REFERENCES evidence(id), quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1)),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(id,task_id),
        FOREIGN KEY(approval_id,task_id) REFERENCES approvals(id,task_id))""",
    """CREATE TABLE attempt_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, attempt_id TEXT NOT NULL REFERENCES execution_attempts(id),
        kind TEXT NOT NULL, from_state TEXT, to_state TEXT, actor_json TEXT NOT NULL CHECK(json_valid(actor_json)),
        reason TEXT NOT NULL, details_json TEXT NOT NULL CHECK(json_valid(details_json)), at TEXT NOT NULL)""",
    """CREATE TABLE evidence (
        id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id), attempt_id TEXT,
        class TEXT NOT NULL CHECK(class IN ('claim','artifact','repository_fact','independent_result')),
        trust TEXT NOT NULL CHECK(trust IN ('unverified','observed','independently_verified')),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL, collected_at TEXT NOT NULL,
        FOREIGN KEY(attempt_id,task_id) REFERENCES execution_attempts(id,task_id))""",
    """CREATE TABLE backend_mappings (
        id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES execution_attempts(id),
        backend TEXT NOT NULL, backend_version TEXT NOT NULL, backend_task_id TEXT NOT NULL,
        backend_session_id TEXT, idempotency_key TEXT NOT NULL,
        observation_json TEXT NOT NULL CHECK(json_valid(observation_json)), created_at TEXT NOT NULL,
        UNIQUE(backend,backend_task_id), UNIQUE(attempt_id,backend))""",
    "CREATE INDEX task_events_task ON task_events(task_id,seq)",
    "CREATE INDEX attempts_task ON execution_attempts(task_id)",
    "CREATE INDEX attempt_events_attempt ON attempt_events(attempt_id,seq)",
]


def data_directory(override=None):
    value = override or os.environ.get("ACP_DATA_DIR")
    if value is None:
        local = os.environ.get("LOCALAPPDATA")
        value = (Path(local) if local else Path.home() / ".local" / "share") / "AgentControlPlane"
    path = Path(value).expanduser().resolve()
    source = Path(__file__).resolve().parent.parent
    require(not path.is_relative_to(source), "Runtime state must be outside the ACP source tree")
    # No repository scanning: inspect only the selected directory's ancestors.
    require(not any((p / ".git").exists() for p in (path, *path.parents)), "Runtime state must not live inside a Git checkout")
    return path


class Store:
    def __init__(self, data_dir=None, *, existing_only=False):
        self.directory = data_directory(data_dir)
        if not existing_only:
            self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "acp.sqlite3"
        require(not self.path.is_symlink(), "Database symlinks are not supported")
        self.db = sqlite3.connect(self.path.as_uri() + '?mode=rw' if existing_only else self.path,
                                  uri=existing_only, isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA busy_timeout=10000")
            if existing_only:
                require(self.db.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION,
                        'Existing canonical schema required; migrate explicitly with CLI')
            else:
                self._migrate()
            self.db.execute("PRAGMA foreign_keys=ON")
            require(not self.db.execute('PRAGMA foreign_key_check').fetchall(), 'Migration foreign key failure')
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
        except Exception:
            self.db.close()
            raise

    def _migrate(self):
        # SQLite's documented table-rebuild sequence. No effects/dispatch during migration.
        self.db.execute('PRAGMA foreign_keys=OFF')
        with self.transaction():
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            require(version in (0, 1, 2, 3, 4, 5, 6, 7, 8, SCHEMA_VERSION), f"Unsupported database version {version}; no downgrade attempted")
            if version == 0:
                require(not self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), "Unversioned nonempty database; refusing to adopt it")
                for statement in SCHEMA:
                    self.db.execute(statement)
                for table in ("task_events", "attempt_events", "approval_events", "evidence", "backend_mappings", "schema_metadata"):
                    for action in ("UPDATE", "DELETE"):
                        self.db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append-only record'); END")
                for table, columns in {
                    "execution_attempts": ("id", "task_id", "contract_json", "contract_digest", "approval_id", "idempotency_key", "created_at"),
                    "approvals": ("id", "task_id", "kind", "envelope_json", "envelope_digest", "authority_json", "policy_ref", "issued_at", "expires_at"),
                    "tasks": ("id", "project_id", "title", "request", "revision", "created_at"),
                    "projects": ("id", "path", "path_key", "repository_identity", "git_root", "observed_head", "context_json", "created_at"),
                }.items():
                    condition = " OR ".join(f"NEW.{c} IS NOT OLD.{c}" for c in columns)
                    self.db.execute(f"CREATE TRIGGER {table}_immutable BEFORE UPDATE ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT,'immutable input'); END")
                    self.db.execute(f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'record deletion forbidden'); END")
                self.db.execute("INSERT INTO schema_metadata VALUES (1,?)", (now(),))
                self.db.execute("PRAGMA user_version=1")
                version = 1
            rows = [r[0] for r in self.db.execute("SELECT version FROM schema_metadata ORDER BY version")]
            require(rows == list(range(1, version + 1)), "Schema metadata mismatch")
            if version == 1:
                self.db.execute("CREATE TABLE project_profiles (project_id TEXT NOT NULL REFERENCES projects(id), revision INTEGER NOT NULL, metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)), actor_json TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(project_id,revision))")
                self.db.execute("CREATE TABLE context_blobs (sha256 TEXT PRIMARY KEY, content TEXT NOT NULL)")
                self.db.execute("CREATE TABLE context_loads (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), package_json TEXT NOT NULL CHECK(json_valid(package_json)), digest TEXT NOT NULL, actor_json TEXT NOT NULL, at TEXT NOT NULL)")
                self.db.execute("CREATE TABLE resolutions (id TEXT PRIMARY KEY, request TEXT NOT NULL, result_json TEXT NOT NULL CHECK(json_valid(result_json)), task_id TEXT REFERENCES tasks(id), actor_json TEXT NOT NULL, at TEXT NOT NULL)")
                for table in ("project_profiles", "context_blobs", "context_loads", "resolutions"):
                    for action in ("UPDATE", "DELETE"):
                        self.db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append-only context audit'); END")
                self.db.execute("INSERT INTO schema_metadata VALUES (2,?)", (now(),))
                self.db.execute("PRAGMA user_version=2")
                version = 2
            if version == 2:
                self.db.execute("CREATE TABLE planning_runs (id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id), input_json TEXT NOT NULL CHECK(json_valid(input_json)), input_digest TEXT NOT NULL, actor_json TEXT NOT NULL, created_at TEXT NOT NULL)")
                self.db.execute("CREATE TABLE planning_results (run_id TEXT PRIMARY KEY REFERENCES planning_runs(id), validation_id TEXT UNIQUE NOT NULL, raw_text TEXT, provider_json TEXT NOT NULL, result_json TEXT NOT NULL CHECK(json_valid(result_json)), created_at TEXT NOT NULL)")
                self.db.execute("CREATE TABLE plan_revisions (plan_id TEXT NOT NULL, revision INTEGER NOT NULL, task_id TEXT NOT NULL REFERENCES tasks(id), run_id TEXT UNIQUE NOT NULL REFERENCES planning_runs(id), record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL, PRIMARY KEY(plan_id,revision))")
                for table in ("planning_runs", "planning_results", "plan_revisions"):
                    for action in ("UPDATE", "DELETE"):
                        self.db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append-only planning audit'); END")
                self.db.execute("INSERT INTO schema_metadata VALUES (3,?)", (now(),))
                self.db.execute("PRAGMA user_version=3")
                version = 3
            if version == 3:
                self.db.execute("""CREATE TABLE execution_bindings (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id),
                    plan_id TEXT NOT NULL, plan_revision INTEGER NOT NULL, work_item_id TEXT NOT NULL,
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
                    envelope_json TEXT NOT NULL CHECK(json_valid(envelope_json)), envelope_digest TEXT NOT NULL,
                    UNIQUE(plan_id,plan_revision,work_item_id),
                    FOREIGN KEY(plan_id,plan_revision) REFERENCES plan_revisions(plan_id,revision))""")
                for table in ("execution_receipts", "execution_dispatches"):
                    self.db.execute(f"""CREATE TABLE {table} (
                        id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE REFERENCES execution_attempts(id),
                        record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
                        created_at TEXT NOT NULL)""")
                self.db.execute("""CREATE TABLE execution_outcomes (
                    id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE REFERENCES execution_attempts(id),
                    outcome TEXT NOT NULL CHECK(outcome IN ('SUCCEEDED','FAILED','REJECTED','UNKNOWN')),
                    evidence_id TEXT NOT NULL REFERENCES evidence(id),
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
                    created_at TEXT NOT NULL)""")
                for table in ("execution_bindings", "execution_receipts", "execution_dispatches", "execution_outcomes"):
                    for action in ("UPDATE", "DELETE"):
                        self.db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append-only controlled execution'); END")
                self.db.execute("INSERT INTO schema_metadata VALUES (4,?)", (now(),))
                self.db.execute("PRAGMA user_version=4")
                version = 4
            if version == 4:
                self.db.execute("CREATE TABLE provider_runs (id TEXT PRIMARY KEY REFERENCES planning_runs(id), record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)")
                for table in ("provider_requests", "provider_dispatches", "provider_invocations", "provider_responses", "provider_validations"):
                    self.db.execute(f"CREATE TABLE {table} (id TEXT PRIMARY KEY, run_id TEXT UNIQUE NOT NULL REFERENCES provider_runs(id), record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)")
                self.db.execute("CREATE TABLE provider_observations (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES provider_runs(id), record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)")
                for table in ("provider_runs", "provider_requests", "provider_dispatches", "provider_invocations", "provider_responses", "provider_validations", "provider_observations"):
                    for action in ("UPDATE", "DELETE"):
                        self.db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append-only provider audit'); END")
                self.db.execute("INSERT INTO schema_metadata VALUES (5,?)", (now(),))
                self.db.execute("PRAGMA user_version=5")
                version = 5
            if version == 5:
                self.db.execute("""CREATE TABLE isolation_task_bindings (
                    id TEXT PRIMARY KEY, task_id TEXT UNIQUE NOT NULL REFERENCES tasks(id),
                    plan_id TEXT NOT NULL, plan_revision INTEGER NOT NULL, work_item_id TEXT NOT NULL,
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
                    UNIQUE(plan_id,plan_revision,work_item_id),
                    FOREIGN KEY(plan_id,plan_revision) REFERENCES plan_revisions(plan_id,revision))""")
                self.db.execute("""CREATE TABLE isolation_instances (
                    id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL REFERENCES execution_attempts(id),
                    binding_id TEXT NOT NULL REFERENCES isolation_task_bindings(id),
                    vmx_path TEXT UNIQUE NOT NULL, workspace_path TEXT UNIQUE NOT NULL,
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)""")
                self.db.execute("""CREATE TABLE isolation_intents (
                    id TEXT PRIMARY KEY, isolation_id TEXT NOT NULL REFERENCES isolation_instances(id),
                    operation TEXT NOT NULL, record_json TEXT NOT NULL CHECK(json_valid(record_json)),
                    digest TEXT NOT NULL, UNIQUE(isolation_id,operation))""")
                self.db.execute("""CREATE TABLE isolation_observations (
                    id TEXT PRIMARY KEY, isolation_id TEXT NOT NULL REFERENCES isolation_instances(id),
                    intent_id TEXT REFERENCES isolation_intents(id), kind TEXT NOT NULL,
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)""")
                self.db.execute("""CREATE TABLE isolation_fences (
                    attempt_id TEXT PRIMARY KEY REFERENCES execution_attempts(id),
                    evidence_id TEXT UNIQUE NOT NULL REFERENCES evidence(id),
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)""")
                self.db.execute("""CREATE TABLE isolation_retries (
                    previous_attempt TEXT PRIMARY KEY REFERENCES execution_attempts(id),
                    candidate_attempt TEXT UNIQUE NOT NULL REFERENCES execution_attempts(id))""")
                for table in ("isolation_task_bindings", "isolation_instances", "isolation_intents",
                              "isolation_observations", "isolation_fences", "isolation_retries"):
                    for action in ("UPDATE", "DELETE"):
                        self.db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append-only isolation audit'); END")
                self.db.execute("INSERT INTO schema_metadata VALUES (6,?)", (now(),))
                self.db.execute("PRAGMA user_version=6")
                version = 6
            if version == 6:
                self.db.execute("""CREATE TABLE dag_executions (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    plan_id TEXT NOT NULL, revision INTEGER NOT NULL,
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
                    UNIQUE(plan_id,revision), FOREIGN KEY(plan_id,revision) REFERENCES plan_revisions(plan_id,revision))""")
                self.db.execute("""CREATE TABLE dag_nodes (
                    execution_id TEXT NOT NULL REFERENCES dag_executions(id), work_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN
                    ('PENDING','WAITING_DEPENDENCY','READY','DISPATCHED','RUNNING','REVIEW','ACCEPTED','BLOCKED','NEEDS_HUMAN','FAILED','CANCELLED')),
                    cause_json TEXT NOT NULL CHECK(json_valid(cause_json)),
                    PRIMARY KEY(execution_id,work_id), UNIQUE(execution_id,ordinal))""")
                self.db.execute("""CREATE TABLE dag_edges (
                    execution_id TEXT NOT NULL, parent TEXT NOT NULL, child TEXT NOT NULL,
                    PRIMARY KEY(execution_id,parent,child),
                    FOREIGN KEY(execution_id,parent) REFERENCES dag_nodes(execution_id,work_id),
                    FOREIGN KEY(execution_id,child) REFERENCES dag_nodes(execution_id,work_id))""")
                self.db.execute("""CREATE TABLE dag_links (
                    execution_id TEXT NOT NULL, work_id TEXT NOT NULL, task_id TEXT UNIQUE NOT NULL REFERENCES tasks(id),
                    binding_id TEXT UNIQUE NOT NULL REFERENCES isolation_task_bindings(id),
                    PRIMARY KEY(execution_id,work_id), FOREIGN KEY(execution_id,work_id) REFERENCES dag_nodes(execution_id,work_id))""")
                self.db.execute("""CREATE TABLE dag_dispatches (
                    id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, work_id TEXT NOT NULL,
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
                    UNIQUE(execution_id,work_id), FOREIGN KEY(execution_id,work_id) REFERENCES dag_nodes(execution_id,work_id))""")
                self.db.execute("""CREATE TABLE dag_allocations (
                    dispatch_id TEXT PRIMARY KEY REFERENCES dag_dispatches(id), attempt_id TEXT UNIQUE NOT NULL REFERENCES execution_attempts(id))""")
                self.db.execute("""CREATE TABLE dag_slots (
                    execution_id TEXT PRIMARY KEY REFERENCES dag_executions(id),
                    dispatch_id TEXT UNIQUE NOT NULL REFERENCES dag_dispatches(id))""")
                self.db.execute("""CREATE TABLE dag_acceptances (
                    execution_id TEXT NOT NULL, work_id TEXT NOT NULL, attempt_id TEXT UNIQUE NOT NULL REFERENCES execution_attempts(id),
                    event_seq INTEGER UNIQUE NOT NULL REFERENCES task_events(seq),
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL,
                    PRIMARY KEY(execution_id,work_id), FOREIGN KEY(execution_id,work_id) REFERENCES dag_nodes(execution_id,work_id))""")
                self.db.execute("""CREATE TABLE dag_facts (
                    id TEXT PRIMARY KEY, execution_id TEXT NOT NULL REFERENCES dag_executions(id), work_id TEXT,
                    kind TEXT NOT NULL, record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)""")
                self.db.execute("""CREATE TABLE dag_projection (
                    execution_id TEXT PRIMARY KEY REFERENCES dag_executions(id),
                    state TEXT NOT NULL CHECK(state IN ('CREATED','ACTIVE','COMPLETE','BLOCKED','NEEDS_HUMAN')),
                    cause_json TEXT NOT NULL CHECK(json_valid(cause_json)))""")
                self.db.execute("""CREATE TABLE dag_plan_acceptances (
                    execution_id TEXT PRIMARY KEY REFERENCES dag_executions(id),
                    record_json TEXT NOT NULL CHECK(json_valid(record_json)), digest TEXT NOT NULL)""")
                for table in ('dag_executions','dag_edges','dag_links','dag_dispatches','dag_allocations','dag_acceptances','dag_facts','dag_plan_acceptances'):
                    for action in ('UPDATE','DELETE'):
                        self.db.execute(f"CREATE TRIGGER {table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append-only DAG authority'); END")
                self.db.execute("CREATE TRIGGER dag_nodes_identity BEFORE UPDATE ON dag_nodes WHEN NEW.execution_id IS NOT OLD.execution_id OR NEW.work_id IS NOT OLD.work_id OR NEW.ordinal IS NOT OLD.ordinal BEGIN SELECT RAISE(ABORT,'immutable DAG node'); END")
                self.db.execute("CREATE TRIGGER dag_nodes_no_delete BEFORE DELETE ON dag_nodes BEGIN SELECT RAISE(ABORT,'immutable DAG graph'); END")
                self.db.execute("INSERT INTO schema_metadata VALUES (7,?)", (now(),))
                self.db.execute("PRAGMA user_version=7")
                version = 7
            if version == 7:
                # Preserve every old authority, assigning its sole slot ordinal 1.
                self.db.execute("""CREATE TABLE dag_slots_v8 (
                    execution_id TEXT NOT NULL REFERENCES dag_executions(id),
                    dispatch_id TEXT UNIQUE NOT NULL REFERENCES dag_dispatches(id),
                    slot_no INTEGER NOT NULL CHECK(slot_no BETWEEN 1 AND 4),
                    PRIMARY KEY(execution_id,slot_no))""")
                self.db.execute('INSERT INTO dag_slots_v8 SELECT execution_id,dispatch_id,1 FROM dag_slots')
                self.db.execute('DROP TABLE dag_slots')
                self.db.execute('ALTER TABLE dag_slots_v8 RENAME TO dag_slots')
                self.db.execute("""CREATE TRIGGER dag_slots_capacity BEFORE INSERT ON dag_slots BEGIN
                    SELECT CASE WHEN NEW.slot_no > coalesce((SELECT json_extract(record_json,'$.concurrency.max_parallel') FROM dag_executions WHERE id=NEW.execution_id),1)
                    OR (SELECT count(*) FROM dag_slots WHERE execution_id=NEW.execution_id) >= coalesce((SELECT json_extract(record_json,'$.concurrency.max_parallel') FROM dag_executions WHERE id=NEW.execution_id),1)
                    OR NOT EXISTS(SELECT 1 FROM dag_dispatches WHERE id=NEW.dispatch_id AND execution_id=NEW.execution_id)
                    THEN RAISE(ABORT,'canonical capacity exceeded or mismatched dispatch') END;
                    END""")
                self.db.execute("CREATE TRIGGER dag_slots_no_update BEFORE UPDATE ON dag_slots BEGIN SELECT RAISE(ABORT,'immutable capacity authority'); END")
                self.db.execute("""CREATE TRIGGER dag_slots_release BEFORE DELETE ON dag_slots BEGIN
                    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM dag_allocations a JOIN dag_acceptances c ON c.attempt_id=a.attempt_id WHERE a.dispatch_id=OLD.dispatch_id AND c.execution_id=OLD.execution_id)
                    AND NOT EXISTS(SELECT 1 FROM dag_allocations a JOIN isolation_fences f ON f.attempt_id=a.attempt_id WHERE a.dispatch_id=OLD.dispatch_id)
                    THEN RAISE(ABORT,'capacity requires canonical acceptance or M08 fence') END;
                    END""")
                self.db.execute('INSERT INTO schema_metadata VALUES (8,?)', (now(),))
                self.db.execute('PRAGMA user_version=8')
                version = 8
            if version == 8:
                from .review_schema import migrate
                migrate(self.db)

    @contextmanager
    def transaction(self):
        # Canonical composition only: inner commit cannot escape outer rollback.
        # External invocation must remain outside every transaction.
        if self.db.in_transaction:
            savepoint = 'acp_' + uuid.uuid4().hex
            self.db.execute('SAVEPOINT ' + savepoint)
            try:
                yield
                self.db.execute('RELEASE ' + savepoint)
            except BaseException:
                self.db.execute('ROLLBACK TO ' + savepoint)
                self.db.execute('RELEASE ' + savepoint)
                raise
            return
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            # A failed commit acknowledgement may follow an actual commit.
            # Preserve the original error; recovery reads committed facts only.
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def one(self, table, record_id):
        require(table in {"projects", "tasks", "execution_attempts", "approvals", "evidence"}, "Invalid record type")
        row = self.db.execute(f"SELECT * FROM {table} WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise ACPError(f"Unknown {table} ID: {record_id}")
        return dict(row)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
