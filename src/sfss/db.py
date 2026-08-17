import json
import hashlib
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class MutationConflictError(RuntimeError):
    """A guarded mutation no longer matched its security precondition."""


class Store:
    # Version 3 replaces project scoping with personal user spaces,
    # platform-level approver roles, and global transfer policies.
    SCHEMA_VERSION = 3

    def __init__(self, path: Path, read_only: bool = False):
        self.path = path.resolve() if read_only else path
        self.read_only = read_only
        self._lock = threading.RLock()
        if read_only:
            if not self.path.is_file(): raise RuntimeError("database does not exist for read-only access")
            self._validate_read_only_schema()
            return
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        self.initialize()
        self.path.chmod(0o600)

    def connect(self):
        if self.read_only:
            connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=15)
        else:
            connection = sqlite3.connect(str(self.path), timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if self.read_only:
            connection.execute("PRAGMA query_only=ON")
            return connection
        connection.execute("PRAGMA journal_mode=WAL")
        # systemd supplies UMask=0077 in production, but keep SQLite sidecars
        # private even in local/manual launches with a permissive process umask.
        for candidate in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            if candidate.exists(): candidate.chmod(0o600)
        return connection

    def _validate_read_only_schema(self):
        with self.connect() as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "schema_metadata" not in tables:
                raise RuntimeError("database schema metadata is missing; read-only verification cannot migrate it")
            row = db.execute("SELECT version FROM schema_metadata WHERE id=1").fetchone()
            if not row or row[0] != self.SCHEMA_VERSION:
                found = row[0] if row else "missing"
                raise RuntimeError(
                    f"database schema version {found} does not match supported version {self.SCHEMA_VERSION}")

    def initialize(self):
        with self.connect() as db:
            existing_tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "schema_metadata" in existing_tables:
                row = db.execute("SELECT version FROM schema_metadata WHERE id=1").fetchone()
                if row and row[0] > self.SCHEMA_VERSION:
                    raise RuntimeError(
                        f"database schema version {row[0]} is newer than supported version {self.SCHEMA_VERSION}")
                if row and row[0] < self.SCHEMA_VERSION:
                    raise RuntimeError(
                        f"database schema version {row[0]} predates the personal-space model; "
                        "project-scoped databases cannot be migrated automatically. Back up the "
                        "old data directory and initialize a fresh one.")
            audit_chain_is_new = "audit_chain" not in existing_tables
            db.executescript("""
            CREATE TABLE IF NOT EXISTS schema_metadata (
              id INTEGER PRIMARY KEY CHECK(id=1),
              version INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
              username TEXT PRIMARY KEY, global_admin INTEGER NOT NULL DEFAULT 0,
              approver INTEGER NOT NULL DEFAULT 0,
              principal_type TEXT NOT NULL DEFAULT 'human' CHECK(principal_type IN ('human','service')),
              enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS objects (
              id TEXT PRIMARY KEY,
              uploader TEXT NOT NULL REFERENCES users(username),
              filename TEXT NOT NULL,
              size INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              media_type TEXT NOT NULL,
              type_known INTEGER NOT NULL,
              type_conflict INTEGER NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('pending_scan','scanning','quarantined','released','rejected','expired')),
              storage_path TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              integrity_mtime_ns INTEGER,
              integrity_ctime_ns INTEGER,
              scan_detail TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS audit_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp INTEGER NOT NULL,
              request_id TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              object_id TEXT,
              outcome TEXT NOT NULL,
              source_zone TEXT NOT NULL,
              remote_addr TEXT NOT NULL,
              details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_chain (
              event_id INTEGER PRIMARY KEY REFERENCES audit_events(id),
              prev_hash TEXT NOT NULL,
              event_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_accounts (
              username TEXT PRIMARY KEY REFERENCES users(username),
              password_salt TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS system_config (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL,
              updated_at INTEGER NOT NULL,
              updated_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
              token_hash TEXT PRIMARY KEY,
              username TEXT NOT NULL REFERENCES users(username),
              auth_backend TEXT NOT NULL DEFAULT 'legacy' CHECK(auth_backend IN ('local','ldap','legacy')),
              zone TEXT NOT NULL DEFAULT 'legacy' CHECK(zone IN ('green','red','admin','development','legacy')),
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              last_seen_at INTEGER NOT NULL,
              revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at,revoked);
            CREATE TABLE IF NOT EXISTS service_tokens (
              id TEXT PRIMARY KEY,
              token_hash TEXT NOT NULL UNIQUE,
              label TEXT NOT NULL,
              username TEXT NOT NULL REFERENCES users(username),
              zone TEXT NOT NULL CHECK(zone IN ('green','red')),
              permissions TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              last_used_at INTEGER,
              created_by TEXT NOT NULL,
              revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS service_tokens_lookup_idx ON service_tokens(token_hash,revoked,expires_at);
            CREATE TABLE IF NOT EXISTS integration_nonces (
              nonce TEXT PRIMARY KEY,
              payload_hash TEXT NOT NULL,
              expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS integration_nonces_expiry_idx ON integration_nonces(expires_at);
            CREATE TABLE IF NOT EXISTS approval_callback_events (
              event_id TEXT PRIMARY KEY,
              approval_id TEXT NOT NULL,
              payload_hash TEXT NOT NULL,
              decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
              actor TEXT NOT NULL,
              received_at INTEGER NOT NULL,
              outcome TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbound_policy (
              id INTEGER PRIMARY KEY CHECK(id=1),
              enabled INTEGER NOT NULL DEFAULT 0,
              allowed_classifications TEXT NOT NULL DEFAULT '["GDS","FPGA_BITFILE","GENERAL"]',
              approval_provider TEXT NOT NULL DEFAULT 'local',
              approval_timeout_hours INTEGER NOT NULL DEFAULT 72,
              download_ttl_hours INTEGER NOT NULL DEFAULT 168,
              updated_at INTEGER NOT NULL,
              updated_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_policy (
              id INTEGER PRIMARY KEY CHECK(id=1),
              inbound_upload_cidrs TEXT NOT NULL DEFAULT '["127.0.0.1/32","::1/128"]',
              outbound_upload_cidrs TEXT NOT NULL DEFAULT '["127.0.0.1/32","::1/128"]',
              updated_at INTEGER NOT NULL,
              updated_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbound_transfers (
              id TEXT PRIMARY KEY,
              uploader TEXT NOT NULL REFERENCES users(username),
              filename TEXT NOT NULL,
              size INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              media_type TEXT NOT NULL,
              type_known INTEGER NOT NULL,
              type_conflict INTEGER NOT NULL,
              classification TEXT,
              state TEXT NOT NULL CHECK(state IN ('pending_scan','scanning','quarantined','classified','pending_approval','approved','approval_rejected','released_to_green','expired')),
              storage_path TEXT NOT NULL,
              scan_detail TEXT NOT NULL DEFAULT '[]',
              approval_provider TEXT NOT NULL DEFAULT 'local',
              approval_id TEXT,
              approval_actor TEXT,
              approval_comment TEXT,
              retention_expires_at INTEGER,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              approval_expires_at INTEGER,
              download_expires_at INTEGER
              ,integrity_mtime_ns INTEGER
              ,integrity_ctime_ns INTEGER
            );
            CREATE TABLE IF NOT EXISTS upload_sessions (
              id TEXT PRIMARY KEY,
              actor TEXT NOT NULL REFERENCES users(username),
              direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound')),
              filename TEXT NOT NULL,
              total_size INTEGER NOT NULL,
              chunk_size INTEGER NOT NULL,
              expected_sha256 TEXT,
              state TEXT NOT NULL CHECK(state IN ('uploading','completing','completed','cancelled','expired')),
              object_id TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS upload_parts (
              upload_id TEXT NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
              part_number INTEGER NOT NULL,
              offset INTEGER NOT NULL,
              size INTEGER NOT NULL,
              sha256 TEXT NOT NULL,
              storage_path TEXT NOT NULL,
              completed_at INTEGER NOT NULL,
              PRIMARY KEY(upload_id,part_number)
            );
            CREATE INDEX IF NOT EXISTS upload_sessions_expiry_idx ON upload_sessions(state,expires_at);
            CREATE TABLE IF NOT EXISTS scan_jobs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL CHECK(kind IN ('scan_object','scan_outbound')),
              object_id TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('queued','running','completed','failed')),
              attempts INTEGER NOT NULL DEFAULT 0,
              available_at INTEGER NOT NULL,
              lease_until INTEGER,
              lease_owner TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              last_error TEXT NOT NULL DEFAULT ''
            );
            CREATE UNIQUE INDEX IF NOT EXISTS scan_jobs_active_idx
              ON scan_jobs(kind,object_id) WHERE state IN ('queued','running');
            CREATE INDEX IF NOT EXISTS scan_jobs_claim_idx ON scan_jobs(state,available_at,lease_until,id);
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_chain_no_update BEFORE UPDATE ON audit_chain
            BEGIN SELECT RAISE(ABORT, 'audit chain is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_chain_no_delete BEFORE DELETE ON audit_chain
            BEGIN SELECT RAISE(ABORT, 'audit chain is append-only'); END;
            """)
            user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
            if "principal_type" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN principal_type TEXT NOT NULL DEFAULT 'human'")
            if "enabled" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
            if "approver" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN approver INTEGER NOT NULL DEFAULT 0")
            session_columns = {row[1] for row in db.execute("PRAGMA table_info(auth_sessions)")}
            if "auth_backend" not in session_columns:
                db.execute("ALTER TABLE auth_sessions ADD COLUMN auth_backend TEXT NOT NULL DEFAULT 'legacy'")
            if "zone" not in session_columns:
                db.execute("ALTER TABLE auth_sessions ADD COLUMN zone TEXT NOT NULL DEFAULT 'legacy'")
            nonce_columns = {row[1] for row in db.execute("PRAGMA table_info(integration_nonces)")}
            if "payload_hash" not in nonce_columns:
                db.execute("ALTER TABLE integration_nonces ADD COLUMN payload_hash TEXT NOT NULL DEFAULT ''")
            outbound_columns = {row[1] for row in db.execute("PRAGMA table_info(outbound_transfers)")}
            if "retention_expires_at" not in outbound_columns:
                db.execute("ALTER TABLE outbound_transfers ADD COLUMN retention_expires_at INTEGER")
            object_columns = {row[1] for row in db.execute("PRAGMA table_info(objects)")}
            outbound_columns = {row[1] for row in db.execute("PRAGMA table_info(outbound_transfers)")}
            for column in ("integrity_mtime_ns", "integrity_ctime_ns"):
                if column not in object_columns:
                    db.execute(f"ALTER TABLE objects ADD COLUMN {column} INTEGER")
                if column not in outbound_columns:
                    db.execute(f"ALTER TABLE outbound_transfers ADD COLUMN {column} INTEGER")
            scan_job_columns = {row[1] for row in db.execute("PRAGMA table_info(scan_jobs)")}
            if "lease_owner" not in scan_job_columns:
                db.execute("ALTER TABLE scan_jobs ADD COLUMN lease_owner TEXT")
            if audit_chain_is_new:
                previous = ""
                for row in db.execute("SELECT * FROM audit_events ORDER BY id"):
                    event = dict(row); digest = self._audit_digest(event, previous)
                    db.execute("INSERT INTO audit_chain(event_id,prev_hash,event_hash) VALUES(?,?,?)",
                               (event["id"], previous, digest))
                    previous = digest
            self._verify_audit_chain(db)
            db.execute(
                "INSERT INTO schema_metadata(id,version,updated_at) VALUES(1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET version=excluded.version,updated_at=excluded.updated_at",
                (self.SCHEMA_VERSION, int(time.time())),
            )

    @staticmethod
    def _audit_digest(event: Dict[str, Any], previous: str) -> str:
        fields = ("id", "timestamp", "request_id", "actor", "action", "object_id",
                  "outcome", "source_zone", "remote_addr", "details")
        canonical = json.dumps([event.get(key) for key in fields], ensure_ascii=False,
                               separators=(",", ":"))
        return hashlib.sha256((previous + "\n" + canonical).encode("utf-8")).hexdigest()

    def _verify_audit_chain(self, db) -> Dict[str, Any]:
        previous = ""; count = 0
        rows = db.execute(
            "SELECT e.*,c.prev_hash,c.event_hash FROM audit_events e "
            "LEFT JOIN audit_chain c ON c.event_id=e.id ORDER BY e.id"
        ).fetchall()
        chain_count = db.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]
        if chain_count != len(rows): raise RuntimeError("audit chain record count mismatch")
        for raw in rows:
            row = dict(raw); stored_previous = row.pop("prev_hash"); stored_hash = row.pop("event_hash")
            expected = self._audit_digest(row, previous)
            if stored_previous != previous or stored_hash != expected:
                raise RuntimeError(f"audit chain verification failed at event {row['id']}")
            previous = expected; count += 1
        return {"events": count, "head": previous}

    def verify_audit_chain(self) -> Dict[str, Any]:
        with self.connect() as db: return self._verify_audit_chain(db)

    def schema_version(self) -> int:
        row = self.one("SELECT version FROM schema_metadata WHERE id=1")
        return int(row["version"]) if row else 0

    def execute(self, sql: str, args=()) -> int:
        with self._lock, self.connect() as db:
            cursor = db.execute(sql, args)
            return cursor.rowcount

    def transaction(self, statements, *, required_rows=None) -> List[int]:
        with self._lock, self.connect() as db:
            counts = [db.execute(sql, args).rowcount for sql, args in statements]
            for index, expected in (required_rows or {}).items():
                if counts[index] != expected:
                    raise MutationConflictError(
                        "security state mutation affected an unexpected number of rows")
            return counts

    def transaction_audited(self, statements, *, audit: Dict[str, Any], required_rows=None) -> List[int]:
        with self._lock, self.connect() as db:
            counts = [db.execute(sql, args).rowcount for sql, args in statements]
            for index, expected in (required_rows or {}).items():
                if counts[index] != expected:
                    raise MutationConflictError(
                        "security state mutation affected an unexpected number of rows")
            self._append_audit(db, **audit)
            return counts

    def execute_audited_counted(self, sql: str, args, *, audit_factory) -> int:
        """Audit an aggregate maintenance mutation with its committed row count.

        Zero-row housekeeping is intentionally silent. The factory is invoked
        inside the write transaction so event details cannot race the mutation.
        """
        with self._lock, self.connect() as db:
            count = db.execute(sql, args).rowcount
            if count:
                self._append_audit(db, **audit_factory(count))
            return count

    def one(self, sql: str, args=()) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute(sql, args).fetchone()
            return dict(row) if row else None

    def all(self, sql: str, args=()) -> List[Dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute(sql, args).fetchall()]

    def ensure_user(self, username: str, global_admin: bool = False):
        self.execute(
            "INSERT INTO users(username,global_admin,principal_type,enabled) VALUES(?,?,'human',1) "
            "ON CONFLICT(username) DO UPDATE SET global_admin=MAX(global_admin,excluded.global_admin)",
            (username, int(global_admin)),
        )

    def is_global_admin(self, username: str) -> bool:
        row = self.one("SELECT global_admin,enabled,principal_type FROM users WHERE username=?", (username,))
        return bool(row and row["global_admin"] and row["enabled"] and row["principal_type"] == "human")

    def is_approver(self, username: str) -> bool:
        row = self.one("SELECT approver,enabled,principal_type FROM users WHERE username=?", (username,))
        return bool(row and row["approver"] and row["enabled"] and row["principal_type"] == "human")

    def audit(self, *, request_id: str, actor: str, action: str,
              object_id: Optional[str], outcome: str, source_zone: str, remote_addr: str,
              details: Dict[str, Any]):
        with self._lock, self.connect() as db:
            self._append_audit(db, request_id=request_id, actor=actor, action=action,
                               object_id=object_id, outcome=outcome,
                               source_zone=source_zone, remote_addr=remote_addr, details=details)

    def _append_audit(self, db, *, request_id: str, actor: str, action: str,
                      object_id: Optional[str], outcome: str,
                      source_zone: str, remote_addr: str, details: Dict[str, Any]):
        values = (int(time.time()), request_id, actor, action, object_id, outcome,
                  source_zone, remote_addr, json.dumps(details, ensure_ascii=False, sort_keys=True))
        cursor = db.execute(
            "INSERT INTO audit_events(timestamp,request_id,actor,action,object_id,outcome,source_zone,remote_addr,details) "
            "VALUES(?,?,?,?,?,?,?,?,?)", values,
        )
        event_id = cursor.lastrowid
        previous_row = db.execute("SELECT event_hash FROM audit_chain ORDER BY event_id DESC LIMIT 1").fetchone()
        previous = previous_row[0] if previous_row else ""
        event = dict(db.execute("SELECT * FROM audit_events WHERE id=?", (event_id,)).fetchone())
        digest = self._audit_digest(event, previous)
        db.execute("INSERT INTO audit_chain(event_id,prev_hash,event_hash) VALUES(?,?,?)",
                   (event_id, previous, digest))

    def execute_audited(self, sql: str, args, *, error: str, audit: Dict[str, Any]) -> int:
        """Commit one security-state mutation and its chained event atomically."""
        with self._lock, self.connect() as db:
            cursor = db.execute(sql, args)
            if cursor.rowcount != 1: raise RuntimeError(error)
            self._append_audit(db, **audit)
            return cursor.rowcount

    def get_config(self, key: str, default: str) -> str:
        row = self.one("SELECT value FROM system_config WHERE key=?", (key,))
        return row["value"] if row else default

    def set_config(self, key: str, value: str, actor: str):
        self.execute(
            "INSERT INTO system_config(key,value,updated_at,updated_by) VALUES(?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            (key, value, int(time.time()), actor),
        )
