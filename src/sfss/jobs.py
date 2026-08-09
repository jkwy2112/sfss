from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import uuid
from typing import Callable, Dict, Optional

from .db import Store


class JobQueue(ABC):
    @abstractmethod
    def submit(self, job: Callable, *args) -> None:
        pass


class ThreadJobQueue(JobQueue):
    """In-process development queue; replace with a durable broker adapter later."""
    def __init__(self, workers: int = 2):
        self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sfss-scan")

    def submit(self, job: Callable, *args) -> None:
        self.executor.submit(job, *args)


class InlineJobQueue(JobQueue):
    """Deterministic test adapter."""
    def submit(self, job: Callable, *args) -> None:
        job(*args)


class SQLiteJobQueue(JobQueue):
    """Durable, leased scan queue for the single-node deployment candidate."""

    ALLOWED_KINDS = {"scan_object", "scan_outbound"}

    def __init__(self, store: Store, workers: int = 2, lease_seconds: int = 900,
                 max_attempts: int = 3):
        self.store = store
        self.workers = max(1, min(workers, 32))
        self.lease_seconds = max(30, lease_seconds)
        self.max_attempts = max(1, max_attempts)
        self.handlers: Dict[str, Callable[[str], None]] = {}
        self.dead_letter: Optional[Callable[[str, str, str], None]] = None
        self._condition = threading.Condition()
        self._started = False
        self._stopping = False
        self._threads = []

    def start(self, handlers: Dict[str, Callable[[str], None]],
              dead_letter: Optional[Callable[[str, str, str], None]] = None):
        if self._started: return
        if set(handlers) != self.ALLOWED_KINDS:
            raise ValueError("durable queue requires both scan handlers")
        self.handlers = dict(handlers); self.dead_letter = dead_letter; self._started = True
        now = int(time.time())
        # SQLite mode is deliberately single-node. Any running lease belongs to
        # the previous process and is made immediately eligible after restart.
        self.store.execute(
            "UPDATE scan_jobs SET state='queued',available_at=?,lease_until=NULL,lease_owner=NULL,updated_at=?,last_error='worker restart' "
            "WHERE state='running'", (now, now),
        )
        for number in range(self.workers):
            thread = threading.Thread(target=self._worker, name=f"sfss-durable-scan-{number + 1}", daemon=True)
            thread.start(); self._threads.append(thread)

    def submit(self, job: Callable, *args) -> None:
        kind = getattr(job, "__name__", "")
        if kind not in self.ALLOWED_KINDS or len(args) != 1 or not isinstance(args[0], str):
            raise ValueError("unsupported durable scan job")
        now = int(time.time())
        self.store.execute(
            "INSERT OR IGNORE INTO scan_jobs(kind,object_id,state,attempts,available_at,created_at,updated_at) "
            "VALUES(?,?,'queued',0,?,?,?)", (kind, args[0], now, now, now),
        )
        with self._condition: self._condition.notify()

    def _claim(self):
        now = int(time.time())
        with self.store._lock, self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM scan_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='running' AND lease_until<=?) "
                "ORDER BY id LIMIT 1", (now, now),
            ).fetchone()
            if not row: return None
            job = dict(row); attempts = int(job["attempts"]) + 1; lease_owner = uuid.uuid4().hex
            updated = db.execute(
                "UPDATE scan_jobs SET state='running',attempts=?,lease_until=?,lease_owner=?,updated_at=? "
                "WHERE id=? AND ((state='queued' AND available_at<=?) OR (state='running' AND lease_until<=?))",
                (attempts, now + self.lease_seconds, lease_owner, now, job["id"], now, now),
            ).rowcount
            if updated != 1: return None
            job["attempts"] = attempts; job["lease_owner"] = lease_owner
            return job

    def _worker(self):
        while not self._stopping:
            job = self._claim()
            if not job:
                with self._condition: self._condition.wait(timeout=1)
                continue
            heartbeat_stop = threading.Event()
            heartbeat = threading.Thread(target=self._heartbeat, args=(job, heartbeat_stop),
                                         name=f"sfss-job-heartbeat-{job['id']}", daemon=True)
            heartbeat.start()
            try:
                self.handlers[job["kind"]](job["object_id"])
            except Exception as exc:
                self._retry_or_fail(job, type(exc).__name__)
            else:
                self.store.execute(
                    "UPDATE scan_jobs SET state='completed',lease_until=NULL,lease_owner=NULL,updated_at=? "
                    "WHERE id=? AND state='running' AND lease_owner=?",
                    (int(time.time()), job["id"], job["lease_owner"]),
                )
            finally:
                heartbeat_stop.set(); heartbeat.join(timeout=2)

    def _renew_lease(self, job) -> bool:
        now = int(time.time())
        return self.store.execute(
            "UPDATE scan_jobs SET lease_until=?,updated_at=? "
            "WHERE id=? AND state='running' AND lease_owner=?",
            (now + self.lease_seconds, now, job["id"], job["lease_owner"]),
        ) == 1

    def _heartbeat(self, job, stopped):
        interval = max(1, min(30, self.lease_seconds // 3))
        while not stopped.wait(interval):
            try:
                if not self._renew_lease(job): return
            except Exception:
                # The original lease still bounds ownership. State transition
                # checks independently prevent a duplicate release if storage
                # remains unavailable long enough for another claim.
                continue

    def _retry_or_fail(self, job, error: str):
        now = int(time.time())
        if job["attempts"] < self.max_attempts:
            delay = min(60, 2 ** job["attempts"])
            self.store.execute(
                "UPDATE scan_jobs SET state='queued',available_at=?,lease_until=NULL,lease_owner=NULL,updated_at=?,last_error=? "
                "WHERE id=? AND state='running' AND lease_owner=?",
                (now + delay, now, error, job["id"], job["lease_owner"]),
            )
            with self._condition: self._condition.notify()
            return
        updated = self.store.execute(
            "UPDATE scan_jobs SET state='failed',lease_until=NULL,lease_owner=NULL,updated_at=?,last_error=? "
            "WHERE id=? AND state='running' AND lease_owner=?",
            (now, error, job["id"], job["lease_owner"]),
        )
        if updated != 1: return
        if self.dead_letter:
            try: self.dead_letter(job["kind"], job["object_id"], error)
            except Exception: pass

    def health(self):
        rows = self.store.all("SELECT state,COUNT(*) AS count FROM scan_jobs GROUP BY state")
        return {row["state"]: row["count"] for row in rows}

    def purge_completed(self, before: int) -> int:
        return self.store.execute("DELETE FROM scan_jobs WHERE state IN ('completed','failed') AND updated_at<=?", (before,))

    def stop(self):
        self._stopping = True
        with self._condition: self._condition.notify_all()
        for thread in self._threads: thread.join(timeout=2)
