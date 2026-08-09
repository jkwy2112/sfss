import tempfile
import threading
import time
import unittest
from pathlib import Path

from sfss.db import Store
from sfss.jobs import SQLiteJobQueue


class DurableJobQueueTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "sfss.db")

    def tearDown(self):
        self.temp.cleanup()

    def test_running_job_heartbeat_renews_only_the_current_owner(self):
        now = int(time.time())
        self.store.execute(
            "INSERT INTO scan_jobs(kind,object_id,state,attempts,available_at,lease_until,lease_owner,created_at,updated_at) "
            "VALUES('scan_object','heartbeat','running',1,?,?,?,?,?)",
            (now, now + 1, "owner-1", now, now),
        )
        queue = SQLiteJobQueue(self.store, workers=1, lease_seconds=30, max_attempts=1)
        row = self.store.one("SELECT * FROM scan_jobs WHERE object_id='heartbeat'")
        self.assertTrue(queue._renew_lease(row))
        renewed = self.store.one("SELECT lease_until FROM scan_jobs WHERE object_id='heartbeat'")["lease_until"]
        self.assertGreaterEqual(renewed, int(time.time()) + 29)
        self.assertFalse(queue._renew_lease({**row, "lease_owner":"stale-owner"}))

    def test_job_is_persisted_claimed_and_completed(self):
        completed = threading.Event()
        queue = SQLiteJobQueue(self.store, workers=1, lease_seconds=30, max_attempts=1)
        def scan_object(object_id):
            self.assertEqual("object-1", object_id); completed.set()
        scan_object.__name__ = "scan_object"
        def scan_outbound(_): pass
        scan_outbound.__name__ = "scan_outbound"
        queue.start({"scan_object":scan_object, "scan_outbound":scan_outbound})
        try:
            queue.submit(scan_object, "object-1")
            self.assertTrue(completed.wait(3))
            for _ in range(100):
                row = self.store.one("SELECT * FROM scan_jobs WHERE object_id='object-1'")
                if row and row["state"] == "completed": break
                completed.wait(0.01)
            self.assertEqual("completed", row["state"])
            self.assertEqual(1, row["attempts"])
        finally:
            queue.stop()

    def test_exhausted_job_is_failed_and_dead_lettered(self):
        dead = threading.Event(); received = []
        queue = SQLiteJobQueue(self.store, workers=1, lease_seconds=30, max_attempts=1)
        def scan_object(_): raise RuntimeError("scanner crashed")
        scan_object.__name__ = "scan_object"
        def scan_outbound(_): pass
        scan_outbound.__name__ = "scan_outbound"
        queue.start({"scan_object":scan_object, "scan_outbound":scan_outbound},
                    lambda kind, object_id, error: (received.append((kind, object_id, error)), dead.set()))
        try:
            queue.submit(scan_object, "object-2")
            self.assertTrue(dead.wait(3))
            row = self.store.one("SELECT * FROM scan_jobs WHERE object_id='object-2'")
            self.assertEqual("failed", row["state"])
            self.assertEqual([("scan_object", "object-2", "RuntimeError")], received)
        finally:
            queue.stop()

    def test_running_job_from_previous_process_is_reclaimed_immediately(self):
        now = 1
        self.store.execute(
            "INSERT INTO scan_jobs(kind,object_id,state,attempts,available_at,lease_until,created_at,updated_at) "
            "VALUES('scan_object','abandoned','running',1,?,?,?,?)", (now, 2 ** 31, now, now),
        )
        handled = threading.Event()
        queue = SQLiteJobQueue(self.store, workers=1, lease_seconds=30, max_attempts=3)
        def scan_object(object_id):
            self.assertEqual("abandoned", object_id); handled.set()
        scan_object.__name__ = "scan_object"
        def scan_outbound(_): pass
        scan_outbound.__name__ = "scan_outbound"
        queue.start({"scan_object":scan_object, "scan_outbound":scan_outbound})
        try:
            self.assertTrue(handled.wait(3))
        finally:
            queue.stop()


if __name__ == "__main__": unittest.main()
