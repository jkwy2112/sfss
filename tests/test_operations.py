import io
import json
import tempfile
import unittest
from pathlib import Path

from sfss.config import Settings
from sfss.db import Store
from sfss.jobs import InlineJobQueue
from sfss.operations import (OperationError, acquire_runtime_lock, backup, config_fingerprint,
                             export_audit, initialize_data, preflight, release_manifest, restore,
                             verify_audit_export, verify_data)
from sfss.scanners import MockScanner
from sfss.service import SFSSService


class OperationsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "data"
        settings = Settings(data_dir=self.root)
        store = Store(self.root / "sfss.db"); store.ensure_user("admin", True)
        self.service = SFSSService(settings, store, [MockScanner()], InlineJobQueue())
        self.service.upload("safe.txt", io.BytesIO(b"safe backup payload"), 19, "admin")

    def tearDown(self):
        self.temp.cleanup()

    def test_offline_verify_backup_and_restore_round_trip(self):
        verification = verify_data(self.root)
        self.assertEqual("ok", verification["status"])
        self.assertEqual(1, verification["payloads"])
        archive = Path(self.temp.name) / "backup.tar"
        result = backup(self.root, archive)
        self.assertEqual(64, len(result["sha256"]))
        self.assertEqual(0o600, archive.stat().st_mode & 0o777)
        restored = Path(self.temp.name) / "restored"
        restored_result = restore(archive, restored, result["sha256"])
        self.assertEqual(result["sha256"], restored_result["archive_sha256"])
        self.assertEqual("ok", restored_result["verified"]["status"])
        self.assertEqual(verification["audit"]["head"], verify_data(restored)["audit"]["head"])

    def test_explicit_initialization_and_configuration_fingerprint(self):
        root = Path(self.temp.name) / "fresh-data"
        initialized = initialize_data(root)
        self.assertEqual(Store.SCHEMA_VERSION, initialized["schema"])
        with self.assertRaisesRegex(OperationError, "already initialized"):
            initialize_data(root)
        settings = Settings(data_dir=root, release_id="candidate-1")
        first = config_fingerprint(root, settings)
        self.assertEqual(64, len(first["sha256"]))
        Store(root / "sfss.db").set_config("max_upload_bytes", "42", "test")
        second = config_fingerprint(root, settings)
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_backup_refuses_a_data_directory_in_use(self):
        lock = acquire_runtime_lock(self.root)
        try:
            with self.assertRaisesRegex(OperationError, "in use"):
                backup(self.root, Path(self.temp.name) / "blocked.tar")
        finally:
            lock.close()

    def test_restore_checks_trusted_digest_and_refuses_archive_symlink(self):
        archive = Path(self.temp.name) / "backup.tar"
        result = backup(self.root, archive)
        with self.assertRaisesRegex(OperationError, "trusted expected value"):
            restore(archive, Path(self.temp.name) / "wrong-digest", "0" * 64)
        link = Path(self.temp.name) / "backup-link.tar"; link.symlink_to(archive)
        with self.assertRaisesRegex(OperationError, "unavailable or unsafe"):
            restore(link, Path(self.temp.name) / "linked-restore", result["sha256"])

    def test_restore_rejects_duplicate_archive_paths(self):
        import tarfile
        archive = Path(self.temp.name) / "duplicate.tar"
        with tarfile.open(archive, "w") as output:
            info = tarfile.TarInfo("sfss-data"); info.type = tarfile.DIRTYPE; info.mode = 0o700
            output.addfile(info)
            for value in (b"first", b"second"):
                info = tarfile.TarInfo("sfss-data/backup-manifest.json")
                info.mode = 0o600; info.size = len(value); output.addfile(info, io.BytesIO(value))
        with self.assertRaisesRegex(OperationError, "duplicate path"):
            restore(archive, Path(self.temp.name) / "duplicate-restore")

    def test_offline_audit_export_is_chained_restricted_and_content_addressed(self):
        output = Path(self.temp.name) / "audit.jsonl"
        result = export_audit(self.root, output)
        self.assertEqual(0o600, output.stat().st_mode & 0o777)
        self.assertEqual(self.service.store.verify_audit_chain()["head"], result["audit_head"])
        lines = output.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result["events"], len(lines))
        self.assertTrue(all('"event_hash"' in line and '"prev_hash"' in line for line in lines))
        self.assertEqual(64, len(result["sha256"]))
        with self.assertRaises(FileExistsError):
            export_audit(self.root, output)

    def test_audit_export_refuses_live_data_directory(self):
        lock = acquire_runtime_lock(self.root)
        try:
            with self.assertRaisesRegex(OperationError, "in use"):
                export_audit(self.root, Path(self.temp.name) / "blocked-audit.jsonl")
        finally:
            lock.close()

    def test_audit_export_can_be_independently_verified_against_trusted_values(self):
        output = Path(self.temp.name) / "independent-audit.jsonl"
        exported = export_audit(self.root, output)
        verified = verify_audit_export(
            output, exported["sha256"], exported["audit_head"], exported["events"])
        self.assertEqual(exported["sha256"], verified["sha256"])
        self.assertEqual(exported["audit_head"], verified["audit_head"])
        self.assertEqual(exported["events"], verified["events"])

        with self.assertRaisesRegex(OperationError, "trusted expected value"):
            verify_audit_export(output, "0" * 64, exported["audit_head"], exported["events"])

        lines = output.read_bytes().splitlines(keepends=True)
        truncated = Path(self.temp.name) / "truncated-audit.jsonl"
        truncated.write_bytes(b"".join(lines[:-1]))
        with self.assertRaisesRegex(OperationError, "event count|chain head"):
            verify_audit_export(truncated, expected_head=exported["audit_head"],
                                expected_events=exported["events"])

        document = json.loads(lines[0]); document["event"]["actor"] = "mallory"
        lines[0] = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        tampered = Path(self.temp.name) / "tampered-audit.jsonl"; tampered.write_bytes(b"".join(lines))
        with self.assertRaisesRegex(OperationError, "verification failed"):
            verify_audit_export(tampered)

        link = Path(self.temp.name) / "audit-link.jsonl"; link.symlink_to(output)
        with self.assertRaisesRegex(OperationError, "symbolic link"):
            verify_audit_export(link)

    def test_release_manifest_is_canonical_restricted_and_detects_links(self):
        artifact = Path(self.temp.name) / "artifact"; artifact.mkdir()
        (artifact / "app.py").write_bytes(b"print('sealed')\n")
        nested = artifact / "deploy"; nested.mkdir(); (nested / "unit").write_bytes(b"unit")
        output = Path(self.temp.name) / "release-manifest.json"
        result = release_manifest(artifact, output)
        self.assertEqual(2, result["files"])
        self.assertEqual(0o600, output.stat().st_mode & 0o777)
        document = __import__("json").loads(output.read_text(encoding="utf-8"))
        self.assertEqual(["app.py", "deploy/unit"], [item["path"] for item in document["files"]])
        self.assertTrue(all(len(item["sha256"]) == 64 for item in document["files"]))
        with self.assertRaises(FileExistsError): release_manifest(artifact, output)
        link_root = Path(self.temp.name) / "linked"; link_root.mkdir()
        (link_root / "link").symlink_to(artifact / "app.py")
        with self.assertRaisesRegex(OperationError, "symbolic link"):
            release_manifest(link_root, Path(self.temp.name) / "linked.json")

    def test_release_manifest_must_be_written_outside_artifact(self):
        artifact = Path(self.temp.name) / "artifact-inside"; artifact.mkdir()
        (artifact / "file").write_bytes(b"content")
        with self.assertRaisesRegex(OperationError, "outside"):
            release_manifest(artifact, artifact / "manifest.json")

    def test_preflight_is_no_port_machine_readable_and_strict_by_default(self):
        development = preflight(self.service.settings, require_production=False)
        self.assertEqual("ok", development["status"])
        self.assertFalse(development["production_candidate"])
        self.assertEqual("ok", development["checks"]["data"]["status"])
        self.assertEqual("ok", development["checks"]["scanners"]["status"])
        self.assertEqual("not_required", development["checks"]["ldap"]["status"])
        strict = preflight(self.service.settings)
        self.assertEqual("degraded", strict["status"])
        self.assertIn("configuration", strict["failed_checks"])

    def test_preflight_refuses_a_running_data_directory(self):
        lock = acquire_runtime_lock(self.root)
        try:
            with self.assertRaisesRegex(OperationError, "in use"):
                preflight(self.service.settings, require_production=False)
        finally:
            lock.close()

    def test_offline_verify_rejects_readable_sqlite_sidecar(self):
        sidecar = self.root / "sfss.db-shm"
        sidecar.write_bytes(b"unsafe test sidecar")
        sidecar.chmod(0o644)
        with self.assertRaisesRegex(OperationError, "broader than 0600"):
            verify_data(self.root)

    def test_offline_verify_rejects_any_broadly_readable_data_entry(self):
        extra = self.root / "unexpected.txt"; extra.write_text("sensitive"); extra.chmod(0o644)
        with self.assertRaisesRegex(OperationError, "group or other access"):
            verify_data(self.root)

    def test_restore_rejects_archive_supplied_broad_or_special_permissions(self):
        import tarfile
        archive = Path(self.temp.name) / "unsafe-mode.tar"
        with tarfile.open(archive, "w") as output:
            root = tarfile.TarInfo("sfss-data"); root.type = tarfile.DIRTYPE; root.mode = 0o755
            output.addfile(root)
            manifest = b'{}'
            info = tarfile.TarInfo("sfss-data/backup-manifest.json")
            info.mode = 0o4755; info.size = len(manifest)
            output.addfile(info, io.BytesIO(manifest))
        with self.assertRaisesRegex(OperationError, "unsafe filesystem permissions"):
            restore(archive, Path(self.temp.name) / "unsafe-mode-restore")

    def test_offline_verify_does_not_modify_database_bytes(self):
        with self.service.store.connect() as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        database = self.root / "sfss.db"
        before = database.read_bytes()
        verification = verify_data(self.root)
        self.assertEqual("ok", verification["status"])
        self.assertEqual(before, database.read_bytes())

    def test_older_binary_refuses_future_database_schema(self):
        self.service.store.execute("UPDATE schema_metadata SET version=999 WHERE id=1")
        with self.assertRaisesRegex(RuntimeError, "newer than supported"):
            Store(self.root / "sfss.db")


if __name__ == "__main__": unittest.main()
