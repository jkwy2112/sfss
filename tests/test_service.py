import io
import hashlib
import json
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

from sfss.auth import LocalAuthenticator, ServiceTokens
from sfss.config import Settings
from sfss.db import Store
from sfss.jobs import InlineJobQueue, JobQueue
from sfss.scanners import MockScanner, ScanResult, Scanner, YaraScanner
from sfss.server import create_runtime, validate_bind_host, validate_listener
from sfss.service import SFSSService, ServiceError


class ErrorScanner(Scanner):
    name = "broken"
    def scan(self, path):
        return ScanResult(self.name, "error", "timeout")


class RaisingScanner(Scanner):
    name = "raising"
    def scan(self, path):
        raise RuntimeError("adapter crashed")


class MutatingCleanScanner(Scanner):
    name = "mutating-clean"
    def scan(self, path):
        with path.open("r+b") as stream:
            stream.seek(0); stream.write(b"X"); stream.flush(); os.fsync(stream.fileno())
        return ScanResult(self.name, "clean", "claimed clean after mutation")


class HoldingQueue(JobQueue):
    def __init__(self):
        self.jobs = []

    def submit(self, job, *args):
        self.jobs.append((job, args))


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.settings = Settings(data_dir=Path(self.temp.name), retention_seconds=60)
        self.store = Store(self.settings.data_dir / "sfss.db")
        self.store.ensure_user("admin", True)
        self.store.ensure_user("alice")
        self.store.ensure_user("reader")
        self.store.ensure_user("approver")
        self.service = SFSSService(self.settings, self.store, [MockScanner()], InlineJobQueue())
        self.service.create_project("chip-a", "Chip A", "admin")
        self.service.add_member("chip-a", "alice", "uploader", "admin")
        self.service.add_member("chip-a", "reader", "downloader", "admin")

    def tearDown(self):
        self.temp.cleanup()

    def upload(self, filename, body):
        return self.service.upload("chip-a", filename, io.BytesIO(body), len(body), "alice")

    def secure_production_settings(self):
        ca_file = self.settings.data_dir / "ldap-ca.pem"
        ca_file.write_text("test CA placeholder", encoding="utf-8"); ca_file.chmod(0o600)
        manifest_key_file = self.settings.data_dir / "manifest-hmac.key"
        manifest_key_file.write_text("x" * 32, encoding="utf-8"); manifest_key_file.chmod(0o600)
        candidate = replace(
            self.settings, environment="production", auth_backend="ldap", dev_tokens_enabled=False,
            scanners="clamav", require_trusted_proxy=True, trusted_zone_proxy_cidrs="127.0.0.1/32",
            require_forwarded_https=True, manifest_hmac_key="x" * 32,
            manifest_hmac_key_file=str(manifest_key_file), ldap_uri="ldaps://ad.example:636",
            ldap_ca_file=str(ca_file), allow_basic_auth=False, bootstrap_admins="admin",
            ldap_ca_sha256=hashlib.sha256(ca_file.read_bytes()).hexdigest(),
            allow_local_approval=False, release_id="test-release",
            session_ttl_seconds=3600, session_idle_seconds=900, max_sessions_per_user=3,
            expected_python_version="3.12.12", expected_config_sha256="0" * 64,
        )
        return replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.store.all("SELECT key,value FROM system_config ORDER BY key")))

    def test_clean_known_content_is_released_and_hashed(self):
        obj = self.upload("notes.txt", b"hello secure shuttle\n")
        self.assertEqual("released", obj["state"])
        self.assertEqual("text/plain", obj["media_type"])
        self.assertEqual(64, len(obj["sha256"]))
        downloaded = self.service.object_for_download("chip-a", obj["id"], "reader")
        self.assertEqual(b"hello secure shuttle\n", Path(downloaded["storage_path"]).read_bytes())

    def test_content_extension_conflict_is_quarantined(self):
        obj = self.upload("deceptive.pdf", b"PK\x03\x04archive")
        self.assertEqual("quarantined", obj["state"])
        with self.assertRaises(ServiceError):
            self.service.object_for_download("chip-a", obj["id"], "reader")

    def test_deceptive_or_nonportable_filenames_are_rejected_at_service_boundary(self):
        invalid = ("../escape.txt", "folder/file.txt", "folder\\file.txt", " report.txt",
                   "report.txt ", "safe\u202egnp.exe", "zero\u200bwidth.txt", "line\nbreak.txt", "e\u0301.txt")
        for filename in invalid:
            with self.subTest(filename=filename), self.assertRaisesRegex(ServiceError, "invalid filename"):
                self.service.create_upload_session("chip-a", "inbound", filename, 1, "alice")
        session = self.service.create_upload_session("chip-a", "inbound", "芯片设计.txt", 1, "alice")
        self.assertEqual("芯片设计.txt", session["filename"])

    def test_unknown_binary_is_quarantined(self):
        obj = self.upload("layout.gds", b"\x00\x01\x02\x03")
        self.assertEqual("quarantined", obj["state"])

    def test_malware_is_rejected(self):
        obj = self.upload("eicar.txt", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
        self.assertEqual("rejected", obj["state"])

    def test_scanner_error_fails_closed(self):
        service = SFSSService(self.settings, self.store, [ErrorScanner()], InlineJobQueue())
        obj = service.upload("chip-a", "notes.txt", io.BytesIO(b"safe looking"), 12, "alice")
        self.assertEqual("quarantined", obj["state"])

    def test_scanner_exception_fails_closed(self):
        service = SFSSService(self.settings, self.store, [RaisingScanner()], InlineJobQueue())
        obj = service.upload("chip-a", "notes.txt", io.BytesIO(b"safe looking"), 12, "alice")
        self.assertEqual("quarantined", obj["state"])

    def test_inbound_payload_changed_by_scanner_is_quarantined_before_release(self):
        service = SFSSService(self.settings, self.store, [MutatingCleanScanner()], InlineJobQueue())
        obj = service.upload("chip-a", "notes.txt", io.BytesIO(b"safe looking"), 12, "alice")
        self.assertEqual("quarantined", obj["state"])
        self.assertIn("post-scan-integrity", obj["scan_detail"])

    def test_outbound_payload_changed_by_scanner_never_reaches_approval(self):
        self.enable_outbound()
        self.service.scanners = [MutatingCleanScanner()]
        body = b"safe outbound text"
        transfer = self.service.upload_outbound(
            "chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        self.assertEqual("quarantined", transfer["state"])
        self.assertIsNone(transfer["approval_id"])
        self.assertIn("post-scan-integrity", transfer["scan_detail"])

    def test_production_runtime_drift_quarantines_background_scan_without_invoking_scanner(self):
        secret = self.settings.data_dir / "runtime-manifest.key"
        secret.write_text("m" * 32, encoding="utf-8"); secret.chmod(0o600)
        candidate = replace(self.settings, environment="production", manifest_hmac_key="m" * 32,
                            manifest_hmac_key_file=str(secret), expected_config_sha256="0" * 64)
        self.service.settings = replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.store.all("SELECT key,value FROM system_config ORDER BY key")))
        self.store.set_config("retention_seconds", "7200", "test-drift")
        scanner = self.service.scanners[0]; original_scan = scanner.scan
        scanner.scan = lambda _path: self.fail("scanner must not run under unaccepted configuration")
        try:
            obj = self.upload("drift.txt", b"drift")
        finally:
            scanner.scan = original_scan
            self.service.settings = self.settings
        current = self.service.get_object(obj["id"])
        self.assertEqual("quarantined", current["state"])
        self.assertEqual("runtime-policy", json.loads(current["scan_detail"])[0]["scanner"])

    def test_platform_admin_does_not_bypass_project_file_role(self):
        obj = self.upload("notes.txt", b"safe")
        self.store.ensure_user("platform-operator", True)
        with self.assertRaises(ServiceError):
            self.service.object_for_download("chip-a", obj["id"], "platform-operator")

    def test_project_rbac_denies_uploader_download(self):
        obj = self.upload("notes.txt", b"safe")
        with self.assertRaises(ServiceError) as context:
            self.service.object_for_download("chip-a", obj["id"], "alice")
        self.assertEqual(403, context.exception.status)

    def test_audit_is_append_only(self):
        self.store.audit(request_id="r1", actor="alice", action="test", project_id="chip-a",
                         object_id=None, outcome="success", source_zone="green",
                         remote_addr="127.0.0.1", details={})
        verification = self.store.verify_audit_chain()
        self.assertGreaterEqual(verification["events"], 1)
        self.assertEqual(64, len(verification["head"]))
        with self.assertRaises(Exception):
            self.store.execute("DELETE FROM audit_events")

    def test_offline_audit_tampering_is_detected_on_startup(self):
        self.store.audit(request_id="r1", actor="alice", action="test", project_id="chip-a",
                         object_id=None, outcome="success", source_zone="green",
                         remote_addr="127.0.0.1", details={})
        with self.store.connect() as db:
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE audit_events SET actor='mallory' WHERE request_id='r1'")
        with self.assertRaisesRegex(RuntimeError, "audit chain verification failed"):
            Store(self.store.path)

    def test_state_transition_events_are_audited(self):
        obj = self.upload("notes.txt", b"safe")
        events = self.store.all(
            "SELECT action,details FROM audit_events WHERE object_id=? ORDER BY id", (obj["id"],)
        )
        self.assertGreaterEqual(len(events), 3)
        self.assertTrue(all(event["action"] in {
            "object.upload", "object.state_changed", "scan.complete"} for event in events))
        released = next(event for event in events if event["action"] == "object.state_changed" and
                        json.loads(event["details"])["to"] == "released")
        self.assertTrue(json.loads(released["details"])["scan_detail"])

    def test_approval_comment_length_is_bounded_before_persistence(self):
        self.enable_outbound(); body = b"approval comment"
        transfer = self.service.upload_outbound(
            "chip-a", "comment.txt", io.BytesIO(body), len(body), "alice")
        with self.assertRaisesRegex(ServiceError, "comment is too long"):
            self.service.decide_outbound(
                "chip-a", transfer["id"], True, "x" * 1001, "approver")
        self.assertEqual("pending_approval", self.service.get_outbound(transfer["id"])["state"])

    def test_invalid_state_transition_is_rejected(self):
        obj = self.upload("notes.txt", b"safe")
        with self.assertRaises(RuntimeError):
            self.service.transition(obj["id"], "pending_scan")

    def test_state_change_rolls_back_when_chained_audit_cannot_commit(self):
        queue = HoldingQueue()
        service = SFSSService(self.settings, self.store, [MockScanner()], queue)
        obj = service.upload("chip-a", "atomic.txt", io.BytesIO(b"atomic audit"), 12, "alice")
        before_events = self.store.one("SELECT COUNT(*) AS value FROM audit_events")["value"]
        with patch.object(self.store, "_append_audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                service.transition(obj["id"], "scanning")
        self.assertEqual("pending_scan", service.get_object(obj["id"])["state"])
        self.assertEqual(before_events,
                         self.store.one("SELECT COUNT(*) AS value FROM audit_events")["value"])

        self.enable_outbound()
        outbound_service = SFSSService(self.settings, self.store, [MockScanner()], HoldingQueue())
        body = b"outbound atomic"
        transfer = outbound_service.upload_outbound(
            "chip-a", "atomic.txt", io.BytesIO(body), len(body), "alice")
        with patch.object(self.store, "_append_audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                outbound_service.outbound_transition(transfer["id"], "scanning")
        self.assertEqual("pending_scan", outbound_service.get_outbound(transfer["id"])["state"])

    def test_upload_creation_and_part_commit_roll_back_when_audit_fails(self):
        before = self.store.one("SELECT COUNT(*) AS value FROM objects")["value"]
        audit = {"request_id":"upload-failure", "actor":"alice", "action":"object.upload",
                 "project_id":"chip-a", "object_id":None, "outcome":"accepted",
                 "source_zone":"green", "remote_addr":"127.0.0.1", "details":{}}
        with patch.object(self.store, "_append_audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                self.service.upload("chip-a", "atomic.txt", io.BytesIO(b"atomic"), 6,
                                    "alice", audit=audit)
        self.assertEqual(before, self.store.one("SELECT COUNT(*) AS value FROM objects")["value"])

        session = self.service.create_upload_session(
            "chip-a", "inbound", "part.txt", 4, "alice")
        part_audit = {"request_id":"part-failure", "actor":"alice",
                      "action":"upload.part.complete", "project_id":"chip-a",
                      "object_id":session["id"], "outcome":"success", "source_zone":"green",
                      "remote_addr":"127.0.0.1", "details":{"part_number":1}}
        with patch.object(self.store, "_append_audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                self.service.put_upload_part(
                    session["id"], 1, io.BytesIO(b"part"), 4,
                    hashlib.sha256(b"part").hexdigest(), "alice", audit=part_audit)
        self.assertIsNone(self.store.one(
            "SELECT part_number FROM upload_parts WHERE upload_id=?", (session["id"],)))
        retry = self.service.put_upload_part(
            session["id"], 1, io.BytesIO(b"part"), 4,
            hashlib.sha256(b"part").hexdigest(), "alice")
        self.assertEqual(1, retry["part_number"])

    def test_member_role_can_be_revoked_but_last_admin_is_protected(self):
        self.service.remove_member("chip-a", "alice", "uploader", "admin")
        self.assertEqual(set(), self.store.roles("chip-a", "alice"))
        with self.assertRaises(ServiceError):
            self.service.remove_member("chip-a", "admin", "admin", "admin")

    def test_membership_token_revocation_rolls_back_when_audit_fails(self):
        self.store.execute(
            "INSERT INTO users(username,principal_type,enabled) VALUES('green-agent','service',1)")
        self.service.add_member("chip-a", "green-agent", "uploader", "admin")
        raw, _ = ServiceTokens(self.store).issue(
            label="atomic membership", username="green-agent", project_id="chip-a",
            zone="green", permissions=["inbound_upload"], expires_at=2 ** 31,
            created_by="admin")
        audit = {"request_id":"membership-failure", "actor":"admin",
                 "action":"membership.remove", "project_id":"chip-a", "object_id":None,
                 "outcome":"success", "source_zone":"admin", "remote_addr":"127.0.0.1",
                 "details":{"username":"green-agent", "role":"uploader"}}
        with patch.object(self.store, "_append_audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                self.service.remove_member(
                    "chip-a", "green-agent", "uploader", "admin", audit=audit)
        self.assertIn("uploader", self.store.roles("chip-a", "green-agent"))
        self.assertEqual("green-agent", ServiceTokens(self.store).authenticate(raw).username)

    def test_quarantined_object_can_be_rescanned_and_released_object_expired(self):
        unknown = self.upload("layout.gds", b"\x00\x01\x02")
        self.service.rescan(unknown["id"])
        self.assertEqual("quarantined", self.service.get_object(unknown["id"])["state"])
        released = self.upload("notes.txt", b"safe")
        self.service.expire_object(released["id"])
        self.assertEqual("expired", self.service.get_object(released["id"])["state"])

    def enable_outbound(self):
        self.service.add_member("chip-a", "alice", "red_uploader", "admin")
        self.service.add_member("chip-a", "approver", "approver", "admin")
        self.service.add_member("chip-a", "reader", "green_downloader", "admin")
        self.service.set_outbound_policy("chip-a", {"enabled": True, "approval_provider": "local",
            "allowed_classifications": ["GDS", "FPGA_BITFILE", "GENERAL"],
            "approval_timeout_hours": 24, "download_ttl_hours": 24}, "admin")

    def test_red_outbound_local_approval_to_green_download(self):
        self.enable_outbound(); body = b"approved general handoff"
        transfer = self.service.upload_outbound("chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        self.assertEqual("pending_approval", transfer["state"])
        self.assertEqual("GENERAL", transfer["classification"])
        transfer = self.service.decide_outbound("chip-a", transfer["id"], True, "approved", "approver")
        self.assertEqual("released_to_green", transfer["state"])
        downloaded = self.service.outbound_for_download("chip-a", transfer["id"], "reader")
        self.assertEqual(body, Path(downloaded["storage_path"]).read_bytes())

    def test_unknown_outbound_is_quarantined_and_cannot_be_approved(self):
        self.enable_outbound(); body = b"\x00\x01\x02\x03"
        transfer = self.service.upload_outbound("chip-a", "layout.bin", io.BytesIO(body), len(body), "alice")
        self.assertEqual("quarantined", transfer["state"])
        with self.assertRaises(ServiceError):
            self.service.decide_outbound("chip-a", transfer["id"], True, "", "approver")

    def test_outbound_rejection_never_releases(self):
        self.enable_outbound(); body = b"reject this handoff"
        transfer = self.service.upload_outbound("chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        transfer = self.service.decide_outbound("chip-a", transfer["id"], False, "policy denied", "approver")
        self.assertEqual("approval_rejected", transfer["state"])
        with self.assertRaises(ServiceError):
            self.service.outbound_for_download("chip-a", transfer["id"], "reader")

    def test_production_runtime_drift_blocks_approved_outbound_promotion(self):
        self.enable_outbound(); body = b"approved but runtime drifted"
        transfer = self.service.upload_outbound(
            "chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        self.store.execute("UPDATE outbound_transfers SET state='approved' WHERE id=?", (transfer["id"],))
        secret = self.settings.data_dir / "outbound-runtime-manifest.key"
        secret.write_text("m" * 32, encoding="utf-8"); secret.chmod(0o600)
        candidate = replace(self.settings, environment="production", manifest_hmac_key="m" * 32,
                            manifest_hmac_key_file=str(secret), expected_config_sha256="0" * 64)
        self.service.settings = replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.store.all("SELECT key,value FROM system_config ORDER BY key")))
        self.store.set_config("retention_seconds", "7200", "test-drift")
        try:
            with self.assertRaisesRegex(ServiceError, "accepted state") as context:
                self.service.release_approved_outbound(transfer["id"])
            self.assertEqual(503, context.exception.status)
        finally:
            self.service.settings = self.settings
        current = self.service.get_outbound(transfer["id"])
        self.assertEqual("approved", current["state"])
        self.assertIn("outbound/isolation", current["storage_path"])

    def test_gds_is_classified_from_binary_records_not_extension(self):
        self.enable_outbound()
        body = (b"\x00\x06\x00\x02\x02\x58" + b"\x00\x1c\x01\x02" + (b"\x00" * 24) +
                b"\x00\x08\x02\x06LIB\x00")
        transfer = self.service.upload_outbound("chip-a", "layout.binary", io.BytesIO(body), len(body), "alice")
        self.assertEqual("pending_approval", transfer["state"])
        self.assertEqual("GDS", transfer["classification"])

    def test_weak_gds_and_fpga_markers_do_not_authorize_classification(self):
        self.enable_outbound()
        weak_gds = b"\x00\x06\x00\x02\x02\x58" + b"\x00\x1c\x01\x02" + (b"\x00" * 24)
        weak_fpga = b"\x00" + b"\xff\x00\xff\x00\xff\x00\xff" + b"\xaa\x99\x55\x66"
        for name, body in (("weak.gds", weak_gds), ("weak.bit", weak_fpga)):
            with self.subTest(name=name):
                transfer = self.service.upload_outbound(
                    "chip-a", name, io.BytesIO(body), len(body), "alice")
                self.assertEqual("quarantined", transfer["state"])
                self.assertIsNone(transfer["classification"])

    def test_structured_xilinx_bit_container_is_classified(self):
        self.enable_outbound()
        magic = b"\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01"
        fields = b"".join(bytes([tag]) + len(value).to_bytes(2, "big") + value for tag, value in (
            (ord("a"), b"design\x00"), (ord("b"), b"part\x00"),
            (ord("c"), b"2026/08/09\x00"), (ord("d"), b"12:00:00\x00")))
        payload = b"\xff\xff\xff\xff\xaa\x99\x55\x66"
        body = magic + fields + b"e" + len(payload).to_bytes(4, "big") + payload
        transfer = self.service.upload_outbound(
            "chip-a", "design.bin", io.BytesIO(body), len(body), "alice")
        self.assertEqual("pending_approval", transfer["state"])
        self.assertEqual("FPGA_BITFILE", transfer["classification"])

    def test_ip_allowlist_normalizes_individual_ipv4_and_ipv6_addresses(self):
        values = self.service.normalize_cidrs(["127.0.0.1", "::1", "10.0.1.7/24"])
        self.assertEqual(["127.0.0.1/32", "::1/128", "10.0.1.0/24"], values)

    def test_approval_move_failure_persists_recoverable_approved_state(self):
        self.enable_outbound(); body = b"safe handoff"
        transfer = self.service.upload_outbound("chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        with patch("sfss.service.os.replace", side_effect=OSError("disk unavailable")):
            with self.assertRaises(ServiceError):
                self.service.decide_outbound("chip-a", transfer["id"], True, "ok", "approver")
        self.assertEqual("approved", self.service.get_outbound(transfer["id"])["state"])
        recovered = self.service.run_maintenance()
        self.assertEqual(1, recovered["approved_release_retried"])
        self.assertEqual("released_to_green", self.service.get_outbound(transfer["id"])["state"])

    def test_approved_release_recovers_crash_after_move_before_database_update(self):
        self.enable_outbound(); body = b"crash recovery handoff"
        transfer = self.service.upload_outbound("chip-a", "recover.txt", io.BytesIO(body), len(body), "alice")
        self.service.outbound_transition(transfer["id"], "approved", approval_actor="approver",
                                         approval_comment="durable decision")
        target_dir = self.service.outbound_released / transfer["id"]
        target_dir.mkdir(mode=0o700)
        target = target_dir / "payload"
        Path(transfer["storage_path"]).replace(target)
        recovered = self.service.release_approved_outbound(transfer["id"])
        self.assertEqual("released_to_green", recovered["state"])
        self.assertEqual(str(target), recovered["storage_path"])
        self.assertEqual(body, target.read_bytes())
        self.assertEqual("released_to_green", self.service.release_approved_outbound(transfer["id"])["state"])

    def test_maintenance_expires_approval_and_purges_payload(self):
        settings = replace(self.settings, purge_grace_seconds=0)
        service = SFSSService(settings, self.store, [MockScanner()], InlineJobQueue())
        self.enable_outbound(); body = b"approval timeout"
        transfer = service.upload_outbound("chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        self.store.execute("UPDATE outbound_transfers SET approval_expires_at=0 WHERE id=?", (transfer["id"],))
        stats = service.run_maintenance()
        expired = service.get_outbound(transfer["id"])
        self.assertEqual("expired", expired["state"])
        self.assertEqual("", expired["storage_path"])
        self.assertEqual(1, stats["outbound_expired"])
        self.assertEqual(1, stats["payloads_purged"])
        self.assertIsNotNone(self.store.one(
            "SELECT id FROM audit_events WHERE action='outbound.payload_purged' AND object_id=?",
            (transfer["id"],)))

    def test_policy_disable_blocks_pending_approval_and_green_download(self):
        self.enable_outbound(); body = b"policy changes"
        transfer = self.service.upload_outbound("chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        self.service.set_outbound_policy("chip-a", {"enabled": False, "approval_provider": "local",
            "allowed_classifications":["GENERAL"], "approval_timeout_hours":24, "download_ttl_hours":24}, "admin")
        with self.assertRaises(ServiceError):
            self.service.decide_outbound("chip-a", transfer["id"], True, "", "approver")

    def test_platform_policy_can_forbid_local_outbound_approval(self):
        locked = SFSSService(replace(self.settings, allow_local_approval=False), self.store,
                             [MockScanner()], InlineJobQueue())
        with self.assertRaisesRegex(ServiceError, "local outbound approval is disabled"):
            locked.set_outbound_policy("chip-a", {"enabled":True, "approval_provider":"local",
                "allowed_classifications":["GENERAL"], "approval_timeout_hours":24,
                "download_ttl_hours":24}, "admin")

    def test_wecom_policy_requires_relay_and_cannot_be_decided_locally(self):
        self.service.add_member("chip-a", "alice", "red_uploader", "admin")
        self.service.add_member("chip-a", "approver", "approver", "admin")
        policy = {"enabled":True, "approval_provider":"wecom", "allowed_classifications":["GENERAL"],
                  "approval_timeout_hours":24, "download_ttl_hours":24}
        with self.assertRaisesRegex(ServiceError, "approval relay is not safely configured"):
            self.service.set_outbound_policy("chip-a", policy, "admin")
        files = []
        for name in ("relay-ca.pem", "relay-client.pem", "relay-key.pem"):
            path = self.settings.data_dir / name; path.write_text("fixture", encoding="utf-8"); files.append(str(path))
        Path(files[2]).chmod(0o600)
        configured = replace(
            self.settings, approval_relay_url="https://approval-relay.internal/v1/requests",
            approval_relay_ca_file=files[0], approval_relay_client_cert=files[1],
            approval_relay_client_key=files[2], approval_relay_submit_hmac_key="s" * 32,
            approval_relay_callback_hmac_key="c" * 32,
        )
        service = SFSSService(configured, self.store, [MockScanner()], InlineJobQueue())
        service.set_outbound_policy("chip-a", policy, "admin")
        with patch("sfss.service.WeComApprovalProvider.create", return_value="relay-request-1"):
            transfer = service.upload_outbound("chip-a", "relay.txt", io.BytesIO(b"relay payload"),
                                               len(b"relay payload"), "alice")
        self.assertEqual("pending_approval", transfer["state"])
        self.assertEqual("relay-request-1", transfer["approval_id"])
        with self.assertRaisesRegex(ServiceError, "cannot be decided locally"):
            service.decide_outbound("chip-a", transfer["id"], True, "bypass", "approver")

    def test_download_integrity_failure_expires_tampered_payload(self):
        obj = self.upload("notes.txt", b"original")
        Path(obj["storage_path"]).chmod(0o600)
        Path(obj["storage_path"]).write_bytes(b"tampered")
        with self.assertRaises(ServiceError):
            self.service.object_for_download("chip-a", obj["id"], "reader")
        self.assertEqual("expired", self.service.get_object(obj["id"])["state"])

    def test_full_integrity_reader_never_follows_symbolic_links(self):
        target = self.settings.data_dir / "integrity-target"
        target.write_bytes(b"trusted bytes")
        link = self.settings.data_dir / "integrity-link"; link.symlink_to(target)
        record = {"size":13, "sha256":hashlib.sha256(b"trusted bytes").hexdigest()}
        self.assertFalse(self.service._full_integrity(record, link))

    def test_isolation_tampering_before_scan_is_quarantined(self):
        queue = HoldingQueue()
        service = SFSSService(self.settings, self.store, [MockScanner()], queue)
        obj = service.upload("chip-a", "pending.txt", io.BytesIO(b"original"), 8, "alice")
        path = Path(obj["storage_path"]); path.write_bytes(b"tampered")
        job, args = queue.jobs.pop(); job(*args)
        current = service.get_object(obj["id"])
        self.assertEqual("quarantined", current["state"])
        self.assertIn("payload changed after upload", current["scan_detail"])

    def test_outbound_tampering_after_scan_blocks_approval(self):
        self.enable_outbound(); body = b"safe handoff"
        transfer = self.service.upload_outbound("chip-a", "handoff.txt", io.BytesIO(body), len(body), "alice")
        path = Path(transfer["storage_path"]); path.write_bytes(b"evil handoff")
        with self.assertRaisesRegex(ServiceError, "integrity"):
            self.service.decide_outbound("chip-a", transfer["id"], True, "ok", "approver")
        self.assertEqual("expired", self.service.get_outbound(transfer["id"])["state"])

    def test_startup_permission_hardening_reseals_verified_legacy_payload(self):
        obj = self.upload("legacy.txt", b"legacy")
        path = Path(obj["storage_path"]); path.chmod(0o644)
        stats = self.service.harden_existing_storage_permissions()
        self.assertEqual(0, stats["invalid"])
        self.assertEqual(0o400, path.stat().st_mode & 0o777)

    def test_restart_requeues_pending_and_quarantines_interrupted_scan(self):
        queue = HoldingQueue()
        service = SFSSService(self.settings, self.store, [MockScanner()], queue)
        pending = service.upload("chip-a", "pending.txt", io.BytesIO(b"pending"), 7, "alice")
        self.assertEqual("pending_scan", pending["state"])
        self.store.execute("UPDATE objects SET state='scanning' WHERE id=?", (pending["id"],))

        stats = service.recover_interrupted_jobs()

        self.assertEqual("quarantined", service.get_object(pending["id"])["state"])
        self.assertEqual(1, stats["interrupted_quarantined"])
        self.assertEqual(0, stats["inbound_requeued"])

        another = service.upload("chip-a", "queued.txt", io.BytesIO(b"queued"), 6, "alice")
        queued_before = len(queue.jobs)
        stats = service.recover_interrupted_jobs()
        self.assertEqual(1, stats["inbound_requeued"])
        self.assertEqual(queued_before + 1, len(queue.jobs))
        self.assertEqual("pending_scan", service.get_object(another["id"])["state"])

    def test_interrupted_or_stale_classification_is_quarantined_not_stranded(self):
        self.enable_outbound()
        service = SFSSService(self.settings, self.store, [MockScanner()], HoldingQueue())
        body = b"classified crash"
        transfer = service.upload_outbound(
            "chip-a", "crash.txt", io.BytesIO(body), len(body), "alice")
        service.outbound_transition(transfer["id"], "scanning")
        service.outbound_transition(transfer["id"], "classified", classification="GENERAL")
        stats = service.recover_interrupted_jobs()
        recovered = service.get_outbound(transfer["id"])
        self.assertEqual("quarantined", recovered["state"])
        self.assertIn("approval submission interrupted", recovered["scan_detail"])
        self.assertEqual(1, stats["interrupted_quarantined"])

        second = service.upload_outbound(
            "chip-a", "stale.txt", io.BytesIO(body), len(body), "alice")
        service.outbound_transition(second["id"], "scanning")
        service.outbound_transition(second["id"], "classified", classification="GENERAL")
        self.store.execute("UPDATE outbound_transfers SET updated_at=? WHERE id=?",
                           (int(__import__("time").time()) - self.settings.scan_timeout_seconds - 1,
                            second["id"]))
        service.run_maintenance()
        self.assertEqual("quarantined", service.get_outbound(second["id"])["state"])

    def test_multipart_completion_recovers_both_database_filesystem_crash_windows(self):
        service = SFSSService(self.settings, self.store, [MockScanner()], HoldingQueue())
        session = service.create_upload_session(
            "chip-a", "inbound", "recover.txt", 7, "alice",
            hashlib.sha256(b"recover").hexdigest())
        service.put_upload_part(session["id"], 1, io.BytesIO(b"recover"), 7,
                                hashlib.sha256(b"recover").hexdigest(), "alice")
        with patch.object(service, "_finalize_upload_session",
                          side_effect=RuntimeError("crash after object registration")):
            with self.assertRaisesRegex(RuntimeError, "crash after object"):
                service.complete_upload_session(session["id"], "alice")
        interrupted = service.get_upload_session(session["id"], "alice")
        self.assertEqual("uploading", interrupted["state"])
        self.assertIsNotNone(service._registered_upload_record(interrupted))
        # A same-process retry can bind the original object without creating a duplicate.
        completed = service.complete_upload_session(session["id"], "alice")
        self.assertEqual(interrupted["object_id"], completed["id"])
        self.assertEqual(1, self.store.one("SELECT COUNT(*) AS value FROM objects WHERE filename='recover.txt'")["value"])

        second = service.create_upload_session("chip-a", "inbound", "retry.txt", 5, "alice")
        service.put_upload_part(second["id"], 1, io.BytesIO(b"retry"), 5,
                                hashlib.sha256(b"retry").hexdigest(), "alice")
        planned = "11111111-1111-1111-1111-111111111111"
        self.store.execute("UPDATE upload_sessions SET state='completing',object_id=? WHERE id=?",
                           (planned, second["id"]))
        orphan = service.isolation / planned; orphan.mkdir(mode=0o700); (orphan / "payload").write_bytes(b"orphan")
        stats = service.recover_interrupted_jobs()
        reset = service.get_upload_session(second["id"], "alice")
        self.assertEqual("uploading", reset["state"])
        self.assertEqual(1, stats["upload_completions_reset"])
        self.assertFalse(orphan.exists())
        self.assertEqual(1, len(reset["parts"]))
        retried = service.complete_upload_session(second["id"], "alice")
        self.assertEqual(planned, retried["id"])

    def test_duplicate_scan_delivery_does_not_change_released_object(self):
        obj = self.upload("notes.txt", b"safe")
        self.service.scan_object(obj["id"])
        self.assertEqual("released", self.service.get_object(obj["id"])["state"])
        event = self.store.one(
            "SELECT outcome FROM audit_events WHERE object_id=? AND action='scan.duplicate_ignored'",
            (obj["id"],),
        )
        self.assertEqual("ignored", event["outcome"])

    def test_sensitive_local_storage_permissions_are_restricted(self):
        self.assertEqual(0o700, self.settings.data_dir.stat().st_mode & 0o777)
        for directory in (self.settings.data_dir / "objects", self.service.isolation,
                          self.service.released, self.settings.data_dir / "outbound",
                          self.service.outbound_isolation, self.service.outbound_released,
                          self.service.upload_staging):
            self.assertEqual(0o700, directory.stat().st_mode & 0o777, str(directory))
        self.assertEqual(0o600, self.store.path.stat().st_mode & 0o777)
        connection = self.store.connect()
        try:
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(self.store.path) + suffix)
                if sidecar.exists(): self.assertEqual(0o600, sidecar.stat().st_mode & 0o777)
        finally:
            connection.close()
        unknown = self.upload("unknown.bin", b"\x00\x01\x02")
        self.assertEqual("quarantined", unknown["state"])
        self.assertEqual(0o600, Path(unknown["storage_path"]).stat().st_mode & 0o777)
        session = self.service.create_upload_session("chip-a", "inbound", "part.txt", 4, "alice")
        self.service.put_upload_part(session["id"], 1, io.BytesIO(b"data"), 4,
                                     hashlib.sha256(b"data").hexdigest(), "alice")
        part = self.store.one("SELECT storage_path FROM upload_parts WHERE upload_id=?", (session["id"],))
        self.assertEqual(0o600, Path(part["storage_path"]).stat().st_mode & 0o777)

    def test_unsafe_production_configuration_is_rejected(self):
        settings = replace(self.settings, environment="production")
        with self.assertRaises(ValueError): settings.validate()

    def test_environment_secret_file_is_private_and_exclusive_with_raw_value(self):
        secret = self.settings.data_dir / "environment-secret"
        secret.write_text("s" * 32, encoding="utf-8"); secret.chmod(0o600)
        with patch.dict(os.environ, {"SFSS_MANIFEST_HMAC_KEY":"",
                                    "SFSS_MANIFEST_HMAC_KEY_FILE":str(secret)}, clear=False):
            loaded = Settings.from_env()
        self.assertEqual("s" * 32, loaded.manifest_hmac_key)
        self.assertEqual(str(secret), loaded.manifest_hmac_key_file)
        with patch.dict(os.environ, {"SFSS_MANIFEST_HMAC_KEY":"r" * 32,
                                    "SFSS_MANIFEST_HMAC_KEY_FILE":str(secret)}, clear=False):
            with self.assertRaisesRegex(ValueError, "exactly one"):
                Settings.from_env()
        secret.chmod(0o644)
        with patch.dict(os.environ, {"SFSS_MANIFEST_HMAC_KEY":"",
                                    "SFSS_MANIFEST_HMAC_KEY_FILE":str(secret)}, clear=False):
            with self.assertRaisesRegex(ValueError, "private regular"):
                Settings.from_env()

    def test_production_rejects_insecure_ldap_transport_and_basic_auth(self):
        settings = replace(
            self.settings, environment="production", auth_backend="ldap", dev_tokens_enabled=False,
            scanners="clamav", require_trusted_proxy=True, trusted_zone_proxy_cidrs="127.0.0.1/32",
            require_forwarded_https=True, manifest_hmac_key="x" * 32,
            ldap_uri="ldap://ad.example:389", ldap_ca_file="/etc/sfss/ldap-ca.pem", allow_basic_auth=True,
        )
        with self.assertRaisesRegex(ValueError, "ldaps://.*Basic authentication"):
            settings.validate()

    def test_production_core_requires_runtime_unix_socket(self):
        settings = self.secure_production_settings()
        validate_listener(settings, None, "/run/sfss/sfss.sock")
        for host in ("127.0.0.1", "::1", "0.0.0.0", "localhost"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "unix-socket"):
                validate_listener(settings, host, None)
        for path in ("relative.sock", "/tmp/sfss.sock", "/run/other/sfss.sock"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_listener(settings, None, path)
        validate_bind_host(settings, "127.0.0.1")
        with self.assertRaisesRegex(ValueError, "trusted zone proxy CIDRs"):
            replace(settings, trusted_zone_proxy_cidrs="10.30.0.0/24").validate()

    def test_production_upload_limit_cannot_exceed_declared_clamav_stream_limit(self):
        settings = self.secure_production_settings()
        with self.assertRaisesRegex(ValueError, "ClamAV StreamMaxLength"):
            replace(settings, max_upload_bytes=settings.clamav_stream_max_bytes + 1).validate()

    def test_production_runtime_rejects_configuration_fingerprint_drift(self):
        settings = replace(self.secure_production_settings(), expected_config_sha256="0" * 64)
        with patch("sfss.config.platform.python_version", return_value="3.12.12"):
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                create_runtime(settings)

    def test_production_startup_refuses_uninitialized_or_permission_drifted_data(self):
        settings = self.secure_production_settings()
        missing = self.settings.data_dir.parent / "missing-production-data"
        with patch("sfss.config.platform.python_version", return_value="3.12.12"):
            with self.assertRaisesRegex(ValueError, "initialized offline"):
                create_runtime(replace(settings, data_dir=missing))
        parent = self.settings.data_dir / "objects"; parent.chmod(0o750)
        try:
            with patch("sfss.config.platform.python_version", return_value="3.12.12"):
                with self.assertRaisesRegex(ValueError, "permissions drifted"):
                    create_runtime(settings)
        finally:
            parent.chmod(0o700)

    def test_production_storage_permission_drift_is_not_silently_repaired(self):
        obj = self.upload("released.txt", b"released")
        path = Path(obj["storage_path"]); path.chmod(0o600)
        self.service.settings = replace(self.settings, environment="production")
        stats = self.service.harden_existing_storage_permissions()
        self.assertEqual(1, stats["invalid"])
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_production_yara_rules_are_hash_locked_and_live_identity_bound(self):
        rules = self.settings.data_dir / "production.yar"
        rules.write_text('rule reviewed { condition: true }\n', encoding="utf-8"); rules.chmod(0o600)
        digest = hashlib.sha256(rules.read_bytes()).hexdigest()
        candidate = replace(self.secure_production_settings(), scanners="clamav,yara",
                            yara_rules=str(rules), yara_rules_sha256=digest)
        candidate = replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.store.all("SELECT key,value FROM system_config ORDER BY key")))
        with patch("sfss.config.platform.python_version", return_value="3.12.12"):
            candidate.validate()
        service = SFSSService(candidate, self.store, [YaraScanner(str(rules))], InlineJobQueue())
        self.assertEqual([], service.runtime_acceptance_errors())
        rules.write_text('rule changed { condition: false }\n', encoding="utf-8")
        self.assertIn("artifact identity drifted", "; ".join(service.runtime_acceptance_errors()))
        with patch("sfss.config.platform.python_version", return_value="3.12.12"):
            with self.assertRaisesRegex(ValueError, "SHA-256 does not match"):
                candidate.validate()

    def test_production_ldap_ca_identity_drift_blocks_trust(self):
        candidate = self.secure_production_settings()
        service = SFSSService(candidate, self.store, [MockScanner()], InlineJobQueue())
        self.assertEqual([], service.ldap_trust_errors())
        Path(candidate.ldap_ca_file).write_text("replacement CA", encoding="utf-8")
        self.assertIn("identity drifted", "; ".join(service.ldap_trust_errors()))
        self.assertIn("security artifact identity drifted",
                      "; ".join(service.runtime_acceptance_errors()))

    def test_production_rejects_end_of_life_python_branch(self):
        settings = replace(self.secure_production_settings(), expected_python_version="3.9.25")
        with patch("sfss.config.platform.python_version", return_value="3.9.25"):
            with self.assertRaisesRegex(ValueError, "3.12 or newer"):
                settings.validate()

    def test_production_rejects_overlong_or_excessive_human_sessions(self):
        settings = self.secure_production_settings()
        for changes, message in (
            ({"session_ttl_seconds":3601}, "lifetime"),
            ({"session_idle_seconds":901}, "idle timeout"),
            ({"max_sessions_per_user":4}, "concurrent human sessions"),
            ({"service_token_max_ttl_seconds":31 * 24 * 3600}, "service token lifetime"),
            ({"request_header_timeout_seconds":16}, "header timeout"),
            ({"request_io_timeout_seconds":3601}, "I/O timeout"),
            ({"max_request_workers":257}, "request worker limit"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, message):
                replace(settings, **changes).validate()

    def test_production_rejects_raw_manifest_secret_even_when_long_enough(self):
        settings = replace(self.secure_production_settings(), manifest_hmac_key_file="")
        with self.assertRaisesRegex(ValueError, "secret file"):
            settings.validate()

    def test_ldap_configuration_rejects_ambiguous_uri_and_template(self):
        for changes in ({"ldap_uri":"ldaps://user@ad.example:636"},
                        {"ldap_uri":"ldaps://ad.example:636/search"},
                        {"ldap_user_template":"uid={username},{unexpected}"},
                        {"ldap_user_template":"uid=static,dc=example"},
                        {"bootstrap_admins":"admin,evil,dc=other"}):
            settings = replace(self.settings, auth_backend="ldap", **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                settings.validate()

    def test_production_rejects_local_approval_downgrade(self):
        settings = replace(self.settings, environment="production", allow_local_approval=True)
        with self.assertRaisesRegex(ValueError, "local outbound approval is forbidden"):
            settings.validate()

    def test_production_startup_rejects_persisted_enabled_local_approval(self):
        self.store.execute(
            "INSERT INTO outbound_policies(project_id,enabled,approval_provider,updated_at,updated_by) "
            "VALUES('chip-a',1,'local',1,'admin')")
        with self.assertRaisesRegex(ValueError, "persisted production policy"):
            with patch("sfss.config.platform.python_version", return_value="3.12.12"):
                create_runtime(self.secure_production_settings())

    def test_startup_rejects_enabled_wecom_policy_without_safe_relay(self):
        self.store.execute(
            "INSERT INTO outbound_policies(project_id,enabled,approval_provider,updated_at,updated_by) "
            "VALUES('chip-a',1,'wecom',1,'admin')")
        with self.assertRaisesRegex(ValueError, "unsafe persisted approval relay configuration"):
            with patch("sfss.config.platform.python_version", return_value="3.12.12"):
                create_runtime(self.secure_production_settings())

    def test_production_ldap_rejects_local_password_database(self):
        LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        with self.assertRaisesRegex(ValueError, "local accounts must not be migrated"):
            with patch("sfss.config.platform.python_version", return_value="3.12.12"):
                create_runtime(self.secure_production_settings())

    def test_production_ldap_rejects_unlisted_platform_administrator(self):
        self.store.ensure_user("shadow-admin", True)
        with self.assertRaisesRegex(ValueError, "outside SFSS_BOOTSTRAP_ADMINS"):
            with patch("sfss.config.platform.python_version", return_value="3.12.12"):
                create_runtime(self.secure_production_settings())

    def test_production_startup_rejects_persisted_overlong_service_token(self):
        self.store.execute(
            "INSERT INTO users(username,global_admin,principal_type,enabled) VALUES('legacy-agent',0,'service',1)")
        self.service.add_member("chip-a", "legacy-agent", "uploader", "admin")
        now = int(__import__("time").time())
        ServiceTokens(self.store).issue(
            label="unsafe legacy lifetime", username="legacy-agent", project_id="chip-a", zone="green",
            permissions=["inbound_upload"], expires_at=now + 31 * 24 * 3600, created_by="admin")
        with self.assertRaisesRegex(ValueError, "service token lifetime exceeds policy"):
            with patch("sfss.config.platform.python_version", return_value="3.12.12"):
                create_runtime(self.secure_production_settings())

    def test_maintenance_expires_incomplete_upload_session(self):
        session = self.service.create_upload_session("chip-a", "inbound", "partial.txt", 4, "alice")
        self.service.put_upload_part(session["id"], 1, io.BytesIO(b"data"), 4,
                                     hashlib.sha256(b"data").hexdigest(), "alice")
        self.store.execute("UPDATE upload_sessions SET expires_at=0 WHERE id=?", (session["id"],))
        stats = self.service.run_maintenance()
        row = self.store.one("SELECT state FROM upload_sessions WHERE id=?", (session["id"],))
        self.assertEqual("expired", row["state"])
        self.assertEqual(1, stats["upload_sessions_expired"])
        self.assertFalse((self.settings.data_dir / "uploads" / session["id"]).exists())

    def test_maintenance_marks_expired_service_tokens_revoked(self):
        self.store.execute(
            "INSERT INTO users(username,principal_type,enabled) VALUES('maintenance-agent','service',1)")
        self.service.add_member("chip-a", "maintenance-agent", "uploader", "admin")
        raw, record = ServiceTokens(self.store).issue(
            label="maintenance", username="maintenance-agent", project_id="chip-a", zone="green",
            permissions=["inbound_upload"], expires_at=2 ** 31, created_by="admin",
        )
        self.store.execute("UPDATE service_tokens SET expires_at=0 WHERE id=?", (record["id"],))
        stats = self.service.run_maintenance()
        self.assertEqual(1, stats["service_tokens_expired"])
        self.assertEqual(1, self.store.one(
            "SELECT revoked FROM service_tokens WHERE id=?", (record["id"],))["revoked"])
        event = self.store.one(
            "SELECT details FROM audit_events WHERE action='service_token.expired' ORDER BY id DESC LIMIT 1")
        self.assertEqual(1, json.loads(event["details"])["revoked"])

    def test_maintenance_credential_cleanup_rolls_back_when_audit_fails(self):
        self.store.execute(
            "INSERT INTO users(username,principal_type,enabled) VALUES('expiry-agent','service',1)")
        self.service.add_member("chip-a", "expiry-agent", "uploader", "admin")
        _, record = ServiceTokens(self.store).issue(
            label="audit failure", username="expiry-agent", project_id="chip-a", zone="green",
            permissions=["inbound_upload"], expires_at=2 ** 31, created_by="admin")
        self.store.execute("UPDATE service_tokens SET expires_at=0 WHERE id=?", (record["id"],))
        with patch.object(self.store, "_append_audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                self.service.run_maintenance()
        self.assertEqual(0, self.store.one(
            "SELECT revoked FROM service_tokens WHERE id=?", (record["id"],))["revoked"])

    def test_late_part_cannot_reopen_or_dirty_a_completed_upload(self):
        session = self.service.create_upload_session("chip-a", "inbound", "race.txt", 4, "alice")
        digest = hashlib.sha256(b"data").hexdigest()
        self.service.put_upload_part(session["id"], 1, io.BytesIO(b"data"), 4, digest, "alice")
        started = threading.Event(); release = threading.Event(); errors = []

        class DelayedStream(io.BytesIO):
            def read(self, size=-1):
                started.set(); release.wait(5); return super().read(size)

        def late_part():
            try:
                self.service.put_upload_part(session["id"], 1, DelayedStream(b"data"), 4, digest, "alice")
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=late_part); worker.start()
        self.assertTrue(started.wait(2))
        record = self.service.complete_upload_session(session["id"], "alice")
        release.set(); worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual("released", record["state"])
        self.assertEqual(1, len(errors)); self.assertIsInstance(errors[0], ServiceError)
        self.assertEqual(409, errors[0].status)
        self.assertIsNone(self.store.one("SELECT upload_id FROM upload_parts WHERE upload_id=?", (session["id"],)))
        self.assertFalse((self.settings.data_dir / "uploads" / session["id"]).exists())

    def test_upload_session_concurrency_and_staging_reservations_are_bounded(self):
        self.store.set_config("max_active_uploads_per_user", "1", "admin")
        first = self.service.create_upload_session("chip-a", "inbound", "first.txt", 2, "alice")
        with self.assertRaisesRegex(ServiceError, "too many active"):
            self.service.create_upload_session("chip-a", "inbound", "second.txt", 2, "alice")
        self.service.cancel_upload_session(first["id"], "alice")
        self.store.set_config("max_active_uploads_per_user", "4", "admin")
        self.store.set_config("max_staged_bytes_per_project", "3", "admin")
        self.service.create_upload_session("chip-a", "inbound", "third.txt", 2, "alice")
        with self.assertRaisesRegex(ServiceError, "staging reservation"):
            self.service.create_upload_session("chip-a", "inbound", "fourth.txt", 2, "alice")

    def test_storage_safety_reserve_fails_closed_before_upload(self):
        self.store.set_config("min_free_bytes", "1000", "admin")
        constrained = SimpleNamespace(total=10_000, used=8_950, free=1_050)
        with patch("sfss.service.shutil.disk_usage", return_value=constrained):
            with self.assertRaisesRegex(ServiceError, "insufficient storage") as direct:
                self.service.upload("chip-a", "blocked.txt", io.BytesIO(b"x" * 100), 100, "alice")
            self.assertEqual(507, direct.exception.status)
            with self.assertRaisesRegex(ServiceError, "insufficient storage") as multipart:
                self.service.create_upload_session("chip-a", "inbound", "blocked.txt", 100, "alice")
            self.assertEqual(507, multipart.exception.status)
        self.assertEqual(0, self.store.one("SELECT COUNT(*) AS value FROM upload_sessions")["value"])

    def test_existing_upload_session_rechecks_revoked_role_and_policy(self):
        inbound = self.service.create_upload_session("chip-a", "inbound", "revoked.txt", 4, "alice")
        self.service.remove_member("chip-a", "alice", "uploader", "admin")
        with self.assertRaisesRegex(ServiceError, "permission denied"):
            self.service.get_upload_session(inbound["id"], "alice")

        self.service.add_member("chip-a", "alice", "red_uploader", "admin")
        self.enable_outbound()
        outbound = self.service.create_upload_session("chip-a", "outbound", "disabled.txt", 4, "alice")
        self.service.set_outbound_policy("chip-a", {"enabled":False, "approval_provider":"local",
            "allowed_classifications":["GENERAL"], "approval_timeout_hours":24,
            "download_ttl_hours":24}, "admin")
        with self.assertRaisesRegex(ServiceError, "disabled"):
            self.service.put_upload_part(outbound["id"], 1, io.BytesIO(b"data"), 4,
                                         hashlib.sha256(b"data").hexdigest(), "alice")


if __name__ == "__main__":
    unittest.main()
