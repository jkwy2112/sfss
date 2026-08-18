import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import threading
import time
import uuid
import ipaddress
import unicodedata
from typing import BinaryIO, Dict, Optional

from .config import Settings
from .db import MutationConflictError, Store
from .jobs import JobQueue
from .scanners import Scanner
from .types import detect_content, extension_conflicts
from .classifiers import OutboundClassifier
from .approvals import LocalApprovalProvider, WeComApprovalProvider


ALLOWED_TRANSITIONS = {
    "pending_scan": {"scanning", "expired"},
    "scanning": {"quarantined", "released", "rejected"},
    "quarantined": {"pending_scan", "expired"},
    "released": {"expired"},
    "rejected": {"expired"},
    "expired": set(),
}

OUTBOUND_TRANSITIONS = {
    "pending_scan": {"scanning", "expired"}, "scanning": {"quarantined", "classified"},
    "quarantined": {"pending_scan", "expired"}, "classified": {"pending_approval", "quarantined"},
    "pending_approval": {"approved", "approval_rejected", "expired"},
    "approved": {"released_to_green", "expired"}, "approval_rejected": {"expired"},
    "released_to_green": {"expired"}, "expired": set(),
}


class ServiceError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class SFSSService:
    def __init__(self, settings: Settings, store: Store, scanners, queue: JobQueue):
        self.settings, self.store, self.scanners, self.queue = settings, store, scanners, queue
        self.isolation = settings.data_dir / "objects" / "isolation"
        self.released = settings.data_dir / "objects" / "released"
        self.outbound_isolation = settings.data_dir / "outbound" / "isolation"
        self.outbound_released = settings.data_dir / "outbound" / "released-green"
        self.upload_staging = settings.data_dir / "uploads"
        self.outbound_classifier = OutboundClassifier()
        self.last_maintenance_at = 0
        self.last_maintenance_error = ""
        self._upload_session_lock = threading.Lock()
        self._upload_locks = {}
        self._accepted_security_artifacts = {}
        private_directories = [settings.data_dir, self.upload_staging]
        if self.workflow_enabled("inbound"):
            private_directories.extend((settings.data_dir / "objects", self.isolation, self.released))
        if self.workflow_enabled("outbound"):
            private_directories.extend((settings.data_dir / "outbound", self.outbound_isolation,
                                        self.outbound_released))
        for directory in private_directories:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        if settings.environment == "production":
            configured = ({"ldap-ca":settings.ldap_ca_file}
                          if settings.auth_backend == "ldap" else {})
            if settings.approval_relay_ca_sha256:
                configured["approval-relay-ca"] = settings.approval_relay_ca_file
            if settings.approval_relay_client_cert_sha256:
                configured["approval-relay-client-cert"] = settings.approval_relay_client_cert
            for scanner in scanners:
                if scanner.name == "yara":
                    configured[f"yara:{scanner.rules_path}"] = scanner.rules_path
            for label, path in configured.items():
                self._accepted_security_artifacts[label] = (str(Path(path)), self._artifact_identity(path))

    def workflow_enabled(self, direction: str) -> bool:
        return self.settings.deployment_mode in {"combined", direction}

    def require_workflow(self, direction: str):
        if direction not in {"inbound", "outbound"} or not self.workflow_enabled(direction):
            raise ServiceError(404, f"{direction} workflow is not deployed on this system")

    @staticmethod
    def _artifact_identity(path):
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode): raise OSError
        return (metadata.st_dev, metadata.st_ino, metadata.st_size,
                metadata.st_mtime_ns, metadata.st_ctime_ns)

    def security_artifact_errors(self):
        if self.settings.environment != "production": return []
        errors = []
        current = ({"ldap-ca":self.settings.ldap_ca_file}
                   if self.settings.auth_backend == "ldap" else {})
        if self.settings.approval_relay_ca_sha256:
            current["approval-relay-ca"] = self.settings.approval_relay_ca_file
        if self.settings.approval_relay_client_cert_sha256:
            current["approval-relay-client-cert"] = self.settings.approval_relay_client_cert
        for scanner in self.scanners:
            if scanner.name == "yara": current[f"yara:{scanner.rules_path}"] = scanner.rules_path
        observed = {}
        for label, path in current.items():
            try: observed[label] = (str(Path(path)), self._artifact_identity(path))
            except OSError: errors.append(f"accepted {label} artifact is unavailable or unsafe")
        if observed != self._accepted_security_artifacts:
            errors.append("accepted security artifact identity drifted")
        return errors

    def ldap_trust_errors(self):
        if self.settings.environment != "production" or self.settings.auth_backend != "ldap": return []
        expected = self._accepted_security_artifacts.get("ldap-ca")
        try: current = (str(Path(self.settings.ldap_ca_file)), self._artifact_identity(self.settings.ldap_ca_file))
        except OSError: return ["accepted LDAP CA artifact is unavailable or unsafe"]
        return [] if current == expected else ["accepted LDAP CA artifact identity drifted"]

    def runtime_acceptance_errors(self):
        """Return production runtime drift that must stop data-plane progress."""
        if self.settings.environment != "production":
            return []
        errors = list(self.settings.runtime_secret_errors())
        fingerprint = self.settings.configuration_fingerprint(
            self.store.all("SELECT key,value FROM system_config ORDER BY key"))
        if fingerprint != self.settings.expected_config_sha256:
            errors.append("effective configuration fingerprint drifted")
        errors.extend(self.security_artifact_errors())
        return errors

    def require_runtime_acceptance(self):
        if self.runtime_acceptance_errors():
            raise ServiceError(503, "production runtime configuration is not in the accepted state")

    def _upload_lock(self, upload_id: str):
        with self._upload_session_lock:
            return self._upload_locks.setdefault(upload_id, threading.RLock())

    def _forget_upload_lock(self, upload_id: str):
        with self._upload_session_lock:
            self._upload_locks.pop(upload_id, None)

    @staticmethod
    def _valid_filename(filename: str) -> bool:
        if not filename or filename != filename.strip() or filename in {".", ".."}:
            return False
        try:
            if len(filename.encode("utf-8")) > 255: return False
        except UnicodeEncodeError:
            return False
        if unicodedata.normalize("NFC", filename) != filename:
            return False
        forbidden = set('/\\<>:"|?*')
        bidi_controls = {chr(value) for value in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
        return not any(character in forbidden or character in bidi_controls or
                       unicodedata.category(character) in {"Cc", "Cf", "Cs"}
                       for character in filename)

    def storage_status(self) -> Dict[str, int]:
        usage = shutil.disk_usage(self.settings.data_dir)
        reserve = int(self.store.get_config("min_free_bytes", str(self.settings.min_free_bytes)))
        return {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
                "reserve_bytes": reserve, "available_bytes": max(0, usage.free - reserve)}

    def require_storage_capacity(self, required_bytes: int):
        status = self.storage_status()
        if required_bytes < 0 or status["free_bytes"] - required_bytes < status["reserve_bytes"]:
            raise ServiceError(507, "insufficient storage capacity while preserving the safety reserve")

    def _require_active_user(self, actor: str):
        row = self.store.one("SELECT enabled FROM users WHERE username=?", (actor,))
        if not row or not row["enabled"]:
            raise ServiceError(403, "account is disabled or unknown")

    def create_upload_session(self, direction: str, filename: str, total_size: int,
                              actor: str, expected_sha256: Optional[str] = None, audit=None) -> Dict:
        self.require_workflow(direction)
        self._require_active_user(actor)
        if direction == "outbound" and not self.outbound_policy()["enabled"]:
            raise ServiceError(403, "outbound transfer is disabled by platform policy")
        if direction not in {"inbound", "outbound"}:
            raise ServiceError(400, "invalid upload direction")
        if not self._valid_filename(filename):
            raise ServiceError(400, "invalid filename")
        maximum = int(self.store.get_config("max_upload_bytes", str(self.settings.max_upload_bytes)))
        if total_size <= 0 or total_size > maximum:
            raise ServiceError(413, "invalid or excessive file size")
        expected = (expected_sha256 or "").lower().strip() or None
        if expected and (len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected)):
            raise ServiceError(400, "expected_sha256 must be a hexadecimal SHA-256 digest")
        configured_chunk = int(self.store.get_config("multipart_chunk_bytes", str(self.settings.multipart_chunk_bytes)))
        session_ttl = int(self.store.get_config("upload_session_ttl_seconds", str(self.settings.upload_session_ttl_seconds)))
        chunk_size = min(max(1024 * 1024, configured_chunk), 128 * 1024 * 1024)
        upload_id = str(uuid.uuid4()); now = int(time.time())
        target = self.upload_staging / upload_id
        with self._upload_session_lock:
            active_limit = int(self.store.get_config(
                "max_active_uploads_per_user", str(self.settings.max_active_uploads_per_user)))
            active = self.store.one(
                "SELECT COUNT(*) AS value FROM upload_sessions WHERE actor=? AND state IN ('uploading','completing')",
                (actor,),
            )["value"]
            if active >= active_limit:
                raise ServiceError(429, "too many active upload sessions for this user")
            staged_limit = int(self.store.get_config(
                "max_staged_bytes_per_user", str(self.settings.max_staged_bytes_per_user)))
            reserved = self.store.one(
                "SELECT COALESCE(SUM(total_size),0) AS value FROM upload_sessions "
                "WHERE actor=? AND state IN ('uploading','completing')", (actor,),
            )["value"]
            if reserved + total_size > staged_limit:
                raise ServiceError(429, "user upload staging reservation is exhausted")
            received = self.store.one(
                "SELECT COALESCE(SUM(p.size),0) AS value FROM upload_parts p JOIN upload_sessions s "
                "ON s.id=p.upload_id WHERE s.state IN ('uploading','completing')"
            )["value"]
            all_reserved = self.store.one(
                "SELECT COALESCE(SUM(total_size),0) AS value FROM upload_sessions "
                "WHERE state IN ('uploading','completing')"
            )["value"]
            # Worst case: all remaining parts arrive and every active upload is
            # assembled concurrently before its parts are removed.
            self.require_storage_capacity((2 * all_reserved - received) + 2 * total_size)
            target.mkdir(mode=0o700)
            try:
                statement = (
                    "INSERT INTO upload_sessions(id,actor,direction,filename,total_size,chunk_size,expected_sha256,state,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (upload_id, actor, direction, filename, total_size, chunk_size, expected,
                     "uploading", now, now, now + max(300, session_ttl)),
                )
                audited = (dict(audit) if audit is not None else {
                    "request_id":f"upload-session-created-{upload_id}", "actor":actor,
                    "action":"upload.session.create", "object_id":upload_id,
                    "outcome":"success", "source_zone":direction, "remote_addr":"local", "details":{}})
                audited["object_id"] = upload_id
                details = dict(audited.get("details") or {})
                details.update({"upload_id":upload_id, "direction":direction,
                                "filename":filename, "size":total_size})
                audited["details"] = details
                self.store.transaction_audited((statement,), audit=audited)
            except Exception:
                shutil.rmtree(target, ignore_errors=True); raise
        return self.get_upload_session(upload_id, actor)

    def get_upload_session(self, upload_id: str, actor: str) -> Dict:
        session = self.store.one("SELECT * FROM upload_sessions WHERE id=?", (upload_id,))
        if not session:
            raise ServiceError(404, "upload session not found")
        if session["actor"] != actor and not self.store.is_global_admin(actor):
            raise ServiceError(403, "upload session permission denied")
        if not self.store.is_global_admin(actor):
            self._require_active_user(actor)
        parts = self.store.all(
            "SELECT part_number,offset,size,sha256,completed_at FROM upload_parts WHERE upload_id=? ORDER BY part_number",
            (upload_id,),
        )
        session["parts"] = parts
        session["received_bytes"] = sum(part["size"] for part in parts)
        session["part_count"] = (session["total_size"] + session["chunk_size"] - 1) // session["chunk_size"]
        return session

    def require_upload_session_write(self, session: Dict, actor: str):
        self.require_workflow(session["direction"])
        self._require_active_user(actor)
        if session["actor"] != actor:
            raise ServiceError(403, "only the upload owner can write this session")
        if session["direction"] == "outbound" and not self.outbound_policy()["enabled"]:
            raise ServiceError(403, "outbound transfer is disabled by platform policy")

    def put_upload_part(self, upload_id: str, part_number: int, stream: BinaryIO, size: int,
                        claimed_sha256: str, actor: str, audit=None) -> Dict:
        session = self.get_upload_session(upload_id, actor)
        self.require_upload_session_write(session, actor)
        if session["state"] != "uploading" or session["expires_at"] <= int(time.time()):
            raise ServiceError(409, "upload session is not writable")
        if part_number < 1 or part_number > session["part_count"]:
            raise ServiceError(400, "invalid part number")
        offset = (part_number - 1) * session["chunk_size"]
        expected_size = min(session["chunk_size"], session["total_size"] - offset)
        if size != expected_size:
            raise ServiceError(400, "part size does not match the upload plan")
        self.require_storage_capacity(size)
        claimed = claimed_sha256.lower().strip()
        if len(claimed) != 64 or any(ch not in "0123456789abcdef" for ch in claimed):
            raise ServiceError(400, "valid X-Part-SHA256 header required")
        directory = self.upload_staging / upload_id
        target = directory / f"part-{part_number:08d}"
        temporary = directory / f".part-{part_number:08d}-{uuid.uuid4().hex}.tmp"
        digest = hashlib.sha256(); written = 0
        try:
            with temporary.open("xb") as output:
                while written < size:
                    block = stream.read(min(1024 * 1024, size - written))
                    if not block: break
                    written += len(block); digest.update(block); output.write(block)
            try: temporary.chmod(0o600)
            except FileNotFoundError as exc:
                raise ServiceError(409, "upload session changed while receiving the part") from exc
            if written != size:
                raise ServiceError(400, "request body shorter than Content-Length")
            actual = digest.hexdigest()
            if actual != claimed:
                raise ServiceError(422, "part SHA-256 mismatch")
            with self._upload_lock(upload_id):
                current = self.get_upload_session(upload_id, actor)
                self.require_upload_session_write(current, actor)
                if current["state"] != "uploading" or current["expires_at"] <= int(time.time()):
                    raise ServiceError(409, "upload session changed while receiving the part")
                os.replace(str(temporary), str(target))
                now = int(time.time())
                statements = (
                    ("INSERT INTO upload_parts(upload_id,part_number,offset,size,sha256,storage_path,completed_at) VALUES(?,?,?,?,?,?,?) "
                     "ON CONFLICT(upload_id,part_number) DO UPDATE SET offset=excluded.offset,size=excluded.size,sha256=excluded.sha256,storage_path=excluded.storage_path,completed_at=excluded.completed_at",
                     (upload_id, part_number, offset, size, actual, str(target), now)),
                    ("UPDATE upload_sessions SET updated_at=? WHERE id=? AND state='uploading'",
                     (now, upload_id)),
                )
                audited = (dict(audit) if audit is not None else {
                    "request_id":f"upload-part-{upload_id}-{part_number}", "actor":actor,
                    "action":"upload.part.complete",
                    "object_id":upload_id, "outcome":"success", "source_zone":current["direction"],
                    "remote_addr":"local", "details":{}})
                details = dict(audited.get("details") or {})
                details.update({"upload_id":upload_id, "part_number":part_number,
                                "offset":offset, "size":size, "sha256":actual})
                audited["details"] = details
                try:
                    self.store.transaction_audited(
                        statements, audit=audited, required_rows={1:1})
                except MutationConflictError as exc:
                    raise ServiceError(409, "upload session changed during part commit") from exc
        finally:
            if temporary.exists(): temporary.unlink()
        return {"part_number": part_number, "offset": offset, "size": size, "sha256": claimed}

    def cancel_upload_session(self, upload_id: str, actor: str):
        with self._upload_lock(upload_id):
            return self._cancel_upload_session_locked(upload_id, actor)

    def _cancel_upload_session_locked(self, upload_id: str, actor: str):
        session = self.get_upload_session(upload_id, actor)
        if session["state"] == "cancelled": return
        if session["state"] != "uploading": raise ServiceError(409, "only an active upload can be cancelled")
        try:
            self.store.execute_audited(
                "UPDATE upload_sessions SET state='cancelled',updated_at=? WHERE id=? AND state='uploading'",
                (int(time.time()), upload_id), error="upload session changed concurrently",
                audit={"request_id":f"upload-cancelled-{upload_id}", "actor":actor,
                       "action":"upload.session.cancelled",
                       "object_id":session.get("object_id"), "outcome":"success",
                       "source_zone":session["direction"], "remote_addr":"local",
                       "details":{"upload_id":upload_id, "direction":session["direction"]}})
        except RuntimeError as exc:
            raise ServiceError(409, str(exc)) from exc
        shutil.rmtree(self.upload_staging / upload_id, ignore_errors=True)
        self.store.execute("DELETE FROM upload_parts WHERE upload_id=?", (upload_id,))
        self._forget_upload_lock(upload_id)

    def complete_upload_session(self, upload_id: str, actor: str) -> Dict:
        with self._upload_lock(upload_id):
            return self._complete_upload_session_locked(upload_id, actor)

    def _complete_upload_session_locked(self, upload_id: str, actor: str) -> Dict:
        session = self.get_upload_session(upload_id, actor)
        if session["state"] == "completed" and session["object_id"]:
            return self.get_object(session["object_id"]) if session["direction"] == "inbound" else self.get_outbound(session["object_id"])
        recovered = self._registered_upload_record(session)
        if recovered:
            self._finalize_upload_session(session, recovered["id"])
            if recovered["state"] == "pending_scan":
                self.queue.submit(self.scan_object if session["direction"] == "inbound" else self.scan_outbound,
                                  recovered["id"])
            return (self.get_object(recovered["id"]) if session["direction"] == "inbound"
                    else self.get_outbound(recovered["id"]))
        if session["state"] != "uploading":
            raise ServiceError(409, "upload session cannot be completed")
        self.require_upload_session_write(session, actor)
        if len(session["parts"]) != session["part_count"] or session["received_bytes"] != session["total_size"]:
            raise ServiceError(409, "upload is incomplete")
        self.require_storage_capacity(session["total_size"])
        planned_object_id = session.get("object_id") or str(uuid.uuid4())
        if self.store.execute(
                "UPDATE upload_sessions SET state='completing',object_id=?,updated_at=? "
                "WHERE id=? AND state='uploading'",
                (planned_object_id, int(time.time()), upload_id)) != 1:
            raise ServiceError(409, "upload completion is already in progress")
        session["object_id"] = planned_object_id
        assembled = self.upload_staging / upload_id / "assembled.tmp"
        digest = hashlib.sha256(); prefix = b""; written = 0
        try:
            with assembled.open("xb") as output:
                for part in session["parts"]:
                    source = self.upload_staging / upload_id / f"part-{part['part_number']:08d}"
                    with source.open("rb") as input_stream:
                        while True:
                            block = input_stream.read(1024 * 1024)
                            if not block: break
                            written += len(block); digest.update(block)
                            if len(prefix) < 8192: prefix += block[:8192 - len(prefix)]
                            output.write(block)
            assembled.chmod(0o600)
            actual = digest.hexdigest()
            if written != session["total_size"] or (session["expected_sha256"] and actual != session["expected_sha256"]):
                raise ServiceError(422, "completed file SHA-256 mismatch")
            record = self._register_assembled_upload(session, assembled, actual, prefix)
            self._finalize_upload_session(session, record["id"])
            self.queue.submit(self.scan_object if session["direction"] == "inbound" else self.scan_outbound,
                              record["id"])
            return (self.get_object(record["id"]) if session["direction"] == "inbound"
                    else self.get_outbound(record["id"]))
        except Exception:
            self.store.execute("UPDATE upload_sessions SET state='uploading',updated_at=? WHERE id=? AND state='completing'",
                               (int(time.time()), upload_id))
            raise
        finally:
            if assembled.exists(): assembled.unlink()

    def _registered_upload_record(self, session: Dict):
        object_id = session.get("object_id")
        if not object_id: return None
        table = "objects" if session["direction"] == "inbound" else "outbound_transfers"
        return self.store.one(f"SELECT * FROM {table} WHERE id=?", (object_id,))

    def _finalize_upload_session(self, session: Dict, object_id: str):
        self.store.execute_audited(
            "UPDATE upload_sessions SET state='completed',object_id=?,updated_at=? "
            "WHERE id=? AND state IN ('uploading','completing','completed')",
            (object_id, int(time.time()), session["id"]),
            error="upload session could not be finalized",
            audit={"request_id":f"upload-completed-{session['id']}", "actor":"system",
                   "action":"upload.session.completed",
                   "object_id":object_id, "outcome":"success", "source_zone":"isolation",
                   "remote_addr":"local", "details":{"upload_id":session["id"],
                   "direction":session["direction"]}})
        shutil.rmtree(self.upload_staging / session["id"], ignore_errors=True)
        self.store.execute("DELETE FROM upload_parts WHERE upload_id=?", (session["id"],))
        self._forget_upload_lock(session["id"])

    def _register_assembled_upload(self, session: Dict, assembled: Path, sha256: str, prefix: bytes) -> Dict:
        self.require_workflow(session["direction"])
        detected = detect_content(prefix); conflict = extension_conflicts(session["filename"], detected)
        object_id = session.get("object_id")
        if not object_id: raise RuntimeError("upload session has no planned object identity")
        now = int(time.time())
        if session["direction"] == "inbound":
            target_dir = self.isolation / object_id; target_dir.mkdir(mode=0o700); target = target_dir / "payload"
            os.replace(str(assembled), str(target))
            try:
                self.store.transaction_audited(((
                    "INSERT INTO objects(id,uploader,filename,size,sha256,media_type,type_known,type_conflict,state,storage_path,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (object_id, session["actor"], session["filename"], session["total_size"], sha256,
                     detected.media_type, int(detected.known), int(conflict), "pending_scan", str(target), now, now,
                     now + int(self.store.get_config("retention_seconds", str(self.settings.retention_seconds)))),
                ),), audit={"request_id":f"object-registered-{object_id}", "actor":session["actor"],
                            "action":"object.registered",
                            "object_id":object_id, "outcome":"success", "source_zone":"isolation",
                            "remote_addr":"local", "details":{"upload_id":session["id"],
                            "sha256":sha256, "size":session["total_size"],
                            "media_type":detected.media_type, "type_conflict":bool(conflict)}})
            except Exception:
                shutil.rmtree(target_dir, ignore_errors=True); raise
            return self.get_object(object_id)
        policy = self.outbound_policy()
        if not policy["enabled"]: raise ServiceError(403, "outbound transfer is disabled by platform policy")
        target_dir = self.outbound_isolation / object_id; target_dir.mkdir(mode=0o700); target = target_dir / "payload"
        os.replace(str(assembled), str(target))
        retention = now + int(self.store.get_config("retention_seconds", str(self.settings.retention_seconds)))
        try:
            self.store.transaction_audited(((
                "INSERT INTO outbound_transfers(id,uploader,filename,size,sha256,media_type,type_known,type_conflict,state,storage_path,approval_provider,retention_expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (object_id, session["actor"], session["filename"], session["total_size"], sha256,
                 detected.media_type, int(detected.known), int(conflict), "pending_scan", str(target), policy["approval_provider"], retention, now, now),
            ),), audit={"request_id":f"outbound-registered-{object_id}", "actor":session["actor"],
                        "action":"outbound.registered",
                        "object_id":object_id, "outcome":"success", "source_zone":"isolation",
                        "remote_addr":"local", "details":{"upload_id":session["id"],
                        "sha256":sha256, "size":session["total_size"],
                        "media_type":detected.media_type, "type_conflict":bool(conflict)}})
        except Exception:
            shutil.rmtree(target_dir, ignore_errors=True); raise
        return self.get_outbound(object_id)

    def outbound_policy(self) -> Dict:
        self.require_workflow("outbound")
        row = self.store.one("SELECT * FROM outbound_policy WHERE id=1")
        return row or {"enabled": 0,
                       "allowed_classifications": '["GDS","FPGA_BITFILE","GENERAL"]',
                       "approval_provider": "local", "approval_timeout_hours": 72,
                       "download_ttl_hours": 168, "updated_at": 0, "updated_by": "system"}

    def network_policy(self) -> Dict:
        row = self.store.one("SELECT * FROM network_policy WHERE id=1")
        return row or {"inbound_upload_cidrs": '["127.0.0.1/32","::1/128"]',
                       "outbound_upload_cidrs": '["127.0.0.1/32","::1/128"]',
                       "updated_at": 0, "updated_by": "system"}

    @staticmethod
    def normalize_cidrs(values) -> list:
        if not isinstance(values, list) or not values or len(values) > 100:
            raise ServiceError(400, "IP allowlist must contain 1 to 100 entries")
        normalized = []
        for value in values:
            try:
                text = str(value).strip()
                if not text: raise ValueError
                network = ipaddress.ip_network(text if "/" in text else text + ("/128" if ":" in text else "/32"), strict=False)
                canonical = str(network)
            except ValueError as exc:
                raise ServiceError(400, f"invalid IP network: {value}") from exc
            if canonical not in normalized: normalized.append(canonical)
        return normalized

    def set_network_policy(self, data: Dict, actor: str, audit=None) -> Dict:
        if not self.store.is_global_admin(actor):
            raise ServiceError(403, "platform administrator required")
        current = self.network_policy()
        inbound = (self.normalize_cidrs(data.get("inbound_upload_cidrs"))
                   if self.workflow_enabled("inbound") else json.loads(current["inbound_upload_cidrs"]))
        outbound = (self.normalize_cidrs(data.get("outbound_upload_cidrs"))
                    if self.workflow_enabled("outbound") else json.loads(current["outbound_upload_cidrs"]))
        now = int(time.time())
        statement = ("""INSERT INTO network_policy(id,inbound_upload_cidrs,outbound_upload_cidrs,updated_at,updated_by)
          VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET inbound_upload_cidrs=excluded.inbound_upload_cidrs,outbound_upload_cidrs=excluded.outbound_upload_cidrs,updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
          (json.dumps(inbound), json.dumps(outbound), now, actor))
        if audit is None: self.store.transaction((statement,))
        else:
            audited = dict(audit); details = dict(audited.get("details") or {})
            details.update({"inbound_upload_cidrs":inbound, "outbound_upload_cidrs":outbound})
            audited["details"] = details
            self.store.transaction_audited((statement,), audit=audited)
        return self.network_policy()

    def require_source_ip(self, direction: str, source_ip: str):
        self.require_workflow(direction)
        key = "inbound_upload_cidrs" if direction == "inbound" else "outbound_upload_cidrs"
        policy = self.network_policy()
        try: address = ipaddress.ip_address(source_ip)
        except ValueError as exc: raise ServiceError(403, "unrecognized source IP") from exc
        networks = [ipaddress.ip_network(value, strict=False) for value in json.loads(policy[key])]
        if not any(address.version == network.version and address in network for network in networks):
            raise ServiceError(403, f"source IP is not allowed for {direction} upload")

    def set_outbound_policy(self, data: Dict, actor: str, audit=None) -> Dict:
        self.require_workflow("outbound")
        if not self.store.is_global_admin(actor):
            raise ServiceError(403, "platform administrator required")
        allowed = data.get("allowed_classifications", ["GDS", "FPGA_BITFILE", "GENERAL"])
        if not isinstance(allowed, list) or not allowed or not set(allowed).issubset({"GDS", "FPGA_BITFILE", "GENERAL"}):
            raise ServiceError(400, "invalid outbound classifications")
        provider = str(data.get("approval_provider", "local"))
        if provider not in {"local", "wecom"}: raise ServiceError(400, "invalid approval provider")
        if provider == "local" and not self.settings.allow_local_approval:
            raise ServiceError(400, "local outbound approval is disabled by the platform security policy")
        if provider == "wecom" and bool(data.get("enabled", False)):
            errors = self.settings.approval_relay_errors()
            if errors: raise ServiceError(400, "approval relay is not safely configured: " + "; ".join(errors))
        try: approval_hours = int(data.get("approval_timeout_hours", 72)); download_hours = int(data.get("download_ttl_hours", 168))
        except (TypeError, ValueError) as exc: raise ServiceError(400, "invalid policy duration") from exc
        if not 1 <= approval_hours <= 720 or not 1 <= download_hours <= 8760: raise ServiceError(400, "policy duration out of range")
        now = int(time.time())
        statement = ("""INSERT INTO outbound_policy(id,enabled,allowed_classifications,approval_provider,approval_timeout_hours,download_ttl_hours,updated_at,updated_by)
          VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,allowed_classifications=excluded.allowed_classifications,approval_provider=excluded.approval_provider,approval_timeout_hours=excluded.approval_timeout_hours,download_ttl_hours=excluded.download_ttl_hours,updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
          (int(bool(data.get("enabled", False))), json.dumps(allowed), provider, approval_hours, download_hours, now, actor))
        if audit is None: self.store.transaction((statement,))
        else:
            audited = dict(audit); details = dict(audited.get("details") or {})
            details.update({"enabled":bool(data.get("enabled", False)),
                            "allowed_classifications":allowed,
                            "approval_provider":provider,
                            "approval_timeout_hours":approval_hours,
                            "download_ttl_hours":download_hours})
            audited["details"] = details
            self.store.transaction_audited((statement,), audit=audited)
        return self.outbound_policy()

    def outbound_transition(self, transfer_id: str, target: str, **fields):
        self.require_workflow("outbound")
        current = self.get_outbound(transfer_id)
        if target not in OUTBOUND_TRANSITIONS[current["state"]]: raise RuntimeError(f"invalid outbound transition {current['state']} -> {target}")
        assignments = ["state=?", "updated_at=?"] + [f"{key}=?" for key in fields]
        values = [target, int(time.time())] + list(fields.values()) + [transfer_id, current["state"]]
        audit_details = {"from":current["state"], "to":target}
        for key in ("classification", "approval_id", "approval_actor", "approval_comment",
                    "approval_expires_at", "download_expires_at", "scan_detail"):
            if key in fields:
                value = fields[key]
                if key == "scan_detail" and isinstance(value, str):
                    try: value = json.loads(value)
                    except json.JSONDecodeError: value = "invalid stored scan detail"
                audit_details[key] = value
        self.store.execute_audited(
            f"UPDATE outbound_transfers SET {','.join(assignments)} WHERE id=? AND state=?", values,
            error="concurrent outbound state transition rejected",
            audit={"request_id":f"outbound-state-{transfer_id}-{target}", "actor":"system",
                   "action":"outbound.state_changed",
                   "object_id":transfer_id, "outcome":"success", "source_zone":"isolation",
                   "remote_addr":"local", "details":audit_details})

    def get_outbound(self, transfer_id: str) -> Dict:
        self.require_workflow("outbound")
        row = self.store.one("SELECT * FROM outbound_transfers WHERE id=?", (transfer_id,))
        if not row: raise ServiceError(404, "outbound transfer not found")
        return row

    def upload_outbound(self, filename: str, stream: BinaryIO, size: int, actor: str,
                        audit=None) -> Dict:
        self.require_workflow("outbound")
        self._require_active_user(actor)
        if not self._valid_filename(filename): raise ServiceError(400, "invalid filename")
        policy = self.outbound_policy()
        if not policy["enabled"]: raise ServiceError(403, "outbound transfer is disabled by platform policy")
        maximum = int(self.store.get_config("max_upload_bytes", str(self.settings.max_upload_bytes)))
        if size <= 0 or size > maximum: raise ServiceError(413, "invalid or excessive content length")
        self.require_storage_capacity(size)
        transfer_id = str(uuid.uuid4()); target_dir = self.outbound_isolation / transfer_id; target_dir.mkdir(mode=0o700); target = target_dir / "payload"
        digest = hashlib.sha256(); prefix = b""; written = 0
        try:
            with target.open("xb") as output:
                while written < size:
                    block = stream.read(min(1024 * 1024, size - written))
                    if not block: break
                    written += len(block); digest.update(block); prefix += block[:max(0, 8192-len(prefix))]; output.write(block)
            target.chmod(0o600)
            if written != size: raise ServiceError(400, "request body shorter than Content-Length")
            detected = detect_content(prefix); conflict = extension_conflicts(filename, detected); now = int(time.time())
            retention_expires = now + int(self.store.get_config("retention_seconds", str(self.settings.retention_seconds)))
            statement = ("""INSERT INTO outbound_transfers(id,uploader,filename,size,sha256,media_type,type_known,type_conflict,state,storage_path,approval_provider,retention_expires_at,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (transfer_id, actor, filename, size, digest.hexdigest(), detected.media_type,
              int(detected.known), int(conflict), "pending_scan", str(target), policy["approval_provider"], retention_expires, now, now))
            audited = (dict(audit) if audit is not None else {
                "request_id":f"outbound-upload-{transfer_id}", "actor":actor,
                "action":"outbound.upload", "object_id":transfer_id,
                "outcome":"accepted", "source_zone":"red", "remote_addr":"local", "details":{}})
            audited["object_id"] = transfer_id
            details = dict(audited.get("details") or {})
            details.update({"sha256":digest.hexdigest(), "size":size, "media_type":detected.media_type})
            audited["details"] = details
            self.store.transaction_audited((statement,), audit=audited)
        except Exception:
            if not self.store.one("SELECT id FROM outbound_transfers WHERE id=?", (transfer_id,)): shutil.rmtree(target_dir, ignore_errors=True)
            raise
        self.queue.submit(self.scan_outbound, transfer_id)
        return self.get_outbound(transfer_id)

    def scan_outbound(self, transfer_id: str):
        try:
            self.outbound_transition(transfer_id, "scanning")
        except RuntimeError:
            transfer = self.get_outbound(transfer_id)
            self.store.audit(request_id=f"outbound-duplicate-{transfer_id}", actor="system", action="outbound.scan.duplicate_ignored",
              object_id=transfer_id, outcome="ignored", source_zone="isolation",
              remote_addr="local", details={"state": transfer["state"]})
            return
        try:
            transfer = self.get_outbound(transfer_id); path = Path(transfer["storage_path"])
            runtime_errors = self.runtime_acceptance_errors()
            if runtime_errors:
                details = [{"scanner":"runtime-policy", "status":"error",
                            "detail":"production runtime configuration is not accepted"}]
                self.outbound_transition(transfer_id, "quarantined", scan_detail=json.dumps(details, sort_keys=True))
                self.audit_outbound_scan(transfer, "quarantined", details); return
            if not self._full_integrity(transfer, path):
                details = [{"scanner":"integrity","status":"error","detail":"payload changed after upload"}]
                self.outbound_transition(transfer_id, "quarantined", scan_detail=json.dumps(details, sort_keys=True))
                self.audit_outbound_scan(transfer, "quarantined", details); return
            results = [scanner.scan(path) for scanner in self.scanners]
            details = [{"scanner": r.scanner, "status": r.status, "detail": r.detail} for r in results]
            if any(r.status != "clean" for r in results) or transfer["type_conflict"]:
                self.outbound_transition(transfer_id, "quarantined", scan_detail=json.dumps(details, sort_keys=True))
                self.audit_outbound_scan(transfer, "quarantined", details); return
            if not self._full_integrity(transfer, path):
                details.append({"scanner":"post-scan-integrity", "status":"error",
                                "detail":"payload changed while scanners were running"})
                self.outbound_transition(transfer_id, "quarantined",
                                         scan_detail=json.dumps(details, sort_keys=True))
                self.audit_outbound_scan(transfer, "quarantined", details); return
            classification = self.outbound_classifier.classify(path, transfer["media_type"], bool(transfer["type_known"]))
            details.append({"scanner": self.outbound_classifier.name, "status": "clean" if classification.category else "error", "detail": classification.detail})
            policy = self.outbound_policy(); allowed = set(json.loads(policy["allowed_classifications"]))
            if not policy["enabled"] or not classification.category or classification.category not in allowed:
                self.outbound_transition(transfer_id, "quarantined", classification=classification.category, scan_detail=json.dumps(details, sort_keys=True))
                self.audit_outbound_scan(transfer, "quarantined", details); return
            self.outbound_transition(transfer_id, "classified", classification=classification.category, scan_detail=json.dumps(details, sort_keys=True))
            provider = (LocalApprovalProvider() if policy["approval_provider"] == "local"
                        else WeComApprovalProvider(self.settings))
            approval_id = provider.create(self.get_outbound(transfer_id))
            self.outbound_transition(transfer_id, "pending_approval", approval_id=approval_id,
                                     approval_expires_at=int(time.time()) + int(policy["approval_timeout_hours"]) * 3600)
            self.audit_outbound_scan(transfer, "pending_approval", details)
        except Exception as exc:
            try:
                current = self.get_outbound(transfer_id)
                if current["state"] in {"scanning", "classified"}:
                    self.outbound_transition(transfer_id, "quarantined", scan_detail=json.dumps([{"scanner":"pipeline","status":"error","detail":type(exc).__name__}]))
            finally:
                current = self.get_outbound(transfer_id)
                self.store.audit(request_id=f"outbound-scan-{transfer_id}", actor="system", action="outbound.scan.error",
                  object_id=transfer_id, outcome=current["state"], source_zone="isolation", remote_addr="local", details={"error":type(exc).__name__})

    def audit_outbound_scan(self, transfer: Dict, outcome: str, details):
        self.store.audit(request_id=f"outbound-scan-{transfer['id']}", actor="system", action="outbound.scan.complete",
          object_id=transfer["id"], outcome=outcome,
          source_zone="isolation", remote_addr="local", details={"results": details})

    def decide_outbound(self, transfer_id: str, approved: bool, comment: str, actor: str) -> Dict:
        if not (self.store.is_approver(actor) or self.store.is_global_admin(actor)):
            raise ServiceError(403, "platform approver required")
        transfer = self.get_outbound(transfer_id)
        if transfer["approval_provider"] != "local":
            raise ServiceError(403, "enterprise approval transfers cannot be decided locally")
        return self._apply_outbound_decision(transfer, approved, comment, actor)

    def _apply_outbound_decision(self, transfer: Dict, approved: bool,
                                 comment: str, actor: str) -> Dict:
        transfer_id = transfer["id"]
        comment = str(comment)
        if len(comment) > 1000: raise ServiceError(400, "approval comment is too long")
        if transfer["state"] != "pending_approval": raise ServiceError(409, "transfer is not pending approval")
        policy = self.outbound_policy()
        if (not policy["enabled"] or policy["approval_provider"] != transfer["approval_provider"] or
                transfer["classification"] not in set(json.loads(policy["allowed_classifications"]))):
            raise ServiceError(409, "current outbound policy no longer permits this transfer")
        if transfer["approval_expires_at"] <= int(time.time()): self.outbound_transition(transfer_id, "expired"); raise ServiceError(409, "approval request expired")
        if not approved:
            self.outbound_transition(transfer_id, "approval_rejected", approval_actor=actor, approval_comment=comment); return self.get_outbound(transfer_id)
        if not self._full_integrity(transfer, Path(transfer["storage_path"])):
            self.outbound_transition(transfer_id, "expired", approval_actor=actor,
                                     approval_comment="integrity verification failed before approval")
            raise ServiceError(409, "outbound payload integrity verification failed")
        # Persist the approval decision before crossing the filesystem boundary.
        # A crash or move failure therefore leaves an explicit recoverable
        # `approved` state, never a misleading pending approval with a missing file.
        self.outbound_transition(transfer_id, "approved", approval_actor=actor, approval_comment=comment)
        return self.release_approved_outbound(transfer_id)

    def process_approval_callback(self, event: Dict, payload_hash: str) -> Dict:
        self.require_workflow("outbound")
        event_id = str(event.get("event_id", "")).strip()
        approval_id = str(event.get("approval_id", "")).strip()
        decision = str(event.get("status", "")).strip().lower()
        actor = str(event.get("actor", "")).strip()
        comment = str(event.get("comment", ""))[:1000]
        safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        if (not 1 <= len(event_id) <= 128 or any(ch not in safe for ch in event_id) or
                not 1 <= len(approval_id) <= 128 or any(ch not in safe for ch in approval_id) or
                decision not in {"approved", "rejected"} or not 1 <= len(actor) <= 128 or
                any(ch not in safe + "@" for ch in actor)):
            raise ServiceError(400, "invalid normalized approval callback")
        existing = self.store.one("SELECT * FROM approval_callback_events WHERE event_id=?", (event_id,))
        if existing and existing["payload_hash"] != payload_hash:
            raise ServiceError(409, "approval event id was reused with a different payload")
        transfer = self.store.one("SELECT * FROM outbound_transfers WHERE approval_id=?", (approval_id,))
        if not transfer or transfer["approval_provider"] != "wecom":
            raise ServiceError(404, "enterprise approval request not found")
        callback_actor = f"wecom:{actor}:{event_id}"
        if existing and existing["outcome"] == "processed":
            return {"status":"duplicate", "transfer":self.get_outbound(transfer["id"])}
        if not existing:
            try:
                self.store.execute(
                    "INSERT INTO approval_callback_events(event_id,approval_id,payload_hash,decision,actor,received_at,outcome) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (event_id, approval_id, payload_hash, decision, callback_actor, int(time.time()), "processing"),
                )
            except Exception:
                existing = self.store.one("SELECT * FROM approval_callback_events WHERE event_id=?", (event_id,))
                if not existing or existing["payload_hash"] != payload_hash: raise ServiceError(409, "approval event replay conflict")
        try:
            current = self.get_outbound(transfer["id"])
            if current["state"] == "approved" and decision == "approved":
                result = self.release_approved_outbound(current["id"])
            elif ((current["state"] == "released_to_green" and decision == "approved") or
                  (current["state"] == "approval_rejected" and decision == "rejected")):
                if current.get("approval_actor") != callback_actor:
                    raise ServiceError(409, "approval callback conflicts with an existing decision")
                result = current
            else:
                result = self._apply_outbound_decision(current, decision == "approved",
                                                       comment, callback_actor)
            self.store.execute("UPDATE approval_callback_events SET outcome='processed' WHERE event_id=?", (event_id,))
            return {"status":"processed", "transfer":result}
        except Exception as exc:
            self.store.execute("UPDATE approval_callback_events SET outcome=? WHERE event_id=?",
                               ("error:" + type(exc).__name__, event_id))
            raise

    def release_approved_outbound(self, transfer_id: str) -> Dict:
        self.require_runtime_acceptance()
        transfer = self.get_outbound(transfer_id)
        if transfer["state"] == "released_to_green": return transfer
        if transfer["state"] != "approved": raise ServiceError(409, "transfer has no durable approval decision")
        policy = self.outbound_policy()
        if (not policy["enabled"] or policy["approval_provider"] != transfer["approval_provider"] or
                transfer["classification"] not in set(json.loads(policy["allowed_classifications"]))):
            self.outbound_transition(transfer_id, "expired")
            raise ServiceError(409, "current outbound policy no longer permits this transfer")
        target_dir = self.outbound_released / transfer_id; target_dir.mkdir(mode=0o700, exist_ok=True)
        target = target_dir / "payload"; source = Path(transfer["storage_path"])
        try:
            if source.resolve() != target.resolve():
                if target.exists():
                    if source.exists() or not self._full_integrity(transfer, target):
                        raise ServiceError(409, "ambiguous or invalid approved payload recovery state")
                else:
                    os.replace(str(source), str(target))
        except Exception as exc:
            if not target.exists(): shutil.rmtree(target_dir, ignore_errors=True)
            if isinstance(exc, ServiceError): raise
            raise ServiceError(503, "could not move approved payload to green release buffer") from exc
        if source.resolve() != target.resolve():
            self.store.execute("UPDATE outbound_transfers SET storage_path=?,updated_at=? WHERE id=? AND state='approved'",
                               (str(target), int(time.time()), transfer_id))
            shutil.rmtree(source.parent, ignore_errors=True)
        self._seal_payload(target, "outbound_transfers", transfer_id)
        self.outbound_transition(transfer_id, "released_to_green", download_expires_at=int(time.time()) + int(policy["download_ttl_hours"]) * 3600)
        return self.get_outbound(transfer_id)

    def outbound_for_download(self, transfer_id: str, actor: str) -> Dict:
        transfer = self.get_outbound(transfer_id)
        if transfer["uploader"] != actor and not self.store.is_global_admin(actor):
            raise ServiceError(404, "outbound transfer not found")
        if transfer["state"] == "released_to_green" and transfer["download_expires_at"] <= int(time.time()): self.outbound_transition(transfer_id, "expired"); transfer = self.get_outbound(transfer_id)
        if transfer["state"] != "released_to_green": raise ServiceError(409, "outbound transfer is not released to green")
        if not self.outbound_policy()["enabled"]:
            raise ServiceError(409, "outbound downloads are disabled by current platform policy")
        if not self._payload_integrity(transfer):
            self.outbound_transition(transfer_id, "expired")
            raise ServiceError(409, "outbound payload integrity verification failed")
        return transfer

    def rescan_outbound(self, transfer_id: str):
        transfer = self.get_outbound(transfer_id)
        if transfer["state"] != "quarantined":
            raise ServiceError(409, "only quarantined outbound transfers can be rescanned")
        self.outbound_transition(transfer_id, "pending_scan")
        self.queue.submit(self.scan_outbound, transfer_id)

    def expire_outbound(self, transfer_id: str):
        transfer = self.get_outbound(transfer_id)
        if transfer["state"] == "expired": return
        if "expired" not in OUTBOUND_TRANSITIONS[transfer["state"]]:
            raise ServiceError(409, "outbound transfer cannot expire in its current state")
        self.outbound_transition(transfer_id, "expired")

    def rescan(self, object_id: str):
        self.require_workflow("inbound")
        obj = self.get_object(object_id)
        if obj["state"] != "quarantined":
            raise ServiceError(409, "only quarantined objects can be rescanned")
        self.transition(object_id, "pending_scan")
        self.queue.submit(self.scan_object, object_id)

    def expire_object(self, object_id: str):
        self.require_workflow("inbound")
        obj = self.get_object(object_id)
        if obj["state"] == "expired":
            return
        if "expired" not in ALLOWED_TRANSITIONS[obj["state"]]:
            raise ServiceError(409, "object cannot expire while scanning")
        self.transition(object_id, "expired")

    def upload(self, filename: str, stream: BinaryIO, size: int, actor: str,
               audit=None) -> Dict:
        self.require_workflow("inbound")
        self._require_active_user(actor)
        if not self._valid_filename(filename): raise ServiceError(400, "invalid filename")
        max_upload_bytes = int(self.store.get_config("max_upload_bytes", str(self.settings.max_upload_bytes)))
        if size <= 0 or size > max_upload_bytes:
            raise ServiceError(413, "invalid or excessive content length")
        self.require_storage_capacity(size)
        object_id = str(uuid.uuid4())
        target_dir = self.isolation / object_id
        target_dir.mkdir(mode=0o700)
        target = target_dir / "payload"
        digest = hashlib.sha256()
        prefix = b""
        written = 0
        try:
            with target.open("xb") as output:
                while written < size:
                    block = stream.read(min(1024 * 1024, size - written))
                    if not block:
                        break
                    written += len(block)
                    digest.update(block)
                    if len(prefix) < 8192:
                        prefix += block[:8192 - len(prefix)]
                    output.write(block)
            target.chmod(0o600)
            if written != size:
                raise ServiceError(400, "request body shorter than Content-Length")
            detected = detect_content(prefix)
            conflict = extension_conflicts(filename, detected)
            now = int(time.time())
            statement = (
                "INSERT INTO objects(id,uploader,filename,size,sha256,media_type,type_known,type_conflict,state,storage_path,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (object_id, actor, filename, written, digest.hexdigest(), detected.media_type,
                 int(detected.known), int(conflict), "pending_scan", str(target), now, now,
                 now + int(self.store.get_config("retention_seconds", str(self.settings.retention_seconds)))),
            )
            audited = (dict(audit) if audit is not None else {
                "request_id":f"object-upload-{object_id}", "actor":actor,
                "action":"object.upload", "object_id":object_id,
                "outcome":"accepted", "source_zone":"green", "remote_addr":"local", "details":{}})
            audited["object_id"] = object_id
            details = dict(audited.get("details") or {})
            details.update({"sha256":digest.hexdigest(), "size":written,
                            "media_type":detected.media_type, "type_conflict":bool(conflict)})
            audited["details"] = details
            self.store.transaction_audited((statement,), audit=audited)
        except Exception:
            if not self.store.one("SELECT id FROM objects WHERE id=?", (object_id,)):
                shutil.rmtree(target_dir, ignore_errors=True)
            raise
        self.queue.submit(self.scan_object, object_id)
        return self.get_object(object_id)

    def transition(self, object_id: str, target: str, scan_detail=None):
        self.require_workflow("inbound")
        current = self.get_object(object_id)
        if target not in ALLOWED_TRANSITIONS[current["state"]]:
            raise RuntimeError(f"invalid state transition {current['state']} -> {target}")
        detail = current["scan_detail"] if scan_detail is None else json.dumps(scan_detail, sort_keys=True)
        audit_details = {"from":current["state"], "to":target}
        if scan_detail is not None: audit_details["scan_detail"] = scan_detail
        self.store.execute_audited(
            "UPDATE objects SET state=?,updated_at=?,scan_detail=? WHERE id=? AND state=?",
            (target, int(time.time()), detail, object_id, current["state"]),
            error="concurrent object state transition rejected",
            audit={"request_id":f"state-{object_id}-{target}", "actor":"system",
                   "action":"object.state_changed",
                   "object_id":object_id, "outcome":"success", "source_zone":"isolation",
                   "remote_addr":"local", "details":audit_details})

    def scan_object(self, object_id: str):
        try:
            self.transition(object_id, "scanning")
        except RuntimeError:
            obj = self.get_object(object_id)
            self.store.audit(request_id=f"scan-duplicate-{object_id}", actor="system", action="scan.duplicate_ignored",
                             object_id=object_id, outcome="ignored",
                             source_zone="isolation", remote_addr="local", details={"state": obj["state"]})
            return
        try:
            obj = self.get_object(object_id)
            path = Path(obj["storage_path"])
            runtime_errors = self.runtime_acceptance_errors()
            if runtime_errors:
                details = [{"scanner":"runtime-policy", "status":"error",
                            "detail":"production runtime configuration is not accepted"}]
                self.transition(object_id, "quarantined", details)
                self.store.audit(request_id=f"scan-{object_id}", actor="system", action="scan.complete",
                                 object_id=object_id, outcome="quarantined",
                                 source_zone="isolation", remote_addr="local", details={"results":details})
                return
            if not self._full_integrity(obj, path):
                details = [{"scanner":"integrity","status":"error","detail":"payload changed after upload"}]
                self.transition(object_id, "quarantined", details)
                self.store.audit(request_id=f"scan-{object_id}", actor="system", action="scan.complete",
                                 object_id=object_id, outcome="quarantined",
                                 source_zone="isolation", remote_addr="local", details={"results":details})
                return
            results = [scanner.scan(path) for scanner in self.scanners]
            details = [{"scanner": r.scanner, "status": r.status, "detail": r.detail} for r in results]
            if any(r.status == "infected" for r in results):
                target = "rejected"
            elif any(r.status != "clean" for r in results) or not obj["type_known"] or obj["type_conflict"]:
                target = "quarantined"
            elif not self._full_integrity(obj, path):
                details.append({"scanner":"post-scan-integrity", "status":"error",
                                "detail":"payload changed while scanners were running"})
                target = "quarantined"
            else:
                released_dir = self.released / object_id
                released_dir.mkdir(mode=0o700)
                released_path = released_dir / "payload"
                os.replace(str(path), str(released_path))
                shutil.rmtree(path.parent, ignore_errors=True)
                self.store.execute("UPDATE objects SET storage_path=? WHERE id=?", (str(released_path), object_id))
                self._seal_payload(released_path, "objects", object_id)
                target = "released"
            self.transition(object_id, target, details)
            self.store.audit(request_id=f"scan-{object_id}", actor="system", action="scan.complete",
                             object_id=object_id, outcome=target,
                             source_zone="isolation", remote_addr="local", details={"results": details})
        except Exception as exc:
            # Any pipeline exception is fail-closed. A scanning object remains inaccessible.
            try:
                current = self.get_object(object_id)
                if current["state"] == "scanning":
                    self.transition(object_id, "quarantined", [{"scanner": "pipeline", "status": "error", "detail": type(exc).__name__}])
            finally:
                obj = self.get_object(object_id)
                self.store.audit(request_id=f"scan-{object_id}", actor="system", action="scan.error",
                                 object_id=object_id, outcome=obj["state"],
                                 source_zone="isolation", remote_addr="local", details={"error": type(exc).__name__})

    def get_object(self, object_id: str) -> Dict:
        self.require_workflow("inbound")
        obj = self.store.one("SELECT * FROM objects WHERE id=?", (object_id,))
        if not obj:
            raise ServiceError(404, "object not found")
        return obj

    def object_for_download(self, object_id: str, actor: str) -> Dict:
        self.require_workflow("inbound")
        obj = self.get_object(object_id)
        if obj["uploader"] != actor and not self.store.is_global_admin(actor):
            raise ServiceError(404, "object not found")
        if obj["expires_at"] <= int(time.time()) and obj["state"] != "expired":
            self.transition(object_id, "expired")
            obj = self.get_object(object_id)
        if obj["state"] != "released":
            raise ServiceError(409, "object is not released")
        if not self._payload_integrity(obj):
            self.transition(object_id, "expired")
            raise ServiceError(409, "payload integrity verification failed")
        return obj

    def _payload_integrity(self, record: Dict) -> bool:
        storage_path = record.get("storage_path", "")
        if not storage_path: return False
        root = self.settings.data_dir.resolve(); path = Path(storage_path).resolve()
        try: inside = os.path.commonpath((str(root), str(path))) == str(root)
        except ValueError: inside = False
        if not inside or not path.is_file(): return False
        stat = path.stat()
        if stat.st_size != record["size"]: return False
        if (record.get("integrity_mtime_ns") == stat.st_mtime_ns and
                record.get("integrity_ctime_ns") == stat.st_ctime_ns):
            return True
        valid = self._full_integrity(record, path)
        if valid:
            table = "outbound_transfers" if "classification" in record else "objects"
            self._seal_payload(path, table, record["id"])
        return valid

    @staticmethod
    def _full_integrity(record: Dict, path: Path) -> bool:
        digest = hashlib.sha256(); size = 0
        try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError: return False
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode): return False
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block: break
                size += len(block); digest.update(block)
            after = os.fstat(descriptor)
            stable = ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                       before.st_ctime_ns) ==
                      (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                       after.st_ctime_ns))
            return stable and size == record["size"] and digest.hexdigest() == record["sha256"]
        finally:
            os.close(descriptor)

    def harden_existing_storage_permissions(self) -> Dict[str, int]:
        stats = {"sealed":0, "isolated":0, "invalid":0, "stale_parts_removed":0}
        released_roots = tuple(root.resolve() for root in
                               (([self.released] if self.workflow_enabled("inbound") else []) +
                                ([self.outbound_released] if self.workflow_enabled("outbound") else [])))
        data_root = self.settings.data_dir.resolve()
        tables = ((["objects"] if self.workflow_enabled("inbound") else []) +
                  (["outbound_transfers"] if self.workflow_enabled("outbound") else []))
        for table in tables:
            for record in self.store.all(f"SELECT * FROM {table} WHERE storage_path!=''"):
                path = Path(record["storage_path"]).resolve()
                try: inside = os.path.commonpath((str(data_root), str(path))) == str(data_root)
                except ValueError: inside = False
                if not inside or not path.is_file() or path.is_symlink():
                    stats["invalid"] += 1; continue
                released = any(os.path.commonpath((str(root), str(path))) == str(root) for root in released_roots)
                expected_mode = 0o400 if released else 0o600
                if self.settings.environment == "production" and path.stat().st_mode & 0o777 != expected_mode:
                    stats["invalid"] += 1; continue
                if not self._full_integrity(record, path):
                    stats["invalid"] += 1; continue
                if released:
                    stat = path.stat()
                    already_sealed = (
                        stat.st_mode & 0o777 == 0o400 and stat.st_size == record["size"] and
                        record.get("integrity_mtime_ns") == stat.st_mtime_ns and
                        record.get("integrity_ctime_ns") == stat.st_ctime_ns
                    )
                    if already_sealed:
                        stats["sealed"] += 1; continue
                    self._seal_payload(path, table, record["id"]); stats["sealed"] += 1
                else:
                    path.chmod(0o600); stats["isolated"] += 1
        stats["stale_parts_removed"] = self.store.execute(
            "DELETE FROM upload_parts WHERE upload_id IN "
            "(SELECT id FROM upload_sessions WHERE state IN ('completed','cancelled','expired'))"
        )
        for part in self.store.all(
            "SELECT p.* FROM upload_parts p JOIN upload_sessions s ON s.id=p.upload_id "
            "WHERE s.state IN ('uploading','completing')"
        ):
            path = Path(part["storage_path"]).resolve()
            try: inside = os.path.commonpath((str(data_root), str(path))) == str(data_root)
            except ValueError: inside = False
            if not inside or not path.is_file() or path.is_symlink() or not self._full_integrity(part, path):
                stats["invalid"] += 1; continue
            if self.settings.environment == "production" and path.stat().st_mode & 0o777 != 0o600:
                stats["invalid"] += 1; continue
            path.chmod(0o600); stats["isolated"] += 1
        return stats

    def _seal_payload(self, path: Path, table: str, object_id: str):
        if table not in {"objects", "outbound_transfers"}: raise ValueError("invalid payload table")
        path.chmod(0o400)
        stat = path.stat()
        self.store.execute(f"UPDATE {table} SET integrity_mtime_ns=?,integrity_ctime_ns=? WHERE id=?",
                           (stat.st_mtime_ns, stat.st_ctime_ns, object_id))

    def expire_due(self) -> int:
        if not self.workflow_enabled("inbound"): return 0
        now = int(time.time())
        due = self.store.all("SELECT id,state FROM objects WHERE expires_at<=? AND state IN ('pending_scan','quarantined','released','rejected')", (now,))
        for obj in due:
            self.transition(obj["id"], "expired")
        return len(due)

    def run_maintenance(self) -> Dict[str, int]:
        now = int(time.time())
        stats = {"inbound_expired": self.expire_due(), "outbound_expired": 0,
                 "upload_sessions_expired": 0, "auth_sessions_purged": 0, "payloads_purged": 0,
                 "service_tokens_expired": 0, "approved_release_retried": 0,
                 "approved_release_errors": 0, "integration_nonces_purged": 0,
                 "scan_jobs_purged": 0}
        stats["auth_sessions_purged"] = self.store.execute_audited_counted(
            "DELETE FROM auth_sessions WHERE revoked=1 OR expires_at<=?", (now,),
            audit_factory=lambda count: {
                "request_id":f"maintenance-session-purge-{now}", "actor":"system",
                "action":"session.records_purged", "object_id":None,
                "outcome":"success", "source_zone":"maintenance", "remote_addr":"local",
                "details":{"purged":count, "criteria":"revoked_or_expired"}})
        stats["service_tokens_expired"] = self.store.execute_audited_counted(
            "UPDATE service_tokens SET revoked=1 WHERE revoked=0 AND expires_at<=?", (now,),
            audit_factory=lambda count: {
                "request_id":f"maintenance-service-token-expiry-{now}", "actor":"system",
                "action":"service_token.expired", "object_id":None,
                "outcome":"success", "source_zone":"maintenance", "remote_addr":"local",
                "details":{"revoked":count, "criteria":"expires_at"}})
        stats["integration_nonces_purged"] = self.store.execute(
            "DELETE FROM integration_nonces WHERE expires_at<=?", (now,)
        )
        stale_uploads = self.store.all(
            "SELECT * FROM upload_sessions WHERE state IN ('uploading','completing') AND expires_at<=?", (now,)
        )
        for upload in stale_uploads:
            with self._upload_lock(upload["id"]):
                try:
                    self.store.execute_audited(
                        "UPDATE upload_sessions SET state='expired',updated_at=? "
                        "WHERE id=? AND state IN ('uploading','completing')",
                        (now, upload["id"]), error="upload session changed during expiry",
                        audit={"request_id":f"upload-expired-{upload['id']}", "actor":"system",
                               "action":"upload.session.expired",
                               "object_id":upload.get("object_id"), "outcome":"success",
                               "source_zone":"maintenance", "remote_addr":"local",
                               "details":{"upload_id":upload["id"],
                                          "direction":upload["direction"]}})
                    shutil.rmtree(self.upload_staging / upload["id"], ignore_errors=True)
                    self.store.execute("DELETE FROM upload_parts WHERE upload_id=?", (upload["id"],))
                    self._forget_upload_lock(upload["id"])
                    stats["upload_sessions_expired"] += 1
                except RuntimeError:
                    continue
        scan_cutoff = now - max(60, self.settings.scan_timeout_seconds)
        if self.workflow_enabled("inbound"):
            for obj in self.store.all("SELECT id FROM objects WHERE state='scanning' AND updated_at<=?", (scan_cutoff,)):
                self.transition(obj["id"], "quarantined", [{"scanner":"maintenance","status":"error","detail":"scan timeout"}])
        outbound_rows = self.store.all(
                "SELECT id,state FROM outbound_transfers WHERE state IN ('scanning','classified') AND updated_at<=?",
                (scan_cutoff,)) if self.workflow_enabled("outbound") else []
        for transfer in outbound_rows:
            detail = ("scan timeout" if transfer["state"] == "scanning" else
                      "approval submission interrupted after classification")
            self.outbound_transition(
                transfer["id"], "quarantined",
                scan_detail=json.dumps([{"scanner":"maintenance", "status":"error", "detail":detail}]))
        approved_rows = (self.store.all("SELECT id FROM outbound_transfers WHERE state='approved'")
                         if self.workflow_enabled("outbound") else [])
        for transfer in approved_rows:
            try:
                self.release_approved_outbound(transfer["id"]); stats["approved_release_retried"] += 1
            except ServiceError:
                stats["approved_release_errors"] += 1
        outbound_due = self.store.all("""SELECT id FROM outbound_transfers WHERE
          (state='pending_approval' AND approval_expires_at IS NOT NULL AND approval_expires_at<=?) OR
          (state='released_to_green' AND download_expires_at IS NOT NULL AND download_expires_at<=?) OR
          (state IN ('pending_scan','quarantined','approved','approval_rejected') AND retention_expires_at IS NOT NULL AND retention_expires_at<=?)""",
          (now, now, now)) if self.workflow_enabled("outbound") else []
        for transfer in outbound_due:
            self.expire_outbound(transfer["id"]); stats["outbound_expired"] += 1
        cutoff = now - max(0, self.settings.purge_grace_seconds)
        purge_tables = (([("objects", "object.payload_purged")] if self.workflow_enabled("inbound") else []) +
                        ([("outbound_transfers", "outbound.payload_purged")] if self.workflow_enabled("outbound") else []))
        for table, action in purge_tables:
            rows = self.store.all(f"SELECT id,storage_path FROM {table} WHERE state='expired' AND updated_at<=? AND storage_path!=''", (cutoff,))
            for row in rows:
                self._purge_payload(row["storage_path"])
                self.store.execute_audited(
                    f"UPDATE {table} SET storage_path='' WHERE id=?", (row["id"],),
                    error="expired payload record disappeared during purge",
                    audit={"request_id":f"purge-{row['id']}", "actor":"system", "action":action,
                           "object_id":row["id"],
                           "outcome":"success", "source_zone":"maintenance",
                           "remote_addr":"local", "details":{}})
                stats["payloads_purged"] += 1
        if hasattr(self.queue, "purge_completed"):
            stats["scan_jobs_purged"] = self.queue.purge_completed(now - 7 * 24 * 3600)
        self.last_maintenance_at = now; self.last_maintenance_error = ""
        return stats

    def fail_scan_job(self, kind: str, object_id: str, error: str):
        """Fail closed after the durable queue exhausts all delivery attempts."""
        detail = [{"scanner":"queue","status":"error","detail":f"job failed after retries: {error}"}]
        if kind == "scan_object":
            current = self.get_object(object_id)
            if current["state"] == "pending_scan": self.transition(object_id, "scanning")
            current = self.get_object(object_id)
            if current["state"] == "scanning": self.transition(object_id, "quarantined", detail)
        elif kind == "scan_outbound":
            current = self.get_outbound(object_id)
            if current["state"] == "pending_scan": self.outbound_transition(object_id, "scanning")
            current = self.get_outbound(object_id)
            if current["state"] in {"scanning", "classified"}:
                self.outbound_transition(object_id, "quarantined", scan_detail=json.dumps(detail, sort_keys=True))

    def recover_interrupted_jobs(self) -> Dict[str, int]:
        stats = {"inbound_requeued":0, "outbound_requeued":0, "interrupted_quarantined":0,
                 "upload_completions_recovered":0, "upload_completions_reset":0,
                 "terminal_upload_staging_cleaned":0}
        for session in self.store.all("SELECT * FROM upload_sessions WHERE state='completing'"):
            record = self._registered_upload_record(session)
            if record:
                self._finalize_upload_session(session, record["id"])
                stats["upload_completions_recovered"] += 1
                continue
            object_id = session.get("object_id")
            if object_id:
                target_root = (self.isolation if session["direction"] == "inbound" else
                               self.outbound_isolation)
                shutil.rmtree(target_root / object_id, ignore_errors=True)
            assembled = self.upload_staging / session["id"] / "assembled.tmp"
            assembled.unlink(missing_ok=True)
            self.store.execute_audited(
                "UPDATE upload_sessions SET state='uploading',updated_at=? "
                "WHERE id=? AND state='completing'", (int(time.time()), session["id"]),
                error="interrupted upload completion changed during recovery",
                audit={"request_id":f"upload-reset-{session['id']}", "actor":"system",
                       "action":"upload.session.completion_reset",
                       "object_id":object_id, "outcome":"quarantined", "source_zone":"startup",
                       "remote_addr":"local", "details":{"upload_id":session["id"],
                       "direction":session["direction"], "reason":"object registration incomplete"}})
            stats["upload_completions_reset"] += 1
        for session in self.store.all(
                "SELECT id FROM upload_sessions WHERE state IN ('completed','cancelled','expired')"):
            staging = self.upload_staging / session["id"]
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
                stats["terminal_upload_staging_cleaned"] += 1
            self.store.execute("DELETE FROM upload_parts WHERE upload_id=?", (session["id"],))
        inbound_scanning = (self.store.all("SELECT id FROM objects WHERE state='scanning'")
                            if self.workflow_enabled("inbound") else [])
        for obj in inbound_scanning:
            self.transition(obj["id"], "quarantined", [{"scanner":"startup","status":"error","detail":"scan interrupted by service restart"}])
            stats["interrupted_quarantined"] += 1
        outbound_scanning = (self.store.all(
                "SELECT id,state FROM outbound_transfers WHERE state IN ('scanning','classified')")
                if self.workflow_enabled("outbound") else [])
        for transfer in outbound_scanning:
            detail = ("scan interrupted by service restart" if transfer["state"] == "scanning" else
                      "approval submission interrupted after classification")
            self.outbound_transition(
                transfer["id"], "quarantined",
                scan_detail=json.dumps([{"scanner":"startup", "status":"error", "detail":detail}]))
            stats["interrupted_quarantined"] += 1
        inbound_pending = (self.store.all("SELECT id FROM objects WHERE state='pending_scan'")
                           if self.workflow_enabled("inbound") else [])
        for obj in inbound_pending:
            self.queue.submit(self.scan_object, obj["id"]); stats["inbound_requeued"] += 1
        outbound_pending = (self.store.all("SELECT id FROM outbound_transfers WHERE state='pending_scan'")
                            if self.workflow_enabled("outbound") else [])
        for transfer in outbound_pending:
            self.queue.submit(self.scan_outbound, transfer["id"]); stats["outbound_requeued"] += 1
        return stats

    def _purge_payload(self, storage_path: str):
        if not storage_path: return
        root = self.settings.data_dir.resolve(); path = Path(storage_path).resolve()
        try: inside = os.path.commonpath((str(root), str(path))) == str(root)
        except ValueError: inside = False
        if not inside:
            raise RuntimeError("refusing to purge payload outside SFSS data directory")
        if path.is_file(): path.unlink()
        parent = path.parent
        if parent != root and parent.exists(): shutil.rmtree(parent)
