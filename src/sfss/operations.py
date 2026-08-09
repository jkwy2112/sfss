"""Offline integrity verification and backup/restore operations for SFSS data."""
import argparse
from dataclasses import replace
import fcntl
import hashlib
import hmac
import io
import json
import os
import platform
import re
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import time
import importlib.util
import importlib.metadata
import socket
import ssl
import stat
from urllib.parse import urlparse

from .config import Settings
from .db import Store
from .scanners import build_scanners
from . import __version__


class OperationError(RuntimeError):
    pass


def acquire_runtime_lock(data_dir: Path):
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700); data_dir.chmod(0o700)
    path = data_dir / "runtime.lock"
    handle = path.open("a+b"); path.chmod(0o600)
    try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close(); raise OperationError("SFSS data directory is in use; stop the service first") from exc
    return handle


def _sha256(path: Path):
    digest = hashlib.sha256(); size = 0
    try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise OperationError(f"unsafe or unavailable file while hashing: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OperationError(f"non-regular file while hashing: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block: break
            size += len(block); digest.update(block)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise OperationError(f"file changed while hashing: {path}")
        return size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _release_file(path: Path):
    """Hash one artifact without following links and detect concurrent mutation."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OperationError(f"release artifact is not a regular file: {path}")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block: break
            digest.update(block)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise OperationError(f"release artifact changed while hashing: {path}")
        return before.st_size, stat.S_IMODE(before.st_mode), digest.hexdigest()
    finally:
        os.close(fd)


def release_manifest(source_root: Path, output: Path):
    """Create a canonical hash inventory for an already sealed build directory."""
    root = source_root.resolve(); destination = output.resolve()
    if not root.is_dir(): raise OperationError("release artifact root does not exist")
    if _inside(root, destination):
        raise OperationError("release manifest output must be outside the artifact root")
    files = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise OperationError(f"release artifact contains a symbolic link: {relative}")
        if stat.S_ISDIR(metadata.st_mode): continue
        if not stat.S_ISREG(metadata.st_mode):
            raise OperationError(f"release artifact contains a special file: {relative}")
        size, mode, digest = _release_file(path)
        files.append({"path":relative, "size":size, "mode":f"{mode:04o}", "sha256":digest})
    if not files: raise OperationError("release artifact root contains no files")
    document = {"format":1, "hash":"sha256", "files":files}
    payload = (json.dumps(document, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    except Exception:
        destination.unlink(missing_ok=True); raise
    return {"status":"ok", "output":str(destination), "files":len(files),
            "sha256":hashlib.sha256(payload).hexdigest()}


def _inside(root: Path, path: Path) -> bool:
    try: return os.path.commonpath((str(root), str(path))) == str(root)
    except ValueError: return False


def initialize_data(data_dir: Path):
    root = data_dir.resolve(); database = root / "sfss.db"
    if database.exists(): raise OperationError("SFSS data directory is already initialized")
    lock = acquire_runtime_lock(root)
    try:
        store = Store(database)
        return {"status":"ok", "data_dir":str(root), "schema":store.schema_version()}
    finally:
        lock.close()


def config_fingerprint(data_dir: Path, settings: Settings):
    root = data_dir.resolve()
    lock = acquire_runtime_lock(root)
    try:
        store = Store(root / "sfss.db", read_only=True)
        digest = settings.configuration_fingerprint(
            store.all("SELECT key,value FROM system_config ORDER BY key"))
        return {"status":"ok", "sha256":digest, "release_id":settings.release_id,
                "python":platform.python_version()}
    finally:
        lock.close()


def verify_data(data_dir: Path):
    root = data_dir.resolve()
    if not root.is_dir(): raise OperationError("SFSS data directory does not exist")
    if root.stat().st_mode & 0o077: raise OperationError("SFSS data directory permissions are broader than 0700")
    if not (root / "sfss.db").is_file(): raise OperationError("SFSS database does not exist")
    for database_file in root.glob("sfss.db*"):
        if database_file.is_file() and database_file.stat().st_mode & 0o077:
            raise OperationError(f"SFSS database file permissions are broader than 0600: {database_file.name}")
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise OperationError(f"unsupported filesystem entry in SFSS data: {path}")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise OperationError(f"SFSS data entry permissions grant group or other access: {path}")
    store = Store(root / "sfss.db", read_only=True)
    audit = store.verify_audit_chain(); payload_count = 0; payload_bytes = 0
    for table in ("objects", "outbound_transfers"):
        for record in store.all(f"SELECT id,size,sha256,storage_path FROM {table} WHERE storage_path!=''"):
            path = Path(record["storage_path"]).resolve()
            if not _inside(root, path) or not path.is_file() or path.is_symlink():
                raise OperationError(f"invalid or missing payload path for {table}:{record['id']}")
            mode = path.stat().st_mode & 0o777
            if mode not in {0o400, 0o600}: raise OperationError(f"unsafe payload mode for {table}:{record['id']}")
            size, digest = _sha256(path)
            if size != record["size"] or digest != record["sha256"]:
                raise OperationError(f"payload integrity mismatch for {table}:{record['id']}")
            payload_count += 1; payload_bytes += size
    part_count = 0
    stale_parts = store.one(
        "SELECT COUNT(*) AS value FROM upload_parts p JOIN upload_sessions s ON s.id=p.upload_id "
        "WHERE s.state NOT IN ('uploading','completing')"
    )["value"]
    if stale_parts: raise OperationError("terminated upload sessions retain stale part metadata; start SFSS once to migrate")
    for part in store.all(
        "SELECT p.upload_id,p.part_number,p.size,p.sha256,p.storage_path FROM upload_parts p "
        "JOIN upload_sessions s ON s.id=p.upload_id WHERE s.state IN ('uploading','completing')"
    ):
        path = Path(part["storage_path"]).resolve()
        if not _inside(root, path) or not path.is_file() or path.is_symlink():
            raise OperationError(f"invalid or missing upload part {part['upload_id']}:{part['part_number']}")
        if path.stat().st_mode & 0o777 != 0o600:
            raise OperationError(f"unsafe upload part mode {part['upload_id']}:{part['part_number']}")
        size, digest = _sha256(path)
        if size != part["size"] or digest != part["sha256"]:
            raise OperationError(f"upload part integrity mismatch {part['upload_id']}:{part['part_number']}")
        part_count += 1
    return {"status":"ok", "audit":audit, "payloads":payload_count,
            "payload_bytes":payload_bytes, "upload_parts":part_count}


def backup(data_dir: Path, output: Path):
    root = data_dir.resolve(); destination = output.resolve()
    if _inside(root, destination): raise OperationError("backup output must be outside the SFSS data directory")
    lock = acquire_runtime_lock(root)
    try:
        if (root / "backup-manifest.json").exists():
            raise OperationError("reserved backup manifest path already exists in SFSS data")
        verification = verify_data(root)
        # Checkpoint without invoking schema initialization/migration. The
        # service is exclusively locked and the current schema was verified.
        import sqlite3
        with sqlite3.connect(str(root / "sfss.db"), timeout=15) as db:
            result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if result and result[0] != 0: raise OperationError("database WAL checkpoint is busy")
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w") as archive:
                archive.add(root, arcname="sfss-data", recursive=True)
                manifest = json.dumps({"format":1, "original_data_dir":str(root),
                                       "audit_head":verification["audit"]["head"]},
                                      sort_keys=True).encode("utf-8")
                info = tarfile.TarInfo("sfss-data/backup-manifest.json")
                info.size = len(manifest); info.mode = 0o600; info.mtime = int(time.time())
                archive.addfile(info, io.BytesIO(manifest))
        except Exception:
            destination.unlink(missing_ok=True); raise
        size, digest = _sha256(destination)
        return {"status":"ok", "archive":str(destination), "size":size, "sha256":digest,
                "verified":verification}
    finally:
        lock.close()


def export_audit(data_dir: Path, output: Path):
    root = data_dir.resolve(); destination = output.resolve()
    if _inside(root, destination):
        raise OperationError("audit export output must be outside the SFSS data directory")
    lock = acquire_runtime_lock(root)
    try:
        store = Store(root / "sfss.db", read_only=True); verified = store.verify_audit_chain()
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        digest = hashlib.sha256(); count = 0
        try:
            with os.fdopen(fd, "wb") as stream, store.connect() as db:
                rows = db.execute(
                    "SELECT e.*,c.prev_hash,c.event_hash FROM audit_events e "
                    "JOIN audit_chain c ON c.event_id=e.id ORDER BY e.id"
                )
                for raw in rows:
                    record = dict(raw); previous = record.pop("prev_hash"); event_hash = record.pop("event_hash")
                    line = (json.dumps({"format":1, "event":record, "prev_hash":previous,
                                        "event_hash":event_hash}, ensure_ascii=False,
                                       sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                    stream.write(line); digest.update(line); count += 1
                stream.flush(); os.fsync(stream.fileno())
        except Exception:
            destination.unlink(missing_ok=True); raise
        if count != verified["events"]:
            destination.unlink(missing_ok=True)
            raise OperationError("audit export count changed during offline export")
        return {"status":"ok", "output":str(destination), "events":count,
                "audit_head":verified["head"], "sha256":digest.hexdigest()}
    finally:
        lock.close()


def verify_audit_export(source: Path, expected_sha256: str = "",
                        expected_head: str = "", expected_events=None):
    """Verify an exported JSONL chain without trusting or opening the SFSS DB."""
    path = source.resolve(strict=False)
    try:
        link_metadata = os.lstat(source)
    except FileNotFoundError as exc:
        raise OperationError("audit export does not exist") from exc
    if stat.S_ISLNK(link_metadata.st_mode):
        raise OperationError("audit export must not be a symbolic link")
    if expected_sha256 and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise OperationError("expected audit export SHA-256 must be 64 lowercase hexadecimal characters")
    if expected_head and not re.fullmatch(r"[0-9a-f]{64}", expected_head):
        raise OperationError("expected audit chain head must be 64 lowercase hexadecimal characters")
    if expected_events is not None and expected_events < 0:
        raise OperationError("expected audit event count cannot be negative")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try: descriptor = os.open(str(source), flags)
    except OSError as exc: raise OperationError("could not safely open audit export") from exc
    digest = hashlib.sha256(); head = ""; count = 0; previous_id = 0
    required_event_fields = {"id", "timestamp", "request_id", "actor", "action", "project_id",
                             "object_id", "outcome", "source_zone", "remote_addr", "details"}
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OperationError("audit export must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while True:
                line = stream.readline(2 * 1024 * 1024 + 1)
                if not line: break
                if len(line) > 2 * 1024 * 1024:
                    raise OperationError("audit export contains an excessive line")
                if not line.endswith(b"\n"):
                    raise OperationError("audit export contains a truncated line")
                digest.update(line)
                try:
                    document = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise OperationError("audit export contains invalid JSONL") from exc
                if (not isinstance(document, dict) or set(document) != {"format", "event", "prev_hash", "event_hash"}
                        or document.get("format") != 1 or not isinstance(document.get("event"), dict)):
                    raise OperationError("audit export record format is invalid")
                event = document["event"]
                if set(event) != required_event_fields:
                    raise OperationError("audit export event fields are invalid")
                event_id = event.get("id")
                if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id != previous_id + 1:
                    raise OperationError("audit export event sequence is invalid")
                if (not isinstance(event.get("timestamp"), int) or isinstance(event.get("timestamp"), bool) or
                        event["timestamp"] < 0 or
                        any(not isinstance(event.get(name), str) for name in
                            ("request_id", "actor", "action", "outcome", "source_zone", "remote_addr", "details")) or
                        any(event.get(name) is not None and not isinstance(event.get(name), str)
                            for name in ("project_id", "object_id"))):
                    raise OperationError("audit export event value types are invalid")
                try: detail_value = json.loads(event["details"])
                except json.JSONDecodeError as exc:
                    raise OperationError("audit export event details are not valid JSON") from exc
                if not isinstance(detail_value, dict):
                    raise OperationError("audit export event details must be a JSON object")
                stored_previous = document.get("prev_hash"); stored_hash = document.get("event_hash")
                if stored_previous != head or not isinstance(stored_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", stored_hash):
                    raise OperationError("audit export chain linkage is invalid")
                calculated = Store._audit_digest(event, head)
                if not hmac.compare_digest(stored_hash, calculated):
                    raise OperationError(f"audit export chain verification failed at event {event_id}")
                head = stored_hash; previous_id = event_id; count += 1
            after = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise OperationError("audit export changed while it was being verified")
    finally:
        if descriptor >= 0: os.close(descriptor)
    actual_sha256 = digest.hexdigest()
    if expected_sha256 and not hmac.compare_digest(actual_sha256, expected_sha256):
        raise OperationError("audit export SHA-256 does not match the trusted expected value")
    if expected_head and not hmac.compare_digest(head, expected_head):
        raise OperationError("audit chain head does not match the trusted expected value")
    if expected_events is not None and count != expected_events:
        raise OperationError("audit event count does not match the trusted expected value")
    return {"status":"ok", "input":str(path), "events":count,
            "audit_head":head, "sha256":actual_sha256}


def _ldap_dependency(settings: Settings):
    if settings.auth_backend != "ldap":
        return {"status":"not_required"}
    if importlib.util.find_spec("ldap3") is None:
        return {"status":"error", "detail":"ldap3 package is unavailable"}
    try:
        versions = {name:importlib.metadata.version(name) for name in ("ldap3", "pyasn1")}
    except importlib.metadata.PackageNotFoundError as exc:
        return {"status":"error", "detail":f"LDAP dependency metadata is unavailable: {exc.name}"}
    parsed = urlparse(settings.ldap_uri)
    if parsed.scheme != "ldaps" or not parsed.hostname:
        return {"status":"error", "detail":"LDAPS endpoint is invalid"}
    try:
        context = ssl.create_default_context(cafile=settings.ldap_ca_file)
        with socket.create_connection((parsed.hostname, parsed.port or 636), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=parsed.hostname) as tls:
                certificate = tls.getpeercert()
        return {"status":"ok", "endpoint":f"{parsed.hostname}:{parsed.port or 636}", "versions":versions,
                "certificate_present":bool(certificate)}
    except Exception as exc:
        return {"status":"error", "detail":f"LDAPS TLS check failed: {type(exc).__name__}"}


def preflight(settings: Settings, require_production: bool = True):
    checks = {}; failures = []

    def record(name, value):
        checks[name] = value
        if value.get("status") == "error": failures.append(name)

    try:
        settings.validate()
        if require_production and settings.environment != "production":
            raise ValueError("strict preflight requires SFSS_ENVIRONMENT=production")
        record("configuration", {"status":"ok", "environment":settings.environment})
    except Exception as exc:
        record("configuration", {"status":"error", "detail":str(exc)})
    record("runtime", {"status":"ok", "sfss_version":__version__,
                       "release_id":settings.release_id, "python":platform.python_version(),
                       "implementation":platform.python_implementation(),
                       "platform":platform.platform()})

    root = settings.data_dir.resolve()
    if not root.is_dir() or not (root / "sfss.db").is_file():
        record("data", {"status":"error", "detail":"initialized SFSS data directory is unavailable"})
        return {"status":"degraded", "production_candidate":False, "checks":checks,
                "failed_checks":failures}

    lock = acquire_runtime_lock(root)
    try:
        try:
            verified = verify_data(root)
            record("data", {"status":"ok", **verified})
        except Exception as exc:
            record("data", {"status":"error", "detail":f"offline verification failed: {type(exc).__name__}: {exc}"})

        try:
            store = Store(root / "sfss.db", read_only=True)
            fingerprint = settings.configuration_fingerprint(
                store.all("SELECT key,value FROM system_config ORDER BY key"))
            fingerprint_ok = (settings.environment != "production" or
                              fingerprint == settings.expected_config_sha256)
            record("configuration_fingerprint", {
                "status":"ok" if fingerprint_ok else "error", "sha256":fingerprint,
                "expected_sha256":settings.expected_config_sha256 or None,
            })
            bootstrap = {value.strip() for value in settings.bootstrap_admins.split(",") if value.strip()}
            identity_errors = []
            if settings.environment == "production" and settings.auth_backend == "ldap":
                if store.one("SELECT username FROM local_accounts LIMIT 1"):
                    identity_errors.append("local password records exist")
                unexpected = [row["username"] for row in store.all(
                    "SELECT username FROM users WHERE global_admin=1 AND enabled=1 AND principal_type='human'")
                    if row["username"] not in bootstrap]
                if unexpected: identity_errors.append("enabled platform administrators are outside bootstrap allowlist")
                mismatched = store.one(
                    "SELECT COUNT(*) AS value FROM auth_sessions WHERE revoked=0 AND auth_backend!=?",
                    (settings.auth_backend,))["value"]
                if mismatched: identity_errors.append("active sessions from another authentication backend exist")
                unbound = store.one(
                    "SELECT COUNT(*) AS value FROM auth_sessions WHERE revoked=0 "
                    "AND zone NOT IN ('green','red','admin')")["value"]
                if unbound: identity_errors.append("active human sessions are not bound to a production entrance")
            if settings.environment == "production" and store.one(
                "SELECT id FROM service_tokens WHERE revoked=0 AND expires_at>? "
                "AND (expires_at<=created_at OR expires_at-created_at>?) LIMIT 1",
                (int(time.time()), settings.service_token_max_ttl_seconds)):
                identity_errors.append("an active service token exceeds the maximum production lifetime")
            if settings.environment == "production" and store.one(
                "SELECT project_id FROM outbound_policies WHERE enabled=1 AND approval_provider='local' LIMIT 1"):
                identity_errors.append("an enabled project still uses local outbound approval")
            record("identity_policy", {"status":"error" if identity_errors else "ok",
                                       "detail":"; ".join(identity_errors) if identity_errors else "persisted identity and approval policy accepted"})

            relay_required = bool(store.one(
                "SELECT project_id FROM outbound_policies WHERE enabled=1 AND approval_provider='wecom' LIMIT 1"))
            relay_errors = settings.approval_relay_errors() if relay_required else []
            record("approval_relay", {"status":"error" if relay_errors else "ok",
                                      "required":relay_required,
                                      "detail":"; ".join(relay_errors) if relay_errors else
                                               "configuration accepted" if relay_required else "not required"})

            scanners = build_scanners(
                store.get_config("scanners", settings.scanners),
                store.get_config("clamav_host", settings.clamav_host),
                int(store.get_config("clamav_port", str(settings.clamav_port))),
                store.get_config("yara_rules", settings.yara_rules),
            )
            scanner_results = []
            for scanner in scanners:
                try:
                    result = scanner.health()
                    scanner_results.append({"name":result.scanner, "status":result.status, "detail":result.detail})
                except Exception as exc:
                    scanner_results.append({"name":scanner.name, "status":"error",
                                            "detail":f"health check failed: {type(exc).__name__}"})
            scanner_names = {item["name"] for item in scanner_results}
            scanner_ok = (all(item["status"] == "clean" for item in scanner_results) and
                          (settings.environment != "production" or
                           ("clamav" in scanner_names and "mock" not in scanner_names)))
            persisted_max_upload = int(store.get_config("max_upload_bytes", str(settings.max_upload_bytes)))
            if "clamav" in scanner_names and persisted_max_upload > settings.clamav_stream_max_bytes:
                scanner_ok = False
            record("scanners", {"status":"ok" if scanner_ok else "error", "adapters":scanner_results,
                                "upload_limit_bytes":persisted_max_upload,
                                "declared_clamav_stream_max_bytes":settings.clamav_stream_max_bytes})

            usage = shutil.disk_usage(root)
            reserve = int(store.get_config("min_free_bytes", str(settings.min_free_bytes)))
            available = max(0, usage.free - reserve)
            record("storage", {"status":"ok" if available > 0 else "error",
                               "free_bytes":usage.free, "reserve_bytes":reserve,
                               "available_after_reserve":available})
        except Exception as exc:
            record("persisted_state", {"status":"error", "detail":f"persisted state check failed: {type(exc).__name__}: {exc}"})

        record("ldap", _ldap_dependency(settings))
    finally:
        lock.close()

    return {"status":"ok" if not failures else "degraded",
            "production_candidate":not failures and settings.environment == "production",
            "checks":checks, "failed_checks":failures}


def restore(archive_path: Path, target: Path, expected_sha256=""):
    source = archive_path.absolute(); destination = target.resolve()
    if expected_sha256 and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise OperationError("trusted backup SHA-256 must be 64 lowercase hexadecimal characters")
    if destination.exists(): raise OperationError("restore target must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".sfss-restore-", dir=str(destination.parent)))
    descriptor = -1
    try:
        try: descriptor = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc: raise OperationError("backup archive is unavailable or unsafe") from exc
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode): raise OperationError("backup archive is not a regular file")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block: break
            digest.update(block)
        observed_sha256 = digest.hexdigest()
        if expected_sha256 and not hmac.compare_digest(observed_sha256, expected_sha256):
            raise OperationError("backup SHA-256 does not match trusted expected value")
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream, tarfile.open(fileobj=stream, mode="r") as archive:
            members = archive.getmembers()
            if len(members) > 1_000_000:
                raise OperationError("backup archive contains too many filesystem entries")
            seen = set(); extracted_bytes = 0
            for member in members:
                name = PurePosixPath(member.name)
                canonical = name.as_posix()
                if (name.is_absolute() or not name.parts or name.parts[0] != "sfss-data" or
                        ".." in name.parts or canonical != member.name.rstrip("/")):
                    raise OperationError("backup archive contains an unsafe path")
                if canonical in seen: raise OperationError("backup archive contains a duplicate path")
                seen.add(canonical)
                if not (member.isdir() or member.isreg()):
                    raise OperationError("backup archive contains an unsupported filesystem entry")
                mode = member.mode & 0o7777
                if ((member.isdir() and mode != 0o700) or
                        (member.isreg() and mode not in {0o400, 0o600})):
                    raise OperationError("backup archive contains unsafe filesystem permissions")
                # Never honor archive-supplied ownership, even when a restore
                # drill is run by root. Ownership transfer is a separate,
                # explicit deployment step after verification.
                member.uid = os.geteuid(); member.gid = os.getegid()
                member.uname = ""; member.gname = ""
                if member.isreg(): extracted_bytes += member.size
            if "sfss-data/backup-manifest.json" not in seen:
                raise OperationError("backup manifest is missing")
            restore_reserve = 1024 * 1024 * 1024
            if extracted_bytes > max(0, shutil.disk_usage(destination.parent).free - restore_reserve):
                raise OperationError("insufficient free space and restore safety reserve for declared backup contents")
            archive.extractall(temporary)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise OperationError("backup archive changed during restore")
        os.lseek(descriptor, 0, os.SEEK_SET); final_digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block: break
            final_digest.update(block)
        if not hmac.compare_digest(observed_sha256, final_digest.hexdigest()):
            raise OperationError("backup archive content changed during restore")
        restored = temporary / "sfss-data"
        manifest_path = restored / "backup-manifest.json"
        if not manifest_path.is_file(): raise OperationError("backup manifest is missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        original = Path(str(manifest.get("original_data_dir", ""))).resolve()
        if manifest.get("format") != 1 or not original.is_absolute():
            raise OperationError("backup manifest is invalid")
        store = Store(restored / "sfss.db")
        for table in ("objects", "outbound_transfers"):
            for record in store.all(f"SELECT id,storage_path FROM {table} WHERE storage_path!=''"):
                source_path = Path(record["storage_path"]).resolve()
                if not _inside(original, source_path):
                    raise OperationError(f"stored payload path is outside original data root: {table}:{record['id']}")
                rebased = restored / source_path.relative_to(original)
                store.execute(f"UPDATE {table} SET storage_path=? WHERE id=?", (str(rebased), record["id"]))
        for part in store.all("SELECT upload_id,part_number,storage_path FROM upload_parts"):
            source_path = Path(part["storage_path"]).resolve()
            if not _inside(original, source_path): raise OperationError("stored upload part path is outside original data root")
            rebased = restored / source_path.relative_to(original)
            store.execute("UPDATE upload_parts SET storage_path=? WHERE upload_id=? AND part_number=?",
                          (str(rebased), part["upload_id"], part["part_number"]))
        manifest_path.unlink()
        verification = verify_data(restored)
        if verification["audit"]["head"] != manifest.get("audit_head"):
            raise OperationError("restored audit head does not match backup manifest")
        os.replace(str(restored), str(destination))
        final_store = Store(destination / "sfss.db")
        for table in ("objects", "outbound_transfers"):
            for record in final_store.all(f"SELECT id,storage_path FROM {table} WHERE storage_path!=''"):
                current = Path(record["storage_path"]).resolve()
                final_store.execute(f"UPDATE {table} SET storage_path=? WHERE id=?",
                                    (str(destination / current.relative_to(restored)), record["id"]))
        for part in final_store.all("SELECT upload_id,part_number,storage_path FROM upload_parts"):
            current = Path(part["storage_path"]).resolve()
            final_store.execute("UPDATE upload_parts SET storage_path=? WHERE upload_id=? AND part_number=?",
                                (str(destination / current.relative_to(restored)), part["upload_id"], part["part_number"]))
        verification = verify_data(destination)
        return {"status":"ok", "target":str(destination), "archive_sha256":observed_sha256,
                "verified":verification}
    finally:
        if descriptor >= 0: os.close(descriptor)
        shutil.rmtree(temporary, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="SFSS offline integrity and backup operations")
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser("verify"); verify_parser.add_argument("--data-dir", required=True)
    init_parser = commands.add_parser("initialize"); init_parser.add_argument("--data-dir", required=True)
    fingerprint_parser = commands.add_parser("config-fingerprint"); fingerprint_parser.add_argument("--data-dir")
    backup_parser = commands.add_parser("backup"); backup_parser.add_argument("--data-dir", required=True); backup_parser.add_argument("--output", required=True)
    export_parser = commands.add_parser("export-audit"); export_parser.add_argument("--data-dir", required=True); export_parser.add_argument("--output", required=True)
    audit_verify_parser = commands.add_parser("verify-audit-export")
    audit_verify_parser.add_argument("--input", required=True)
    audit_verify_parser.add_argument("--expected-sha256", default="")
    audit_verify_parser.add_argument("--expected-head", default="")
    audit_verify_parser.add_argument("--expected-events", type=int)
    manifest_parser = commands.add_parser("release-manifest"); manifest_parser.add_argument("--root", required=True); manifest_parser.add_argument("--output", required=True)
    preflight_parser = commands.add_parser("preflight")
    preflight_parser.add_argument("--data-dir")
    preflight_parser.add_argument("--allow-non-production", action="store_true")
    restore_parser = commands.add_parser("restore"); restore_parser.add_argument("--archive", required=True); restore_parser.add_argument("--target", required=True); restore_parser.add_argument("--expected-sha256", default="")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            lock = acquire_runtime_lock(Path(args.data_dir))
            try: result = verify_data(Path(args.data_dir))
            finally: lock.close()
        elif args.command == "initialize": result = initialize_data(Path(args.data_dir))
        elif args.command == "config-fingerprint":
            settings = Settings.from_env()
            data_dir = Path(args.data_dir) if args.data_dir else settings.data_dir
            result = config_fingerprint(data_dir, settings)
        elif args.command == "backup": result = backup(Path(args.data_dir), Path(args.output))
        elif args.command == "export-audit": result = export_audit(Path(args.data_dir), Path(args.output))
        elif args.command == "verify-audit-export":
            result = verify_audit_export(Path(args.input), args.expected_sha256,
                                         args.expected_head, args.expected_events)
        elif args.command == "release-manifest": result = release_manifest(Path(args.root), Path(args.output))
        elif args.command == "preflight":
            settings = Settings.from_env()
            if args.data_dir: settings = replace(settings, data_dir=Path(args.data_dir))
            result = preflight(settings, require_production=not args.allow_non_production)
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            if result["status"] != "ok": raise SystemExit(1)
            return
        else: result = restore(Path(args.archive), Path(args.target), args.expected_sha256)
    except (OperationError, RuntimeError, OSError, tarfile.TarError) as exc:
        raise SystemExit(f"error: {exc}")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__": main()
