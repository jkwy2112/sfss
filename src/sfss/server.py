import argparse
import ipaddress
import hashlib
import hmac
import json
import mimetypes
import os
import signal
import stat
import platform
import socketserver
import socket
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse
import uuid
import threading
import time

from .auth import (AuthenticationError, LDAPAuthenticator, LocalAuthenticator, ServiceTokens,
                   human_session_zone, local_credentials, local_tokens, valid_username)
from .approvals import relay_signature
from .config import Settings, trusted_artifact_sha256
from .db import Store
from .jobs import SQLiteJobQueue
from .operations import OperationError, acquire_runtime_lock
from .scanners import build_scanners
from .service import SFSSService, ServiceError
from . import __version__


class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    """Reject excess accepted connections before allocating another thread."""
    daemon_threads = True

    def __init__(self, *args, max_request_workers=128, **kwargs):
        self.max_request_workers = max_request_workers
        self._request_slots = threading.BoundedSemaphore(max_request_workers)
        self.rejected_connections = 0
        self._rejected_connections_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            with self._rejected_connections_lock:
                self.rejected_connections += 1
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class ThreadingUnixHTTPServer(BoundedThreadingMixIn, socketserver.UnixStreamServer):
    sfss_unix_socket = True

    def server_bind(self):
        super().server_bind()
        os.chmod(self.server_address, 0o660)
        metadata = os.lstat(self.server_address)
        self._socket_identity = (metadata.st_dev, metadata.st_ino)

    def server_close(self):
        super().server_close()
        try:
            metadata = os.lstat(self.server_address)
            if (stat.S_ISSOCK(metadata.st_mode) and
                    (metadata.st_dev, metadata.st_ino) == getattr(self, "_socket_identity", None)):
                os.unlink(self.server_address)
        except FileNotFoundError:
            pass


class BoundedThreadingHTTPServer(BoundedThreadingMixIn, HTTPServer):
    pass


def prepare_unix_socket(path: Path):
    if not path.is_absolute(): raise ValueError("SFSS Unix socket path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if os.path.lexists(path):
        metadata = os.lstat(path)
        if not stat.S_ISSOCK(metadata.st_mode):
            raise ValueError("refusing to replace a non-socket Unix listener path")
        os.unlink(path)


def json_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")


def ip_in_cidrs(address: str, configured: str) -> bool:
    try: parsed = ipaddress.ip_address(address)
    except ValueError: return False
    for value in configured.split(","):
        value = value.strip()
        if not value: continue
        try: network = ipaddress.ip_network(value, strict=False)
        except ValueError: continue
        if parsed.version == network.version and parsed in network: return True
    return False


def public_object(obj):
    return {key: obj[key] for key in (
        "id", "uploader", "filename", "size", "sha256", "media_type",
        "type_known", "type_conflict", "state", "created_at", "updated_at", "expires_at",
        "scan_detail",
    )}


def public_outbound(obj):
    keys = ("id", "uploader", "filename", "size", "sha256", "media_type",
            "type_known", "type_conflict", "classification", "state", "scan_detail",
            "approval_provider", "approval_id", "approval_actor", "approval_comment", "created_at",
            "updated_at", "approval_expires_at", "download_expires_at")
    return {key: obj.get(key) for key in keys}


def public_upload(session):
    return {key: session.get(key) for key in (
        "id", "actor", "direction", "filename", "total_size", "chunk_size",
        "expected_sha256", "state", "object_id", "created_at", "updated_at", "expires_at",
        "parts", "received_bytes", "part_count",
    )}


def public_service_token(record):
    return {"id":record["id"], "label":record["label"], "username":record["username"],
            "zone":record["zone"],
            "permissions":json.loads(record["permissions"]), "created_at":record["created_at"],
            "expires_at":record["expires_at"], "last_used_at":record.get("last_used_at"),
            "created_by":record["created_by"], "revoked":bool(record["revoked"])}


def build_authenticator(settings: Settings, store=None):
    if settings.auth_backend == "local":
        tokens = local_tokens(settings.dev_users) if settings.dev_tokens_enabled else {}
        return LocalAuthenticator(
            tokens, local_credentials(settings.local_credentials), store,
            settings.session_ttl_seconds, settings.session_idle_seconds,
            settings.max_sessions_per_user,
        )
    if settings.auth_backend == "ldap":
        return LDAPAuthenticator(
            settings.ldap_uri,
            settings.ldap_base_dn,
            settings.ldap_user_template,
            store,
            settings.session_ttl_seconds,
            settings.ldap_ca_file,
            settings.allow_basic_auth,
            settings.session_idle_seconds,
            settings.max_sessions_per_user,
        )
    raise ValueError("SFSS_AUTH_BACKEND must be local or ldap")


def make_handler(service: SFSSService, authenticator):
    failed_logins = {}
    failed_login_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"SFSS/{__version__}"
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            # Header parsing happens after setup(), so slow clients are bounded
            # even when the trusted gateway is absent or misconfigured.
            self.connection.settimeout(service.settings.request_header_timeout_seconds)

        def log_message(self, fmt, *args):
            print(f"{self.peer_address()} {fmt % args}")

        def peer_address(self):
            if getattr(getattr(self, "server", None), "sfss_unix_socket", False): return "local-unix"
            try: return self.client_address[0]
            except (IndexError, TypeError): return "unknown"

        @property
        def request_id(self):
            if not hasattr(self, "_request_id"):
                candidate = self.headers.get("X-Request-ID", "").strip()
                if (not 1 <= len(candidate) <= 128 or
                        any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in candidate)):
                    candidate = str(uuid.uuid4())
                self._request_id = candidate
            return self._request_id

        def respond(self, status: int, value=None, headers=None):
            body = b"" if value is None else json_bytes(value)
            try:
                unread_body = (int(self.headers.get("Content-Length", "0")) > 0 and
                               not getattr(self, "_body_consumed", False))
            except ValueError:
                unread_body = True
            unread_body = unread_body or getattr(self, "_force_close", False)
            if unread_body:
                # The unread bytes must never be interpreted as another HTTP/1.1
                # request on this connection. Advertise the close before headers
                # are committed, then let handle_method close it after responding.
                self.close_connection = True
            self.send_response(status)
            self.send_header("X-Request-ID", self.request_id)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            if unread_body:
                self.send_header("Connection", "close")
            if value is not None:
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
            for key, val in (headers or {}).items():
                self.send_header(key, val)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def respond_file(self, path: Path, content_type: str):
            try:
                body = path.read_bytes()
            except FileNotFoundError:
                raise ServiceError(404, "asset not found")
            self.send_response(200)
            self.send_header("X-Request-ID", self.request_id)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def respond_text(self, status: int, value: str, content_type: str):
            body = value.encode("utf-8")
            self.send_response(status)
            self.send_header("X-Request-ID", self.request_id)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        @staticmethod
        def metric_label(value):
            return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')

        @staticmethod
        def scanner_health(scanner):
            try:
                result = scanner.health()
                return {"name":result.scanner, "status":result.status, "detail":result.detail}
            except Exception as exc:
                return {"name":scanner.name, "status":"error",
                        "detail":f"health check failed: {type(exc).__name__}"}

        def metrics(self):
            lines = [
                "# HELP sfss_build_info SFSS build and database schema information.",
                "# TYPE sfss_build_info gauge",
                f'sfss_build_info{{version="{self.metric_label(__version__)}",schema="{service.store.schema_version()}"}} 1',
            ]
            inbound = {row["state"]:row["count"] for row in service.store.all(
                "SELECT state,COUNT(*) AS count FROM objects GROUP BY state")}
            outbound = {row["state"]:row["count"] for row in service.store.all(
                "SELECT state,COUNT(*) AS count FROM outbound_transfers GROUP BY state")}
            lines += ["# TYPE sfss_inbound_objects gauge"]
            for state in ("pending_scan", "scanning", "quarantined", "released", "rejected", "expired"):
                lines.append(f'sfss_inbound_objects{{state="{state}"}} {inbound.get(state, 0)}')
            lines += ["# TYPE sfss_outbound_transfers gauge"]
            for state in ("pending_scan", "scanning", "quarantined", "classified", "pending_approval",
                          "approved", "approval_rejected", "released_to_green", "expired"):
                lines.append(f'sfss_outbound_transfers{{state="{state}"}} {outbound.get(state, 0)}')
            queue = service.queue.health() if hasattr(service.queue, "health") else {}
            lines.append("# TYPE sfss_scan_jobs gauge")
            for state in ("queued", "running", "completed", "failed"):
                lines.append(f'sfss_scan_jobs{{state="{state}"}} {int(queue.get(state, 0))}')
            storage = service.storage_status()
            lines += ["# TYPE sfss_storage_bytes gauge",
                      f'sfss_storage_bytes{{kind="free"}} {storage["free_bytes"]}',
                      f'sfss_storage_bytes{{kind="reserve"}} {storage["reserve_bytes"]}',
                      f'sfss_storage_bytes{{kind="available_after_reserve"}} {storage["available_bytes"]}']
            active_uploads = service.store.one(
                "SELECT COUNT(*) AS value FROM upload_sessions WHERE state IN ('uploading','completing')")["value"]
            lines += ["# TYPE sfss_active_upload_sessions gauge", f"sfss_active_upload_sessions {active_uploads}"]
            audit_count = service.store.one("SELECT COUNT(*) AS value FROM audit_events")["value"]
            lines += ["# TYPE sfss_audit_events_total counter", f"sfss_audit_events_total {audit_count}",
                      "# TYPE sfss_rejected_connections_total counter",
                      f"sfss_rejected_connections_total {int(getattr(getattr(self, 'server', None), 'rejected_connections', 0))}",
                      "# TYPE sfss_runtime_accepted gauge",
                      f"sfss_runtime_accepted {0 if service.runtime_acceptance_errors() else 1}",
                      "# TYPE sfss_maintenance_last_run_seconds gauge",
                      f"sfss_maintenance_last_run_seconds {service.last_maintenance_at}",
                      "# TYPE sfss_maintenance_error gauge",
                      f"sfss_maintenance_error {1 if service.last_maintenance_error else 0}"]
            lines.append("# TYPE sfss_scanner_up gauge")
            for scanner in service.scanners:
                result = self.scanner_health(scanner)
                lines.append(f'sfss_scanner_up{{scanner="{self.metric_label(result["name"])}"}} '
                             f'{1 if result["status"] == "clean" else 0}')
            callback_counts = service.store.one(
                "SELECT COUNT(*) AS total,SUM(CASE WHEN outcome='processed' THEN 1 ELSE 0 END) AS processed,"
                "SUM(CASE WHEN outcome LIKE 'error:%' THEN 1 ELSE 0 END) AS errors FROM approval_callback_events")
            lines += ["# TYPE sfss_approval_callback_events gauge",
                      f'sfss_approval_callback_events{{outcome="total"}} {callback_counts["total"] or 0}',
                      f'sfss_approval_callback_events{{outcome="processed"}} {callback_counts["processed"] or 0}',
                      f'sfss_approval_callback_events{{outcome="error"}} {callback_counts["errors"] or 0}']
            return "\n".join(lines) + "\n"

        def respond_download(self, record, source: Path, method="GET"):
            if service.settings.runtime_secret_errors():
                raise ServiceError(503, "download signing secret is not in the accepted state")
            size = int(record["size"]); start, end = 0, size - 1; status = 200
            range_header = self.headers.get("Range", "").strip()
            if_range = self.headers.get("If-Range", "").strip()
            etag = f'"{record["sha256"]}"'
            if range_header and (not if_range or if_range == etag):
                if not range_header.startswith("bytes=") or "," in range_header:
                    raise ServiceError(416, "only a single byte range is supported")
                value = range_header[6:]
                try:
                    first, separator, last = value.partition("-")
                    if not separator: raise ValueError
                    if first:
                        start = int(first); end = int(last) if last else size - 1
                    else:
                        suffix = int(last)
                        if suffix <= 0: raise ValueError
                        start = max(0, size - suffix); end = size - 1
                    if start < 0 or end < start or start >= size: raise ValueError
                    end = min(end, size - 1)
                except ValueError as exc:
                    self.respond(416, {"error": "requested byte range is not satisfiable"},
                                 {"Content-Range": f"bytes */{size}"})
                    return False
                status = 206
            try:
                descriptor = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError as exc:
                raise ServiceError(409, "released payload is unavailable") from exc
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or opened.st_size != size:
                    raise ServiceError(409, "released payload changed before download")
                length = end - start + 1
                self.send_response(status)
                self.send_header("X-Request-ID", self.request_id)
                self.send_header("Content-Type", record["media_type"])
                self.send_header("Content-Length", str(length))
                self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(record["filename"], safe=""))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("ETag", etag)
                manifest = f'{record["id"]}\n{size}\n{record["sha256"]}'
                if service.settings.manifest_hmac_key:
                    signature = hmac.new(service.settings.manifest_hmac_key.encode(), manifest.encode(), hashlib.sha256).hexdigest()
                    self.send_header("X-SFSS-Manifest-Signature", signature)
                if status == 206: self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if method == "HEAD": return True
                stream = os.fdopen(descriptor, "rb")
                descriptor = -1
                stream.seek(start); remaining = length
                with stream:
                    while remaining:
                        block = stream.read(min(1024 * 1024, remaining))
                        if not block: raise ConnectionError("released payload became truncated during download")
                        self.wfile.write(block); remaining -= len(block)
                return True
            finally:
                if descriptor >= 0: os.close(descriptor)

        def identity_record(self):
            if not hasattr(self, "_identity"):
                self._identity = authenticator.authenticate(self.authentication_headers())
                service.store.ensure_user(self._identity.username)
            return self._identity

        @staticmethod
        def session_cookie_name():
            return "__Host-sfss_session"

        def session_cookie_token(self):
            if service.settings.environment != "production" or self.headers.get("Authorization"):
                return None
            values = []
            for header in self.headers.get_all("Cookie", []) or []:
                if len(header) > 4096: return None
                for item in header.split(";"):
                    name, separator, value = item.strip().partition("=")
                    if separator and name == self.session_cookie_name(): values.append(value)
            if len(values) != 1: return None
            token = values[0]
            if not 20 <= len(token) <= 128 or any(
                    character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                    for character in token):
                return None
            return token

        def authentication_headers(self):
            token = self.session_cookie_token()
            if not token: return self.headers
            headers = {key:value for key, value in self.headers.items()}
            headers["Authorization"] = "Bearer " + token
            return headers

        def enforce_cookie_csrf(self, method, path):
            if (method in {"POST", "PUT", "PATCH", "DELETE"} and
                    path not in (["v1", "auth", "login"],
                                 ["v1", "integrations", "wecom", "callback"]) and
                    self.session_cookie_token() and
                    self.headers.get("X-SFSS-CSRF") != "1"):
                raise ServiceError(403, "cookie-authenticated mutation requires CSRF header")

        def identity(self):
            return self.identity_record().username

        def zone(self):
            return self.headers.get("X-SFSS-Zone", "unknown").lower()

        def gateway_role(self):
            return self.headers.get("X-SFSS-Gateway-Role", "").strip().lower()

        def is_trusted_proxy(self):
            return (getattr(getattr(self, "server", None), "sfss_unix_socket", False) or
                    ip_in_cidrs(self.peer_address(), service.settings.trusted_zone_proxy_cidrs))

        def client_ip(self):
            if self.is_trusted_proxy():
                forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
                try:
                    if forwarded: return str(ipaddress.ip_address(forwarded))
                except ValueError: pass
            return self.peer_address()

        def enforce_gateway_boundary(self, path):
            settings = service.settings
            if settings.require_trusted_proxy and not self.is_trusted_proxy():
                raise ServiceError(403, "request did not arrive through a trusted zone gateway")
            if settings.require_forwarded_https and self.headers.get("X-Forwarded-Proto", "").lower() != "https":
                raise ServiceError(403, "trusted gateway did not assert HTTPS")
            if settings.require_trusted_proxy:
                role = self.gateway_role()
                if role not in {"green", "red", "admin"}:
                    raise ServiceError(403, "trusted gateway identity is missing or invalid")
                if role in {"green", "red"} and self.zone() != role:
                    raise ServiceError(403, "gateway identity and asserted zone do not match")
                if role == "admin" and self.zone() in {"green", "red"}:
                    raise ServiceError(403, "management gateway cannot assert a data zone")
                method = getattr(self, "_request_method", "")
                management_route = (
                    path == ["admin"] or path[:2] == ["v1", "admin"] or
                    path in (["ready"], ["metrics"], ["v1", "integrations", "wecom", "callback"]) or
                    (len(path) == 4 and path[:2] == ["v1", "outbound"] and path[3] == "decision")
                )
                if management_route and role != "admin":
                    raise ServiceError(403, "operation is available only through the management gateway")
                if path == ["green"] and role != "green":
                    raise ServiceError(403, "green portal requires the green gateway")
                if path == ["red"] and role != "red":
                    raise ServiceError(403, "red portal requires the red gateway")
            is_admin = (path in (["admin"], ["ready"], ["metrics"]) or path[:2] == ["v1", "admin"] or
                        path == ["v1", "integrations", "wecom", "callback"])
            if is_admin and not ip_in_cidrs(self.client_ip(), settings.admin_source_cidrs):
                raise ServiceError(403, "management plane source address is not allowed")

        def enforce_runtime_acceptance(self, method, path):
            if not service.runtime_acceptance_errors():
                return
            # Keep only authentication, observability, configuration rollback,
            # and credential/session containment available during drift.
            if path == ["v1", "auth", "login"] and service.ldap_trust_errors():
                raise ServiceError(503, "LDAP trust artifact is not in the accepted state")
            if path in (["v1", "auth", "login"], ["v1", "auth", "logout"], ["v1", "me"]):
                return
            if method == "GET" and path[:2] == ["v1", "admin"]:
                return
            if method == "PUT" and path == ["v1", "admin", "config"]:
                return
            if (method == "POST" and
                    (path == ["v1", "admin", "sessions", "revoke-all"] or
                     (len(path) == 5 and path[:3] == ["v1", "admin", "users"] and
                      path[4] == "revoke-sessions"))):
                return
            if (method == "PUT" and len(path) == 4 and path[:3] == ["v1", "admin", "users"]):
                return
            if (method == "PUT" and len(path) == 4 and
                    path[:3] == ["v1", "admin", "service-identities"]):
                return
            if (method == "DELETE" and len(path) == 4 and
                    path[:3] == ["v1", "admin", "service-tokens"]):
                return
            raise ServiceError(503, "production runtime configuration is not in the accepted state")

        def audit(self, actor, action, outcome, object_id=None, details=None):
            service.store.audit(**self.audit_payload(actor, action, outcome, object_id, details))

        def audit_payload(self, actor, action, outcome, object_id=None, details=None):
            context = dict(details or {})
            identity = getattr(self, "_identity", None)
            if identity and identity.credential_type == "service":
                context.update({"credential_type":"service", "service_token_id":identity.token_id})
            return {"request_id":self.request_id, "actor":actor, "action":action,
                    "object_id":object_id, "outcome":outcome,
                    "source_zone":self.zone(), "remote_addr":self.client_ip(),
                    "details":context}

        def require_service_permission(self, identity, permission: str):
            if identity.credential_type != "service": return
            if identity.zone != self.zone() or permission not in identity.permissions:
                raise ServiceError(403, "service token scope does not permit this operation")

        def enforce_service_scope(self, method: str, path, identity):
            if identity.credential_type != "service": return
            if self.zone() != identity.zone:
                raise ServiceError(403, "service token is bound to a different zone")
            if method == "GET" and path in (["v1", "me"], ["v1", "objects"], ["v1", "outbound"]): return
            if path[:2] == ["v1", "uploads"] and len(path) >= 3:
                session = service.store.one("SELECT actor,direction FROM upload_sessions WHERE id=?", (path[2],))
                if not session: raise ServiceError(404, "upload session not found")
                if session["actor"] != identity.username:
                    raise ServiceError(403, "service token does not own this upload session")
                permission = "inbound_upload" if session["direction"] == "inbound" else "outbound_upload"
                self.require_service_permission(identity, permission); return
            if path[:2] == ["v1", "objects"] and len(path) >= 3:
                permission = "inbound_upload"
                if len(path) == 4 and path[3] == "download": permission = "inbound_download"
                record = service.store.one("SELECT uploader FROM objects WHERE id=?", (path[2],))
                if record and record["uploader"] != identity.username:
                    raise ServiceError(404, "object not found")
                self.require_service_permission(identity, permission); return
            if path[:2] == ["v1", "outbound"] and len(path) >= 3:
                if len(path) == 4 and path[3] == "decision":
                    raise ServiceError(403, "service tokens cannot approve transfers")
                permission = "outbound_download" if identity.zone == "green" else "outbound_upload"
                if len(path) == 4 and path[3] == "download":
                    record = service.store.one("SELECT uploader FROM outbound_transfers WHERE id=?", (path[2],))
                    if record and record["uploader"] != identity.username:
                        raise ServiceError(404, "outbound transfer not found")
                self.require_service_permission(identity, permission); return
            raise ServiceError(403, "service token cannot access this endpoint")

        def read_json(self):
            try: length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc: raise ServiceError(400, "invalid JSON content length") from exc
            if length <= 0 or length > 64 * 1024:
                raise ServiceError(400, "invalid JSON content length")
            try:
                value = json.loads(self.rfile.read(length)); self._body_consumed = True; return value
            except Exception as exc:
                raise ServiceError(400, "invalid JSON") from exc

        def read_limited_body(self, maximum=64 * 1024):
            try: length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc: raise ServiceError(400, "invalid content length") from exc
            if length <= 0 or length > maximum: raise ServiceError(400, "invalid content length")
            body = self.rfile.read(length); self._body_consumed = True
            if len(body) != length: raise ServiceError(400, "request body shorter than Content-Length")
            return body

        def handle_approval_callback(self):
            if service.settings.environment == "production" and (
                    service.settings.runtime_secret_errors() or service.settings.approval_relay_errors()):
                raise ServiceError(503, "approval callback secrets are not in the accepted state")
            key = service.settings.approval_relay_callback_hmac_key
            if len(key) < 32: raise ServiceError(503, "approval callback is not configured")
            timestamp = self.headers.get("X-SFSS-Approval-Timestamp", "").strip()
            nonce = self.headers.get("X-SFSS-Approval-Nonce", "").strip()
            signature = self.headers.get("X-SFSS-Approval-Signature", "").strip().lower()
            safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            try: timestamp_value = int(timestamp)
            except ValueError as exc: raise ServiceError(401, "invalid approval callback timestamp") from exc
            now = int(time.time()); skew = service.settings.approval_callback_max_skew_seconds
            if abs(now - timestamp_value) > skew: raise ServiceError(401, "approval callback timestamp is outside the allowed window")
            if not 1 <= len(nonce) <= 128 or any(ch not in safe for ch in nonce):
                raise ServiceError(401, "invalid approval callback nonce")
            if len(signature) != 64 or any(ch not in "0123456789abcdef" for ch in signature):
                raise ServiceError(401, "invalid approval callback signature")
            body = self.read_limited_body()
            expected = relay_signature(key, timestamp, nonce, body)
            if not hmac.compare_digest(signature, expected):
                raise ServiceError(401, "invalid approval callback signature")
            payload_hash = hashlib.sha256(body).hexdigest()
            previous = service.store.one("SELECT payload_hash FROM integration_nonces WHERE nonce=?", (nonce,))
            if previous and previous["payload_hash"] != payload_hash:
                raise ServiceError(409, "approval callback nonce was reused with a different payload")
            if not previous:
                try:
                    service.store.execute(
                        "INSERT INTO integration_nonces(nonce,payload_hash,expires_at) VALUES(?,?,?)",
                        (nonce, payload_hash, now + 2 * skew),
                    )
                except Exception:
                    previous = service.store.one("SELECT payload_hash FROM integration_nonces WHERE nonce=?", (nonce,))
                    if not previous or previous["payload_hash"] != payload_hash:
                        raise ServiceError(409, "approval callback nonce replay conflict")
            try: event = json.loads(body)
            except Exception as exc: raise ServiceError(400, "invalid approval callback JSON") from exc
            result = service.process_approval_callback(event, payload_hash)
            transfer = result.pop("transfer")
            self.audit("approval-relay", "outbound.approval.callback", result["status"],
                       transfer["id"],
                       {"event_id":event.get("event_id"), "approval_id":event.get("approval_id")})
            return self.respond(200, {**result, "transfer":public_outbound(transfer)})

        def validate_request_framing(self):
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
                self._force_close = True
                raise ServiceError(400, "unsupported or ambiguous request framing")
            if lengths:
                try: length = int(lengths[0])
                except ValueError as exc:
                    self._force_close = True; raise ServiceError(400, "invalid Content-Length") from exc
                if length < 0:
                    self._force_close = True; raise ServiceError(400, "invalid Content-Length")

        def dispatch(self, method):
            path = [unquote(piece) for piece in urlparse(self.path).path.split("/") if piece]
            if (path == ["v1", "integrations", "wecom", "callback"] or
                    (len(path) >= 3 and path[:3] == ["v1", "admin", "outbound"]) or
                    path[:2] == ["v1", "outbound"] or
                    (len(path) == 3 and path[:2] == ["v1", "admin"] and
                     path[2] in {"outbound-policy", "audit"})):
                service.require_workflow("outbound")
            if ((len(path) >= 3 and path[:3] == ["v1", "admin", "objects"]) or
                    path[:2] == ["v1", "objects"]):
                service.require_workflow("inbound")
            if path != ["health"]: self.enforce_gateway_boundary(path)
            web_dir = Path(__file__).parent / "web"
            if method == "GET" and (not path or path in (["green"], ["red"], ["admin"])):
                return self.respond_file(web_dir / "index.html", "text/html; charset=utf-8")
            if method == "GET" and path == ["app.js"]:
                return self.respond_file(web_dir / "app.js", "text/javascript; charset=utf-8")
            if method == "GET" and path == ["styles.css"]:
                return self.respond_file(web_dir / "styles.css", "text/css; charset=utf-8")
            if method == "GET" and path == ["favicon.ico"]:
                return self.respond(204)
            if method == "GET" and path == ["health"]:
                service.store.one("SELECT 1 AS ok")
                return self.respond(200, {"status": "ok"})
            if method == "GET" and path == ["ready"]:
                service.store.one("SELECT 1 AS ok")
                results = [self.scanner_health(scanner) for scanner in service.scanners]
                storage = service.storage_status()
                relay_required = bool(service.store.one(
                    "SELECT id FROM outbound_policy WHERE enabled=1 AND approval_provider='wecom' LIMIT 1"))
                relay_errors = service.settings.approval_relay_errors() if relay_required else []
                secret_errors = service.settings.runtime_secret_errors()
                artifact_errors = service.security_artifact_errors()
                fingerprint = service.settings.configuration_fingerprint(
                    service.store.all("SELECT key,value FROM system_config ORDER BY key"))
                configuration_ok = (service.settings.environment != "production" or
                                    fingerprint == service.settings.expected_config_sha256)
                maintenance_age = max(0, int(time.time()) - service.last_maintenance_at) if service.last_maintenance_at else None
                maintenance_ok = (not service.last_maintenance_error and maintenance_age is not None and
                                  maintenance_age <= max(60, service.settings.maintenance_interval_seconds * 3))
                ready = (all(result["status"] == "clean" for result in results) and
                         storage["available_bytes"] > 0 and not relay_errors and
                         not secret_errors and not artifact_errors and configuration_ok and maintenance_ok)
                return self.respond(200 if ready else 503, {
                    "status":"ready" if ready else "degraded",
                    "deployment_mode":service.settings.deployment_mode,
                    "scanners":results,
                    "queue":service.queue.health() if hasattr(service.queue, "health") else {},
                    "storage":storage,
                    "maintenance":{"status":"ok" if maintenance_ok else "degraded",
                                   "last_run":service.last_maintenance_at,
                                   "age_seconds":maintenance_age,
                                   "error":service.last_maintenance_error or None},
                    "approval_relay":{"required":relay_required,
                                      "status":"configured" if relay_required and not relay_errors else
                                               "degraded" if relay_required else "not_required"},
                    "secrets":{"status":"configured" if not secret_errors else "degraded"},
                    "security_artifacts":{"status":"accepted" if not artifact_errors else "drifted"},
                    "configuration":{"status":"accepted" if configuration_ok else "drifted",
                                     "sha256":fingerprint,
                                     "release_id":service.settings.release_id,
                                     "python":platform.python_version()},
                })
            if method == "GET" and path == ["metrics"]:
                return self.respond_text(200, self.metrics(), "text/plain; version=0.0.4; charset=utf-8")
            self.enforce_runtime_acceptance(method, path)
            self.enforce_cookie_csrf(method, path)
            if method == "POST" and path == ["v1", "integrations", "wecom", "callback"]:
                return self.handle_approval_callback()
            if method == "POST" and path == ["v1", "auth", "login"]:
                data = self.read_json()
                username = str(data.get("username", ""))
                if not valid_username(username): raise AuthenticationError("invalid username or password")
                login_key = (self.client_ip(), username)
                now = int(time.time())
                with failed_login_lock:
                    for key, values in list(failed_logins.items()):
                        current = [timestamp for timestamp in values if timestamp > now - 300]
                        if current: failed_logins[key] = current
                        else: failed_logins.pop(key, None)
                    if len(failed_logins) >= 10000 and login_key not in failed_logins:
                        raise ServiceError(429, "login protection capacity reached; retry later")
                    attempts = [timestamp for timestamp in failed_logins.get(login_key, []) if timestamp > now - 300]
                    failed_logins[login_key] = attempts
                if len(attempts) >= 5: raise ServiceError(429, "too many failed login attempts; retry later")
                if not hasattr(authenticator, "login"): raise ServiceError(405, "password login is unavailable")
                login_zone = human_session_zone(self.headers)
                login_audit = self.audit_payload(username, "session.login", "success")
                try: token = authenticator.login(username, str(data.get("password", "")), login_zone,
                                                  audit=login_audit)
                except AuthenticationError:
                    with failed_login_lock: failed_logins.setdefault(login_key, []).append(now)
                    raise
                with failed_login_lock: failed_logins.pop(login_key, None)
                if not getattr(authenticator, "sessions", None):
                    service.store.ensure_user(username); self.audit(username, "session.login", "success")
                if service.settings.environment == "production":
                    cookie = (f"{self.session_cookie_name()}={token}; Path=/; "
                              f"Max-Age={service.settings.session_ttl_seconds}; Secure; HttpOnly; "
                              "SameSite=Strict")
                    return self.respond(200, {"username":username, "session_zone":login_zone,
                                              "session_transport":"cookie"},
                                        {"Set-Cookie":cookie})
                return self.respond(200, {"token": token, "username": username,
                                          "session_zone": login_zone,
                                          "session_transport":"bearer"})
            identity = self.identity_record(); actor = identity.username
            self.enforce_service_scope(method, path, identity)

            if method == "POST" and path == ["v1", "auth", "logout"]:
                audited = False
                if hasattr(authenticator, "logout"):
                    audited = bool(authenticator.logout(
                        self.authentication_headers(),
                        audit=self.audit_payload(actor, "session.logout", "success")))
                if not audited: self.audit(actor, "session.logout", "success")
                headers = None
                if service.settings.environment == "production":
                    headers = {"Set-Cookie":
                               f"{self.session_cookie_name()}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"}
                return self.respond(204, headers=headers)

            if method == "GET" and path == ["v1", "me"]:
                return self.respond(200, {"username": actor, "global_admin": service.store.is_global_admin(actor),
                                          "approver": service.store.is_approver(actor),
                                          "deployment_mode":service.settings.deployment_mode})

            if method == "GET" and path == ["v1", "admin", "overview"]:
                if not service.store.is_global_admin(actor):
                    raise ServiceError(403, "platform administrator required")
                inbound_enabled = service.workflow_enabled("inbound")
                outbound_enabled = service.workflow_enabled("outbound")
                counts = {
                    "users": service.store.one("SELECT COUNT(*) AS value FROM users")["value"],
                    "objects": service.store.one("SELECT ?*(SELECT COUNT(*) FROM objects)+?*(SELECT COUNT(*) FROM outbound_transfers) AS value", (int(inbound_enabled), int(outbound_enabled)))["value"],
                    "bytes": service.store.one("SELECT ?*(SELECT COALESCE(SUM(size),0) FROM objects)+?*(SELECT COALESCE(SUM(size),0) FROM outbound_transfers) AS value", (int(inbound_enabled), int(outbound_enabled)))["value"],
                    "active_uploads": service.store.one("SELECT COUNT(*) AS value FROM upload_sessions WHERE state IN ('uploading','completing')")["value"],
                    "staged_bytes": service.store.one("SELECT COALESCE(SUM(size),0) AS value FROM upload_parts p JOIN upload_sessions s ON s.id=p.upload_id WHERE s.state IN ('uploading','completing')")["value"],
                }
                storage = service.storage_status()
                states = {row["state"]: row["count"] for row in service.store.all(
                    "SELECT state,COUNT(*) AS count FROM objects GROUP BY state"
                )} if inbound_enabled else {}
                outbound_states = {row["state"]: row["count"] for row in service.store.all(
                    "SELECT state,COUNT(*) AS count FROM outbound_transfers GROUP BY state"
                )} if outbound_enabled else {}
                users = service.store.all("""
                    SELECT u.username,u.global_admin,u.approver,u.principal_type,
                           (u.enabled AND COALESCE(a.enabled,1)) AS enabled,
                           (SELECT COUNT(*) FROM objects o WHERE o.uploader=u.username) +
                           (SELECT COUNT(*) FROM outbound_transfers t WHERE t.uploader=u.username) AS object_count
                    FROM users u LEFT JOIN local_accounts a ON a.username=u.username
                    ORDER BY u.global_admin DESC,u.username
                """)
                objects = service.store.all(
                    "SELECT id,uploader,filename,size,media_type,state,created_at FROM objects ORDER BY created_at DESC,id DESC LIMIT 100"
                ) if inbound_enabled else []
                outbound_objects = service.store.all(
                    "SELECT id,uploader,filename,size,media_type,state,created_at FROM outbound_transfers ORDER BY created_at DESC,id DESC LIMIT 100"
                ) if outbound_enabled else []
                pending_approvals = service.store.all(
                    "SELECT * FROM outbound_transfers WHERE state='pending_approval' "
                    "ORDER BY created_at DESC,id DESC LIMIT 100"
                ) if outbound_enabled else []
                events = service.store.all("SELECT * FROM audit_events ORDER BY id DESC LIMIT 100")
                audit_chain = service.store.verify_audit_chain()
                self.audit(actor, "admin.overview", "success")
                return self.respond(200, {"deployment_mode":service.settings.deployment_mode,
                                          "counts": counts, "states": states, "outbound_states": outbound_states,
                                          "users": users, "objects": objects,
                                          "outbound_objects": outbound_objects,
                                          "pending_approvals": [public_outbound(row) for row in pending_approvals],
                                          "events": events, "audit_chain": audit_chain,
                                          "storage": storage,
                                          "queue": service.queue.health() if hasattr(service.queue, "health") else {}})

            if method == "GET" and path == ["v1", "admin", "config"]:
                if not service.store.is_global_admin(actor):
                    raise ServiceError(403, "platform administrator required")
                self.audit(actor, "admin.config.read", "success")
                return self.respond(200, {
                    "retention_hours": int(service.store.get_config("retention_seconds", str(service.settings.retention_seconds))) // 3600,
                    "max_upload_mb": int(service.store.get_config("max_upload_bytes", str(service.settings.max_upload_bytes))) // (1024 * 1024),
                    "multipart_chunk_mb": int(service.store.get_config("multipart_chunk_bytes", str(service.settings.multipart_chunk_bytes))) // (1024 * 1024),
                    "upload_session_hours": int(service.store.get_config("upload_session_ttl_seconds", str(service.settings.upload_session_ttl_seconds))) // 3600,
                    "max_active_uploads_per_user": int(service.store.get_config("max_active_uploads_per_user", str(service.settings.max_active_uploads_per_user))),
                    "max_staged_gb_per_user": int(service.store.get_config("max_staged_bytes_per_user", str(service.settings.max_staged_bytes_per_user))) // (1024 ** 3),
                    "min_free_gb": int(service.store.get_config("min_free_bytes", str(service.settings.min_free_bytes))) // (1024 ** 3),
                    "scanners": service.store.get_config("scanners", service.settings.scanners),
                    "clamav_host": service.store.get_config("clamav_host", service.settings.clamav_host),
                    "clamav_port": int(service.store.get_config("clamav_port", str(service.settings.clamav_port))),
                    "clamav_stream_max_mb": service.settings.clamav_stream_max_bytes // (1024 * 1024),
                    "yara_rules": service.store.get_config("yara_rules", service.settings.yara_rules),
                    "service_token_max_hours": service.settings.service_token_max_ttl_seconds // 3600,
                })

            if method == "GET" and path == ["v1", "admin", "sessions"]:
                if not service.store.is_global_admin(actor):
                    raise ServiceError(403, "platform administrator required")
                now = int(time.time())
                rows = service.store.all(
                    "SELECT s.username,s.auth_backend,s.zone,s.created_at,s.expires_at,s.last_seen_at "
                    "FROM auth_sessions s JOIN users u ON u.username=s.username "
                    "WHERE s.revoked=0 AND s.expires_at>? AND s.last_seen_at>? "
                    "AND u.enabled=1 AND u.principal_type='human' "
                    "ORDER BY s.last_seen_at DESC,s.created_at DESC LIMIT 500",
                    (now, now - service.settings.session_idle_seconds),
                )
                self.audit(actor, "admin.session.list", "success", details={"count":len(rows)})
                return self.respond(200, {"sessions":rows, "absolute_ttl_seconds":service.settings.session_ttl_seconds,
                                          "idle_ttl_seconds":service.settings.session_idle_seconds,
                                          "max_per_user":service.settings.max_sessions_per_user})

            if method == "POST" and len(path) == 5 and path[:3] == ["v1", "admin", "users"] and path[4] == "revoke-sessions":
                if not service.store.is_global_admin(actor):
                    raise ServiceError(403, "platform administrator required")
                username = path[3]
                principal = service.store.one(
                    "SELECT principal_type FROM users WHERE username=?", (username,))
                if not principal or principal["principal_type"] != "human":
                    raise ServiceError(404, "human user not found")
                data = self.read_json()
                if data.get("confirmation") != username:
                    raise ServiceError(400, "session revocation confirmation does not match username")
                revoked_count = service.store.one(
                    "SELECT COUNT(*) AS value FROM auth_sessions WHERE username=? AND revoked=0",
                    (username,))["value"]
                service.store.transaction_audited(((
                    "UPDATE auth_sessions SET revoked=1 WHERE username=? AND revoked=0", (username,)),),
                    audit=self.audit_payload(actor, "admin.session.revoke_user", "success",
                                             details={"username":username, "revoked":revoked_count}))
                return self.respond(200, {"status":"revoked", "username":username,
                                          "revoked":revoked_count})

            if method == "POST" and path == ["v1", "admin", "sessions", "revoke-all"]:
                if not service.store.is_global_admin(actor):
                    raise ServiceError(403, "platform administrator required")
                data = self.read_json()
                if data.get("confirmation") != "REVOKE ALL HUMAN SESSIONS":
                    raise ServiceError(400, "global session revocation confirmation is invalid")
                revoked_count = service.store.one(
                    "SELECT COUNT(*) AS value FROM auth_sessions WHERE revoked=0")["value"]
                service.store.transaction_audited(((
                    "UPDATE auth_sessions SET revoked=1 WHERE revoked=0", ()),),
                    audit=self.audit_payload(actor, "admin.session.revoke_all", "success",
                                             details={"revoked":revoked_count}))
                return self.respond(200, {"status":"revoked", "revoked":revoked_count})

            if method == "PUT" and path == ["v1", "admin", "config"]:
                if not service.store.is_global_admin(actor):
                    raise ServiceError(403, "platform administrator required")
                data = self.read_json()
                try:
                    retention_hours = int(data.get("retention_hours"))
                    max_upload_mb = int(data.get("max_upload_mb"))
                    multipart_chunk_mb = int(data.get("multipart_chunk_mb", 32))
                    upload_session_hours = int(data.get("upload_session_hours", 24))
                    active_uploads = int(data.get("max_active_uploads_per_user", service.store.get_config(
                        "max_active_uploads_per_user", str(service.settings.max_active_uploads_per_user))))
                    staged_gb = int(data.get("max_staged_gb_per_user", int(service.store.get_config(
                        "max_staged_bytes_per_user", str(service.settings.max_staged_bytes_per_user))) // (1024 ** 3)))
                    min_free_gb = int(data.get("min_free_gb", int(service.store.get_config(
                        "min_free_bytes", str(service.settings.min_free_bytes))) // (1024 ** 3)))
                    clamav_port = int(data.get("clamav_port", 3310))
                except (TypeError, ValueError) as exc:
                    raise ServiceError(400, "numeric configuration is invalid") from exc
                scanners = str(data.get("scanners", "")).strip()
                scanner_names = {name.strip() for name in scanners.split(",") if name.strip()}
                if not 1 <= retention_hours <= 8760 or not 1 <= max_upload_mb <= 1048576:
                    raise ServiceError(400, "retention or upload limit is out of range")
                if not 1 <= multipart_chunk_mb <= 128 or not 1 <= upload_session_hours <= 168:
                    raise ServiceError(400, "multipart chunk size or upload session lifetime is out of range")
                if not 1 <= active_uploads <= 100 or not 1 <= staged_gb <= 1048576:
                    raise ServiceError(400, "upload concurrency or staging quota is out of range")
                if not 0 <= min_free_gb <= 1048576 or (service.settings.environment == "production" and min_free_gb < 1):
                    raise ServiceError(400, "storage safety reserve is out of range")
                if staged_gb * 1024 < max_upload_mb:
                    raise ServiceError(400, "user staging quota must be at least the single-file limit")
                if not scanner_names or not scanner_names.issubset({"mock", "clamav", "yara"}):
                    raise ServiceError(400, "scanner list must contain mock, clamav, or yara")
                if service.settings.environment == "production" and ("mock" in scanner_names or "clamav" not in scanner_names):
                    raise ServiceError(400, "production scanner policy requires clamav and forbids mock")
                if "clamav" in scanner_names and max_upload_mb * 1024 * 1024 > service.settings.clamav_stream_max_bytes:
                    raise ServiceError(400, "upload limit exceeds declared ClamAV StreamMaxLength")
                if not 1 <= clamav_port <= 65535:
                    raise ServiceError(400, "invalid ClamAV port")
                clamav_host = str(data.get("clamav_host", "127.0.0.1")).strip()
                yara_rules = str(data.get("yara_rules", "")).strip()
                if "clamav" in scanner_names and not clamav_host:
                    raise ServiceError(400, "ClamAV host is required")
                if "yara" in scanner_names and not yara_rules:
                    raise ServiceError(400, "YARA rules path is required")
                if "yara" in scanner_names and not Path(yara_rules).is_absolute():
                    raise ServiceError(400, "YARA rules path must be absolute")
                new_scanners = build_scanners(scanners, clamav_host, clamav_port, yara_rules)
                if service.settings.environment == "production":
                    unhealthy = [result for result in (scanner.health() for scanner in new_scanners)
                                 if result.status != "clean"]
                    if unhealthy:
                        raise ServiceError(503, "scanner configuration health check failed")
                values = {
                    "retention_seconds": str(retention_hours * 3600),
                    "max_upload_bytes": str(max_upload_mb * 1024 * 1024), "scanners": scanners,
                    "multipart_chunk_bytes": str(multipart_chunk_mb * 1024 * 1024),
                    "upload_session_ttl_seconds": str(upload_session_hours * 3600),
                    "max_active_uploads_per_user": str(active_uploads),
                    "max_staged_bytes_per_user": str(staged_gb * 1024 ** 3),
                    "min_free_bytes": str(min_free_gb * 1024 ** 3),
                    "clamav_host": clamav_host, "clamav_port": str(clamav_port), "yara_rules": yara_rules,
                }
                projected = {row["key"]:row["value"] for row in service.store.all(
                    "SELECT key,value FROM system_config ORDER BY key")}
                projected.update(values)
                observed_fingerprint = service.settings.configuration_fingerprint(
                    ({"key":key, "value":value} for key, value in sorted(projected.items())))
                accepted = (service.settings.environment != "production" or
                            observed_fingerprint == service.settings.expected_config_sha256)
                response_status = "updated" if accepted else "staged"
                updated_at = int(time.time())
                statements = tuple((
                    "INSERT INTO system_config(key,value,updated_at,updated_by) VALUES(?,?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                    (key, value, updated_at, actor),
                ) for key, value in values.items())
                service.store.transaction_audited(
                    statements, audit=self.audit_payload(
                        actor, "admin.config.update", "success",
                        details={"keys":sorted(values), "configuration_status":response_status,
                                 "observed_sha256":observed_fingerprint}))
                service.scanners = new_scanners
                return self.respond(200, {"status":response_status,
                                          "configuration_accepted":accepted,
                                          "observed_sha256":observed_fingerprint,
                                          "restart_required":not accepted})

            if method == "POST" and path == ["v1", "admin", "service-identities"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                data = self.read_json(); username = str(data.get("username", "")).strip()
                if (not username or len(username) > 64 or
                        not username.replace("-", "").replace("_", "").replace(".", "").isalnum()):
                    raise ServiceError(400, "invalid service identity username")
                if service.store.one("SELECT username FROM users WHERE username=?", (username,)):
                    raise ServiceError(409, "principal already exists")
                service.store.transaction_audited(((
                    "INSERT INTO users(username,global_admin,principal_type,enabled) VALUES(?,0,'service',1)",
                    (username,)),), audit=self.audit_payload(
                        actor, "admin.service_identity.create", "success", details={"username":username}))
                return self.respond(201, {"username":username, "principal_type":"service", "enabled":True})

            if method == "PUT" and len(path) == 4 and path[:3] == ["v1", "admin", "service-identities"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                principal = service.store.one("SELECT principal_type FROM users WHERE username=?", (path[3],))
                if not principal or principal["principal_type"] != "service":
                    raise ServiceError(404, "service identity not found")
                data = self.read_json()
                if not isinstance(data.get("enabled"), bool): raise ServiceError(400, "enabled must be boolean")
                statements = [("UPDATE users SET enabled=? WHERE username=?",
                               (int(data["enabled"]), path[3]))]
                if not data["enabled"]:
                    statements.extend((
                        ("UPDATE service_tokens SET revoked=1 WHERE username=?", (path[3],)),
                        ("UPDATE auth_sessions SET revoked=1 WHERE username=?", (path[3],)),
                    ))
                service.store.transaction_audited(
                    statements, audit=self.audit_payload(
                        actor, "admin.service_identity.update", "success",
                        details={"username":path[3], "enabled":data["enabled"]}))
                return self.respond(200, {"status":"updated"})

            if method == "POST" and path == ["v1", "admin", "users"]:
                if not service.store.is_global_admin(actor) or not isinstance(authenticator, LocalAuthenticator):
                    raise ServiceError(403, "local platform administrator required")
                data = self.read_json(); username = str(data.get("username", "")).strip(); password = str(data.get("password", ""))
                if not username or len(username) > 64 or not username.replace("-", "").replace("_", "").isalnum():
                    raise ServiceError(400, "invalid username")
                if len(password) < 8: raise ServiceError(400, "password must contain at least 8 characters")
                if "global_admin" in data and not isinstance(data["global_admin"], bool):
                    raise ServiceError(400, "global_admin must be boolean")
                if service.store.one("SELECT username FROM users WHERE username=?", (username,)):
                    raise ServiceError(409, "user already exists")
                try:
                    authenticator.mutate_account(
                        username, password=password, global_admin=bool(data.get("global_admin", False)),
                        create=True, audit=self.audit_payload(
                            actor, "admin.user.create", "success",
                            details={"username":username,
                                     "global_admin":bool(data.get("global_admin", False))}))
                except ValueError as exc: raise ServiceError(400, str(exc)) from exc
                return self.respond(201, {"username": username})

            if method == "PUT" and len(path) == 4 and path[:3] == ["v1", "admin", "users"]:
                if not service.store.is_global_admin(actor) or not isinstance(authenticator, LocalAuthenticator):
                    raise ServiceError(403, "local platform administrator required")
                username = path[3]; data = self.read_json()
                account = service.store.one("SELECT u.global_admin,a.enabled FROM users u JOIN local_accounts a ON a.username=u.username WHERE u.username=?", (username,))
                if not account: raise ServiceError(404, "local account not found")
                if username == actor and (data.get("enabled") is False or data.get("global_admin") is False):
                    raise ServiceError(409, "cannot disable or demote the current administrator")
                allowed = {"password", "enabled", "global_admin"}
                if not data or not set(data).issubset(allowed):
                    raise ServiceError(400, "local account update contains unsupported fields")
                if "enabled" in data and not isinstance(data["enabled"], bool):
                    raise ServiceError(400, "enabled must be boolean")
                if "global_admin" in data and not isinstance(data["global_admin"], bool):
                    raise ServiceError(400, "global_admin must be boolean")
                try:
                    authenticator.mutate_account(
                        username, password=(str(data["password"]) if "password" in data else None),
                        enabled=data.get("enabled"), global_admin=data.get("global_admin"),
                        audit=self.audit_payload(actor, "admin.user.update", "success",
                                                 details={"username":username,
                                                          "changed":sorted(data.keys())}))
                except ValueError as exc: raise ServiceError(400, str(exc)) from exc
                return self.respond(200, {"status": "updated"})

            if method == "PUT" and len(path) == 5 and path[:3] == ["v1", "admin", "users"] and path[4] == "approver":
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                username = path[3]; data = self.read_json()
                if not isinstance(data.get("approver"), bool): raise ServiceError(400, "approver must be boolean")
                account = service.store.one("SELECT principal_type,enabled FROM users WHERE username=?", (username,))
                if not account: raise ServiceError(404, "user not found")
                if account["principal_type"] != "human":
                    raise ServiceError(409, "the platform approver role belongs to a human identity")
                service.store.execute_audited(
                    "UPDATE users SET approver=? WHERE username=?",
                    (int(data["approver"]), username),
                    error="user disappeared during approver grant",
                    audit=self.audit_payload(actor, "admin.user.approver", "success",
                                             details={"username":username, "approver":data["approver"]}))
                return self.respond(200, {"username":username, "approver":data["approver"]})

            if method == "GET" and path == ["v1", "admin", "service-tokens"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                rows = service.store.all("SELECT * FROM service_tokens ORDER BY created_at DESC,id DESC LIMIT 500")
                self.audit(actor, "admin.service_token.list", "success", details={"count":len(rows)})
                return self.respond(200, {"tokens":[public_service_token(row) for row in rows]})

            if method == "POST" and path == ["v1", "admin", "service-tokens"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                data = self.read_json(); username = str(data.get("username", "")).strip()
                zone = str(data.get("zone", "")).strip()
                label = str(data.get("label", "")).strip()[:100]
                permissions = data.get("permissions", [])
                maximum_token_hours = service.settings.service_token_max_ttl_seconds // 3600
                try: expires_hours = int(data.get("expires_hours", min(720, maximum_token_hours)))
                except (TypeError, ValueError) as exc: raise ServiceError(400, "invalid token lifetime") from exc
                if not label or not 1 <= expires_hours <= maximum_token_hours or not isinstance(permissions, list):
                    raise ServiceError(400, "label, permissions, or token lifetime is invalid")
                if not service.store.one("SELECT username FROM users WHERE username=?", (username,)):
                    raise ServiceError(404, "service identity user not found")
                principal = service.store.one("SELECT principal_type,enabled FROM users WHERE username=?", (username,))
                if principal["principal_type"] != "service" or not principal["enabled"]:
                    raise ServiceError(409, "token owner must be an enabled service identity")
                normalized = set(str(value) for value in permissions)
                zone_permissions = {"green":{"inbound_upload","outbound_download"},
                                    "red":{"inbound_download","outbound_upload"}}
                deployed_permissions = ({"inbound_upload", "inbound_download"}
                                        if service.settings.deployment_mode == "inbound" else
                                        {"outbound_upload", "outbound_download"}
                                        if service.settings.deployment_mode == "outbound" else
                                        {"inbound_upload", "inbound_download", "outbound_upload", "outbound_download"})
                if zone not in zone_permissions or not normalized or not normalized.issubset(zone_permissions[zone]):
                    raise ServiceError(400, "service token permissions do not match its zone")
                if not normalized.issubset(deployed_permissions):
                    raise ServiceError(400, "service token scope belongs to a workflow not deployed here")
                raw, record = ServiceTokens(service.store).issue(
                    label=label, username=username, zone=zone,
                    permissions=normalized, expires_at=int(time.time()) + expires_hours * 3600, created_by=actor,
                    audit=self.audit_payload(actor, "admin.service_token.create", "success",
                                             details={"username":username, "zone":zone,
                                                      "permissions":sorted(normalized),
                                                      "expires_hours":expires_hours}),
                )
                response = public_service_token(record); response["token"] = raw
                return self.respond(201, response)

            if method == "DELETE" and len(path) == 4 and path[:3] == ["v1", "admin", "service-tokens"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                record = service.store.one("SELECT * FROM service_tokens WHERE id=?", (path[3],))
                if not record: raise ServiceError(404, "service token not found")
                service.store.execute_audited(
                    "UPDATE service_tokens SET revoked=1 WHERE id=?", (path[3],),
                    error="service token disappeared during revocation",
                     audit=self.audit_payload(actor, "admin.service_token.revoke", "success",
                                              details={"token_id":path[3]}))
                return self.respond(204)

            if method == "POST" and len(path) == 5 and path[:3] == ["v1", "admin", "objects"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                object_id, action = path[3], path[4]
                if action == "rescan": service.rescan(object_id)
                elif action == "expire": service.expire_object(object_id)
                else: raise ServiceError(404, "unknown object action")
                obj = service.get_object(object_id)
                self.audit(actor, f"admin.object.{action}", "success", object_id=object_id)
                return self.respond(202 if action == "rescan" else 200, public_object(obj))

            if method == "POST" and len(path) == 5 and path[:3] == ["v1", "admin", "outbound"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                transfer_id, action = path[3], path[4]
                if action == "rescan": service.rescan_outbound(transfer_id)
                elif action == "expire": service.expire_outbound(transfer_id)
                else: raise ServiceError(404, "unknown outbound action")
                transfer = service.get_outbound(transfer_id)
                self.audit(actor, f"admin.outbound.{action}", "success", object_id=transfer_id)
                return self.respond(202 if action == "rescan" else 200, public_outbound(transfer))

            if method == "GET" and path == ["v1", "objects"]:
                is_admin = service.store.is_global_admin(actor)
                if self.zone() == "red":
                    rows = service.store.all(
                        "SELECT * FROM objects WHERE state='released' AND (uploader=? OR ?) "
                        "ORDER BY created_at DESC,id DESC LIMIT 500", (actor, int(is_admin)))
                elif is_admin:
                    rows = service.store.all(
                        "SELECT * FROM objects ORDER BY created_at DESC,id DESC LIMIT 500")
                else:
                    rows = service.store.all(
                        "SELECT * FROM objects WHERE uploader=? ORDER BY created_at DESC,id DESC LIMIT 500",
                        (actor,))
                self.audit(actor, "object.list", "success", details={"count":len(rows)})
                return self.respond(200, {"objects": [public_object(row) for row in rows]})

            if method == "POST" and path == ["v1", "objects"]:
                if service.settings.environment == "production":
                    raise ServiceError(405, "direct uploads are disabled in production; use multipart upload sessions")
                if self.zone() != "green":
                    raise ServiceError(403, "uploads are accepted only from the green zone")
                service.require_source_ip("inbound", self.client_ip())
                filename = self.headers.get("X-Filename", "")
                if not service._valid_filename(filename):
                    raise ServiceError(400, "valid X-Filename header required")
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc:
                    raise ServiceError(400, "invalid Content-Length") from exc
                obj = service.upload(
                    filename, self.rfile, length, actor,
                    audit=self.audit_payload(actor, "object.upload", "accepted",
                                             details={"filename":filename, "size":length}))
                self._body_consumed = True
                return self.respond(202, public_object(obj), {"Location": f"/v1/objects/{obj['id']}"})

            if method == "GET" and len(path) == 3 and path[:2] == ["v1", "objects"]:
                obj = service.get_object(path[2])
                if obj["uploader"] != actor and not service.store.is_global_admin(actor):
                    raise ServiceError(404, "object not found")
                if self.zone() == "red" and obj["state"] != "released":
                    raise ServiceError(404, "object not found")
                self.audit(actor, "object.read_metadata", "success", path[2])
                return self.respond(200, public_object(obj))

            if method in {"GET", "HEAD"} and len(path) == 4 and path[:2] == ["v1", "objects"] and path[3] == "download":
                if self.zone() != "red":
                    raise ServiceError(403, "downloads are served only to the red zone")
                obj = service.object_for_download(path[2], actor)
                source = Path(obj["storage_path"])
                if not self.respond_download(obj, source, method): return
                self.audit(actor, "object.download", "success", path[2],
                           {"sha256": obj["sha256"], "size": obj["size"], "range": self.headers.get("Range")})
                return

            if method == "GET" and path == ["v1", "outbound"]:
                is_admin = service.store.is_global_admin(actor)
                sees_all = is_admin or service.store.is_approver(actor)
                if self.zone() == "green":
                    rows = service.store.all(
                        "SELECT * FROM outbound_transfers WHERE state='released_to_green' AND (uploader=? OR ?) "
                        "ORDER BY created_at DESC,id DESC LIMIT 500", (actor, int(sees_all)))
                elif sees_all:
                    rows = service.store.all(
                        "SELECT * FROM outbound_transfers ORDER BY created_at DESC,id DESC LIMIT 500")
                else:
                    rows = service.store.all(
                        "SELECT * FROM outbound_transfers WHERE uploader=? ORDER BY created_at DESC,id DESC LIMIT 500",
                        (actor,))
                self.audit(actor, "outbound.list", "success", details={"count":len(rows)})
                return self.respond(200, {"transfers": [public_outbound(row) for row in rows]})

            if method == "POST" and path == ["v1", "outbound"]:
                if service.settings.environment == "production":
                    raise ServiceError(405, "direct uploads are disabled in production; use multipart upload sessions")
                if self.zone() != "red": raise ServiceError(403, "outbound uploads are accepted only from the red zone")
                service.require_source_ip("outbound", self.client_ip())
                filename = self.headers.get("X-Filename", "")
                if not service._valid_filename(filename): raise ServiceError(400, "valid X-Filename header required")
                try: length = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc: raise ServiceError(400, "invalid Content-Length") from exc
                transfer = service.upload_outbound(
                    filename, self.rfile, length, actor,
                    audit=self.audit_payload(actor, "outbound.upload", "accepted",
                                             details={"filename":filename, "size":length}))
                self._body_consumed = True
                return self.respond(202, public_outbound(transfer))

            if method == "POST" and len(path) == 4 and path[:2] == ["v1", "outbound"] and path[3] == "decision":
                data = self.read_json()
                if self.zone() in {"green", "red"}:
                    raise ServiceError(403, "approval decisions are available only from the management plane")
                if not isinstance(data.get("approved"), bool): raise ServiceError(400, "approved must be boolean")
                transfer = service.decide_outbound(path[2], data["approved"], str(data.get("comment", ""))[:1000], actor)
                self.audit(actor, "outbound.approval.decision", "approved" if data["approved"] else "rejected", path[2])
                return self.respond(200, public_outbound(transfer))

            if method in {"GET", "HEAD"} and len(path) == 4 and path[:2] == ["v1", "outbound"] and path[3] == "download":
                if self.zone() != "green": raise ServiceError(403, "outbound downloads are served only to the green zone")
                transfer = service.outbound_for_download(path[2], actor); source = Path(transfer["storage_path"])
                if not self.respond_download(transfer, source, method): return
                self.audit(actor, "outbound.download", "success", path[2],
                           {"sha256":transfer["sha256"],"size":transfer["size"],"range":self.headers.get("Range")})
                return

            if method == "POST" and path == ["v1", "uploads"]:
                data = self.read_json(); direction = str(data.get("direction", ""))
                required_zone = "green" if direction == "inbound" else "red" if direction == "outbound" else ""
                if not required_zone or self.zone() != required_zone:
                    raise ServiceError(403, "upload session is not allowed from this zone")
                self.require_service_permission(identity, "inbound_upload" if direction == "inbound" else "outbound_upload")
                service.require_source_ip(direction, self.client_ip())
                try: total_size = int(data.get("total_size", 0))
                except (TypeError, ValueError) as exc: raise ServiceError(400, "invalid total_size") from exc
                session = service.create_upload_session(direction, str(data.get("filename", "")),
                                                        total_size, actor, data.get("expected_sha256"),
                                                        audit=self.audit_payload(
                                                            actor, "upload.session.create", "success",
                                                            details={"direction":direction,
                                                                     "filename":str(data.get("filename", "")),
                                                                     "size":total_size}))
                return self.respond(201, public_upload(session), {"Location": f"/v1/uploads/{session['id']}"})

            if method == "GET" and len(path) == 3 and path[:2] == ["v1", "uploads"]:
                session = service.get_upload_session(path[2], actor)
                expected_zone = "green" if session["direction"] == "inbound" else "red"
                if self.zone() in {"green", "red"} and self.zone() != expected_zone:
                    raise ServiceError(403, "upload session is not visible from this zone")
                self.audit(actor, "upload.session.read", "success", path[2],
                           {"direction":session["direction"], "state":session["state"]})
                return self.respond(200, public_upload(session))

            if method == "DELETE" and len(path) == 3 and path[:2] == ["v1", "uploads"]:
                session = service.get_upload_session(path[2], actor)
                expected_zone = "green" if session["direction"] == "inbound" else "red"
                if self.zone() in {"green", "red"} and self.zone() != expected_zone:
                    raise ServiceError(403, "upload cancellation is not allowed from this zone")
                service.cancel_upload_session(path[2], actor)
                self.audit(actor, "upload.session.cancel", "success", path[2],
                           {"direction": session["direction"]})
                return self.respond(204)

            if method == "PUT" and len(path) == 5 and path[:2] == ["v1", "uploads"] and path[3] == "parts":
                session = service.get_upload_session(path[2], actor)
                expected_zone = "green" if session["direction"] == "inbound" else "red"
                if self.zone() != expected_zone: raise ServiceError(403, "upload part is not allowed from this zone")
                service.require_source_ip(session["direction"], self.client_ip())
                try: part_number = int(path[4]); length = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc: raise ServiceError(400, "invalid part number or Content-Length") from exc
                part = service.put_upload_part(path[2], part_number, self.rfile, length,
                                               self.headers.get("X-Part-SHA256", ""), actor,
                                               audit=self.audit_payload(
                                                   actor, "upload.part.complete", "success",
                                                   path[2],
                                                   {"part_number":part_number, "size":length}))
                self._body_consumed = True
                return self.respond(200, part)

            if method == "POST" and len(path) == 4 and path[:2] == ["v1", "uploads"] and path[3] == "complete":
                session = service.get_upload_session(path[2], actor)
                expected_zone = "green" if session["direction"] == "inbound" else "red"
                if self.zone() != expected_zone: raise ServiceError(403, "upload completion is not allowed from this zone")
                service.require_source_ip(session["direction"], self.client_ip())
                record = service.complete_upload_session(path[2], actor)
                self.audit(actor, "upload.session.complete", "success", record["id"],
                           {"upload_id": path[2], "direction": session["direction"], "sha256": record["sha256"]})
                return self.respond(202, public_object(record) if session["direction"] == "inbound" else public_outbound(record))

            if method == "GET" and path == ["v1", "admin", "outbound-policy"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                policy = service.outbound_policy(); policy["allowed_classifications"] = json.loads(policy["allowed_classifications"])
                policy["local_approval_allowed"] = service.settings.allow_local_approval
                self.audit(actor, "outbound.policy.read", "success")
                return self.respond(200, policy)

            if method == "PUT" and path == ["v1", "admin", "outbound-policy"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                policy = service.set_outbound_policy(
                    self.read_json(), actor,
                    audit=self.audit_payload(actor, "outbound.policy.update", "success"))
                policy["allowed_classifications"] = json.loads(policy["allowed_classifications"])
                policy["local_approval_allowed"] = service.settings.allow_local_approval
                return self.respond(200, policy)

            if method == "GET" and path == ["v1", "admin", "network-policy"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                policy = service.network_policy()
                policy["inbound_upload_cidrs"] = json.loads(policy["inbound_upload_cidrs"])
                policy["outbound_upload_cidrs"] = json.loads(policy["outbound_upload_cidrs"])
                self.audit(actor, "platform.network_policy.read", "success")
                return self.respond(200, policy)

            if method == "PUT" and path == ["v1", "admin", "network-policy"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                policy = service.set_network_policy(
                    self.read_json(), actor,
                    audit=self.audit_payload(actor, "platform.network_policy.update", "success"))
                policy["inbound_upload_cidrs"] = json.loads(policy["inbound_upload_cidrs"])
                policy["outbound_upload_cidrs"] = json.loads(policy["outbound_upload_cidrs"])
                return self.respond(200, policy)

            if method == "GET" and path == ["v1", "admin", "audit"]:
                if not service.store.is_global_admin(actor): raise ServiceError(403, "platform administrator required")
                rows = service.store.all("SELECT * FROM audit_events ORDER BY id DESC LIMIT 500")
                self.audit(actor, "audit.list", "success", details={"count":len(rows)})
                return self.respond(200, {"events": rows})

            raise ServiceError(404, "route not found")

        def handle_method(self, method):
            self._body_consumed = False
            self._force_close = False
            self._request_method = method
            connection = getattr(self, "connection", None)
            if connection is not None:
                connection.settimeout(service.settings.request_io_timeout_seconds)
            try:
                self.validate_request_framing()
                if method not in {"GET", "POST", "PUT", "DELETE", "HEAD"}:
                    raise ServiceError(405, "method not allowed")
                self.dispatch(method)
            except AuthenticationError as exc:
                self.audit("anonymous", "request.authenticate", "denied", details={"reason": str(exc)})
                self.respond(401, {"error": "authentication failed"}, {"WWW-Authenticate": "Bearer"})
            except ServiceError as exc:
                actor = "unknown"
                try: actor = authenticator.authenticate(self.authentication_headers()).username
                except Exception: pass
                pieces = [unquote(piece) for piece in urlparse(self.path).path.split("/") if piece]
                object_id = pieces[2] if len(pieces) >= 3 and pieces[:2] in (["v1", "objects"], ["v1", "outbound"]) else None
                self.audit(actor, "request.denied", "denied", object_id=object_id,
                           details={"method": method, "status": exc.status, "reason": str(exc)})
                self.respond(exc.status, {"error": str(exc)})
            except (TimeoutError, socket.timeout):
                self.close_connection = True
                try:
                    self.audit("unknown", "request.timeout", "error",
                               details={"method": method})
                    self.respond(408, {"error": "request timed out"}, {"Connection": "close"})
                except Exception:
                    pass
            except Exception as exc:
                self.audit("unknown", "request.error", "error", details={"error": type(exc).__name__})
                self.respond(500, {"error": "internal server error"})
            finally:
                try: declared_body = int(self.headers.get("Content-Length", "0")) > 0
                except ValueError: declared_body = True
                if declared_body and not self._body_consumed:
                    # Never parse a subsequent keep-alive request after an unread body.
                    self.close_connection = True

        def do_GET(self): self.handle_method("GET")
        def do_POST(self): self.handle_method("POST")
        def do_PUT(self): self.handle_method("PUT")
        def do_PATCH(self): self.handle_method("PATCH")
        def do_DELETE(self): self.handle_method("DELETE")
        def do_HEAD(self): self.handle_method("HEAD")

    return Handler


def create_runtime(settings: Settings):
    settings.validate()
    if settings.environment == "production":
        _validate_production_data_tree(settings.data_dir)
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    settings.data_dir.chmod(0o700)
    store = Store(settings.data_dir / "sfss.db")
    _validate_deployment_database_scope(settings, store)
    fingerprint = settings.configuration_fingerprint(
        store.all("SELECT key,value FROM system_config ORDER BY key"))
    if settings.environment == "production" and fingerprint != settings.expected_config_sha256:
        raise ValueError(f"production configuration fingerprint mismatch; observed {fingerprint}")
    bootstrap_admins = {name.strip() for name in settings.bootstrap_admins.split(",") if name.strip()}
    if settings.environment == "production" and settings.auth_backend == "ldap":
        if store.one("SELECT username FROM local_accounts LIMIT 1"):
            raise ValueError("unsafe production identity database: local accounts must not be migrated into LDAP production")
        unexpected_admins = [row["username"] for row in store.all(
            "SELECT username FROM users WHERE global_admin=1 AND enabled=1 AND principal_type='human'")
            if row["username"] not in bootstrap_admins]
        if unexpected_admins:
            raise ValueError("unsafe production identity database: platform administrators are outside SFSS_BOOTSTRAP_ADMINS")
    revoked = store.one(
        "SELECT COUNT(*) AS value FROM auth_sessions WHERE revoked=0 AND auth_backend!=?",
        (settings.auth_backend,))["value"]
    if revoked:
        store.transaction_audited(((
            "UPDATE auth_sessions SET revoked=1 WHERE revoked=0 AND auth_backend!=?",
            (settings.auth_backend,)),), audit={
                "request_id":"startup-auth-backend-revoke", "actor":"system",
                "action":"session.backend_mismatch_revoked", "object_id":None,
                "outcome":"success", "source_zone":"startup", "remote_addr":"local",
                "details":{"revoked":revoked, "required_backend":settings.auth_backend}})
    if settings.environment == "production":
        revoked_zones = store.one(
            "SELECT COUNT(*) AS value FROM auth_sessions WHERE revoked=0 "
            "AND zone NOT IN ('green','red','admin')")["value"]
        if revoked_zones:
            store.transaction_audited(((
                "UPDATE auth_sessions SET revoked=1 WHERE revoked=0 "
                "AND zone NOT IN ('green','red','admin')", ()),), audit={
                    "request_id":"startup-session-zone-revoke", "actor":"system",
                    "action":"session.unbound_revoked", "object_id":None,
                    "outcome":"success", "source_zone":"startup", "remote_addr":"local",
                    "details":{"revoked":revoked_zones}})
        unsafe_token = store.one(
            "SELECT id FROM service_tokens WHERE revoked=0 AND expires_at>? "
            "AND (expires_at<=created_at OR expires_at-created_at>?) LIMIT 1",
            (int(time.time()), settings.service_token_max_ttl_seconds),
        )
        if unsafe_token:
            raise ValueError("unsafe production identity database: active service token lifetime exceeds policy")
    if settings.environment == "production" and store.one(
        "SELECT id FROM outbound_policy WHERE enabled=1 AND approval_provider='local' LIMIT 1"
    ):
        raise ValueError("unsafe persisted production policy: enabled local outbound approval")
    if store.one("SELECT id FROM outbound_policy WHERE enabled=1 AND approval_provider='wecom' LIMIT 1"):
        relay_errors = settings.approval_relay_errors()
        if relay_errors:
            raise ValueError("unsafe persisted approval relay configuration: " + "; ".join(relay_errors))
    if settings.auth_backend == "local":
        for item in settings.dev_users.split(","):
            username = item.partition(":")[0].strip()
            if username:
                store.ensure_user(username, global_admin=(username in bootstrap_admins))
    else:
        for username in bootstrap_admins:
            store.ensure_user(username, global_admin=True)
    scanners = build_scanners(
        store.get_config("scanners", settings.scanners),
        store.get_config("clamav_host", settings.clamav_host),
        int(store.get_config("clamav_port", str(settings.clamav_port))),
        store.get_config("yara_rules", settings.yara_rules),
    )
    if settings.environment == "production":
        for scanner in scanners:
            if scanner.name == "yara":
                try: observed = trusted_artifact_sha256(scanner.rules_path, "persisted YARA rules")
                except ValueError as exc: raise ValueError(str(exc)) from exc
                if not hmac.compare_digest(observed, settings.yara_rules_sha256):
                    raise ValueError("persisted YARA rules SHA-256 does not match accepted policy")
    if settings.environment == "production" and (any(scanner.name == "mock" for scanner in scanners)
                                                   or not any(scanner.name == "clamav" for scanner in scanners)):
        raise ValueError("unsafe persisted production scanner configuration")
    persisted_max_upload = int(store.get_config("max_upload_bytes", str(settings.max_upload_bytes)))
    if any(scanner.name == "clamav" for scanner in scanners) and persisted_max_upload > settings.clamav_stream_max_bytes:
        raise ValueError("persisted upload limit exceeds declared ClamAV StreamMaxLength")
    if settings.environment == "production":
        unhealthy = [result for result in (scanner.health() for scanner in scanners) if result.status != "clean"]
        if unhealthy:
            raise ValueError("production scanner dependency is unavailable: " +
                             ", ".join(f"{result.scanner}={result.detail}" for result in unhealthy))
    allowed_kinds = ({"scan_object"} if settings.deployment_mode == "inbound" else
                     {"scan_outbound"} if settings.deployment_mode == "outbound" else
                     {"scan_object", "scan_outbound"})
    queue = SQLiteJobQueue(store, settings.job_workers, settings.job_lease_seconds,
                           settings.job_max_attempts, allowed_kinds=allowed_kinds)
    service = SFSSService(settings, store, scanners, queue)
    return service


def _validate_deployment_database_scope(settings: Settings, store: Store):
    if settings.deployment_mode == "combined":
        return
    if settings.deployment_mode == "inbound":
        checks = (
            ("SELECT 1 FROM outbound_transfers LIMIT 1", "outbound transfer records"),
            ("SELECT 1 FROM outbound_policy LIMIT 1", "outbound policy"),
            ("SELECT 1 FROM upload_sessions WHERE direction='outbound' LIMIT 1", "outbound upload sessions"),
            ("SELECT 1 FROM scan_jobs WHERE kind='scan_outbound' LIMIT 1", "outbound scan jobs"),
            ("SELECT 1 FROM service_tokens WHERE permissions LIKE '%outbound_%' LIMIT 1", "outbound service tokens"),
        )
    else:
        checks = (
            ("SELECT 1 FROM objects LIMIT 1", "inbound object records"),
            ("SELECT 1 FROM upload_sessions WHERE direction='inbound' LIMIT 1", "inbound upload sessions"),
            ("SELECT 1 FROM scan_jobs WHERE kind='scan_object' LIMIT 1", "inbound scan jobs"),
            ("SELECT 1 FROM service_tokens WHERE permissions LIKE '%inbound_%' LIMIT 1", "inbound service tokens"),
        )
    for query, label in checks:
        if store.one(query):
            raise ValueError(f"deployment database scope violation: {label} exist in {settings.deployment_mode} system")


def _validate_production_data_tree(root: Path):
    try: root_metadata = os.lstat(root)
    except FileNotFoundError as exc:
        raise ValueError("production data directory must be initialized offline before startup") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise ValueError("production data directory must be a real directory, not a link")
    if stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise ValueError("production data directory permissions must be exactly 0700")
    database = root / "sfss.db"
    try: database_metadata = os.lstat(database)
    except FileNotFoundError as exc:
        raise ValueError("production database must be initialized offline before startup") from exc
    if (not stat.S_ISREG(database_metadata.st_mode) or stat.S_ISLNK(database_metadata.st_mode) or
            stat.S_IMODE(database_metadata.st_mode) != 0o600):
        raise ValueError("production database must be a mode-0600 regular non-link file")
    for path in root.rglob("*"):
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or
                                                 stat.S_ISREG(metadata.st_mode)):
            raise ValueError(f"production data tree contains an unsupported entry: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"production data tree permissions drifted: {path}")


def validate_bind_host(settings: Settings, host: str):
    if settings.environment != "production": return
    try: address = ipaddress.ip_address(host)
    except ValueError as exc: raise ValueError("production SFSS bind host must be a literal loopback address") from exc
    if not address.is_loopback:
        raise ValueError("production SFSS bind host must be loopback; expose only the blue mTLS gateway")


def validate_listener(settings: Settings, host, unix_socket):
    if unix_socket:
        path = Path(unix_socket)
        if not path.is_absolute(): raise ValueError("SFSS Unix socket path must be absolute")
        expected_parent = (Path("/run/sfss") if settings.deployment_mode == "combined" else
                           Path(f"/run/sfss-{settings.deployment_mode}"))
        if settings.environment == "production" and path.parent != expected_parent:
            raise ValueError(f"production SFSS Unix socket must be directly under {expected_parent}")
        return
    selected_host = host or "127.0.0.1"
    if settings.environment == "production":
        raise ValueError("production SFSS must use --unix-socket; TCP listeners are forbidden")
    validate_bind_host(settings, selected_host)


def shutdown_handler(server, stop_event):
    def handle(signum, _frame):
        stop_event.set()
        # BaseServer.shutdown must be called from a different thread than
        # serve_forever. Keep the signal handler itself non-blocking.
        threading.Thread(target=server.shutdown, name=f"sfss-shutdown-{signum}", daemon=True).start()
    return handle


def main():
    parser = argparse.ArgumentParser(description="SFSS foundation API")
    listeners = parser.add_mutually_exclusive_group()
    listeners.add_argument("--host")
    listeners.add_argument("--unix-socket")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    settings = Settings.from_env()
    validate_listener(settings, args.host, args.unix_socket)
    try: runtime_lock = acquire_runtime_lock(settings.data_dir)
    except OperationError as exc: raise SystemExit(str(exc))
    try: service = create_runtime(settings)
    except Exception:
        runtime_lock.close(); raise
    permission_stats = service.harden_existing_storage_permissions()
    if permission_stats["invalid"]:
        runtime_lock.close()
        raise SystemExit("storage integrity validation failed during startup")
    handlers = ({"scan_object":service.scan_object} if settings.deployment_mode == "inbound" else
                {"scan_outbound":service.scan_outbound} if settings.deployment_mode == "outbound" else
                {"scan_object":service.scan_object, "scan_outbound":service.scan_outbound})
    service.queue.start(handlers, service.fail_scan_job)
    service.recover_interrupted_jobs()
    try: service.run_maintenance()
    except Exception as exc: service.last_maintenance_error = type(exc).__name__

    maintenance_stop = threading.Event()

    def maintenance_worker():
        interval = max(5, settings.maintenance_interval_seconds)
        while not maintenance_stop.wait(interval):
            try: service.run_maintenance()
            except Exception as exc: service.last_maintenance_error = type(exc).__name__

    threading.Thread(target=maintenance_worker, name="sfss-maintenance", daemon=True).start()
    handler_type = make_handler(service, build_authenticator(settings, service.store))
    if args.unix_socket:
        socket_path = Path(args.unix_socket); prepare_unix_socket(socket_path)
        server = ThreadingUnixHTTPServer(str(socket_path), handler_type,
                                         max_request_workers=settings.max_request_workers)
        listener_description = f"unix:{socket_path}"
    else:
        selected_host = args.host or "127.0.0.1"
        server = BoundedThreadingHTTPServer((selected_host, args.port), handler_type,
                                            max_request_workers=settings.max_request_workers)
        listener_description = f"http://{selected_host}:{args.port}"
    handler = shutdown_handler(server, maintenance_stop)
    previous_sigterm = signal.signal(signal.SIGTERM, handler)
    previous_sigint = signal.signal(signal.SIGINT, handler)
    print(f"SFSS listening on {listener_description}; auth={settings.auth_backend}; scanners={','.join(s.name for s in service.scanners)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        maintenance_stop.set()
        server.server_close()
        if hasattr(service.queue, "stop"): service.queue.stop()
        runtime_lock.close()
        signal.signal(signal.SIGTERM, previous_sigterm)
        signal.signal(signal.SIGINT, previous_sigint)


if __name__ == "__main__":
    main()
