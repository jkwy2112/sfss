import io
import hashlib
import hmac
import json
import tempfile
import threading
import unittest
import socket
from email.message import Message
from pathlib import Path
from dataclasses import replace
from types import MethodType
from unittest.mock import patch

from sfss.auth import LocalAuthenticator
from sfss.approvals import relay_signature
from sfss.config import Settings
from sfss.db import Store
from sfss.jobs import InlineJobQueue
from sfss.scanners import MockScanner
from sfss.server import ThreadingUnixHTTPServer, make_handler, prepare_unix_socket, shutdown_handler
from sfss.service import SFSSService


class HttpTest(unittest.TestCase):
    def test_unix_listener_refuses_regular_path_and_cleans_owned_socket(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sfss.sock"; path.write_text("do not replace", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-socket"):
                prepare_unix_socket(path)
            path.unlink()
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); stale.bind(str(path)); stale.close()
            prepare_unix_socket(path)
            self.assertFalse(path.exists())
            server = ThreadingUnixHTTPServer(str(path), self.handler_type)
            self.assertEqual(0o660, path.stat().st_mode & 0o777)
            server.server_close()
            self.assertFalse(path.exists())

    def test_unix_listener_rejects_connection_when_worker_limit_is_exhausted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sfss.sock"
            server = ThreadingUnixHTTPServer(str(path), self.handler_type,
                                             max_request_workers=1)
            server._request_slots.acquire()
            accepted, peer = socket.socketpair()
            try:
                server.process_request(accepted, "local")
                self.assertEqual(1, server.rejected_connections)
                peer.settimeout(1)
                self.assertEqual(b"", peer.recv(1))
            finally:
                peer.close()
                server._request_slots.release()
                server.server_close()

    def test_shutdown_signal_requests_nonblocking_server_stop(self):
        stopped = threading.Event(); maintenance = threading.Event()
        class FakeServer:
            def shutdown(self): stopped.set()
        handler = shutdown_handler(FakeServer(), maintenance)
        handler(15, None)
        self.assertTrue(maintenance.is_set())
        self.assertTrue(stopped.wait(2))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        settings = Settings(data_dir=Path(self.temp.name), retention_seconds=60,
                            multipart_chunk_bytes=1024 * 1024)
        store = Store(settings.data_dir / "sfss.db")
        store.ensure_user("admin", True)
        store.ensure_user("alice")
        store.ensure_user("charlie")
        store.ensure_user("reader")
        store.ensure_user("approver")
        store.execute("UPDATE users SET approver=1 WHERE username='approver'")
        service = SFSSService(settings, store, [MockScanner()], InlineJobQueue())
        service.set_outbound_policy({"enabled": True, "approval_provider": "local",
                                     "allowed_classifications": ["GENERAL"],
                                     "approval_timeout_hours": 24, "download_ttl_hours": 24}, "admin")
        service.run_maintenance()
        auth = LocalAuthenticator({"a": "alice", "c": "charlie", "r": "reader", "p": "approver"}, {"admin": "admin123"}, store)
        self.auth = auth
        self.handler_type = make_handler(service, auth)
        self.service = service

    def tearDown(self):
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None, client_address="127.0.0.1"):
        # Exercise the real request dispatcher without opening a listening socket.
        handler = object.__new__(self.handler_type)
        handler.path = path
        handler.client_address = (client_address, 12345)
        handler.rfile = io.BytesIO(body or b"")
        handler.wfile = io.BytesIO()
        handler.headers = Message()
        for key, value in (headers or {}).items():
            if isinstance(value, (list, tuple)):
                for item in value: handler.headers.add_header(key, item)
            else:
                handler.headers[key] = value
        captured = {"status": None, "headers": {}}
        handler.send_response = MethodType(lambda this, status: captured.update(status=status), handler)
        handler.send_header = MethodType(lambda this, key, value: captured["headers"].__setitem__(key, value), handler)
        handler.end_headers = MethodType(lambda this: None, handler)
        handler.handle_method(method)
        return captured["status"], captured["headers"], handler.wfile.getvalue()

    def test_green_upload_then_red_download(self):
        body = b"design handoff"
        status, headers, payload = self.request("POST", "/v1/objects", body, {
            "Authorization": "Bearer a", "X-SFSS-Zone": "green", "X-Filename": "design.txt",
            "Content-Length": str(len(body)),
        })
        self.assertEqual(202, status)
        obj = json.loads(payload)
        self.assertEqual("released", obj["state"])
        status, _, downloaded = self.request("GET", f"/v1/objects/{obj['id']}/download", headers={
            "Authorization": "Bearer a", "X-SFSS-Zone": "red",
        })
        self.assertEqual(200, status)
        self.assertEqual(body, downloaded)

    def test_request_io_timeout_fails_closed_and_is_audited(self):
        with patch.object(self.handler_type, "dispatch", side_effect=TimeoutError):
            status, headers, payload = self.request("GET", "/health")
        self.assertEqual(408, status)
        self.assertEqual("close", headers["Connection"])
        self.assertEqual("request timed out", json.loads(payload)["error"])
        event = self.service.store.one(
            "SELECT action,outcome FROM audit_events ORDER BY id DESC LIMIT 1")
        self.assertEqual(("request.timeout", "error"), (event["action"], event["outcome"]))

    def test_zone_metadata_visibility_is_owner_only(self):
        released = self.service.upload("owned.txt", io.BytesIO(b"owned safe text"), 15, "alice")
        quarantined = self.service.upload("unknown.bin", io.BytesIO(b"\x00\x01\x02\x03"), 4, "alice")
        status, _, _ = self.request("GET", f"/v1/objects/{released['id']}", headers={
            "Authorization":"Bearer c", "X-SFSS-Zone":"green"})
        self.assertEqual(404, status)
        status, _, _ = self.request("GET", f"/v1/objects/{quarantined['id']}", headers={
            "Authorization":"Bearer r", "X-SFSS-Zone":"red"})
        self.assertEqual(404, status)
        status, _, _ = self.request("GET", f"/v1/objects/{released['id']}", headers={
            "Authorization":"Bearer r", "X-SFSS-Zone":"red"})
        self.assertEqual(404, status)  # only the uploader may see their own object
        status, _, payload = self.request("GET", f"/v1/objects/{released['id']}", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"red"})
        self.assertEqual(200, status)
        self.assertEqual(released["id"], json.loads(payload)["id"])
        status, _, payload = self.request("GET", "/v1/objects", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"red"})
        self.assertEqual(["owned.txt"],
                         [item["filename"] for item in json.loads(payload)["objects"]])

    def test_production_rejects_legacy_direct_upload_routes(self):
        original = self.service.settings
        secret = Path(self.temp.name) / "legacy-route-manifest.key"
        secret.write_text("m" * 32, encoding="utf-8"); secret.chmod(0o600)
        candidate = replace(original, environment="production", manifest_hmac_key="m" * 32,
                            manifest_hmac_key_file=str(secret), expected_config_sha256="0" * 64)
        self.service.settings = replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.service.store.all("SELECT key,value FROM system_config ORDER BY key")))
        try:
            for path, zone in (("/v1/objects", "green"),
                               ("/v1/outbound", "red")):
                status, _, payload = self.request("POST", path, b"data", {
                    "Authorization":"Bearer a", "X-SFSS-Zone":zone,
                    "X-Filename":"direct.txt", "Content-Length":"4",
                })
                self.assertEqual(405, status)
                self.assertIn("multipart", json.loads(payload)["error"])
        finally:
            self.service.settings = original

    def test_resumable_multipart_upload_and_range_download(self):
        body = (b"A" * (1024 * 1024)) + b"resume-tail"
        whole_hash = hashlib.sha256(body).hexdigest()
        create = json.dumps({"direction":"inbound","filename":"large.txt","total_size":len(body),
                             "expected_sha256":whole_hash}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", create, {
            "Authorization":"Bearer a","X-SFSS-Zone":"green","Content-Type":"application/json",
            "Content-Length":str(len(create)),
        })
        self.assertEqual(201, status); session = json.loads(payload)
        self.assertEqual(2, session["part_count"])
        first, second = body[:session["chunk_size"]], body[session["chunk_size"]:]
        for number, part in ((1, first), (2, second)):
            status, _, _ = self.request("PUT", f"/v1/uploads/{session['id']}/parts/{number}", part, {
                "Authorization":"Bearer a","X-SFSS-Zone":"green","Content-Length":str(len(part)),
                "X-Part-SHA256":hashlib.sha256(part).hexdigest(),
            })
            self.assertEqual(200, status)
        status, _, payload = self.request("GET", f"/v1/uploads/{session['id']}", headers={"Authorization":"Bearer a"})
        self.assertEqual(len(body), json.loads(payload)["received_bytes"])
        status, _, payload = self.request("POST", f"/v1/uploads/{session['id']}/complete", headers={
            "Authorization":"Bearer a","X-SFSS-Zone":"green",
        })
        self.assertEqual(202, status); obj = json.loads(payload); self.assertEqual("released", obj["state"])
        status, headers, downloaded = self.request("GET", f"/v1/objects/{obj['id']}/download", headers={
            "Authorization":"Bearer a","X-SFSS-Zone":"red","Range":"bytes=1048576-",
            "If-Range":f'"{whole_hash}"',
        })
        self.assertEqual(206, status); self.assertEqual(second, downloaded)
        self.assertEqual(f"bytes 1048576-{len(body)-1}/{len(body)}", headers["Content-Range"])
        self.assertEqual("bytes", headers["Accept-Ranges"])

    def test_bad_part_hash_is_rejected_without_progress(self):
        create = json.dumps({"direction":"inbound","filename":"bad.txt","total_size":4}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", create, {
            "Authorization":"Bearer a","X-SFSS-Zone":"green","Content-Type":"application/json",
            "Content-Length":str(len(create)),
        })
        self.assertEqual(201, status); upload_id = json.loads(payload)["id"]
        status, _, _ = self.request("PUT", f"/v1/uploads/{upload_id}/parts/1", b"data", {
            "Authorization":"Bearer a","X-SFSS-Zone":"green","Content-Length":"4","X-Part-SHA256":"0" * 64,
        })
        self.assertEqual(422, status)
        status, _, payload = self.request("GET", f"/v1/uploads/{upload_id}", headers={"Authorization":"Bearer a"})
        self.assertEqual(0, json.loads(payload)["received_bytes"])

    def test_outbound_multipart_enters_approval_pipeline(self):
        body = b"red multipart handoff"
        create = json.dumps({"direction":"outbound","filename":"handoff.txt","total_size":len(body)}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", create, {
            "Authorization":"Bearer a","X-SFSS-Zone":"red","Content-Type":"application/json",
            "Content-Length":str(len(create)),
        })
        self.assertEqual(201, status); session = json.loads(payload)
        status, _, _ = self.request("PUT", f"/v1/uploads/{session['id']}/parts/1", body, {
            "Authorization":"Bearer a","X-SFSS-Zone":"red","Content-Length":str(len(body)),
            "X-Part-SHA256":hashlib.sha256(body).hexdigest(),
        })
        self.assertEqual(200, status)
        status, _, payload = self.request("POST", f"/v1/uploads/{session['id']}/complete", headers={
            "Authorization":"Bearer a","X-SFSS-Zone":"red",
        })
        self.assertEqual(202, status); self.assertEqual("pending_approval", json.loads(payload)["state"])

    def test_upload_session_can_be_cancelled(self):
        create = json.dumps({"direction":"inbound","filename":"cancel.txt","total_size":4}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", create, {
            "Authorization":"Bearer a","X-SFSS-Zone":"green","Content-Type":"application/json",
            "Content-Length":str(len(create)),
        })
        upload_id = json.loads(payload)["id"]
        status, _, _ = self.request("GET", f"/v1/uploads/{upload_id}", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"red"})
        self.assertEqual(403, status)
        status, _, _ = self.request("DELETE", f"/v1/uploads/{upload_id}", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"red"})
        self.assertEqual(403, status)
        status, _, _ = self.request("DELETE", f"/v1/uploads/{upload_id}", headers={"Authorization":"Bearer a"})
        self.assertEqual(204, status)
        status, _, payload = self.request("GET", f"/v1/uploads/{upload_id}", headers={"Authorization":"Bearer a"})
        self.assertEqual("cancelled", json.loads(payload)["state"])

    def test_zone_portals_are_available(self):
        for path, title in (("/green", "登录绿区文件门户"), ("/red", "登录红区文件门户"), ("/admin", "管理员后台")):
            status, _, page = self.request("GET", path)
            self.assertEqual(200, status)
            if path == "/admin": self.assertIn("管理员后台".encode(), page)
            else:
                status, _, script = self.request("GET", "/app.js")
                self.assertEqual(200, status); self.assertIn(title.encode(), script)

    def test_range_request_rejects_invalid_offset(self):
        body = b"range content"
        status, _, payload = self.request("POST", "/v1/objects", body, {
            "Authorization":"Bearer a","X-SFSS-Zone":"green","X-Filename":"range.txt","Content-Length":str(len(body)),
        })
        obj = json.loads(payload)
        status, headers, _ = self.request("GET", f"/v1/objects/{obj['id']}/download", headers={
            "Authorization":"Bearer a","X-SFSS-Zone":"red","Range":"bytes=999-1000",
        })
        self.assertEqual(416, status); self.assertEqual(f"bytes */{len(body)}", headers["Content-Range"])

    def test_download_manifest_is_signed_when_key_is_configured(self):
        obj = self.service.upload("signed.txt", io.BytesIO(b"signed payload"), 14, "alice")
        settings = replace(self.service.settings, manifest_hmac_key="k" * 32)
        service = SFSSService(settings, self.service.store, [MockScanner()], InlineJobQueue())
        original = self.handler_type; self.handler_type = make_handler(service, self.auth)
        try:
            status, headers, _ = self.request("GET", f"/v1/objects/{obj['id']}/download", headers={
                "Authorization":"Bearer a","X-SFSS-Zone":"red",
            })
        finally:
            self.handler_type = original
        manifest = f'{obj["id"]}\n14\n{obj["sha256"]}'
        expected = hmac.new(("k" * 32).encode(), manifest.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(200, status); self.assertEqual(expected, headers["X-SFSS-Manifest-Signature"])

    def test_wrong_zone_and_missing_auth_are_denied(self):
        status, _, _ = self.request("POST", "/v1/objects", b"x", {
            "Authorization": "Bearer a", "X-SFSS-Zone": "red", "X-Filename": "x.txt",
            "Content-Length": "1",
        })
        self.assertEqual(403, status)
        status, _, _ = self.request("GET", "/v1/admin/audit")
        self.assertEqual(401, status)

    def test_trusted_gateway_boundary_and_forwarded_client_ip(self):
        settings = replace(self.service.settings, require_trusted_proxy=True,
                           trusted_zone_proxy_cidrs="10.30.0.0/24", require_forwarded_https=True)
        service = SFSSService(settings, self.service.store, [MockScanner()], InlineJobQueue())
        service.run_maintenance()
        handler_type = make_handler(service, self.auth)
        original = self.handler_type; self.handler_type = handler_type
        try:
            status, _, _ = self.request("GET", "/v1/objects", headers={"Authorization":"Bearer a","X-SFSS-Zone":"green"})
            self.assertEqual(403, status)
            status, _, _ = self.request("GET", "/v1/objects", headers={
                "Authorization":"Bearer a","X-SFSS-Zone":"green","X-Forwarded-Proto":"https",
                "X-Forwarded-For":"127.0.0.1","X-SFSS-Gateway-Role":"green",
            }, client_address="10.30.0.9")
            self.assertEqual(200, status)
            policy = json.dumps({"inbound_upload_cidrs":["10.0.0.0/8"]}).encode()
            status, _, _ = self.request("PUT", "/v1/admin/network-policy", policy, headers={
                "Authorization":"Bearer admin","X-SFSS-Zone":"green","X-Forwarded-Proto":"https",
                "X-Forwarded-For":"127.0.0.1","X-SFSS-Gateway-Role":"green",
                "Content-Type":"application/json","Content-Length":str(len(policy)),
            }, client_address="10.30.0.9")
            self.assertEqual(403, status)
            callback = b"{}"
            status, _, _ = self.request("POST", "/v1/integrations/wecom/callback", callback, headers={
                "X-Forwarded-Proto":"https", "X-Forwarded-For":"127.0.0.1",
                "X-SFSS-Gateway-Role":"green", "X-SFSS-Zone":"green",
                "Content-Type":"application/json", "Content-Length":str(len(callback)),
            }, client_address="10.30.0.9")
            self.assertEqual(403, status)
            for path in ("/ready", "/metrics"):
                status, _, _ = self.request("GET", path, headers={
                    "X-Forwarded-Proto":"https", "X-Forwarded-For":"127.0.0.1",
                    "X-SFSS-Gateway-Role":"green", "X-SFSS-Zone":"green",
                }, client_address="10.30.0.9")
                self.assertEqual(403, status)
            status, _, _ = self.request("GET", "/ready", headers={
                "X-Forwarded-Proto":"https", "X-Forwarded-For":"127.0.0.1",
                "X-SFSS-Gateway-Role":"admin",
            }, client_address="10.30.0.9")
            self.assertEqual(200, status)
        finally:
            self.handler_type = original

    def test_web_console_and_local_login(self):
        status, headers, page = self.request("GET", "/")
        self.assertEqual(200, status)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("登录控制台".encode("utf-8"), page)
        body = json.dumps({"username": "admin", "password": "admin123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", body, {
            "Content-Type": "application/json", "Content-Length": str(len(body)),
        })
        self.assertEqual(200, status)
        token = json.loads(payload)["token"]
        status, _, payload = self.request("GET", "/v1/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, status)
        self.assertEqual("admin", json.loads(payload)["username"])
        self.assertTrue(json.loads(payload)["global_admin"])

    def test_login_session_cannot_be_replayed_between_green_and_red(self):
        body = json.dumps({"username": "admin", "password": "admin123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", body, {
            "Content-Type":"application/json", "Content-Length":str(len(body)),
            "X-SFSS-Zone":"green",
        })
        self.assertEqual(200, status)
        login = json.loads(payload); self.assertEqual("green", login["session_zone"])
        headers = {"Authorization":f"Bearer {login['token']}", "X-SFSS-Zone":"green"}
        self.assertEqual(200, self.request("GET", "/v1/objects", headers=headers)[0])
        headers["X-SFSS-Zone"] = "red"
        self.assertEqual(401, self.request("GET", "/v1/objects", headers=headers)[0])
        headers["X-SFSS-Zone"] = "green"
        self.assertEqual(200, self.request("GET", "/v1/objects", headers=headers)[0])

    def test_bad_local_password_is_rejected(self):
        body = json.dumps({"username": "admin", "password": "wrong"}).encode()
        status, _, _ = self.request("POST", "/v1/auth/login", body, {
            "Content-Type": "application/json", "Content-Length": str(len(body)),
        })
        self.assertEqual(401, status)

    def test_admin_overview_is_global_admin_only(self):
        body = json.dumps({"username": "admin", "password": "admin123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", body, {
            "Content-Type": "application/json", "Content-Length": str(len(body)),
        })
        token = json.loads(payload)["token"]
        status, _, payload = self.request("GET", "/v1/admin/overview", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, status)
        overview = json.loads(payload)
        self.assertGreaterEqual(overview["counts"]["users"], 3)
        status, _, _ = self.request("GET", "/v1/admin/overview", headers={"Authorization": "Bearer a"})
        self.assertEqual(403, status)
        status, _, _ = self.request("GET", "/v1/admin/sessions", headers={"Authorization": "Bearer a"})
        self.assertEqual(403, status)

    def admin_token(self):
        body = json.dumps({"username": "admin", "password": "admin123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", body, {
            "Content-Type": "application/json", "Content-Length": str(len(body)),
        })
        self.assertEqual(200, status)
        return json.loads(payload)["token"]

    def test_admin_can_persist_policy_and_manage_local_user(self):
        token = self.admin_token()
        status, _, payload = self.request("GET", "/v1/admin/outbound-policy", headers={
            "Authorization":f"Bearer {token}"})
        self.assertEqual(200, status)
        self.assertTrue(json.loads(payload)["local_approval_allowed"])
        config = json.dumps({"retention_hours": 24, "max_upload_mb": 8, "min_free_gb": 2, "scanners": "mock",
                             "clamav_host": "127.0.0.1", "clamav_port": 3310, "yara_rules": ""}).encode()
        status, _, payload = self.request("PUT", "/v1/admin/config", config, {
            "Authorization": f"Bearer {token}", "Content-Type": "application/json", "Content-Length": str(len(config)),
        })
        self.assertEqual(200, status)
        update = json.loads(payload)
        self.assertEqual("updated", update["status"])
        self.assertTrue(update["configuration_accepted"])
        self.assertFalse(update["restart_required"])
        status, _, payload = self.request("GET", "/v1/admin/config", headers={"Authorization": f"Bearer {token}"})
        saved = json.loads(payload)
        self.assertEqual(24, saved["retention_hours"])
        self.assertEqual(2, saved["min_free_gb"])
        self.assertEqual(720, saved["service_token_max_hours"])
        user = json.dumps({"username": "bob", "password": "bob-pass-123", "global_admin": False}).encode()
        status, _, _ = self.request("POST", "/v1/admin/users", user, {
            "Authorization": f"Bearer {token}", "Content-Type": "application/json", "Content-Length": str(len(user)),
        })
        self.assertEqual(201, status)
        self.assertTrue(self.auth.login("bob", "bob-pass-123"))

    def test_admin_can_inspect_and_revoke_user_sessions_without_token_hash_disclosure(self):
        admin = self.admin_token()
        create = json.dumps({"username":"bob", "password":"bob-pass-123", "global_admin":False}).encode()
        status, _, _ = self.request("POST", "/v1/admin/users", create, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(create)),
        })
        self.assertEqual(201, status)
        login = json.dumps({"username":"bob", "password":"bob-pass-123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", login, {
            "Content-Type":"application/json", "Content-Length":str(len(login)),
        })
        self.assertEqual(200, status); bob = json.loads(payload)["token"]
        status, _, payload = self.request("GET", "/v1/admin/sessions", headers={
            "Authorization":f"Bearer {admin}"})
        self.assertEqual(200, status); document = json.loads(payload)
        self.assertIn("bob", [row["username"] for row in document["sessions"]])
        self.assertNotIn("token_hash", payload.decode())

        bad = json.dumps({"confirmation":"wrong"}).encode()
        status, _, _ = self.request("POST", "/v1/admin/users/bob/revoke-sessions", bad, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(bad)),
        })
        self.assertEqual(400, status)
        confirmation = json.dumps({"confirmation":"bob"}).encode()
        status, _, payload = self.request("POST", "/v1/admin/users/bob/revoke-sessions", confirmation, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(confirmation)),
        })
        self.assertEqual(200, status); self.assertEqual(1, json.loads(payload)["revoked"])
        self.assertEqual(401, self.request("GET", "/v1/me", headers={
            "Authorization":f"Bearer {bob}"})[0])
        self.assertEqual(200, self.request("GET", "/v1/me", headers={
            "Authorization":f"Bearer {admin}"})[0])

    def test_global_emergency_session_revocation_requires_phrase_and_revokes_caller(self):
        admin = self.admin_token()
        invalid = json.dumps({"confirmation":"revoke"}).encode()
        status, _, _ = self.request("POST", "/v1/admin/sessions/revoke-all", invalid, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(invalid)),
        })
        self.assertEqual(400, status)
        self.assertEqual(200, self.request("GET", "/v1/me", headers={
            "Authorization":f"Bearer {admin}"})[0])
        body = json.dumps({"confirmation":"REVOKE ALL HUMAN SESSIONS"}).encode()
        status, _, payload = self.request("POST", "/v1/admin/sessions/revoke-all", body, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(body)),
        })
        self.assertEqual(200, status); self.assertGreaterEqual(json.loads(payload)["revoked"], 1)
        self.assertEqual(401, self.request("GET", "/v1/me", headers={
            "Authorization":f"Bearer {admin}"})[0])
        event = self.service.store.one(
            "SELECT action,outcome FROM audit_events WHERE action='admin.session.revoke_all' ORDER BY id DESC LIMIT 1")
        self.assertEqual({"action":"admin.session.revoke_all", "outcome":"success"}, event)

    def test_zone_scoped_service_token_cannot_escape_scope(self):
        admin = self.admin_token()
        identity_body = json.dumps({"username":"green-agent"}).encode()
        status, _, _ = self.request("POST", "/v1/admin/service-identities", identity_body, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(identity_body)),
        })
        self.assertEqual(201, status)
        excessive = json.dumps({"label":"too long", "username":"green-agent",
                                "zone":"green", "permissions":["inbound_upload"],
                                "expires_hours":721}).encode()
        status, _, _ = self.request("POST", "/v1/admin/service-tokens", excessive, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(excessive)),
        })
        self.assertEqual(400, status)
        cross_zone = json.dumps({"label":"cross zone", "username":"green-agent",
                                 "zone":"green", "permissions":["outbound_upload"],
                                 "expires_hours":24}).encode()
        status, _, _ = self.request("POST", "/v1/admin/service-tokens", cross_zone, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(cross_zone)),
        })
        self.assertEqual(400, status)
        body = json.dumps({"label":"green uploader", "username":"green-agent",
                           "zone":"green", "permissions":["inbound_upload"], "expires_hours":24}).encode()
        status, _, payload = self.request("POST", "/v1/admin/service-tokens", body, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(body)),
        })
        self.assertEqual(201, status); issued = json.loads(payload); token = issued["token"]
        row = self.service.store.one("SELECT token_hash FROM service_tokens WHERE id=?", (issued["id"],))
        self.assertNotEqual(token, row["token_hash"])

        headers = {"Authorization":f"Bearer {token}", "X-SFSS-Zone":"green",
                   "X-Filename":"agent.txt", "Content-Length":"10"}
        status, _, payload = self.request("POST", "/v1/objects", b"agent data", headers)
        self.assertEqual(202, status); object_id = json.loads(payload)["id"]
        status, _, _ = self.request("GET", f"/v1/objects/{object_id}/download", headers={
            "Authorization":f"Bearer {token}", "X-SFSS-Zone":"red"})
        self.assertEqual(403, status)  # upload scope cannot download
        status, _, _ = self.request("GET", "/v1/admin/overview", headers={
            "Authorization":f"Bearer {token}", "X-SFSS-Zone":"green"})
        self.assertEqual(403, status)
        self.service.store.execute("UPDATE users SET enabled=0 WHERE username='green-agent'")
        status, _, _ = self.request("POST", "/v1/objects", b"agent data", headers)
        self.assertEqual(401, status)  # identity disable kills every derived token
        self.service.store.execute("UPDATE users SET enabled=1 WHERE username='green-agent'")
        status, _, _ = self.request("DELETE", f"/v1/admin/service-tokens/{issued['id']}", headers={
            "Authorization":f"Bearer {admin}"})
        self.assertEqual(204, status)
        status, _, _ = self.request("GET", "/v1/objects", headers={
            "Authorization":f"Bearer {token}", "X-SFSS-Zone":"green"})
        self.assertEqual(401, status)

    def test_service_tokens_require_non_interactive_identity_and_disable_revokes(self):
        admin = self.admin_token()
        human_body = json.dumps({"label":"invalid", "username":"alice",
                                 "zone":"green", "permissions":["inbound_upload"],
                                 "expires_hours":24}).encode()
        status, _, _ = self.request("POST", "/v1/admin/service-tokens", human_body, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(human_body)),
        })
        self.assertEqual(409, status)

        identity_body = json.dumps({"username":"disabled-agent"}).encode()
        status, _, _ = self.request("POST", "/v1/admin/service-identities", identity_body, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(identity_body)),
        })
        self.assertEqual(201, status)
        issue_body = json.dumps({"label":"disable test", "username":"disabled-agent",
                                 "zone":"green", "permissions":["inbound_upload"],
                                 "expires_hours":24}).encode()
        status, _, payload = self.request("POST", "/v1/admin/service-tokens", issue_body, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(issue_body)),
        })
        self.assertEqual(201, status); service_token = json.loads(payload)["token"]
        login_body = json.dumps({"username":"disabled-agent", "password":"not-a-real-password"}).encode()
        status, _, _ = self.request("POST", "/v1/auth/login", login_body, {
            "Content-Type":"application/json", "Content-Length":str(len(login_body)),
        })
        self.assertEqual(401, status)

        disable_body = json.dumps({"enabled":False}).encode()
        status, _, _ = self.request("PUT", "/v1/admin/service-identities/disabled-agent", disable_body, {
            "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
            "Content-Length":str(len(disable_body)),
        })
        self.assertEqual(200, status)
        status, _, _ = self.request("GET", "/v1/objects", headers={
            "Authorization":f"Bearer {service_token}", "X-SFSS-Zone":"green"})
        self.assertEqual(401, status)

    def test_red_upload_requires_red_zone_and_green_download_requires_green_zone(self):
        body = b"outbound general text"
        headers = {"Authorization": "Bearer a", "X-SFSS-Zone": "green", "X-Filename": "out.txt", "Content-Length": str(len(body))}
        status, _, _ = self.request("POST", "/v1/outbound", body, headers)
        self.assertEqual(403, status)
        headers["X-SFSS-Zone"] = "red"
        status, _, payload = self.request("POST", "/v1/outbound", body, headers)
        self.assertEqual(202, status); transfer = json.loads(payload)
        decision = json.dumps({"approved": True, "comment": "ok"}).encode()
        status, _, _ = self.request("POST", f"/v1/outbound/{transfer['id']}/decision", decision, {
            "Authorization": "Bearer p", "Content-Type": "application/json", "Content-Length": str(len(decision)),
        })
        self.assertEqual(200, status)
        status, _, _ = self.request("GET", f"/v1/outbound/{transfer['id']}/download", headers={"Authorization":"Bearer a","X-SFSS-Zone":"red"})
        self.assertEqual(403, status)
        status, _, _ = self.request("GET", f"/v1/outbound/{transfer['id']}/download", headers={"Authorization":"Bearer r","X-SFSS-Zone":"green"})
        self.assertEqual(404, status)  # only the submitting user may receive the release
        status, _, downloaded = self.request("GET", f"/v1/outbound/{transfer['id']}/download", headers={"Authorization":"Bearer a","X-SFSS-Zone":"green"})
        self.assertEqual(200, status); self.assertEqual(body, downloaded)

    def test_signed_enterprise_approval_callback_is_idempotent_and_replay_safe(self):
        body = b"enterprise approval payload"
        transfer = self.service.upload_outbound("approval.txt", io.BytesIO(body), len(body), "alice")
        self.service.store.execute(
            "UPDATE outbound_transfers SET approval_provider='wecom',approval_id='relay-approval-1' WHERE id=?",
            (transfer["id"],))
        self.service.store.execute(
            "UPDATE outbound_policy SET approval_provider='wecom' WHERE id=1")
        callback_key = "callback-secret-" + "x" * 32
        self.service.settings = replace(self.service.settings, approval_relay_callback_hmac_key=callback_key)
        self.handler_type = make_handler(self.service, self.auth)
        event = {"event_id":"event-1", "approval_id":"relay-approval-1", "status":"approved",
                 "actor":"wecom-user", "comment":"approved in enterprise workflow"}
        raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        timestamp = str(int(__import__("time").time())); nonce = "nonce-1"
        headers = {"Content-Type":"application/json", "Content-Length":str(len(raw)),
                   "X-SFSS-Approval-Timestamp":timestamp, "X-SFSS-Approval-Nonce":nonce,
                   "X-SFSS-Approval-Signature":relay_signature(callback_key, timestamp, nonce, raw)}
        status, _, payload = self.request("POST", "/v1/integrations/wecom/callback", raw, headers)
        self.assertEqual(200, status)
        self.assertEqual("released_to_green", json.loads(payload)["transfer"]["state"])
        status, _, payload = self.request("POST", "/v1/integrations/wecom/callback", raw, headers)
        self.assertEqual(200, status)
        self.assertEqual("duplicate", json.loads(payload)["status"])

        changed = json.dumps({**event, "comment":"different"}, sort_keys=True, separators=(",", ":")).encode()
        changed_headers = {**headers, "Content-Length":str(len(changed)),
                           "X-SFSS-Approval-Signature":relay_signature(callback_key, timestamp, nonce, changed)}
        status, _, _ = self.request("POST", "/v1/integrations/wecom/callback", changed, changed_headers)
        self.assertEqual(409, status)

    def test_enterprise_callback_rejects_stale_or_bad_signature(self):
        callback_key = "callback-secret-" + "y" * 32
        self.service.settings = replace(self.service.settings, approval_relay_callback_hmac_key=callback_key)
        self.handler_type = make_handler(self.service, self.auth)
        raw = b'{"event_id":"event-stale"}'
        stale = "1"; nonce = "nonce-stale"
        headers = {"Content-Type":"application/json", "Content-Length":str(len(raw)),
                   "X-SFSS-Approval-Timestamp":stale, "X-SFSS-Approval-Nonce":nonce,
                   "X-SFSS-Approval-Signature":relay_signature(callback_key, stale, nonce, raw)}
        status, _, _ = self.request("POST", "/v1/integrations/wecom/callback", raw, headers)
        self.assertEqual(401, status)
        current = str(int(__import__("time").time()))
        headers.update({"X-SFSS-Approval-Timestamp":current,
                        "X-SFSS-Approval-Signature":"0" * 64})
        status, _, _ = self.request("POST", "/v1/integrations/wecom/callback", raw, headers)
        self.assertEqual(401, status)

    def test_project_ip_allowlists_block_uploads_before_content_processing(self):
        token = self.admin_token()
        policy = json.dumps({"inbound_upload_cidrs": ["10.10.0.0/16"], "outbound_upload_cidrs": ["10.20.0.0/16"]}).encode()
        status, _, _ = self.request("PUT", "/v1/admin/network-policy", policy, {
            "Authorization": f"Bearer {token}", "Content-Type": "application/json", "Content-Length": str(len(policy)),
        })
        self.assertEqual(200, status)
        body = b"blocked"
        status, _, _ = self.request("POST", "/v1/objects", body, {
            "Authorization":"Bearer a","X-SFSS-Zone":"green","X-Filename":"a.txt","Content-Length":str(len(body))})
        self.assertEqual(403, status)
        status, _, _ = self.request("POST", "/v1/outbound", body, {
            "Authorization":"Bearer a","X-SFSS-Zone":"red","X-Filename":"a.txt","Content-Length":str(len(body))})
        self.assertEqual(403, status)
        self.assertEqual(0, len(self.service.store.all("SELECT id FROM objects")))
        self.assertEqual(0, len(self.service.store.all("SELECT id FROM outbound_transfers")))

    def test_upload_completion_rechecks_changed_source_ip_policy(self):
        create = json.dumps({"direction":"inbound", "filename":"policy.txt", "total_size":4}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", create, {
            "Authorization":"Bearer a", "X-SFSS-Zone":"green", "Content-Length":str(len(create))})
        self.assertEqual(201, status); upload_id = json.loads(payload)["id"]
        status, _, _ = self.request("PUT", f"/v1/uploads/{upload_id}/parts/1", b"data", {
            "Authorization":"Bearer a", "X-SFSS-Zone":"green", "Content-Length":"4",
            "X-Part-SHA256":hashlib.sha256(b"data").hexdigest()})
        self.assertEqual(200, status)
        self.service.set_network_policy({
            "inbound_upload_cidrs":["10.10.0.0/16"], "outbound_upload_cidrs":["127.0.0.1/32"]}, "admin")
        status, _, _ = self.request("POST", f"/v1/uploads/{upload_id}/complete", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"green"})
        self.assertEqual(403, status)
        self.assertEqual("uploading", self.service.store.one(
            "SELECT state FROM upload_sessions WHERE id=?", (upload_id,))["state"])

    def test_invalid_network_policy_is_rejected(self):
        token = self.admin_token(); body = json.dumps({"inbound_upload_cidrs":["not-an-ip"],"outbound_upload_cidrs":["127.0.0.1"]}).encode()
        status, _, _ = self.request("PUT", "/v1/admin/network-policy", body, {
            "Authorization":f"Bearer {token}","Content-Type":"application/json","Content-Length":str(len(body))})
        self.assertEqual(400, status)

    def test_personal_space_lists_only_own_files_and_approver_sees_all(self):
        self.service.upload("mine.txt", io.BytesIO(b"mine"), 4, "alice")
        self.service.upload("theirs.txt", io.BytesIO(b"theirs"), 6, "reader")
        status, _, payload = self.request("GET", "/v1/objects", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"green"})
        self.assertEqual(["mine.txt"],
                         [item["filename"] for item in json.loads(payload)["objects"]])
        status, _, payload = self.request("GET", "/v1/objects", headers={
            "Authorization":"Bearer r"})
        self.assertEqual(["theirs.txt"],
                         [item["filename"] for item in json.loads(payload)["objects"]])
        transfer = self.service.upload_outbound("req.txt", io.BytesIO(b"request"), 7, "reader")
        status, _, payload = self.request("GET", "/v1/outbound", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"red"})
        self.assertEqual([], json.loads(payload)["transfers"])  # alice sees only her own
        status, _, payload = self.request("GET", "/v1/outbound", headers={
            "Authorization":"Bearer p", "X-SFSS-Zone":"red"})
        self.assertIn(transfer["id"],
                      [row["id"] for row in json.loads(payload)["transfers"]])  # approver sees all

    def test_green_released_outbound_list_is_personal_even_for_admin(self):
        own = self.service.upload_outbound("own-release.txt", io.BytesIO(b"own"), 3, "alice")
        other = self.service.upload_outbound("other-release.txt", io.BytesIO(b"other"), 5, "reader")
        for record in (own, other):
            self.service.decide_outbound(record["id"], True, "approved", "approver")
        # Even a platform administrator/approver sees only their own releases
        # in the green personal portal; everything else lives in the console.
        body = json.dumps({"username": "admin", "password": "admin123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", body, {
            "Content-Type": "application/json", "Content-Length": str(len(body)),
            "X-SFSS-Zone": "green"})
        self.assertEqual(200, status)
        admin_green = json.loads(payload)["token"]
        status, _, payload = self.request("GET", "/v1/outbound", headers={
            "Authorization":f"Bearer {admin_green}", "X-SFSS-Zone":"green"})
        self.assertEqual([], [row["id"] for row in json.loads(payload)["transfers"]])
        status, _, payload = self.request("GET", "/v1/outbound", headers={
            "Authorization":"Bearer a", "X-SFSS-Zone":"green"})
        rows = [row["id"] for row in json.loads(payload)["transfers"]]
        self.assertEqual([own["id"]], rows)
        self.assertNotIn(other["id"], rows)

    def test_static_console_has_security_headers(self):
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(200, status)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual("no-referrer", headers["Referrer-Policy"])

    def test_request_id_is_bounded_and_safe_before_echo_and_audit(self):
        status, headers, _ = self.request("GET", "/health", headers={"X-Request-ID":"trace_123-ok"})
        self.assertEqual(200, status)
        self.assertEqual("trace_123-ok", headers["X-Request-ID"])
        status, headers, _ = self.request("GET", "/health", headers={"X-Request-ID":"x" * 1024})
        self.assertEqual(200, status)
        self.assertNotEqual("x" * 1024, headers["X-Request-ID"])
        self.assertEqual(36, len(headers["X-Request-ID"]))

    def test_liveness_is_minimal_and_metrics_are_low_cardinality(self):
        status, _, payload = self.request("GET", "/health")
        self.assertEqual(200, status)
        self.assertEqual({"status":"ok"}, json.loads(payload))
        status, headers, payload = self.request("GET", "/metrics")
        self.assertEqual(200, status)
        self.assertIn("text/plain", headers["Content-Type"])
        metrics = payload.decode()
        self.assertIn("sfss_build_info", metrics)
        self.assertIn('sfss_inbound_objects{state="released"}', metrics)
        self.assertIn("sfss_storage_bytes", metrics)
        self.assertIn("sfss_runtime_accepted", metrics)
        self.assertNotIn("alice", metrics)
        self.assertNotIn("p1", metrics)
        original_health = self.service.scanners[0].health
        self.service.scanners[0].health = lambda: (_ for _ in ()).throw(RuntimeError("scanner unavailable"))
        try:
            status, _, payload = self.request("GET", "/metrics")
            self.assertEqual(200, status)
            self.assertIn('sfss_scanner_up{scanner="mock"} 0', payload.decode())
        finally:
            self.service.scanners[0].health = original_health

    def test_readiness_checks_scanner_dependencies(self):
        status, _, payload = self.request("GET", "/ready")
        self.assertEqual(200, status)
        self.assertEqual("ready", json.loads(payload)["status"])
        original = self.service.storage_status
        self.service.storage_status = lambda: {"total_bytes":100, "used_bytes":100, "free_bytes":0,
                                               "reserve_bytes":1, "available_bytes":0}
        try:
            status, _, payload = self.request("GET", "/ready")
            self.assertEqual(503, status)
            self.assertEqual("degraded", json.loads(payload)["status"])
        finally:
            self.service.storage_status = original
        original_health = self.service.scanners[0].health
        self.service.scanners[0].health = lambda: (_ for _ in ()).throw(RuntimeError("scanner unavailable"))
        try:
            status, _, payload = self.request("GET", "/ready")
            self.assertEqual(503, status)
            self.assertEqual("error", json.loads(payload)["scanners"][0]["status"])
        finally:
            self.service.scanners[0].health = original_health
        self.service.last_maintenance_error = "RuntimeError"
        status, _, payload = self.request("GET", "/ready")
        self.assertEqual(503, status)
        self.assertEqual("degraded", json.loads(payload)["maintenance"]["status"])
        self.service.last_maintenance_error = ""
        original_artifacts = self.service.security_artifact_errors
        self.service.security_artifact_errors = lambda: ["trust artifact drifted"]
        try:
            status, _, payload = self.request("GET", "/ready")
            self.assertEqual(503, status)
            self.assertEqual("drifted", json.loads(payload)["security_artifacts"]["status"])
        finally:
            self.service.security_artifact_errors = original_artifacts
        self.service.store.execute(
            "UPDATE outbound_policy SET approval_provider='wecom',enabled=1 WHERE id=1")
        status, _, payload = self.request("GET", "/ready")
        self.assertEqual(503, status)
        self.assertEqual("degraded", json.loads(payload)["approval_relay"]["status"])

    def test_readiness_detects_production_secret_file_drift(self):
        secret = Path(self.temp.name) / "manifest-hmac.key"
        secret.write_text("m" * 32, encoding="utf-8"); secret.chmod(0o600)
        released = self.service.upload("drift.txt", io.BytesIO(b"drift payload"), 13, "alice")
        original = self.service.settings
        candidate = replace(original, environment="production", manifest_hmac_key="m" * 32,
                            manifest_hmac_key_file=str(secret), expected_config_sha256="0" * 64)
        self.service.settings = replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.service.store.all("SELECT key,value FROM system_config ORDER BY key")))
        try:
            status, _, payload = self.request("GET", "/ready")
            self.assertEqual(200, status)
            self.assertEqual("configured", json.loads(payload)["secrets"]["status"])
            secret.write_text("n" * 32, encoding="utf-8")
            status, _, payload = self.request("GET", "/ready")
            self.assertEqual(503, status)
            self.assertEqual("degraded", json.loads(payload)["secrets"]["status"])
            status, _, _ = self.request(
                "GET", f"/v1/objects/{released['id']}/download",
                headers={"Authorization":"Bearer r", "X-SFSS-Zone":"red"})
            self.assertEqual(503, status)
        finally:
            self.service.settings = original

    def test_production_configuration_drift_blocks_data_plane_but_keeps_recovery_plane(self):
        secret = Path(self.temp.name) / "runtime-manifest.key"
        secret.write_text("m" * 32, encoding="utf-8"); secret.chmod(0o600)
        original = self.service.settings
        admin = self.admin_token()
        candidate = replace(original, environment="production", manifest_hmac_key="m" * 32,
                            manifest_hmac_key_file=str(secret), expected_config_sha256="0" * 64)
        self.service.settings = replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.service.store.all("SELECT key,value FROM system_config ORDER BY key")))
        try:
            self.assertEqual(200, self.request("GET", "/v1/objects", headers={
                "Authorization":"Bearer a", "X-SFSS-Zone":"green"})[0])
            self.service.store.set_config("retention_seconds", "7200", "test-drift")
            self.assertEqual(200, self.request("GET", "/health")[0])
            status, _, payload = self.request("GET", "/ready")
            self.assertEqual(503, status)
            self.assertEqual("drifted", json.loads(payload)["configuration"]["status"])
            self.assertEqual(503, self.request("GET", "/v1/objects", headers={
                "Authorization":"Bearer a", "X-SFSS-Zone":"green"})[0])
            self.assertEqual(503, self.request("POST", "/v1/objects", b"data", {
                "Authorization":"Bearer a", "X-SFSS-Zone":"green", "X-Filename":"drift.txt",
                "Content-Length":"4"})[0])
            self.assertEqual(200, self.request("GET", "/v1/admin/config", headers={
                "Authorization":f"Bearer {admin}"})[0])
            self.assertEqual(200, self.request("GET", "/v1/admin/sessions", headers={
                "Authorization":f"Bearer {admin}"})[0])
        finally:
            self.service.settings = original

    def test_production_admin_config_change_is_reported_as_staged_not_live(self):
        secret = Path(self.temp.name) / "staged-config-manifest.key"
        secret.write_text("m" * 32, encoding="utf-8"); secret.chmod(0o600)
        original = self.service.settings
        admin = self.admin_token()
        candidate = replace(original, environment="production", manifest_hmac_key="m" * 32,
                            manifest_hmac_key_file=str(secret), expected_config_sha256="0" * 64)
        self.service.settings = replace(candidate, expected_config_sha256=candidate.configuration_fingerprint(
            self.service.store.all("SELECT key,value FROM system_config ORDER BY key")))
        try:
            config = json.dumps({"retention_hours":24, "max_upload_mb":8, "multipart_chunk_mb":32,
                                 "upload_session_hours":24, "max_active_uploads_per_user":4,
                                 "max_staged_gb_per_user":4, "min_free_gb":1,
                                 "scanners":"clamav", "clamav_host":"127.0.0.1",
                                 "clamav_port":3310, "yara_rules":""}).encode()
            with patch("sfss.server.build_scanners", return_value=[MockScanner()]):
                status, _, payload = self.request("PUT", "/v1/admin/config", config, {
                    "Authorization":f"Bearer {admin}", "Content-Type":"application/json",
                    "Content-Length":str(len(config)),
                })
            self.assertEqual(200, status); result = json.loads(payload)
            self.assertEqual("staged", result["status"])
            self.assertFalse(result["configuration_accepted"])
            self.assertTrue(result["restart_required"])
            self.assertEqual(64, len(result["observed_sha256"]))
            self.assertEqual(503, self.request("GET", "/v1/objects", headers={
                "Authorization":"Bearer a", "X-SFSS-Zone":"green"})[0])
        finally:
            self.service.settings = original

    def test_logout_revokes_server_session(self):
        token = self.admin_token()
        status, headers, _ = self.request("POST", "/v1/auth/logout", b"{}", {
            "Authorization":f"Bearer {token}","Content-Type":"application/json","Content-Length":"2"})
        self.assertEqual(204, status)
        self.assertEqual("close", headers["Connection"])
        status, _, _ = self.request("GET", "/v1/me", headers={"Authorization":f"Bearer {token}"})
        self.assertEqual(401, status)

    def test_production_human_session_uses_httponly_cookie_and_csrf_guard(self):
        original = self.service.settings
        self.service.settings = replace(original, environment="production")
        try:
            body = json.dumps({"username":"admin", "password":"admin123"}).encode()
            status, headers, payload = self.request("POST", "/v1/auth/login", body, {
                "Content-Type":"application/json", "Content-Length":str(len(body)),
            })
            self.assertEqual(200, status); result = json.loads(payload)
            self.assertNotIn("token", result)
            self.assertEqual("cookie", result["session_transport"])
            cookie = headers["Set-Cookie"]
            self.assertTrue(cookie.startswith("__Host-sfss_session="))
            for attribute in ("Path=/", "Secure", "HttpOnly", "SameSite=Strict"):
                self.assertIn(attribute, cookie)
            pair = cookie.split(";", 1)[0]
            self.assertEqual(200, self.request("GET", "/v1/me", headers={"Cookie":pair})[0])
            self.assertEqual(403, self.request("POST", "/v1/auth/logout", headers={
                "Cookie":pair})[0])
            status, cleared, _ = self.request("POST", "/v1/auth/logout", headers={
                "Cookie":pair, "X-SFSS-CSRF":"1"})
            self.assertEqual(204, status); self.assertIn("Max-Age=0", cleared["Set-Cookie"])
            self.assertEqual(401, self.request("GET", "/v1/me", headers={"Cookie":pair})[0])
        finally:
            self.service.settings = original

    def test_ambiguous_or_chunked_request_framing_is_rejected_and_closed(self):
        status, headers, _ = self.request("POST", "/v1/auth/login", headers={
            "Transfer-Encoding":"chunked", "Content-Type":"application/json",
        })
        self.assertEqual(400, status); self.assertEqual("close", headers["Connection"])
        status, headers, _ = self.request("POST", "/v1/auth/login", b"{}", headers={
            "Content-Length":["2", "2"], "Content-Type":"application/json",
        })
        self.assertEqual(400, status); self.assertEqual("close", headers["Connection"])

    def test_failed_login_is_rate_limited(self):
        body = json.dumps({"username":"admin","password":"wrong-password"}).encode()
        headers = {"Content-Type":"application/json","Content-Length":str(len(body))}
        for _ in range(5):
            status, _, _ = self.request("POST", "/v1/auth/login", body, headers); self.assertEqual(401, status)
        status, _, _ = self.request("POST", "/v1/auth/login", body, headers)
        self.assertEqual(429, status)


if __name__ == "__main__":
    unittest.main()
