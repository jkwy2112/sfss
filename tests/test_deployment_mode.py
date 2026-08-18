import io
import json
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from types import MethodType

from sfss.auth import LocalAuthenticator
from sfss.config import Settings
from sfss.db import Store
from sfss.jobs import InlineJobQueue, SQLiteJobQueue
from sfss.scanners import MockScanner
from sfss.server import create_runtime, make_handler
from sfss.service import SFSSService, ServiceError


class DeploymentModeTestBase(unittest.TestCase):
    deployment_mode = "combined"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.settings = Settings(data_dir=Path(self.temp.name),
                                 deployment_mode=self.deployment_mode,
                                 retention_seconds=60, multipart_chunk_bytes=1024 * 1024)
        self.store = Store(self.settings.data_dir / "sfss.db")
        self.store.ensure_user("admin", True)
        self.store.ensure_user("alice")
        self.store.ensure_user("reader")
        self.service = SFSSService(self.settings, self.store, [MockScanner()], InlineJobQueue())
        self.auth = LocalAuthenticator({"a": "alice", "r": "reader"}, {"admin": "admin123"}, self.store)
        self.handler_type = make_handler(self.service, self.auth)

    def tearDown(self):
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        handler = object.__new__(self.handler_type)
        handler.path = path
        handler.client_address = ("127.0.0.1", 12345)
        handler.rfile = io.BytesIO(body or b"")
        handler.wfile = io.BytesIO()
        handler.headers = Message()
        for key, value in (headers or {}).items():
            handler.headers[key] = value
        captured = {"status": None, "headers": {}}
        handler.send_response = MethodType(lambda this, status: captured.update(status=status), handler)
        handler.send_header = MethodType(lambda this, key, value: captured["headers"].__setitem__(key, value), handler)
        handler.end_headers = MethodType(lambda this: None, handler)
        handler.handle_method(method)
        return captured["status"], captured["headers"], handler.wfile.getvalue()

    def login_headers(self, token, zone):
        return {"Authorization": f"Bearer {token}", "X-SFSS-Zone": zone}

    def admin_token(self):
        body = json.dumps({"username": "admin", "password": "admin123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", body, {
            "Content-Type": "application/json", "Content-Length": str(len(body)),
        })
        self.assertEqual(200, status)
        return json.loads(payload)["token"]

    def issue_service_token(self, permission):
        zone = "green" if permission in {"inbound_upload", "outbound_download"} else "red"
        body = json.dumps({"username": "svc"}).encode()
        status, _, _ = self.request("POST", "/v1/admin/service-identities", body, {
            "Authorization": f"Bearer {self.admin_token()}", "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        self.assertIn(status, (201, 409))
        request = json.dumps({"label": "agent", "username": "svc",
                              "zone": zone, "permissions": [permission],
                              "expires_hours": 24}).encode()
        status, _, payload = self.request("POST", "/v1/admin/service-tokens", request, {
            "Authorization": f"Bearer {self.admin_token()}", "Content-Type": "application/json",
            "Content-Length": str(len(request)),
        })
        return status


class InboundSystemTest(DeploymentModeTestBase):
    deployment_mode = "inbound"

    def test_green_upload_and_red_download_flow_is_served(self):
        body = b"design handoff"
        status, _, payload = self.request("POST", "/v1/objects", body, {
            "Authorization": "Bearer a", "X-SFSS-Zone": "green", "X-Filename": "design.txt",
            "Content-Length": str(len(body)),
        })
        self.assertEqual(202, status)
        object_id = json.loads(payload)["id"]
        status, _, downloaded = self.request(
            "GET", f"/v1/objects/{object_id}/download",
            headers=self.login_headers("a", "red"))
        self.assertEqual(200, status)
        self.assertEqual(body, downloaded)

    def test_multipart_inbound_sessions_are_served(self):
        request = json.dumps({"direction": "inbound", "filename": "netlist.txt",
                              "total_size": 16}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", request, {
            "Authorization": "Bearer a", "X-SFSS-Zone": "green",
            "Content-Type": "application/json", "Content-Length": str(len(request)),
        })
        self.assertEqual(201, status)
        self.assertEqual("inbound", json.loads(payload)["direction"])

    def test_outbound_routes_are_not_deployed(self):
        checks = (
            ("GET", "/v1/outbound", self.login_headers("a", "red")),
            ("GET", "/v1/admin/outbound-policy", self.login_headers("a", "red")),
            ("POST", "/v1/outbound", {"Authorization": "Bearer a", "X-SFSS-Zone": "red",
                                                  "X-Filename": "leak.txt", "Content-Length": "1"}),
            ("POST", "/v1/integrations/wecom/callback", {"Content-Type": "application/json",
                                                          "Content-Length": "2"}),
            ("POST", "/v1/admin/outbound/t1/rescan", {"Authorization": f"Bearer {self.admin_token()}",
                                                      "Content-Length": "0"}),
        )
        for method, path, headers in checks:
            with self.subTest(path=path):
                status, _, _ = self.request(method, path, b"{}" if "Content-Length" in headers else None,
                                            headers)
                self.assertEqual(404, status)

    def test_outbound_multipart_sessions_are_rejected(self):
        request = json.dumps({"direction": "outbound", "filename": "leak.txt",
                              "total_size": 16}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", request, {
            "Authorization": "Bearer a", "X-SFSS-Zone": "red",
            "Content-Type": "application/json", "Content-Length": str(len(request)),
        })
        self.assertEqual(404, status)
        self.assertEqual("outbound workflow is not deployed on this system",
                         json.loads(payload)["error"])

    def test_outbound_token_scopes_are_rejected(self):
        self.assertEqual(400, self.issue_service_token("outbound_download"))
        self.assertEqual(201, self.issue_service_token("inbound_upload"))

    def test_network_policy_cannot_grant_outbound_direction(self):
        policy = self.service.set_network_policy(
            {"inbound_upload_cidrs": ["127.0.0.1/32"], "outbound_upload_cidrs": ["10.9.0.0/16"]},
            "admin")
        self.assertEqual(["127.0.0.1/32", "::1/128"], json.loads(policy["outbound_upload_cidrs"]))
        with self.assertRaisesRegex(ServiceError, "not deployed"):
            self.service.require_source_ip("outbound", "127.0.0.1")


class OutboundSystemTest(DeploymentModeTestBase):
    deployment_mode = "outbound"

    def setUp(self):
        super().setUp()
        self.store.execute("UPDATE users SET approver=1 WHERE username='admin'")
        self.service.set_outbound_policy({"enabled": True, "approval_provider": "local",
                                          "allowed_classifications": ["GENERAL"],
                                          "approval_timeout_hours": 24,
                                          "download_ttl_hours": 24}, "admin")

    def test_red_upload_approval_and_green_download_flow_is_served(self):
        body = b"ok outbound text"
        status, _, payload = self.request("POST", "/v1/outbound", body, {
            "Authorization": "Bearer a", "X-SFSS-Zone": "red", "X-Filename": "handoff.txt",
            "Content-Length": str(len(body)),
        })
        self.assertEqual(202, status)
        transfer = json.loads(payload)
        self.assertEqual("pending_approval", transfer["state"])
        decision = json.dumps({"approved": True, "comment": "ok"}).encode()
        status, _, payload = self.request(
            "POST", f"/v1/outbound/{transfer['id']}/decision", decision, {
                "Authorization": f"Bearer {self.admin_token()}", "Content-Type": "application/json",
                "Content-Length": str(len(decision)),
            })
        self.assertEqual(200, status)
        transfer = json.loads(payload)
        self.assertEqual("released_to_green", transfer["state"])
        status, _, _ = self.request(
            "GET", f"/v1/outbound/{transfer['id']}/download",
            headers=self.login_headers("r", "green"))
        self.assertEqual(404, status)  # only the submitting user may download
        status, _, downloaded = self.request(
            "GET", f"/v1/outbound/{transfer['id']}/download",
            headers=self.login_headers("a", "green"))
        self.assertEqual(200, status)
        self.assertEqual(body, downloaded)

    def test_multipart_outbound_sessions_are_served(self):
        request = json.dumps({"direction": "outbound", "filename": "bitfile.bin",
                              "total_size": 16}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", request, {
            "Authorization": "Bearer a", "X-SFSS-Zone": "red",
            "Content-Type": "application/json", "Content-Length": str(len(request)),
        })
        self.assertEqual(201, status)
        self.assertEqual("outbound", json.loads(payload)["direction"])

    def test_inbound_routes_are_not_deployed(self):
        checks = (
            ("POST", "/v1/objects", {"Authorization": "Bearer a", "X-SFSS-Zone": "green",
                                                 "X-Filename": "netlist.txt", "Content-Length": "1"}),
            ("GET", "/v1/objects", self.login_headers("a", "green")),
            ("GET", "/v1/objects/o1/download", self.login_headers("r", "red")),
            ("POST", "/v1/admin/objects/o1/rescan", {"Authorization": f"Bearer {self.admin_token()}",
                                                     "Content-Length": "0"}),
        )
        for method, path, headers in checks:
            with self.subTest(path=path):
                status, _, _ = self.request(method, path, b"x" if "Content-Length" in headers else None,
                                            headers)
                self.assertEqual(404, status)

    def test_inbound_multipart_sessions_are_rejected(self):
        request = json.dumps({"direction": "inbound", "filename": "netlist.txt",
                              "total_size": 16}).encode()
        status, _, payload = self.request("POST", "/v1/uploads", request, {
            "Authorization": "Bearer a", "X-SFSS-Zone": "green",
            "Content-Type": "application/json", "Content-Length": str(len(request)),
        })
        self.assertEqual(404, status)
        self.assertEqual("inbound workflow is not deployed on this system",
                         json.loads(payload)["error"])

    def test_inbound_token_scopes_are_rejected(self):
        self.assertEqual(400, self.issue_service_token("inbound_upload"))
        self.assertEqual(201, self.issue_service_token("outbound_upload"))

    def test_maintenance_and_recovery_run_without_inbound_workflow(self):
        stats = self.service.run_maintenance()
        self.assertIn("upload_sessions_expired", stats)
        stats = self.service.recover_interrupted_jobs()
        self.assertIn("outbound_requeued", stats)


class DeploymentModeSettingsTest(unittest.TestCase):
    def test_invalid_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "SFSS_DEPLOYMENT_MODE"):
                Settings(data_dir=Path(temp), deployment_mode="both").validate()

    def test_production_forbids_combined_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(data_dir=Path(temp), environment="production",
                                deployment_mode="combined")
            with self.assertRaisesRegex(ValueError, "single-purpose"):
                settings.validate()
            for mode in ("inbound", "outbound"):
                candidate = Settings(data_dir=Path(temp), environment="production",
                                     deployment_mode=mode)
                with self.assertRaises(ValueError) as context:
                    candidate.validate()
                self.assertNotIn("deployment mode", str(context.exception))


class DeploymentDatabaseScopeTest(unittest.TestCase):
    def test_inbound_runtime_rejects_outbound_records(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(data_dir=Path(temp), deployment_mode="inbound")
            store = Store(settings.data_dir / "sfss.db")
            store.execute("INSERT INTO outbound_policy(id,enabled,approval_provider,"
                          "updated_at,updated_by) VALUES(1,0,'local',1,'admin')")
            with self.assertRaisesRegex(ValueError, "deployment database scope violation"):
                create_runtime(settings)

    def test_outbound_runtime_rejects_inbound_records(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(data_dir=Path(temp), deployment_mode="outbound")
            store = Store(settings.data_dir / "sfss.db")
            store.execute("INSERT INTO users(username) VALUES('alice')")
            store.execute("INSERT INTO objects(id,uploader,filename,size,sha256,media_type,"
                          "type_known,type_conflict,state,storage_path,created_at,updated_at,expires_at) "
                          "VALUES('o1','alice','x.txt',1,'h','text/plain',1,0,'expired','none',1,1,1)")
            with self.assertRaisesRegex(ValueError, "deployment database scope violation"):
                create_runtime(settings)

    def test_clean_single_purpose_databases_start(self):
        for mode in ("inbound", "outbound"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                service = create_runtime(Settings(data_dir=Path(temp), deployment_mode=mode))
                other = "outbound" if mode == "inbound" else "inbound"
                self.assertTrue(service.workflow_enabled(mode))
                self.assertFalse(service.workflow_enabled(other))


class DeploymentJobQueueTest(unittest.TestCase):
    def test_queue_rejects_cross_workflow_job_kinds(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "sfss.db")
            with self.assertRaisesRegex(ValueError, "invalid allowed job kinds"):
                SQLiteJobQueue(store, 1, 60, 3, allowed_kinds={"scan_object", "unexpected"})
            outbound_queue = SQLiteJobQueue(store, 1, 60, 3, allowed_kinds={"scan_object"})
            with self.assertRaisesRegex(ValueError, "do not match this deployment"):
                outbound_queue.start({"scan_object": lambda o: None,
                                      "scan_outbound": lambda t: None})
            inbound_queue = SQLiteJobQueue(store, 1, 60, 3, allowed_kinds={"scan_object"})
            inbound_queue.start({"scan_object": lambda object_id: None})
            try:
                with self.assertRaisesRegex(ValueError, "unsupported durable scan job"):
                    inbound_queue.submit(lambda transfer_id: None, "t1")
            finally:
                inbound_queue.stop()


if __name__ == "__main__":
    unittest.main()
