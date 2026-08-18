import io
import json
import tempfile
import unittest
from dataclasses import replace
from email.message import Message
from pathlib import Path
from types import MethodType
from unittest.mock import patch

from sfss.auth import LocalAuthenticator
from sfss.config import Settings
from sfss.db import Store
from sfss.jobs import InlineJobQueue
from sfss.ldap_sync import (LdapSyncError, ldap_sync_document, run_ldap_sync,
                            save_ldap_sync_config)
from sfss.scanners import MockScanner
from sfss.server import make_handler
from sfss.service import SFSSService


class FakeDirectory:
    def __init__(self, users, member_dns=(), member_uids=()):
        self.users = list(users)
        self.member_dns = set(member_dns)
        self.member_uids = set(member_uids)
        self.closed = False

    def search_users(self, base_dn, user_filter, username_attribute):
        return list(self.users)

    def search_group_members(self, group_dn):
        return set(self.member_dns), set(self.member_uids)

    def close(self):
        self.closed = True


class LdapSyncTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.settings = Settings(data_dir=Path(self.temp.name))
        self.store = Store(self.settings.data_dir / "sfss.db")
        self.store.ensure_user("admin", True)
        self.service = SFSSService(self.settings, self.store, [MockScanner()], InlineJobQueue())

    def tearDown(self):
        self.temp.cleanup()

    def enable(self, **overrides):
        config = {"enabled": True, "uri": "ldaps://ad.example.internal:636",
                  "base_dn": "dc=example,dc=internal",
                  "bind_dn": "cn=sfss-sync,dc=example,dc=internal",
                  "bind_password": "sync-secret-1"}
        config.update(overrides)
        return save_ldap_sync_config(self.store, self.settings, config, "admin")

    def test_document_defaults_and_password_never_echoed(self):
        document = ldap_sync_document(self.store, self.settings)
        self.assertFalse(document["enabled"])
        self.assertFalse(document["bind_password_set"])
        self.assertIsNone(document["last_run"])
        self.assertNotIn("bind_secret", document)
        self.assertNotIn("bind_password", document)

    def test_config_validation_is_strict(self):
        for changes, message in (
            ({"enabled": True, "uri": "not-a-uri", "base_dn": "dc=x", "bind_dn": "cn=s",
              "bind_password": "p"}, "URI"),
            ({"enabled": True, "uri": "ldaps://ad:636/a/b", "base_dn": "dc=x", "bind_dn": "cn=s",
              "bind_password": "p"}, "URI"),
            ({"enabled": True, "uri": "ldaps://ad:636", "bind_dn": "cn=s",
              "bind_password": "p"}, "Base DN"),
            ({"enabled": True, "uri": "ldaps://ad:636", "base_dn": "dc=x",
              "bind_password": "p"}, "Bind DN"),
            ({"enabled": True, "uri": "ldaps://ad:636", "base_dn": "dc=x", "bind_dn": "cn=s",
              "bind_password": "p", "user_filter": "objectClass=person"}, "过滤器"),
            ({"enabled": True, "uri": "ldaps://ad:636", "base_dn": "dc=x", "bind_dn": "cn=s",
              "bind_password": "p", "username_attribute": "bad attr!"}, "用户名属性"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(LdapSyncError, message):
                save_ldap_sync_config(self.store, self.settings, changes, "admin")

    def test_enabled_config_requires_password(self):
        with self.assertRaisesRegex(LdapSyncError, "Bind 密码"):
            save_ldap_sync_config(self.store, self.settings,
                                  {"enabled": True, "uri": "ldaps://ad:636", "base_dn": "dc=x",
                                   "bind_dn": "cn=s"}, "admin")
        self.enable()
        document = ldap_sync_document(self.store, self.settings)
        self.assertTrue(document["bind_password_set"])
        self.assertTrue(document["enabled"])
        save_ldap_sync_config(self.store, self.settings,
                              {"enabled": False, "uri": "ldaps://ad:636", "base_dn": "dc=x",
                               "bind_dn": "cn=s"}, "admin")
        self.assertFalse(ldap_sync_document(self.store, self.settings)["enabled"])

    def test_production_requires_ldaps_uri(self):
        production = replace(self.settings, environment="production")
        with self.assertRaisesRegex(LdapSyncError, "ldaps"):
            save_ldap_sync_config(self.store, production,
                                  {"enabled": True, "uri": "ldap://ad:636", "base_dn": "dc=x",
                                   "bind_dn": "cn=s", "bind_password": "p"}, "admin")

    def test_sync_imports_users_and_grants_approvers_from_group(self):
        self.enable(approver_group_dn="cn=sfss-approvers,dc=example,dc=internal")
        directory = FakeDirectory(
            users=[("cn=alice,dc=example,dc=internal", "alice"),
                   ("cn=bob,dc=example,dc=internal", "bob"),
                   ("cn=broken,dc=example,dc=internal", "非法用户!")],
            member_dns={"CN=Alice,DC=example,DC=internal"})
        summary = run_ldap_sync(self.store, self.settings, directory=directory, actor="admin")
        self.assertEqual("ok", summary["status"])
        self.assertEqual(2, summary["users_synced"])
        self.assertEqual(1, summary["skipped_invalid"])
        self.assertEqual(1, summary["approvers_granted"])
        self.assertEqual(0, summary["disabled"])
        alice = self.store.one("SELECT approver,enabled,ldap_synced,principal_type FROM users WHERE username='alice'")
        self.assertEqual((1, 1, 1, "human"), (alice["approver"], alice["enabled"],
                                              alice["ldap_synced"], alice["principal_type"]))
        bob = self.store.one("SELECT approver FROM users WHERE username='bob'")
        self.assertEqual(0, bob["approver"])
        self.assertIsNone(self.store.one("SELECT username FROM users WHERE username='非法用户!'"))
        document = ldap_sync_document(self.store, self.settings)
        self.assertEqual("ok", document["last_run"]["status"])
        event = self.store.one(
            "SELECT action,outcome FROM audit_events WHERE action='admin.ldap_sync.run' ORDER BY id DESC LIMIT 1")
        self.assertEqual(("admin.ldap_sync.run", "success"), (event["action"], event["outcome"]))

    def test_deprovision_disables_only_missing_synced_users(self):
        self.enable(deprovision_missing=True)
        directory = FakeDirectory(users=[("cn=alice,dc=x", "alice"), ("cn=carol,dc=x", "carol")])
        run_ldap_sync(self.store, self.settings, directory=directory, actor="admin")
        self.store.ensure_user("local-only")
        self.store.ensure_user("boss-admin", True)
        self.store.execute("UPDATE users SET ldap_synced=1 WHERE username='boss-admin'")
        directory.users = [("cn=alice,dc=x", "alice")]
        summary = run_ldap_sync(self.store, self.settings, directory=directory, actor="admin")
        self.assertEqual(["carol"], summary["disabled_sample"])
        self.assertEqual(0, self.store.one(
            "SELECT enabled FROM users WHERE username='carol'")["enabled"])
        self.assertEqual(1, self.store.one(
            "SELECT enabled FROM users WHERE username='local-only'")["enabled"])
        self.assertEqual(1, self.store.one(
            "SELECT enabled FROM users WHERE username='boss-admin'")["enabled"])
        directory.users = [("cn=alice,dc=x", "alice"), ("cn=carol,dc=x", "carol")]
        run_ldap_sync(self.store, self.settings, directory=directory, actor="admin")
        self.assertEqual(1, self.store.one(
            "SELECT enabled FROM users WHERE username='carol'")["enabled"])

    def test_empty_directory_aborts_without_disabling_anyone(self):
        self.enable(deprovision_missing=True)
        run_ldap_sync(self.store, self.settings,
                      directory=FakeDirectory(users=[("cn=alice,dc=x", "alice")]), actor="admin")
        with self.assertRaisesRegex(LdapSyncError, "0 个有效用户"):
            run_ldap_sync(self.store, self.settings,
                          directory=FakeDirectory(users=[]), actor="admin")
        self.assertEqual(1, self.store.one(
            "SELECT enabled FROM users WHERE username='alice'")["enabled"])
        document = ldap_sync_document(self.store, self.settings)
        self.assertEqual("error", document["last_run"]["status"])

    def test_run_requires_enabled_config(self):
        with self.assertRaisesRegex(LdapSyncError, "未启用"):
            run_ldap_sync(self.store, self.settings, directory=FakeDirectory(users=[]), actor="admin")

    def test_directory_failure_is_recorded_in_state(self):
        self.enable()
        with patch("sfss.ldap_sync.Ldap3Directory",
                   side_effect=LdapSyncError("无法连接或绑定 LDAP 目录: LDAPSocketOpenError")):
            with self.assertRaisesRegex(LdapSyncError, "无法连接"):
                run_ldap_sync(self.store, self.settings, actor="admin")
        document = ldap_sync_document(self.store, self.settings)
        self.assertEqual("error", document["last_run"]["status"])
        self.assertIn("无法连接", document["last_run"]["summary"]["error"])
        event = self.store.one(
            "SELECT outcome FROM audit_events WHERE action='admin.ldap_sync.run' ORDER BY id DESC LIMIT 1")
        self.assertEqual("error", event["outcome"])


class LdapSyncHttpTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        settings = Settings(data_dir=Path(self.temp.name), retention_seconds=60)
        self.store = Store(settings.data_dir / "sfss.db")
        self.store.ensure_user("admin", True)
        self.store.ensure_user("alice")
        self.service = SFSSService(settings, self.store, [MockScanner()], InlineJobQueue())
        self.auth = LocalAuthenticator({"a": "alice"}, {"admin": "admin123"}, self.store)
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

    def admin_headers(self):
        body = json.dumps({"username": "admin", "password": "admin123"}).encode()
        status, _, payload = self.request("POST", "/v1/auth/login", body, {
            "Content-Type": "application/json", "Content-Length": str(len(body)),
        })
        self.assertEqual(200, status)
        return {"Authorization": "Bearer " + json.loads(payload)["token"]}

    def test_ldap_sync_endpoints_are_admin_only_and_round_trip(self):
        admin = self.admin_headers()
        status, _, payload = self.request("GET", "/v1/admin/ldap-sync",
                                          headers={"Authorization": "Bearer a"})
        self.assertEqual(403, status)
        status, _, payload = self.request("GET", "/v1/admin/ldap-sync", headers=admin)
        self.assertEqual(200, status)
        self.assertFalse(json.loads(payload)["enabled"])
        config = json.dumps({"enabled": True, "uri": "ldaps://ad.example.internal:636",
                             "base_dn": "dc=example,dc=internal",
                             "bind_dn": "cn=sfss-sync,dc=example,dc=internal",
                             "bind_password": "secret-9",
                             "username_attribute": "sAMAccountName",
                             "approver_group_dn": "cn=approvers,dc=example,dc=internal"}).encode()
        status, _, payload = self.request("PUT", "/v1/admin/ldap-sync", config, {
            **admin, "Content-Type": "application/json", "Content-Length": str(len(config)),
        })
        self.assertEqual(200, status)
        saved = json.loads(payload)
        self.assertTrue(saved["enabled"])
        self.assertTrue(saved["bind_password_set"])
        self.assertNotIn("bind_password", saved)
        self.assertNotIn("secret-9", payload.decode())
        status, _, payload = self.request("GET", "/v1/admin/ldap-sync", headers=admin)
        document = json.loads(payload)
        self.assertEqual("sAMAccountName", document["username_attribute"])

    def test_invalid_config_is_rejected_with_clear_error(self):
        admin = self.admin_headers()
        config = json.dumps({"enabled": True, "uri": "http://ad.example.internal:636",
                             "base_dn": "dc=x", "bind_dn": "cn=s"}).encode()
        status, _, payload = self.request("PUT", "/v1/admin/ldap-sync", config, {
            **admin, "Content-Type": "application/json", "Content-Length": str(len(config)),
        })
        self.assertEqual(400, status)
        self.assertIn("URI", json.loads(payload)["error"])

    def test_run_endpoint_executes_sync_and_reports_summary(self):
        admin = self.admin_headers()
        with patch("sfss.server.run_ldap_sync",
                   return_value={"status": "ok", "users_synced": 3, "approvers_granted": 1,
                                 "disabled": 0}) as runner:
            status, _, payload = self.request("POST", "/v1/admin/ldap-sync/run", b"", {
                **admin, "Content-Length": "0",
            })
        self.assertEqual(200, status)
        self.assertEqual(3, json.loads(payload)["users_synced"])
        runner.assert_called_once()

    def test_run_endpoint_maps_sync_error_to_400(self):
        admin = self.admin_headers()
        with patch("sfss.server.run_ldap_sync", side_effect=LdapSyncError("目录不可达")):
            status, _, payload = self.request("POST", "/v1/admin/ldap-sync/run", b"", {
                **admin, "Content-Length": "0",
            })
        self.assertEqual(400, status)
        self.assertEqual("目录不可达", json.loads(payload)["error"])


if __name__ == "__main__":
    unittest.main()
