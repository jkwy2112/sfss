import hashlib
import tempfile
import time
import unittest
from unittest.mock import patch
from email.message import Message
from pathlib import Path

from sfss.auth import AuthenticationError, LDAPAuthenticator, LocalAuthenticator, ServiceTokens
from sfss.db import Store


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "sfss.db")
        self.store.ensure_user("admin", True)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def headers(token, zone=None, gateway_role=None):
        headers = Message(); headers["Authorization"] = f"Bearer {token}"
        if zone: headers["X-SFSS-Zone"] = zone
        if gateway_role: headers["X-SFSS-Gateway-Role"] = gateway_role
        return headers

    def test_session_survives_authenticator_recreation_and_token_is_hashed(self):
        first = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        token = first.login("admin", "admin123")
        row = self.store.one("SELECT token_hash,auth_backend,zone FROM auth_sessions")
        self.assertEqual(hashlib.sha256(token.encode()).hexdigest(), row["token_hash"])
        self.assertNotIn(token, row["token_hash"])
        self.assertEqual("local", row["auth_backend"])
        self.assertEqual("development", row["zone"])
        second = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        self.assertEqual("admin", second.authenticate(self.headers(token)).username)

    def test_session_cannot_cross_authentication_backends(self):
        local = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        token = local.login("admin", "admin123")
        ldap = LDAPAuthenticator("ldaps://ad.example:636", "dc=example,dc=com", store=self.store,
                                 ca_file="/etc/ssl/cert.pem", allow_basic=False)
        with self.assertRaises(AuthenticationError): ldap.authenticate(self.headers(token))
        self.assertIsNone(self.store.one("SELECT token_hash FROM auth_sessions WHERE revoked=0"))

    def test_password_reset_revokes_existing_sessions(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        token = auth.login("admin", "admin123")
        auth.set_password("admin", "new-admin-password")
        with self.assertRaises(AuthenticationError): auth.authenticate(self.headers(token))

    def test_transaction_rolls_back_all_identity_changes_on_late_sql_failure(self):
        with self.assertRaises(Exception):
            self.store.transaction((
                ("UPDATE users SET enabled=0 WHERE username='admin'", ()),
                ("THIS IS NOT VALID SQL", ()),
            ))
        self.assertEqual(1, self.store.one(
            "SELECT enabled FROM users WHERE username='admin'")["enabled"])

    def test_password_and_session_revocation_roll_back_when_audit_append_fails(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        token = auth.login("admin", "admin123")
        audit = {"request_id":"failure-injection", "actor":"admin",
                 "action":"admin.user.update", "project_id":None, "object_id":None,
                 "outcome":"success", "source_zone":"admin", "remote_addr":"127.0.0.1",
                 "details":{"username":"admin", "changed":["password"]}}
        with patch.object(self.store, "_append_audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                auth.set_password("admin", "new-admin-password", audit=audit)
        self.assertEqual("admin", auth.authenticate(self.headers(token)).username)
        self.assertTrue(auth.login("admin", "admin123"))
        with self.assertRaises(AuthenticationError): auth.login("admin", "new-admin-password")

    def test_expired_session_is_rejected_and_retained_revoked_for_maintenance(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        token = auth.login("admin", "admin123")
        self.store.execute("UPDATE auth_sessions SET expires_at=0")
        with self.assertRaises(AuthenticationError): auth.authenticate(self.headers(token))
        self.assertEqual(1, self.store.one("SELECT revoked FROM auth_sessions")["revoked"])

    def test_human_session_is_bound_to_issuing_entrance_without_revoking_original(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600, 900, 3)
        token = auth.login("admin", "admin123", "green")
        self.assertEqual("green", auth.authenticate(self.headers(token, "green")).zone)
        with self.assertRaises(AuthenticationError):
            auth.authenticate(self.headers(token, "red"))
        self.assertEqual("admin", auth.authenticate(self.headers(token, "green")).username)

        management = auth.login("admin", "admin123", "admin")
        self.assertEqual("admin", auth.authenticate(
            self.headers(management, gateway_role="admin")).zone)

    def test_idle_session_is_rejected_and_retained_revoked_for_maintenance(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600, 120, 3)
        token = auth.login("admin", "admin123")
        self.store.execute("UPDATE auth_sessions SET last_seen_at=?", (int(time.time()) - 121,))
        with self.assertRaises(AuthenticationError): auth.authenticate(self.headers(token))
        self.assertEqual(1, self.store.one("SELECT revoked FROM auth_sessions")["revoked"])

    def test_concurrent_session_limit_revokes_oldest_session(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600, 900, 2)
        first = auth.login("admin", "admin123")
        second = auth.login("admin", "admin123")
        third = auth.login("admin", "admin123")
        with self.assertRaises(AuthenticationError): auth.authenticate(self.headers(first))
        self.assertEqual("admin", auth.authenticate(self.headers(second)).username)
        self.assertEqual("admin", auth.authenticate(self.headers(third)).username)
        active = self.store.one("SELECT COUNT(*) AS value FROM auth_sessions WHERE revoked=0")
        self.assertEqual(2, active["value"])

    def test_session_insert_rechecks_identity_after_password_verification(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        original = self.store.transaction
        def disable_before_commit(statements, **kwargs):
            self.store.execute("UPDATE users SET enabled=0 WHERE username='admin'")
            return original(statements, **kwargs)
        with patch.object(self.store, "transaction", side_effect=disable_before_commit):
            with self.assertRaisesRegex(AuthenticationError, "changed during session issuance"):
                auth.login("admin", "admin123")
        self.assertEqual(0, self.store.one(
            "SELECT COUNT(*) AS value FROM auth_sessions")["value"])

    def test_session_insert_rechecks_local_password_generation(self):
        auth = LocalAuthenticator({}, {"admin":"admin123"}, self.store, 3600)
        original = self.store.transaction
        def reset_before_commit(statements, **kwargs):
            self.store.execute(
                "UPDATE local_accounts SET password_hash=? WHERE username='admin'", ("0" * 64,))
            return original(statements, **kwargs)
        with patch.object(self.store, "transaction", side_effect=reset_before_commit):
            with self.assertRaisesRegex(AuthenticationError, "changed during session issuance"):
                auth.login("admin", "admin123")
        self.assertEqual(0, self.store.one(
            "SELECT COUNT(*) AS value FROM auth_sessions")["value"])

    def test_service_token_insert_rechecks_enabled_identity_and_cannot_resurrect(self):
        self.store.execute("INSERT INTO users(username,principal_type,enabled) VALUES('agent','service',1)")
        original = self.store.transaction
        def disable_identity_before_commit(statements, **kwargs):
            self.store.execute("UPDATE users SET enabled=0 WHERE username='agent'")
            return original(statements, **kwargs)
        with patch.object(self.store, "transaction", side_effect=disable_identity_before_commit):
            with self.assertRaisesRegex(ValueError, "no longer authorized"):
                ServiceTokens(self.store).issue(
                    label="raced", username="agent", zone="green",
                    permissions=["inbound_upload"], expires_at=2 ** 31, created_by="admin")
        self.store.execute("UPDATE users SET enabled=1 WHERE username='agent'")
        self.assertEqual(0, self.store.one(
            "SELECT COUNT(*) AS value FROM service_tokens")["value"])

    def test_ldap_basic_auth_can_be_disabled_for_bearer_only_requests(self):
        auth = LDAPAuthenticator("ldaps://ad.example:636", "dc=example,dc=com", store=self.store,
                                 ca_file="/etc/ssl/cert.pem", allow_basic=False)
        headers = Message(); headers["Authorization"] = "Basic YWRtaW46c2VjcmV0"
        with self.assertRaisesRegex(AuthenticationError, "bearer session"):
            auth.authenticate(headers)

    def test_ldap_bind_identifier_rejects_template_injection_characters(self):
        auth = LDAPAuthenticator("ldaps://ad.example:636", "dc=example,dc=com")
        for username in ("admin,dc=evil", "admin=evil", "DOMAIN\\admin", "admin\nuser", "用户"):
            with self.subTest(username=username), self.assertRaisesRegex(AuthenticationError, "invalid username"):
                auth._bind(username, "password")

    def test_ldap_login_grants_bootstrap_admin_without_demoting_others(self):
        auth = LDAPAuthenticator("ldap://ad.example:389", "dc=example,dc=com",
                                 "uid={username},ou=People,{base_dn}", store=self.store,
                                 bootstrap_admins="diradmin, other-admin")
        with patch.object(LDAPAuthenticator, "_bind"):
            auth.login("diradmin", "pw", "admin")
            auth.login("ordinary", "pw", "green")
        self.assertEqual(1, self.store.one(
            "SELECT global_admin FROM users WHERE username='diradmin'")["global_admin"])
        self.assertEqual(0, self.store.one(
            "SELECT global_admin FROM users WHERE username='ordinary'")["global_admin"])
        # A later manual promotion must survive bootstrap logins.
        self.store.execute("UPDATE users SET global_admin=1 WHERE username='ordinary'")
        with patch.object(LDAPAuthenticator, "_bind"):
            auth.login("ordinary", "pw", "green")
        self.assertEqual(1, self.store.one(
            "SELECT global_admin FROM users WHERE username='ordinary'")["global_admin"])

    def test_ldap_fallback_admin_signs_in_when_directory_fails(self):
        auth = LDAPAuthenticator("ldap://ad.example:389", "dc=example,dc=com",
                                 "uid={username},ou=People,{base_dn}", store=self.store,
                                 fallback_admin="admin",
                                 fallback_credentials={"admin": "admin123"})
        # Directory rejects everyone (bind raises).
        with patch.object(LDAPAuthenticator, "_bind",
                          side_effect=AuthenticationError("LDAP authentication failed")):
            token = auth.login("admin", "admin123", "admin")
            self.assertTrue(token)
            with self.assertRaises(AuthenticationError):
                auth.login("admin", "wrong-password", "admin")
            with self.assertRaises(AuthenticationError):
                auth.login("someone-else", "admin123", "green")
        self.assertEqual(1, self.store.one(
            "SELECT global_admin FROM users WHERE username='admin'")["global_admin"])
        session = auth.authenticate(_headers_with_bearer(token, "admin"))
        self.assertEqual("admin", session.username)

    def test_ldap_fallback_requires_configuration_and_durable_account_in_production(self):
        auth = LDAPAuthenticator("ldap://ad.example:389", "dc=example,dc=com",
                                 "uid={username},ou=People,{base_dn}", store=self.store)
        with patch.object(LDAPAuthenticator, "_bind",
                          side_effect=AuthenticationError("LDAP authentication failed")):
            with self.assertRaises(AuthenticationError):
                auth.login("admin", "anything", "admin")
        # A durable local account is honored even without configured credentials.
        LocalAuthenticator({}, {"admin": "durable-pass-1"}, self.store).set_password(
            "admin", "durable-pass-1")
        configured = LDAPAuthenticator("ldap://ad.example:389", "dc=example,dc=com",
                                       "uid={username},ou=People,{base_dn}", store=self.store,
                                       fallback_admin="admin")
        with patch.object(LDAPAuthenticator, "_bind",
                          side_effect=AuthenticationError("LDAP authentication failed")):
            self.assertTrue(configured.login("admin", "durable-pass-1", "admin"))
            with self.assertRaises(AuthenticationError):
                configured.login("admin", "admin123", "admin")


def _headers_with_bearer(token: str, zone: str):
    from email.message import Message
    message = Message(); message["Authorization"] = f"Bearer {token}"
    message["X-SFSS-Gateway-Role"] = zone
    return message

    def test_service_token_is_hashed_scoped_and_revocable(self):
        self.store.execute("INSERT INTO users(username,principal_type,enabled) VALUES('red-agent','service',1)")
        raw, record = ServiceTokens(self.store).issue(
            label="red downloader", username="red-agent", zone="red",
            permissions=["inbound_download"], expires_at=2 ** 31, created_by="admin",
        )
        stored = self.store.one("SELECT token_hash FROM service_tokens WHERE id=?", (record["id"],))
        self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), stored["token_hash"])
        self.assertNotEqual(raw, stored["token_hash"])
        identity = ServiceTokens(self.store).authenticate(raw)
        self.assertEqual(("inbound_download",), identity.permissions)
        self.assertEqual("red", identity.zone)
        ServiceTokens(self.store).revoke(record["id"])
        with self.assertRaises(AuthenticationError): ServiceTokens(self.store).authenticate(raw)


if __name__ == "__main__":
    unittest.main()
