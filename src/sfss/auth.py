from abc import ABC, abstractmethod
import base64
import json
import secrets
import hashlib
import ssl
import time
import uuid
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from .db import MutationConflictError


class AuthenticationError(Exception):
    pass


USERNAME_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._@+\-]{0,126}[A-Za-z0-9])?\Z")
HUMAN_SESSION_ZONES = {"green", "red", "admin", "development"}


def valid_username(username: str) -> bool:
    return bool(USERNAME_PATTERN.fullmatch(username or ""))


def human_session_zone(headers) -> str:
    """Return the trusted logical entrance for a human session.

    Production gateways overwrite both headers after authenticating each other
    with mTLS.  The development value keeps the local single-portal workflow
    usable without pretending that a browser-supplied header is trustworthy.
    """
    role = headers.get("X-SFSS-Gateway-Role", "").strip().lower()
    zone = headers.get("X-SFSS-Zone", "").strip().lower()
    if role == "admin":
        return "admin"
    if zone in {"green", "red"}:
        return zone
    return "development"


@dataclass(frozen=True)
class Identity:
    username: str
    credential_type: str = "user"
    token_id: Optional[str] = None
    zone: Optional[str] = None
    permissions: Tuple[str, ...] = ()


class ServiceTokens:
    ALLOWED_PERMISSIONS = {"inbound_upload", "inbound_download", "outbound_upload", "outbound_download"}

    def __init__(self, store): self.store = store

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue(self, *, label: str, username: str, zone: str,
              permissions, expires_at: int, created_by: str, audit=None):
        normalized = tuple(sorted(set(permissions)))
        if zone not in {"green", "red"} or not normalized or not set(normalized).issubset(self.ALLOWED_PERMISSIONS):
            raise ValueError("invalid service token scope")
        principal = self.store.one(
            "SELECT principal_type,enabled FROM users WHERE username=?", (username,))
        if not principal or principal["principal_type"] != "service" or not principal["enabled"]:
            raise ValueError("token owner must be an enabled service identity")
        token_id = str(uuid.uuid4()); raw = secrets.token_urlsafe(32); now = int(time.time())
        statement = (
            "INSERT INTO service_tokens(id,token_hash,label,username,zone,permissions,created_at,expires_at,created_by) "
            "SELECT ?,?,?,?,?,?,?,?,? FROM users u "
            "WHERE u.username=? AND u.principal_type='service' AND u.enabled=1",
            (token_id, self.token_hash(raw), label, username, zone,
             json.dumps(normalized, separators=(",", ":")), now, expires_at, created_by,
             username),
        )
        try:
            if audit is None:
                self.store.transaction((statement,), required_rows={0:1})
            else:
                audited = dict(audit); details = dict(audited.get("details") or {})
                details["token_id"] = token_id; audited["details"] = details
                self.store.transaction_audited((statement,), audit=audited, required_rows={0:1})
        except MutationConflictError as exc:
            raise ValueError("service token scope is no longer authorized") from exc
        return raw, self.store.one("SELECT * FROM service_tokens WHERE id=?", (token_id,))

    def authenticate(self, token: str) -> Identity:
        now = int(time.time()); digest = self.token_hash(token)
        row = self.store.one(
            "SELECT t.*,u.principal_type,u.enabled AS principal_enabled,a.enabled AS local_enabled "
            "FROM service_tokens t JOIN users u ON u.username=t.username "
            "LEFT JOIN local_accounts a ON a.username=t.username "
            "WHERE t.token_hash=?", (digest,),
        )
        if (not row or row["revoked"] or row["expires_at"] <= now or row["principal_type"] != "service" or
                row["principal_enabled"] == 0 or row.get("local_enabled") == 0):
            raise AuthenticationError("invalid or expired service token")
        self.store.execute("UPDATE service_tokens SET last_used_at=? WHERE id=?", (now, row["id"]))
        return Identity(row["username"], "service", row["id"], row["zone"],
                        tuple(json.loads(row["permissions"])))

    def revoke(self, token_id: str):
        return self.store.execute("UPDATE service_tokens SET revoked=1 WHERE id=? AND revoked=0", (token_id,))


class Authenticator(ABC):
    @abstractmethod
    def authenticate(self, headers) -> Identity:
        """Authenticate request headers or raise AuthenticationError."""


class PersistentSessions:
    def __init__(self, store, ttl_seconds: int, idle_seconds: int,
                 max_sessions_per_user: int, auth_backend: str):
        self.store = store
        self.ttl_seconds = max(60, ttl_seconds)
        self.idle_seconds = max(60, idle_seconds)
        self.max_sessions_per_user = max(1, max_sessions_per_user)
        if auth_backend not in {"local", "ldap"}: raise ValueError("invalid session authentication backend")
        self.auth_backend = auth_backend

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue(self, username: str, zone: str = "development", *, audit=None, pre_statements=(),
              credential_guard=None) -> str:
        if zone not in HUMAN_SESSION_ZONES:
            raise AuthenticationError("invalid session entrance")
        token = secrets.token_urlsafe(32); now = int(time.time())
        prefix = tuple(pre_statements)
        credential_sql = ""
        credential_args = ()
        if self.auth_backend == "local":
            if not credential_guard: raise AuthenticationError("local credential guard is missing")
            credential_sql = (" AND EXISTS(SELECT 1 FROM local_accounts a WHERE a.username=users.username "
                              "AND a.enabled=1 AND a.password_hash=?)")
            credential_args = (credential_guard,)
        statements = prefix + (
            ("INSERT INTO auth_sessions(token_hash,username,auth_backend,zone,created_at,expires_at,last_seen_at,revoked) "
             "SELECT ?,?,?,?,?,?,?,0 FROM users WHERE username=? AND enabled=1 AND principal_type='human'" +
             credential_sql,
             (self.token_hash(token), username, self.auth_backend, zone, now,
              now + self.ttl_seconds, now, username, *credential_args)),
            # The insert and eviction are one transaction. rowid disambiguates
            # same-second issues and a crash cannot leave N+1 live sessions.
            ("UPDATE auth_sessions SET revoked=1 WHERE token_hash IN ("
             "SELECT token_hash FROM auth_sessions WHERE username=? AND auth_backend=? AND revoked=0 "
             "ORDER BY created_at DESC,rowid DESC LIMIT -1 OFFSET ?)",
             (username, self.auth_backend, self.max_sessions_per_user)),
        )
        session_index = len(prefix)
        try:
            if audit is None: self.store.transaction(statements, required_rows={session_index:1})
            else: self.store.transaction_audited(
                statements, audit=audit, required_rows={session_index:1})
        except MutationConflictError as exc:
            raise AuthenticationError("identity or credential changed during session issuance") from exc
        return token

    def authenticate(self, token: str, requested_zone: str = "development") -> Identity:
        if requested_zone not in HUMAN_SESSION_ZONES:
            raise AuthenticationError("invalid session entrance")
        digest = self.token_hash(token); now = int(time.time())
        row = self.store.one(
            "SELECT s.username,s.auth_backend,s.zone,s.expires_at,s.last_seen_at,s.revoked,u.enabled,u.principal_type FROM auth_sessions s "
            "JOIN users u ON u.username=s.username WHERE s.token_hash=?", (digest,))
        if (not row or row["revoked"] or row["auth_backend"] != self.auth_backend or
                row["expires_at"] <= now or row["last_seen_at"] + self.idle_seconds <= now or not row["enabled"] or
                row["principal_type"] != "human"):
            # Retain the invalidated record until audited maintenance cleanup;
            # immediate deletion would erase useful session forensics.
            if row:
                self.store.execute(
                    "UPDATE auth_sessions SET revoked=1 WHERE token_hash=? AND revoked=0", (digest,))
            raise AuthenticationError("invalid or expired session")
        # Do not revoke a valid session merely because somebody attempted to
        # replay it at another entrance; retain evidence and original access.
        # Development-entrance sessions are the compatibility entrance: they
        # stay usable from the dedicated portals too (the reverse is still
        # rejected), so a root-path login keeps working on /green, /red, and
        # /admin without another sign-in.
        if row["zone"] != requested_zone and not (row["zone"] == "development"):
            raise AuthenticationError("session is not valid for this entrance")
        self.store.execute("UPDATE auth_sessions SET last_seen_at=? WHERE token_hash=?", (now, digest))
        return Identity(row["username"], zone=row["zone"])

    def revoke(self, token: str, *, audit=None):
        statement = ("UPDATE auth_sessions SET revoked=1 WHERE token_hash=?", (self.token_hash(token),))
        if audit is None: self.store.transaction((statement,))
        else: self.store.transaction_audited((statement,), audit=audit)

    def revoke_user(self, username: str):
        self.store.execute("UPDATE auth_sessions SET revoked=1 WHERE username=?", (username,))


class LocalAuthenticator(Authenticator):
    """Development-only identity provider using opaque bearer tokens."""

    def __init__(self, tokens: Dict[str, str], credentials: Optional[Dict[str, str]] = None, store=None,
                 session_ttl_seconds: int = 8 * 3600, session_idle_seconds: int = 30 * 60,
                 max_sessions_per_user: int = 3):
        self.tokens = tokens
        self.static_tokens = set(tokens)
        self.token_expiries: Dict[str, int] = {}
        self.token_zones: Dict[str, str] = {}
        self.session_ttl_seconds = max(60, session_ttl_seconds)
        self.credentials = credentials or {}
        self.store = store
        self.sessions = (PersistentSessions(store, self.session_ttl_seconds, session_idle_seconds,
                                            max_sessions_per_user, "local") if store else None)
        self.service_tokens = ServiceTokens(store) if store else None
        if store:
            for username, password in self.credentials.items():
                store.ensure_user(username)
                if not store.one("SELECT username FROM local_accounts WHERE username=?", (username,)):
                    self.set_password(username, password)

    def authenticate(self, headers) -> Identity:
        value = headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            raise AuthenticationError("missing bearer token")
        raw_token = value[7:]
        username = self.tokens.get(raw_token)
        if not username and self.sessions:
            try: return self.sessions.authenticate(raw_token, human_session_zone(headers))
            except AuthenticationError: pass
        if not username and self.service_tokens:
            try: return self.service_tokens.authenticate(raw_token)
            except AuthenticationError: pass
        if not username: raise AuthenticationError("invalid bearer token")
        expiry = self.token_expiries.get(raw_token)
        if expiry is not None and expiry <= int(time.time()):
            self.tokens.pop(raw_token, None); self.token_expiries.pop(raw_token, None); self.token_zones.pop(raw_token, None)
            raise AuthenticationError("session expired")
        issued_zone = self.token_zones.get(raw_token)
        if issued_zone is not None and issued_zone != human_session_zone(headers):
            raise AuthenticationError("session is not valid for this entrance")
        if self.store:
            account = self.store.one(
                "SELECT u.enabled AS principal_enabled,u.principal_type,a.enabled AS local_enabled "
                "FROM users u LEFT JOIN local_accounts a ON a.username=u.username WHERE u.username=?", (username,))
            if account and (not account["principal_enabled"] or account["principal_type"] != "human" or
                            account.get("local_enabled") == 0):
                raise AuthenticationError("account disabled")
        return Identity(username, zone=issued_zone)

    def login(self, username: str, password: str, zone: str = "development", *, audit=None) -> str:
        if zone not in HUMAN_SESSION_ZONES: raise AuthenticationError("invalid session entrance")
        credential_guard = None
        if self.store:
            account = self.store.one(
                "SELECT a.*,u.enabled AS principal_enabled,u.principal_type FROM local_accounts a "
                "JOIN users u ON u.username=a.username WHERE a.username=?", (username,))
            if not account or not account["enabled"] or not account["principal_enabled"] or account["principal_type"] != "human":
                raise AuthenticationError("invalid username or password")
            candidate = self._hash(password, account["password_salt"])
            if not secrets.compare_digest(account["password_hash"], candidate):
                raise AuthenticationError("invalid username or password")
            credential_guard = account["password_hash"]
        else:
            expected = self.credentials.get(username)
            if expected is None or not secrets.compare_digest(expected, password):
                raise AuthenticationError("invalid username or password")
        if self.sessions:
            return self.sessions.issue(username, zone, audit=audit,
                                       credential_guard=credential_guard)
        token = secrets.token_urlsafe(32); self.tokens[token] = username
        self.token_expiries[token] = int(time.time()) + self.session_ttl_seconds
        self.token_zones[token] = zone
        return token

    def logout(self, headers, *, audit=None):
        value = headers.get("Authorization", "")
        if value.startswith("Bearer ") and value[7:] not in self.static_tokens:
            if self.sessions: self.sessions.revoke(value[7:], audit=audit)
            self.tokens.pop(value[7:], None); self.token_expiries.pop(value[7:], None); self.token_zones.pop(value[7:], None)
            return bool(self.sessions and audit is not None)
        return False

    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 210_000).hex()

    def mutate_account(self, username: str, *, password=None, enabled=None,
                       global_admin=None, create: bool = False, audit=None):
        """Apply a local identity lifecycle change as one durable transaction.

        Password/status changes and credential revocation must never be split:
        otherwise a crash followed by re-enablement can resurrect old sessions.
        """
        if not self.store:
            if password is not None: self.credentials[username] = password
            return
        if password is not None and len(password) < 8:
            raise ValueError("password must contain at least 8 characters")
        principal = self.store.one(
            "SELECT principal_type,enabled FROM users WHERE username=?", (username,))
        if not create and principal and principal["principal_type"] != "human":
            raise ValueError("interactive passwords are forbidden for service identities")
        now = int(time.time()); statements = []
        if create:
            statements.append((
                "INSERT INTO users(username,global_admin,principal_type,enabled) VALUES(?,?,'human',1)",
                (username, int(bool(global_admin))),
            ))
        if password is not None:
            salt = secrets.token_hex(16); digest = self._hash(password, salt)
            statements.append((
                "INSERT INTO local_accounts(username,password_salt,password_hash,enabled,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(username) DO UPDATE SET password_salt=excluded.password_salt,password_hash=excluded.password_hash,updated_at=excluded.updated_at",
                (username, salt, digest, 1, now),
            ))
            statements.append(("UPDATE auth_sessions SET revoked=1 WHERE username=?", (username,)))
        if enabled is not None:
            statements.extend((
                ("UPDATE local_accounts SET enabled=?,updated_at=? WHERE username=?",
                 (int(enabled), now, username)),
                ("UPDATE users SET enabled=? WHERE username=?", (int(enabled), username)),
            ))
            if not enabled:
                statements.extend((
                    ("UPDATE auth_sessions SET revoked=1 WHERE username=?", (username,)),
                    ("UPDATE service_tokens SET revoked=1 WHERE username=?", (username,)),
                ))
        if global_admin is not None and not create:
            statements.append(("UPDATE users SET global_admin=? WHERE username=?",
                               (int(bool(global_admin)), username)))
        if not statements: raise ValueError("no local account changes requested")
        if audit is None: self.store.transaction(statements)
        else: self.store.transaction_audited(statements, audit=audit)
        if enabled is False:
            for token, owner in list(self.tokens.items()):
                if owner == username:
                    if token not in self.static_tokens:
                        self.tokens.pop(token, None); self.token_expiries.pop(token, None); self.token_zones.pop(token, None)

    def set_password(self, username: str, password: str, *, audit=None):
        self.mutate_account(username, password=password, audit=audit)

    def set_enabled(self, username: str, enabled: bool, *, audit=None):
        self.mutate_account(username, enabled=enabled, audit=audit)


class LDAPAuthenticator(Authenticator):
    """LDAP/AD adapter. ldap3 is optional and loaded only in LDAP mode."""

    def __init__(self, server_uri: str, base_dn: str, user_template: str = "{username}", store=None,
                 session_ttl_seconds: int = 8 * 3600, ca_file: str = "", allow_basic: bool = True,
                 session_idle_seconds: int = 30 * 60, max_sessions_per_user: int = 3,
                 bootstrap_admins: str = "", fallback_admin: str = "",
                 fallback_credentials: Optional[Dict[str, str]] = None):
        self.server_uri = server_uri
        self.base_dn = base_dn
        self.user_template = user_template
        self.store = store
        self.ca_file = ca_file
        self.allow_basic = allow_basic
        self.bootstrap_admins = {value.strip() for value in bootstrap_admins.split(",") if value.strip()}
        # Break-glass identity: exactly one username may authenticate against the
        # local password store when the directory is unreachable or misconfigured.
        self.fallback_admin = (fallback_admin or "").strip()
        self.fallback_credentials = dict(fallback_credentials or {})
        self.sessions = (PersistentSessions(store, session_ttl_seconds, session_idle_seconds,
                                            max_sessions_per_user, "ldap") if store else None)
        self.service_tokens = ServiceTokens(store) if store else None

    def authenticate(self, headers) -> Identity:
        value = headers.get("Authorization", "")
        if value.startswith("Bearer ") and self.sessions:
            try: return self.sessions.authenticate(value[7:], human_session_zone(headers))
            except AuthenticationError:
                if self.service_tokens: return self.service_tokens.authenticate(value[7:])
                raise
        if not self.allow_basic or not value.startswith("Basic "):
            raise AuthenticationError("LDAP mode requires a bearer session")
        try:
            raw = base64.b64decode(value[6:], validate=True).decode("utf-8")
            username, password = raw.split(":", 1)
            self._bind(username, password)
        except Exception as exc:
            if isinstance(exc, AuthenticationError): raise
            raise AuthenticationError("LDAP authentication failed") from exc
        return Identity(username)

    def _bind(self, username: str, password: str):
        if not valid_username(username) or not password: raise AuthenticationError("invalid username or password")
        if self.store:
            principal = self.store.one("SELECT principal_type,enabled FROM users WHERE username=?", (username,))
            if principal and (principal["principal_type"] != "human" or not principal["enabled"]):
                raise AuthenticationError("interactive login is disabled for this principal")
        try:
            import ldap3  # type: ignore
            parsed = urlparse(self.server_uri)
            if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname:
                raise AuthenticationError("invalid LDAP server URI")
            use_ssl = parsed.scheme == "ldaps"
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.ca_file or None) if use_ssl else None
            server = ldap3.Server(parsed.hostname, port=parsed.port or (636 if use_ssl else 389),
                                  use_ssl=use_ssl, tls=tls, connect_timeout=10)
            bind_name = self.user_template.format(username=username, base_dn=self.base_dn)
            connection = ldap3.Connection(server, user=bind_name, password=password, auto_bind=True,
                                          receive_timeout=10, client_strategy=ldap3.SAFE_SYNC)
            connection.unbind()
        except AuthenticationError: raise
        except Exception as exc: raise AuthenticationError("LDAP authentication failed") from exc

    def _verify_fallback(self, username: str, password: str) -> bool:
        if not self.fallback_admin or username != self.fallback_admin or not password:
            return False
        if self.store:
            account = self.store.one(
                "SELECT a.*,u.enabled AS principal_enabled,u.principal_type FROM local_accounts a "
                "JOIN users u ON u.username=a.username WHERE a.username=?", (username,))
            if account:
                if (not account["enabled"] or not account["principal_enabled"] or
                        account["principal_type"] != "human"):
                    return False
                candidate = LocalAuthenticator._hash(password, account["password_salt"])
                return secrets.compare_digest(account["password_hash"], candidate)
            # No durable local account (LDAP mode never seeds one). Accept the
            # configured credential only outside production; a production
            # deployment must provision the break-glass account offline.
            import os
            if os.getenv("SFSS_ENVIRONMENT", "development") == "production":
                return False
        expected = self.fallback_credentials.get(username)
        return bool(expected and secrets.compare_digest(expected, password))

    def login(self, username: str, password: str, zone: str = "development", *, audit=None) -> str:
        fallback_used = False
        try:
            self._bind(username, password)
        except AuthenticationError:
            # The designated break-glass administrator may sign in locally when
            # the directory cannot authenticate it (outage, misconfiguration,
            # or the account simply not existing in the directory yet).
            if not self._verify_fallback(username, password):
                raise
            fallback_used = True
        if not self.sessions: raise AuthenticationError("persistent LDAP session store unavailable")
        # A bootstrap administrator keeps its platform grant on first login;
        # the upsert never demotes an already-promoted identity. The fallback
        # administrator is always a platform administrator by definition.
        is_bootstrap = int(username in self.bootstrap_admins or fallback_used)
        audited = dict(audit) if audit is not None else None
        if fallback_used and audited is not None:
            details = dict(audited.get("details") or {})
            details["ldap_fallback"] = True
            audited["details"] = details
        return self.sessions.issue(username, zone, audit=audited, pre_statements=((
            "INSERT INTO users(username,global_admin,principal_type,enabled) VALUES(?,?,'human',1) "
            "ON CONFLICT(username) DO UPDATE SET global_admin=MAX(users.global_admin,excluded.global_admin)",
            (username, is_bootstrap)),))

    def logout(self, headers, *, audit=None):
        value = headers.get("Authorization", "")
        if value.startswith("Bearer ") and self.sessions:
            self.sessions.revoke(value[7:], audit=audit)
            return audit is not None
        return False


def local_tokens(dev_users: str) -> Dict[str, str]:
    # The token format is intentionally explicit and development-only.
    result = {}
    for item in dev_users.split(","):
        username = item.partition(":")[0].strip()
        if username:
            result[f"dev-{username}"] = username
    return result


def local_credentials(value: str) -> Dict[str, str]:
    result = {}
    for item in value.split(","):
        username, separator, password = item.partition(":")
        if separator and username.strip() and password:
            result[username.strip()] = password
    return result
