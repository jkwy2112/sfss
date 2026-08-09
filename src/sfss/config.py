from dataclasses import asdict, dataclass
import hashlib
import hmac
import ipaddress
import json
import os
import platform
from pathlib import Path
import re
import stat
import string
from urllib.parse import urlparse


def read_private_secret(path_value: str, label: str) -> str:
    path = Path(path_value)
    if not path.is_absolute(): raise ValueError(f"{label} secret file path must be absolute")
    try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise ValueError(f"{label} secret file is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"{label} secret file must be a private regular file")
        if not 32 <= metadata.st_size <= 4096:
            raise ValueError(f"{label} secret file size is invalid")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    try: secret = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc: raise ValueError(f"{label} secret file is not UTF-8") from exc
    if len(secret) < 32 or any(ord(character) < 33 or ord(character) > 126 for character in secret):
        raise ValueError(f"{label} secret file content is invalid")
    return secret


def secret_from_environment(name: str, label: str):
    raw = os.getenv(name, ""); path = os.getenv(name + "_FILE", "")
    if raw and path: raise ValueError(f"configure exactly one of {name} or {name}_FILE")
    return (read_private_secret(path, label) if path else raw), path


def trusted_artifact_sha256(path_value: str, label: str) -> str:
    path = Path(path_value)
    if not path.is_absolute(): raise ValueError(f"{label} path must be absolute")
    try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise ValueError(f"{label} is unavailable or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) & 0o022 or
                not 1 <= before.st_size <= 64 * 1024 * 1024):
            raise ValueError(f"{label} must be a bounded regular file not writable by group or others")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block: break
            digest.update(block)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError(f"{label} changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    auth_backend: str = "local"
    scanners: str = "mock"
    clamav_host: str = "127.0.0.1"
    clamav_port: int = 3310
    clamav_stream_max_bytes: int = 100 * 1024 * 1024
    yara_rules: str = ""
    yara_rules_sha256: str = ""
    retention_seconds: int = 7 * 24 * 3600
    max_upload_bytes: int = 100 * 1024 * 1024
    dev_users: str = "admin:admin,alice:uploader,reader:downloader"
    bootstrap_admins: str = "admin"
    local_credentials: str = "admin:admin123,alice:alice123,reader:reader123"
    purge_grace_seconds: int = 24 * 3600
    maintenance_interval_seconds: int = 30
    dev_tokens_enabled: bool = True
    session_ttl_seconds: int = 8 * 3600
    session_idle_seconds: int = 30 * 60
    max_sessions_per_user: int = 3
    service_token_max_ttl_seconds: int = 30 * 24 * 3600
    request_header_timeout_seconds: int = 15
    request_io_timeout_seconds: int = 60 * 60
    max_request_workers: int = 128
    scan_timeout_seconds: int = 30 * 60
    multipart_chunk_bytes: int = 32 * 1024 * 1024
    upload_session_ttl_seconds: int = 24 * 3600
    environment: str = "development"
    release_id: str = "development"
    expected_python_version: str = ""
    expected_config_sha256: str = ""
    trusted_zone_proxy_cidrs: str = ""
    admin_source_cidrs: str = "127.0.0.1/32,::1/128"
    require_trusted_proxy: bool = False
    require_forwarded_https: bool = False
    manifest_hmac_key: str = ""
    manifest_hmac_key_file: str = ""
    job_workers: int = 2
    job_lease_seconds: int = 15 * 60
    job_max_attempts: int = 3
    ldap_uri: str = "ldap://127.0.0.1:389"
    ldap_base_dn: str = "dc=example,dc=com"
    ldap_user_template: str = "uid={username},{base_dn}"
    ldap_ca_file: str = ""
    ldap_ca_sha256: str = ""
    allow_basic_auth: bool = True
    max_active_uploads_per_user: int = 4
    max_staged_bytes_per_project: int = 4 * 1024 * 1024 * 1024
    min_free_bytes: int = 1024 * 1024 * 1024
    allow_local_approval: bool = True
    approval_relay_url: str = ""
    approval_relay_ca_file: str = ""
    approval_relay_client_cert: str = ""
    approval_relay_client_key: str = ""
    approval_relay_ca_sha256: str = ""
    approval_relay_client_cert_sha256: str = ""
    approval_relay_submit_hmac_key: str = ""
    approval_relay_callback_hmac_key: str = ""
    approval_relay_submit_hmac_key_file: str = ""
    approval_relay_callback_hmac_key_file: str = ""
    approval_relay_timeout_seconds: int = 10
    approval_callback_max_skew_seconds: int = 300

    @classmethod
    def from_env(cls) -> "Settings":
        auth_backend = os.getenv("SFSS_AUTH_BACKEND", "local")
        environment = os.getenv("SFSS_ENVIRONMENT", "development").lower()
        manifest_key, manifest_key_file = secret_from_environment(
            "SFSS_MANIFEST_HMAC_KEY", "manifest HMAC")
        relay_submit_key, relay_submit_key_file = secret_from_environment(
            "SFSS_APPROVAL_RELAY_SUBMIT_HMAC_KEY", "approval relay submission HMAC")
        relay_callback_key, relay_callback_key_file = secret_from_environment(
            "SFSS_APPROVAL_RELAY_CALLBACK_HMAC_KEY", "approval relay callback HMAC")
        return cls(
            data_dir=Path(os.getenv("SFSS_DATA_DIR", "var")),
            auth_backend=auth_backend,
            scanners=os.getenv("SFSS_SCANNERS", "mock"),
            clamav_host=os.getenv("SFSS_CLAMAV_HOST", "127.0.0.1"),
            clamav_port=int(os.getenv("SFSS_CLAMAV_PORT", "3310")),
            clamav_stream_max_bytes=int(os.getenv("SFSS_CLAMAV_STREAM_MAX_BYTES", str(100 * 1024 * 1024))),
            yara_rules=os.getenv("SFSS_YARA_RULES", ""),
            yara_rules_sha256=os.getenv("SFSS_YARA_RULES_SHA256", "").lower().strip(),
            retention_seconds=int(os.getenv("SFSS_RETENTION_SECONDS", str(7 * 24 * 3600))),
            max_upload_bytes=int(os.getenv("SFSS_MAX_UPLOAD_BYTES", str(100 * 1024 * 1024))),
            dev_users=os.getenv("SFSS_DEV_USERS", "admin:admin,alice:uploader,reader:downloader"),
            bootstrap_admins=os.getenv("SFSS_BOOTSTRAP_ADMINS", "admin" if auth_backend == "local" else ""),
            local_credentials=os.getenv("SFSS_LOCAL_CREDENTIALS", "admin:admin123,alice:alice123,reader:reader123"),
            purge_grace_seconds=int(os.getenv("SFSS_PURGE_GRACE_SECONDS", str(24 * 3600))),
            maintenance_interval_seconds=int(os.getenv("SFSS_MAINTENANCE_INTERVAL_SECONDS", "30")),
            dev_tokens_enabled=os.getenv("SFSS_DEV_TOKENS_ENABLED", "true").lower() in {"1", "true", "yes"},
            session_ttl_seconds=int(os.getenv("SFSS_SESSION_TTL_SECONDS", str(8 * 3600))),
            session_idle_seconds=int(os.getenv("SFSS_SESSION_IDLE_SECONDS", str(30 * 60))),
            max_sessions_per_user=int(os.getenv("SFSS_MAX_SESSIONS_PER_USER", "3")),
            service_token_max_ttl_seconds=int(os.getenv("SFSS_SERVICE_TOKEN_MAX_TTL_SECONDS", str(30 * 24 * 3600))),
            request_header_timeout_seconds=int(os.getenv("SFSS_REQUEST_HEADER_TIMEOUT_SECONDS", "15")),
            request_io_timeout_seconds=int(os.getenv("SFSS_REQUEST_IO_TIMEOUT_SECONDS", str(60 * 60))),
            max_request_workers=int(os.getenv("SFSS_MAX_REQUEST_WORKERS", "128")),
            scan_timeout_seconds=int(os.getenv("SFSS_SCAN_TIMEOUT_SECONDS", str(30 * 60))),
            multipart_chunk_bytes=int(os.getenv("SFSS_MULTIPART_CHUNK_BYTES", str(32 * 1024 * 1024))),
            upload_session_ttl_seconds=int(os.getenv("SFSS_UPLOAD_SESSION_TTL_SECONDS", str(24 * 3600))),
            environment=environment,
            release_id=os.getenv("SFSS_RELEASE_ID", "development"),
            expected_python_version=os.getenv("SFSS_EXPECTED_PYTHON_VERSION", ""),
            expected_config_sha256=os.getenv("SFSS_EXPECTED_CONFIG_SHA256", ""),
            trusted_zone_proxy_cidrs=os.getenv("SFSS_TRUSTED_ZONE_PROXY_CIDRS", ""),
            admin_source_cidrs=os.getenv("SFSS_ADMIN_SOURCE_CIDRS", "127.0.0.1/32,::1/128"),
            require_trusted_proxy=os.getenv("SFSS_REQUIRE_TRUSTED_PROXY", "false").lower() in {"1", "true", "yes"},
            require_forwarded_https=os.getenv("SFSS_REQUIRE_FORWARDED_HTTPS", "false").lower() in {"1", "true", "yes"},
            manifest_hmac_key=manifest_key,
            manifest_hmac_key_file=manifest_key_file,
            job_workers=int(os.getenv("SFSS_JOB_WORKERS", "2")),
            job_lease_seconds=int(os.getenv("SFSS_JOB_LEASE_SECONDS", str(15 * 60))),
            job_max_attempts=int(os.getenv("SFSS_JOB_MAX_ATTEMPTS", "3")),
            ldap_uri=os.getenv("SFSS_LDAP_URI", "ldap://127.0.0.1:389"),
            ldap_base_dn=os.getenv("SFSS_LDAP_BASE_DN", "dc=example,dc=com"),
            ldap_user_template=os.getenv("SFSS_LDAP_USER_TEMPLATE", "uid={username},{base_dn}"),
            ldap_ca_file=os.getenv("SFSS_LDAP_CA_FILE", ""),
            ldap_ca_sha256=os.getenv("SFSS_LDAP_CA_SHA256", "").lower().strip(),
            allow_basic_auth=os.getenv("SFSS_ALLOW_BASIC_AUTH", "true").lower() in {"1", "true", "yes"},
            max_active_uploads_per_user=int(os.getenv("SFSS_MAX_ACTIVE_UPLOADS_PER_USER", "4")),
            max_staged_bytes_per_project=int(os.getenv("SFSS_MAX_STAGED_BYTES_PER_PROJECT", str(4 * 1024 * 1024 * 1024))),
            min_free_bytes=int(os.getenv("SFSS_MIN_FREE_BYTES", str(1024 * 1024 * 1024))),
            allow_local_approval=os.getenv(
                "SFSS_ALLOW_LOCAL_APPROVAL", "false" if environment == "production" else "true"
            ).lower() in {"1", "true", "yes"},
            approval_relay_url=os.getenv("SFSS_APPROVAL_RELAY_URL", ""),
            approval_relay_ca_file=os.getenv("SFSS_APPROVAL_RELAY_CA_FILE", ""),
            approval_relay_client_cert=os.getenv("SFSS_APPROVAL_RELAY_CLIENT_CERT", ""),
            approval_relay_client_key=os.getenv("SFSS_APPROVAL_RELAY_CLIENT_KEY", ""),
            approval_relay_ca_sha256=os.getenv("SFSS_APPROVAL_RELAY_CA_SHA256", "").lower().strip(),
            approval_relay_client_cert_sha256=os.getenv(
                "SFSS_APPROVAL_RELAY_CLIENT_CERT_SHA256", "").lower().strip(),
            approval_relay_submit_hmac_key=relay_submit_key,
            approval_relay_callback_hmac_key=relay_callback_key,
            approval_relay_submit_hmac_key_file=relay_submit_key_file,
            approval_relay_callback_hmac_key_file=relay_callback_key_file,
            approval_relay_timeout_seconds=int(os.getenv("SFSS_APPROVAL_RELAY_TIMEOUT_SECONDS", "10")),
            approval_callback_max_skew_seconds=int(os.getenv("SFSS_APPROVAL_CALLBACK_MAX_SKEW_SECONDS", "300")),
        )

    def approval_relay_errors(self):
        errors = []
        parsed = urlparse(self.approval_relay_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
                parsed.query or parsed.fragment):
            errors.append("approval relay URL must be HTTPS without userinfo, query, or fragment")
        for label, value in (("CA", self.approval_relay_ca_file),
                             ("client certificate", self.approval_relay_client_cert),
                             ("client key", self.approval_relay_client_key)):
            if not value or not Path(value).is_absolute() or not Path(value).is_file():
                errors.append(f"approval relay {label} file is unavailable")
        if (self.approval_relay_client_key and Path(self.approval_relay_client_key).is_file() and
                Path(self.approval_relay_client_key).stat().st_mode & 0o077):
            errors.append("approval relay client key permissions must not grant group or other access")
        if len(self.approval_relay_submit_hmac_key) < 32:
            errors.append("approval relay submit HMAC key must contain at least 32 characters")
        if len(self.approval_relay_callback_hmac_key) < 32:
            errors.append("approval relay callback HMAC key must contain at least 32 characters")
        if self.environment == "production":
            for label, path, configured in (
                ("submission HMAC", self.approval_relay_submit_hmac_key_file,
                 self.approval_relay_submit_hmac_key),
                ("callback HMAC", self.approval_relay_callback_hmac_key_file,
                 self.approval_relay_callback_hmac_key),
            ):
                if not path:
                    errors.append(f"approval relay {label} must be loaded from a secret file")
                else:
                    try:
                        if read_private_secret(path, f"approval relay {label}") != configured:
                            errors.append(f"approval relay {label} secret binding does not match")
                    except ValueError as exc: errors.append(str(exc))
            for label, path, expected in (
                ("CA", self.approval_relay_ca_file, self.approval_relay_ca_sha256),
                ("client certificate", self.approval_relay_client_cert,
                 self.approval_relay_client_cert_sha256),
            ):
                if not re.fullmatch(r"[0-9a-f]{64}", expected):
                    errors.append(f"approval relay {label} SHA-256 is required")
                else:
                    try:
                        if not hmac.compare_digest(
                                trusted_artifact_sha256(path, f"approval relay {label}"), expected):
                            errors.append(f"approval relay {label} SHA-256 does not match")
                    except ValueError as exc: errors.append(str(exc))
        if (self.approval_relay_submit_hmac_key and
                self.approval_relay_submit_hmac_key == self.approval_relay_callback_hmac_key):
            errors.append("approval relay submission and callback HMAC keys must be different")
        if not 1 <= self.approval_relay_timeout_seconds <= 60:
            errors.append("approval relay timeout must be between 1 and 60 seconds")
        if not 30 <= self.approval_callback_max_skew_seconds <= 900:
            errors.append("approval callback clock skew must be between 30 and 900 seconds")
        return errors

    def runtime_secret_errors(self):
        if self.environment != "production": return []
        errors = []
        if not self.manifest_hmac_key_file:
            errors.append("production manifest HMAC key must be loaded from a secret file")
        else:
            try:
                if read_private_secret(self.manifest_hmac_key_file, "manifest HMAC") != self.manifest_hmac_key:
                    errors.append("manifest HMAC secret binding does not match")
            except ValueError as exc: errors.append(str(exc))
        return errors

    def configuration_fingerprint(self, persisted=()) -> str:
        values = asdict(self)
        for name in ("local_credentials", "manifest_hmac_key",
                     "approval_relay_submit_hmac_key", "approval_relay_callback_hmac_key",
                     "expected_config_sha256"):
            values.pop(name, None)
        configured = sorted((str(row["key"]), str(row["value"])) for row in persisted)
        payload = json.dumps({"settings":values, "persisted":configured}, ensure_ascii=False,
                             sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def validate(self):
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("SFSS_ENVIRONMENT must be development, test, or production")
        if self.auth_backend not in {"local", "ldap"}: raise ValueError("SFSS_AUTH_BACKEND must be local or ldap")
        if self.auth_backend == "ldap":
            try:
                parsed_ldap = urlparse(self.ldap_uri)
                _ = parsed_ldap.port
                if (parsed_ldap.scheme not in {"ldap", "ldaps"} or not parsed_ldap.hostname or
                        parsed_ldap.username or parsed_ldap.password or parsed_ldap.path not in {"", "/"} or
                        parsed_ldap.query or parsed_ldap.fragment):
                    raise ValueError
            except ValueError as exc:
                raise ValueError("SFSS_LDAP_URI must be a plain ldap:// or ldaps:// host endpoint") from exc
            try:
                fields = {field for _, field, _, _ in string.Formatter().parse(self.ldap_user_template) if field}
                if "username" not in fields or not fields.issubset({"username", "base_dn"}): raise ValueError
                self.ldap_user_template.format(username="preflight", base_dn=self.ldap_base_dn)
            except (KeyError, ValueError, IndexError) as exc:
                raise ValueError("SFSS_LDAP_USER_TEMPLATE must use only {username} and optional {base_dn}") from exc
            bootstrap = [value.strip() for value in self.bootstrap_admins.split(",") if value.strip()]
            identity_pattern = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._@+\-]{0,126}[A-Za-z0-9])?\Z")
            if any(not identity_pattern.fullmatch(value) for value in bootstrap):
                raise ValueError("SFSS_BOOTSTRAP_ADMINS contains an invalid LDAP identity")
        if not 1 <= self.clamav_port <= 65535: raise ValueError("SFSS_CLAMAV_PORT is invalid")
        if self.clamav_stream_max_bytes <= 0: raise ValueError("SFSS_CLAMAV_STREAM_MAX_BYTES must be positive")
        if self.max_upload_bytes <= 0: raise ValueError("SFSS_MAX_UPLOAD_BYTES must be positive")
        if not 1024 * 1024 <= self.multipart_chunk_bytes <= 128 * 1024 * 1024:
            raise ValueError("SFSS_MULTIPART_CHUNK_BYTES must be between 1 MiB and 128 MiB")
        if min(self.retention_seconds, self.purge_grace_seconds, self.maintenance_interval_seconds,
               self.session_ttl_seconds, self.session_idle_seconds, self.scan_timeout_seconds,
               self.upload_session_ttl_seconds) <= 0:
            raise ValueError("SFSS lifetime and maintenance settings must be positive")
        if self.session_ttl_seconds < 60 or self.session_idle_seconds < 60:
            raise ValueError("SFSS human session lifetime and idle timeout must each be at least 60 seconds")
        if self.session_idle_seconds > self.session_ttl_seconds:
            raise ValueError("SFSS_SESSION_IDLE_SECONDS cannot exceed SFSS_SESSION_TTL_SECONDS")
        if not 1 <= self.max_sessions_per_user <= 10:
            raise ValueError("SFSS_MAX_SESSIONS_PER_USER must be between 1 and 10")
        if not 3600 <= self.service_token_max_ttl_seconds <= 365 * 24 * 3600:
            raise ValueError("SFSS_SERVICE_TOKEN_MAX_TTL_SECONDS must be between 1 hour and 365 days")
        if not 1 <= self.request_header_timeout_seconds <= 60:
            raise ValueError("SFSS_REQUEST_HEADER_TIMEOUT_SECONDS must be between 1 and 60")
        if not 30 <= self.request_io_timeout_seconds <= 24 * 3600:
            raise ValueError("SFSS_REQUEST_IO_TIMEOUT_SECONDS must be between 30 and 86400")
        if not 1 <= self.max_request_workers <= 512:
            raise ValueError("SFSS_MAX_REQUEST_WORKERS must be between 1 and 512")
        if not 1 <= self.job_workers <= 32: raise ValueError("SFSS_JOB_WORKERS must be between 1 and 32")
        if not 30 <= self.job_lease_seconds <= 24 * 3600: raise ValueError("SFSS_JOB_LEASE_SECONDS must be between 30 and 86400")
        if not 1 <= self.job_max_attempts <= 20: raise ValueError("SFSS_JOB_MAX_ATTEMPTS must be between 1 and 20")
        if not 1 <= self.max_active_uploads_per_user <= 100:
            raise ValueError("SFSS_MAX_ACTIVE_UPLOADS_PER_USER must be between 1 and 100")
        if self.max_staged_bytes_per_project < self.max_upload_bytes:
            raise ValueError("SFSS_MAX_STAGED_BYTES_PER_PROJECT must be at least SFSS_MAX_UPLOAD_BYTES")
        if self.min_free_bytes < 0: raise ValueError("SFSS_MIN_FREE_BYTES cannot be negative")
        if not 1 <= self.approval_relay_timeout_seconds <= 60:
            raise ValueError("SFSS_APPROVAL_RELAY_TIMEOUT_SECONDS must be between 1 and 60")
        if not 30 <= self.approval_callback_max_skew_seconds <= 900:
            raise ValueError("SFSS_APPROVAL_CALLBACK_MAX_SKEW_SECONDS must be between 30 and 900")
        if self.environment != "production": return
        errors = []
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}", self.release_id):
            errors.append("production release ID is required and must be a safe identifier")
        if not re.fullmatch(r"\d+\.\d+\.\d+", self.expected_python_version):
            errors.append("production expected Python version must be an exact major.minor.patch")
        elif tuple(int(value) for value in self.expected_python_version.split(".")) < (3, 12, 0):
            errors.append("production Python runtime must be from a supported 3.12 or newer branch")
        elif self.expected_python_version != platform.python_version():
            errors.append("running Python version does not match SFSS_EXPECTED_PYTHON_VERSION")
        if not re.fullmatch(r"[0-9a-f]{64}", self.expected_config_sha256):
            errors.append("production expected configuration SHA-256 is required")
        if self.auth_backend == "local": errors.append("local authentication is forbidden in production")
        if self.auth_backend == "ldap":
            if urlparse(self.ldap_uri).scheme.lower() != "ldaps": errors.append("production LDAP must use ldaps://")
            if not self.ldap_base_dn.strip(): errors.append("production LDAP base DN is required")
            if not self.bootstrap_admins.strip(): errors.append("production LDAP requires explicit bootstrap administrators")
            if not self.ldap_ca_file or not Path(self.ldap_ca_file).is_absolute():
                errors.append("production LDAP requires an absolute CA certificate path")
            if not re.fullmatch(r"[0-9a-f]{64}", self.ldap_ca_sha256):
                errors.append("production LDAP CA SHA-256 is required")
            else:
                try:
                    if not hmac.compare_digest(
                            trusted_artifact_sha256(self.ldap_ca_file, "production LDAP CA"),
                            self.ldap_ca_sha256):
                        errors.append("production LDAP CA SHA-256 does not match")
                except ValueError as exc: errors.append(str(exc))
            if self.allow_basic_auth: errors.append("per-request LDAP Basic authentication must be disabled")
        if self.dev_tokens_enabled: errors.append("development bearer tokens must be disabled")
        if self.session_ttl_seconds > 3600:
            errors.append("production human session lifetime must not exceed 3600 seconds")
        if self.session_idle_seconds > 900:
            errors.append("production human session idle timeout must not exceed 900 seconds")
        if self.max_sessions_per_user > 3:
            errors.append("production concurrent human sessions per user must not exceed 3")
        if self.service_token_max_ttl_seconds > 30 * 24 * 3600:
            errors.append("production service token lifetime must not exceed 30 days")
        if self.request_header_timeout_seconds > 15:
            errors.append("production request header timeout must not exceed 15 seconds")
        if self.request_io_timeout_seconds > 3600:
            errors.append("production request I/O timeout must not exceed 3600 seconds")
        if self.max_request_workers > 256:
            errors.append("production request worker limit must not exceed 256")
        scanner_names = {name.strip() for name in self.scanners.split(",") if name.strip()}
        if "mock" in scanner_names or "clamav" not in scanner_names:
            errors.append("production scanners must include clamav and exclude mock")
        if "clamav" in scanner_names and self.max_upload_bytes > self.clamav_stream_max_bytes:
            errors.append("production upload limit exceeds declared ClamAV StreamMaxLength")
        if "yara" in scanner_names and (not self.yara_rules or not Path(self.yara_rules).is_absolute()):
            errors.append("production YARA rules path must be absolute")
        if "yara" in scanner_names:
            if not re.fullmatch(r"[0-9a-f]{64}", self.yara_rules_sha256):
                errors.append("production YARA rules SHA-256 is required")
            else:
                try:
                    if not hmac.compare_digest(
                            trusted_artifact_sha256(self.yara_rules, "production YARA rules"),
                            self.yara_rules_sha256):
                        errors.append("production YARA rules SHA-256 does not match")
                except ValueError as exc: errors.append(str(exc))
        if not self.require_trusted_proxy or not self.trusted_zone_proxy_cidrs.strip():
            errors.append("trusted zone proxy enforcement and CIDRs are required")
        else:
            try:
                proxy_networks = [ipaddress.ip_network(value.strip(), strict=False)
                                  for value in self.trusted_zone_proxy_cidrs.split(",") if value.strip()]
                if not proxy_networks or any(not network.network_address.is_loopback or
                                             not network.broadcast_address.is_loopback
                                             for network in proxy_networks):
                    raise ValueError
            except ValueError: errors.append("trusted zone proxy CIDRs are invalid")
        try:
            admin_cidrs = [value.strip() for value in self.admin_source_cidrs.split(",") if value.strip()]
            if not admin_cidrs: raise ValueError
            for value in admin_cidrs: ipaddress.ip_network(value, strict=False)
        except ValueError: errors.append("management source CIDRs are required and must be valid")
        if not self.require_forwarded_https: errors.append("forwarded HTTPS enforcement is required")
        if not self.data_dir.is_absolute(): errors.append("production data directory must be absolute")
        if len(self.manifest_hmac_key) < 32: errors.append("a manifest HMAC key of at least 32 characters is required")
        errors.extend(self.runtime_secret_errors())
        if self.min_free_bytes < 1024 * 1024 * 1024:
            errors.append("production storage safety reserve must be at least 1 GiB")
        if self.allow_local_approval:
            errors.append("local outbound approval is forbidden in production")
        if self.auth_backend == "ldap" and self.ldap_ca_file and not Path(self.ldap_ca_file).is_file():
            errors.append("production LDAP CA certificate file is unavailable")
        if errors: raise ValueError("unsafe production configuration: " + "; ".join(errors))
