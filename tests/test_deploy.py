import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentTemplateTest(unittest.TestCase):
    def test_four_zone_architecture_has_explicit_default_deny_boundary(self):
        architecture = (ROOT / "docs/FOUR_ZONE_ARCHITECTURE.md").read_text(encoding="utf-8")
        for term in ("Green", "Yellow", "Blue", "Red", "Unix socket only",
                     "Explicitly deny green-to-red", "no approved egress service exists"):
            self.assertIn(term, architecture)
        traceability = (ROOT / "docs/SECURITY_TRACEABILITY.md").read_text(encoding="utf-8")
        self.assertIn("External evidence still required", traceability)
        self.assertIn("release remains blocked", traceability)

    def test_production_template_requires_release_runtime_fingerprint_and_secret_files(self):
        env = (ROOT / "deploy/sfss.env.example").read_text(encoding="utf-8")
        for name in ("SFSS_RELEASE_ID", "SFSS_EXPECTED_PYTHON_VERSION",
                     "SFSS_EXPECTED_CONFIG_SHA256", "SFSS_MANIFEST_HMAC_KEY_FILE",
                     "SFSS_APPROVAL_RELAY_SUBMIT_HMAC_KEY_FILE",
                     "SFSS_APPROVAL_RELAY_CALLBACK_HMAC_KEY_FILE", "SFSS_LDAP_CA_SHA256",
                     "SFSS_APPROVAL_RELAY_CA_SHA256",
                     "SFSS_APPROVAL_RELAY_CLIENT_CERT_SHA256"):
            self.assertIn(name + "=", env)
        self.assertNotIn("SFSS_MANIFEST_HMAC_KEY=", env)
        self.assertNotIn("SFSS_APPROVAL_RELAY_SUBMIT_HMAC_KEY=", env)
        self.assertNotIn("SFSS_APPROVAL_RELAY_CALLBACK_HMAC_KEY=", env)
        self.assertIn("SFSS_SESSION_TTL_SECONDS=3600", env)
        self.assertIn("SFSS_SESSION_IDLE_SECONDS=900", env)
        self.assertIn("SFSS_MAX_SESSIONS_PER_USER=3", env)
        self.assertIn("SFSS_SERVICE_TOKEN_MAX_TTL_SECONDS=2592000", env)
        self.assertIn("SFSS_REQUEST_HEADER_TIMEOUT_SECONDS=15", env)
        self.assertIn("SFSS_REQUEST_IO_TIMEOUT_SECONDS=3600", env)
        self.assertIn("SFSS_MAX_REQUEST_WORKERS=128", env)

    def test_production_ldap_dependencies_are_exact_and_hash_locked(self):
        requirements = (ROOT / "requirements-production.txt").read_text(encoding="utf-8")
        self.assertIn("--only-binary=:all:", requirements)
        self.assertIn("--require-hashes", requirements)
        self.assertIn("ldap3==2.9.1", requirements)
        self.assertIn("pyasn1==0.6.4", requirements)
        self.assertEqual(2, requirements.count("--hash=sha256:"))
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('ldap3==2.9.1', project)
        self.assertIn('pyasn1==0.6.4', project)

    def test_clamav_candidate_is_pinned_bounded_and_fail_closed_on_limits(self):
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("clamav/clamav:1.5.3", compose)
        self.assertNotIn("clamav/clamav:1.4", compose)
        self.assertIn('127.0.0.1:3310:3310', compose)
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("clamd.container.conf:/etc/clamav/clamd.conf:ro", compose)
        host = (ROOT / "deploy/clamav/clamd.conf.example").read_text(encoding="utf-8")
        container = (ROOT / "deploy/clamav/clamd.container.conf").read_text(encoding="utf-8")
        self.assertIn("TCPAddr 127.0.0.1", host)
        self.assertIn("TCPAddr 0.0.0.0", container)
        for config in (host, container):
            for setting in ("StreamMaxLength 2G", "MaxFileSize 2G", "MaxScanSize 2G",
                            "AlertExceedsMax yes", "AlertEncryptedArchive yes",
                            "ExitOnOOM yes", "EnableShutdownCommand no"):
                self.assertIn(setting, config)
        env = (ROOT / "deploy/sfss.env.example").read_text(encoding="utf-8")
        self.assertIn("SFSS_MAX_UPLOAD_BYTES=2147483648", env)
        self.assertIn("SFSS_CLAMAV_STREAM_MAX_BYTES=2147483648", env)
        self.assertIn("SFSS_YARA_RULES_SHA256=REPLACE_WITH_64_HEX_SHA256", env)

    def test_blue_gateway_derives_zone_from_client_certificate(self):
        config = (ROOT / "deploy/nginx/blue-core.conf").read_text(encoding="utf-8")
        self.assertIn("$ssl_client_s_dn $sfss_gateway_role", config)
        self.assertIn("CN=sfss-green-gateway", config)
        self.assertIn("X-SFSS-Gateway-Role $sfss_gateway_role", config)
        self.assertIn("X-SFSS-Zone $sfss_zone", config)
        self.assertNotIn("X-SFSS-Zone $http_x_sfss_zone", config)
        self.assertIn("ssl_crl /etc/sfss/tls/zone-gateway-ca.crl.pem", config)
        self.assertIn("ssl_verify_depth 2", config)
        self.assertIn("ssl_session_tickets off", config)

    def test_all_gateway_hops_verify_mtls_and_overwrite_client_address(self):
        for name in ("green", "red", "admin"):
            include = (ROOT / f"deploy/nginx/sfss-{name}-proxy.inc").read_text(encoding="utf-8")
            self.assertIn("proxy_ssl_verify on", include)
            self.assertIn("proxy_ssl_crl /etc/sfss/tls/blue-ca.crl.pem", include)
            self.assertIn("X-Forwarded-For $remote_addr", include)
            self.assertIn("limit_req", include)

    def test_public_gateway_tls_disables_session_tickets(self):
        for name in ("green", "red", "admin"):
            config = (ROOT / f"deploy/nginx/{name}.conf").read_text(encoding="utf-8")
            self.assertIn("ssl_protocols TLSv1.2 TLSv1.3", config)
            self.assertIn("ssl_session_tickets off", config)
            self.assertIn("Strict-Transport-Security", config)
            self.assertIn("server_tokens off", config)

    def test_zone_gateways_restrict_methods_before_blue_core(self):
        green = (ROOT / "deploy/nginx/green.conf").read_text(encoding="utf-8")
        red = (ROOT / "deploy/nginx/red.conf").read_text(encoding="utf-8")
        for config in (green, red):
            self.assertIn("/parts/[0-9]+$ { limit_except PUT", config)
            self.assertIn("/complete$ { limit_except POST", config)
            self.assertIn("/uploads$ { limit_except POST", config)
        self.assertIn("/objects$ { limit_except GET", green)
        self.assertNotIn("/objects$ { limit_except GET POST", green)
        self.assertIn("/outbound$ { limit_except GET", green)
        self.assertIn("/objects$ { limit_except GET", red)
        self.assertIn("/outbound$ { limit_except GET", red)
        self.assertNotIn("/outbound$ { limit_except GET POST", red)

    def test_approval_callback_is_only_exposed_on_management_gateway(self):
        admin = (ROOT / "deploy/nginx/admin.conf").read_text(encoding="utf-8")
        self.assertIn("location = /v1/integrations/wecom/callback", admin)
        self.assertIn("client_max_body_size 64k", admin)
        self.assertIn("limit_except POST", admin)
        for name in ("green", "red"):
            config = (ROOT / f"deploy/nginx/{name}.conf").read_text(encoding="utf-8")
            self.assertNotIn("integrations/wecom/callback", config)

    def test_detailed_observability_is_management_only(self):
        admin = (ROOT / "deploy/nginx/admin.conf").read_text(encoding="utf-8")
        self.assertIn("health|ready|metrics", admin)
        for name in ("green", "red"):
            config = (ROOT / f"deploy/nginx/{name}.conf").read_text(encoding="utf-8")
            self.assertIn("favicon\\.ico|health)", config)
            self.assertNotIn("|ready", config)
            self.assertNotIn("|metrics", config)

    def test_web_large_download_uses_disk_streaming_and_bounds_memory_fallback(self):
        app = (ROOT / "src/sfss/web/app.js").read_text(encoding="utf-8")
        self.assertIn('"showSaveFilePicker" in window', app)
        self.assertIn("response.body.getReader()", app)
        self.assertIn("received!==record.size", app)
        self.assertIn("record.size>256*1024*1024", app)

    def test_web_console_supports_cookie_csrf_and_direction_bound_multipart(self):
        app = (ROOT / "src/sfss/web/app.js").read_text(encoding="utf-8")
        self.assertIn('credentials:"same-origin"', app)
        self.assertIn('headers.set("X-SFSS-CSRF","1")', app)
        self.assertIn('const zoneHeaders={"X-SFSS-Zone":direction==="inbound"?"green":"red"}', app)

    def test_service_unit_has_process_and_filesystem_hardening(self):
        unit = (ROOT / "deploy/systemd/sfss.service").read_text(encoding="utf-8")
        self.assertIn("sfss --unix-socket /run/sfss/sfss.sock", unit)
        self.assertIn("RuntimeDirectory=sfss", unit)
        for directive in ("NoNewPrivileges=true", "ProtectSystem=strict", "PrivateDevices=true",
                          "MemoryDenyWriteExecute=true", "TasksMax=512", "ProtectProc=invisible",
                          "RestrictNamespaces=true", "SystemCallFilter=@system-service",
                          "KillSignal=SIGTERM", "TimeoutStopSec=3700s"):
            self.assertIn(directive, unit)

    def test_blue_core_uses_permissioned_unix_socket_not_tcp(self):
        config = (ROOT / "deploy/nginx/blue-core.conf").read_text(encoding="utf-8")
        self.assertIn("server unix:/run/sfss/sfss.sock;", config)
        self.assertIn("proxy_pass http://sfss_core;", config)
        self.assertNotIn("proxy_pass http://127.0.0.1", config)


if __name__ == "__main__": unittest.main()
