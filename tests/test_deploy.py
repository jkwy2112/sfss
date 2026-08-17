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

    def test_split_system_units_are_single_purpose_and_separated(self):
        for mode in ("inbound", "outbound"):
            unit = (ROOT / f"deploy/systemd/sfss-{mode}.service").read_text(encoding="utf-8")
            env = (ROOT / f"deploy/sfss-{mode}.env.example").read_text(encoding="utf-8")
            self.assertIn(f"sfss --unix-socket /run/sfss-{mode}/sfss.sock", unit)
            self.assertIn(f"RuntimeDirectory=sfss-{mode}", unit)
            self.assertIn(f"ReadWritePaths=/srv/sfss-{mode}", unit)
            self.assertIn(f"EnvironmentFile=/etc/sfss/sfss-{mode}.env", unit)
            for directive in ("NoNewPrivileges=true", "ProtectSystem=strict", "MemoryDenyWriteExecute=true",
                              "SystemCallFilter=@system-service", "KillSignal=SIGTERM"):
                self.assertIn(directive, unit)
            self.assertIn(f"SFSS_DEPLOYMENT_MODE={mode}", env)
            self.assertIn(f"SFSS_DATA_DIR=/srv/sfss-{mode}", env)
            self.assertIn("SFSS_ENVIRONMENT=production", env)
            self.assertIn("SFSS_MANIFEST_HMAC_KEY_FILE=", env)
        combined = (ROOT / "deploy/systemd/sfss.service").read_text(encoding="utf-8")
        self.assertIn("sfss --unix-socket /run/sfss/sfss.sock", combined)
        self.assertNotIn("SFSS_DEPLOYMENT_MODE", combined)

    def test_split_blue_cores_proxy_their_own_socket_and_hostname(self):
        for mode, socket, host in (("inbound", "/run/sfss-inbound/sfss.sock", "blue-in-sfss.internal"),
                                   ("outbound", "/run/sfss-outbound/sfss.sock", "blue-out-sfss.internal")):
            config = (ROOT / f"deploy/nginx/blue-core-{mode}.conf").read_text(encoding="utf-8")
            self.assertIn(f"server unix:{socket};", config)
            self.assertIn(f"server_name {host};", config)
            self.assertIn("$ssl_client_s_dn $sfss_gateway_role", config)
            self.assertIn("X-SFSS-Gateway-Role $sfss_gateway_role", config)
            self.assertIn("ssl_crl /etc/sfss/tls/zone-gateway-ca.crl.pem", config)
            self.assertNotIn("proxy_pass http://127.0.0.1", config)
            for other in ("inbound", "outbound"):
                if other != mode:
                    self.assertNotIn(f"/run/sfss-{other}/", config)

    def test_split_zone_gateways_expose_only_their_workflow_routes(self):
        expectations = {
            "green-inbound.conf": ("/etc/nginx/sfss-in-green-proxy.inc",
                                   ("/v1/projects/[^/]+/uploads$", "/v1/uploads/[^/]+/complete$",
                                    "/v1/uploads/[^/]+/parts/[0-9]+$"),
                                   ("/v1/projects/[^/]+/outbound", "/download")),
            "red-inbound.conf": ("/etc/nginx/sfss-in-red-proxy.inc",
                                 ("/v1/projects/[^/]+/objects/[^/]+/download$",),
                                 ("/v1/projects/[^/]+/outbound", "/uploads")),
            "red-outbound.conf": ("/etc/nginx/sfss-out-red-proxy.inc",
                                  ("/v1/projects/[^/]+/uploads$", "/v1/uploads/[^/]+/parts/[0-9]+$",
                                   "/v1/projects/[^/]+/outbound$"),
                                  ("/v1/projects/[^/]+/objects", "decision", "/download")),
            "green-outbound.conf": ("/etc/nginx/sfss-out-green-proxy.inc",
                                   ("/v1/projects/[^/]+/outbound$", "/v1/projects/[^/]+/outbound/[^/]+/download$"),
                                   ("/uploads", "/v1/projects/[^/]+/objects")),
        }
        for name, (include, required, forbidden) in expectations.items():
            config = (ROOT / f"deploy/nginx/{name}").read_text(encoding="utf-8")
            with self.subTest(gateway=name):
                self.assertIn(include, config)
                self.assertIn("proxy_ssl_verify on", (ROOT / "deploy/nginx" /
                                                      include.split("/")[-1]).read_text(encoding="utf-8"))
                for route in required:
                    self.assertIn(route, config)
                for route in forbidden:
                    self.assertNotIn(route, config)
                for directive in ("ssl_protocols TLSv1.2 TLSv1.3", "ssl_session_tickets off",
                                  "Strict-Transport-Security", "server_tokens off"):
                    self.assertIn(directive, config)

    def test_split_blue_upstream_targets_and_management_callback_split(self):
        for system, host in (("in", "blue-in-sfss.internal"), ("out", "blue-out-sfss.internal")):
            for zone in ("green", "red", "admin"):
                include = (ROOT / f"deploy/nginx/sfss-{system}-{zone}-proxy.inc").read_text(encoding="utf-8")
                self.assertIn(f"proxy_pass https://{host}:8443;", include)
                self.assertIn(f"proxy_ssl_name {host};", include)
                expected_zone = '""' if zone == "admin" else zone
                self.assertIn(f"proxy_set_header X-SFSS-Zone {expected_zone};", include)
                self.assertIn("proxy_ssl_verify on", include)
                self.assertIn("proxy_ssl_crl /etc/sfss/tls/blue-ca.crl.pem", include)
                self.assertIn("X-Forwarded-For $remote_addr", include)
        inbound_admin = (ROOT / "deploy/nginx/admin-inbound.conf").read_text(encoding="utf-8")
        self.assertNotIn("integrations/wecom/callback", inbound_admin)
        self.assertIn("sfss-in-admin-proxy.inc", inbound_admin)
        outbound_admin = (ROOT / "deploy/nginx/admin-outbound.conf").read_text(encoding="utf-8")
        self.assertIn("location = /v1/integrations/wecom/callback", outbound_admin)
        self.assertIn("client_max_body_size 64k", outbound_admin)
        self.assertIn("sfss-out-admin-proxy.inc", outbound_admin)
        for config in (inbound_admin, outbound_admin):
            self.assertIn("health|ready|metrics", config)
            self.assertIn("allow 10.20.10.0/24", config)

    def test_split_outbound_env_keeps_approval_relay_and_inbound_drops_it(self):
        outbound = (ROOT / "deploy/sfss-outbound.env.example").read_text(encoding="utf-8")
        inbound = (ROOT / "deploy/sfss-inbound.env.example").read_text(encoding="utf-8")
        for name in ("SFSS_APPROVAL_RELAY_SUBMIT_HMAC_KEY_FILE",
                     "SFSS_APPROVAL_RELAY_CALLBACK_HMAC_KEY_FILE",
                     "SFSS_APPROVAL_RELAY_CA_SHA256", "SFSS_ALLOW_LOCAL_APPROVAL=false"):
            self.assertIn(name, outbound)
            self.assertNotIn(name, inbound)
        for name in ("SFSS_LDAP_CA_SHA256", "SFSS_YARA_RULES_SHA256", "SFSS_SCANNERS=clamav,yara",
                     "SFSS_REQUIRE_TRUSTED_PROXY=true"):
            for env in (inbound, outbound):
                self.assertIn(name, env)


if __name__ == "__main__": unittest.main()
