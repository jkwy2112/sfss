# SFSS four-zone deployment candidate

This directory is a hardened deployment **template**, not a production security certification. Replace every example address, certificate path, LDAP DN, and account with values approved for the target network.

Use [the four-zone architecture and firewall matrix](../docs/FOUR_ZONE_ARCHITECTURE.md) as the network-review baseline and [security traceability](../docs/SECURITY_TRACEABILITY.md) to distinguish repository controls from evidence that must be collected in the target environment.

## Placement

- Green zone: `nginx/green.conf`, exposing only `/green` and green data operations.
- Yellow zone red-side portal: `nginx/red.conf`, exposing only `/red`, released inbound downloads, and outbound uploads.
- Yellow management network: `nginx/admin.conf`, restricted to management source CIDRs.
- Yellow/internal integration network: deploy a separately reviewed WeCom approval relay; only it holds WeCom credentials and Internet/API reachability.
- Blue exchange zone: `nginx/blue-core.conf`, the only TLS/mTLS ingress to the SFSS core; SFSS accepts HTTP only through `/run/sfss/sfss.sock`.
- Red zone: install the `sfss-agent` CLI with a red-agent service identity and client certificate. It pulls released inbound objects and pushes outbound objects; it receives no Internet route.

There is no green-to-red route. Gateway-to-blue traffic uses mTLS. The blue Nginx proxy is the only process allowed to connect to the SFSS application socket and overwrites forwarding metadata before passing it to SFSS.

Production startup forbids every TCP application listener and accepts only an absolute Unix socket directly below `/run/sfss`. The socket is created mode `0660`; systemd owns its parent runtime directory mode `0750`, and shutdown removes only the exact socket inode created by that process. Add the blue Nginx worker identity to the `sfss` group so it can traverse the runtime directory and connect, but keep `/srv/sfss` mode `0700` so group membership does not grant data access. Do not widen socket permissions as a convenience; scale-out requires the reviewed HA service/data architecture and an equivalent authenticated workload boundary.

Green and red gateway templates also enforce an HTTP method allowlist per route before traffic reaches blue. Green permits inbound upload creation/parts and approved outbound reads; red permits released inbound reads and outbound upload creation/parts. This is defense in depth—the SFSS core independently repeats zone, gateway-role, project-role, token-scope, and method checks.

The deployment templates do not expose the legacy direct-upload POST routes. Production mode also rejects them in the core, so large transfers must use multipart sessions and retain resumability, part hashes, capacity reservations, and continuous authorization checks.

Data-zone gateways expose only the minimal `/health` liveness result. Detailed `/ready` and `/metrics` are routed only by the yellow management gateway, additionally restricted by management source CIDRs in Nginx and SFSS. Configure the monitoring collector through this mTLS management path; never scrape blue directly or re-expose operational metrics on green/red DNS names.

At minimum, alert on `/ready` returning non-200, any `sfss_scanner_up` value of zero, scan jobs accumulating in `failed` or `queued`, storage approaching the configured reserve, a stale/failed maintenance run, approval callback errors, and transfers remaining in an intermediate state beyond the approved service-level objective. Send alerts and audit events to the internal monitoring/SIEM platform without adding project, user, object, or filename labels to time-series data.

## Required setup

1. Create a dedicated unprivileged `sfss` account and `/srv/sfss` owned by that account with mode `0700`.
2. Build the SFSS wheel in a controlled build environment. From the approved internal artifact mirror, install `requirements-production.txt` first and then install the wheel with `--no-deps` into `/opt/sfss/venv`; install the reviewed OS-packaged `yara` CLI for the production adapter. The requirements file permits only wheels, pins `ldap3` and `pyasn1`, and verifies their PyPI SHA-256 hashes. Do not give a blue-zone runtime host direct PyPI access.
3. Generate independent client certificates for the green, yellow-red, and yellow-admin gateways. Their subject common names must be exactly `sfss-green-gateway`, `sfss-red-gateway`, and `sfss-admin-gateway`, matching `nginx/blue-core.conf`. Configure the blue proxy to trust only the gateway CA. Install current CRLs as `/etc/sfss/tls/zone-gateway-ca.crl.pem` on blue and `/etc/sfss/tls/blue-ca.crl.pem` on every gateway. The blue proxy derives zone and gateway role from the verified, non-revoked certificate subject; it never trusts an incoming zone header.
4. Generate the manifest and approval-relay HMAC secrets using at least 32 random bytes from the organization's secrets manager. Materialize each as a different absolute mode-`0600` regular file and configure the corresponding `*_FILE` variables. Production rejects raw environment HMAC values, links, special files, group/other permissions, short files, control characters, and a file whose current content differs from the startup-loaded value. Independently record the LDAP CA, approval-relay CA, and approval-relay client-certificate digests in their `*_SHA256` settings; startup hashes them safely and runtime identity drift closes the data plane. LDAP CA drift additionally disables login even though bounded recovery login normally remains available. Do not place secrets in source control or the environment file.
5. Copy `sfss.env.example` to `/etc/sfss/sfss.env`, mode `0600`, and replace all network/LDAP/rule settings. Set `SFSS_RELEASE_ID` to the signed immutable build identifier and `SFSS_EXPECTED_PYTHON_VERSION` to the exact `major.minor.patch` runtime from a currently supported Python 3.12-or-newer branch; startup rejects an older branch or mismatch. Python 3.9 reached end of life on 2025-10-31 and is not a production option.
6. Install `systemd/sfss.service`, then install the four Nginx configurations on their corresponding hosts.
7. Confirm no process is listening on application TCP port 8080. Only blue Nginx's explicitly authorized group may connect to `/run/sfss/sfss.sock`; only certificate-authenticated zone gateways may reach blue Nginx `8443`.
8. Run the full test suite, backup/restore drill, EICAR rejection, YARA test rule, large-file interruption test, and firewall bypass test before release.

Install a currently supported, security-fixed ClamAV build. This repository's minimum accepted branches are 1.4.5 or 1.5.3/newer; health fails when VERSION is disabled, unparseable, or older. The local Compose tag is a developer convenience, not production provenance—production must pin the approved package/container digest and retain signature/SBOM/vulnerability evidence. The 1.5.3/1.4.5 releases address multiple malicious-file parser and limit-bypass vulnerabilities documented in the official [ClamAV releases](https://github.com/Cisco-Talos/clamav/releases).

Store the reviewed YARA bundle as an absolute regular non-link file that is not writable by group or others, and put its independently recorded SHA-256 in `SFSS_YARA_RULES_SHA256`. Validation hashes the configured file and the actual persisted administrator-selected path at startup. The running service binds its device/inode/size/mtime/ctime identity into the acceptance gate; any in-place edit, replacement, link, or scanner-path switch closes the data plane until the reviewed hash, configuration fingerprint, preflight, and restart process is completed.

For same-host clamd, start from `clamav/clamd.conf.example`, which binds only loopback. The Compose-only variant binds inside the container but Docker publishes it only on host loopback; never install that variant on a host. Confirm with `clamconf -n` that `StreamMaxLength`, `MaxFileSize`, `MaxScanSize`, `AlertExceedsMax`, encrypted/broken alerts, recursion/file/time limits, and disabled administrative commands match the release record. The declared `SFSS_CLAMAV_STREAM_MAX_BYTES` and effective upload limit must not exceed the actual daemon stream limit. Because clamd TCP has no authentication or encryption, it must never be exposed to a data-zone or untrusted interface.

Interactive LDAP names are intentionally limited to ASCII account/UPN characters (`A-Z`, `a-z`, digits, `.`, `_`, `@`, `+`, `-`) with an alphanumeric first and last character. Configure users to enter a UPN or approved account name; DN fragments, `DOMAIN\\user`, control characters, and Unicode confusables are rejected before template expansion. The LDAP URI must be a host-only endpoint and the bind template may reference only `{username}` and `{base_dn}`. If the enterprise requires another identifier form, add an independently reviewed canonicalization/mapping adapter instead of weakening these checks.

Interactive sessions are issued for the gateway entrance derived by blue Nginx from mTLS identity. Keep `SFSS_SESSION_TTL_SECONDS` at 3600 or below, `SFSS_SESSION_IDLE_SECONDS` at 900 or below, and `SFSS_MAX_SESSIONS_PER_USER` at three or below; production validation rejects weaker values. On upgrade, legacy/unbound sessions are revoked at startup. Exercise green, red, and admin logins independently and verify that copying any token to another entrance returns 401 while its original entrance remains usable. This limits bearer replay but does not provide MFA or instant AD disable notification; the target identity architecture must supply and test those controls.

For a new data directory, initialize the schema without listening on a port, calculate the effective non-secret configuration fingerprint, write the returned digest to `SFSS_EXPECTED_CONFIG_SHA256`, and then run strict preflight. Production runtime deliberately refuses a missing/uninitialized database, a linked data root, any group/other permission anywhere below the root, or payload/part modes that do not match their state; it does not silently `chmod` evidence of permission drift. Development mode may repair verified legacy modes for migration convenience.

```sh
set -a
. /etc/sfss/sfss.env
set +a
/opt/sfss/venv/bin/sfss-admin initialize --data-dir /srv/sfss
/opt/sfss/venv/bin/sfss-admin config-fingerprint --data-dir /srv/sfss
# Update SFSS_EXPECTED_CONFIG_SHA256 in the controlled environment file, then reload it.
/opt/sfss/venv/bin/sfss-admin preflight
```

`initialize` refuses an existing database. The fingerprint excludes raw credentials/HMAC values but includes their configured file paths, every other effective setting, and persisted administrator-editable system configuration. Any later setting/configuration change makes startup or `/ready` fail until an authorized change process records the new fingerprint. A running production process also blocks data-plane requests, callbacks, scans, and approved promotion on drift; only observability and tightly bounded rollback/credential-containment routes remain. Do not bypass this 503 gate. Stop intake, review the audited change, restore the accepted values or approve a new fingerprint through change control, run preflight, and restart. The preflight command exits nonzero unless production configuration, runtime/release identity, fingerprint, read-only data/audit/payload verification, persisted identity/approval policy, scanner health, disk reserve, the LDAP client package, and an authenticated LDAPS TLS handshake all pass. Archive the JSON result with the release evidence. The LDAPS check validates connectivity and the server certificate but deliberately does not store or exercise a user's password; a separately controlled real bind/login test is still required.

The preflight records installed LDAP dependency versions. `ldap3` 2.9.1 is the latest stable release currently published on PyPI, but its age is itself a review concern, not a security endorsement. Run an approved software-composition/vulnerability scan on the exact wheel set and review the project's maintenance status before each release. A future version or alternate LDAP client must go through compatibility, AD, fail-closed, and thread-safety testing before updating the lock.

Generate the canonical file inventory from the final read-only/staged artifact directory, with the output outside that directory:

```sh
/opt/sfss/venv/bin/sfss-admin release-manifest --root /secure-build/sfss-artifact --output /secure-evidence/sfss-release-manifest.json
```

The command rejects links and special files, opens payloads without following symlinks, detects mutation while hashing, records mode/size/SHA-256 for every file, and creates the manifest mode `0600` without overwriting existing evidence. Sign the manifest using the organization's code-signing service, attach the SBOM and vulnerability results, and verify all signatures again after transfer into the deployment network. This inventory does not replace signed source revision, build provenance, or container/package signatures.

The approval relay must expose its submission endpoint to blue over mTLS and reach the management gateway callback path `/v1/integrations/wecom/callback` from an address included in both the gateway and `SFSS_ADMIN_SOURCE_CIDRS` allowlists. Keep the relay client key mode `0600` and use separate HMAC keys for submission and callback. Synchronize clocks from the approved internal time source; callbacks outside `SFSS_APPROVAL_CALLBACK_MAX_SKEW_SECONDS` are rejected. The relay must persist Tencent event IDs, validate/decrypt official callbacks with the approved SDK, emit only normalized final decisions, and demonstrate duplicate, reordered, delayed, forged, revoked-certificate, API-timeout, and callback-loss tests. `GET /ready` reports a degraded relay configuration when any enabled WeCom policy loses its required local files or keys; live relay/API monitoring remains an external alerting responsibility.

Implement the connector against [the versioned internal relay contract](../docs/APPROVAL_RELAY_PROTOCOL.md). In particular, `transfer_id` is the submission idempotency key and the exact callback `event_id`/body must survive relay retries and restarts.

Before every Nginx reload, run `nginx -t`. CRL distribution must be automated from the internal PKI, monitored for freshness, written atomically, and followed by a successful configuration test/reload on every gateway and blue node. A missing, stale, unreadable, or failed-to-reload CRL is a production incident and must fail the deployment gate; do not remove `ssl_crl`/`proxy_ssl_crl` to restore traffic. Keep gateway certificate lifetimes short and test emergency certificate revocation from each zone as part of the release drill.

The supplied systemd unit uses `ProtectProc`, namespace restrictions, and the `@system-service` syscall allowlist. Validate it with `systemd-analyze security sfss.service` and a real LDAP/scanner/upload/download smoke test on the exact target distribution; do not silently remove a hardening directive when an older systemd release rejects it. Public gateway templates send HSTS and suppress Nginx version tokens. Confirm that the internal DNS names are dedicated to HTTPS before enabling the templates because HSTS is intentionally sticky.

SIGTERM triggers graceful shutdown: the core stops accepting requests, wakes the maintenance loop, waits for active HTTP handler threads, stops queue workers, and releases the runtime lock. The supplied `TimeoutStopSec=3700s` is slightly longer than the gateway/Agent default maximum request window. Recalculate these values together if the approved request timeout changes; shortening only the systemd timeout turns routine deployments into forced mid-request termination. Scanner jobs interrupted by a forced stop remain fail closed and are recovered/quarantined on restart.

## Transfer Agent identities and token rotation

Create a different non-interactive SFSS service identity for each project, zone, and operational direction. Assign only the matching project role, then issue the narrowest token from the administrator configuration page. Never issue an Agent token to a human LDAP identity and never reuse an interactive bearer session in automation.

Set `SFSS_AGENT_PRODUCTION=true` (or pass `--production`) in every managed invocation. The production Agent refuses raw token/HMAC environment or command-line values, plain HTTP, missing CA/mTLS identity, unsigned downloads, and output overwrite. Treat a failure of this gate as a deployment error rather than removing the flag.

| Agent placement | Project role | Token zone/scope |
|---|---|---|
| Green inbound sender | `uploader` | `green` / `inbound_upload` |
| Red inbound receiver | `downloader` | `red` / `inbound_download` |
| Red outbound sender | `red_uploader` | `red` / `outbound_upload` |
| Green outbound receiver | `green_downloader` | `green` / `outbound_download` |

The raw token is returned only once and the database retains only its SHA-256 digest. Have the approved secret manager materialize it as a root-managed, Agent-readable mode-`0600` regular file and set `SFSS_AGENT_TOKEN_FILE`; do not put it in a command line, environment file, unit file, shell history, source repository, URL, or logs. Production `SFSS_SERVICE_TOKEN_MAX_TTL_SECONDS` is at most 2592000 (30 days); issuance rejects a longer request, while startup and preflight reject any still-active historical token created with a longer original lifetime. Set a shorter operational lifetime where possible, maintain overlapping old/new tokens only for the rotation window, validate the new token on the correct mTLS gateway, then explicitly revoke the old one. Disabling the service identity or archiving the project revokes all associated tokens. Certificate and token rotation are independent: both must be completed and audited.

Size `SFSS_AGENT_TIMEOUT_SECONDS` from the slowest approved link and multipart chunk size, within the enforced 30–86400 second range. The Agent performs one full streaming source-hash pass before the per-part upload passes so the server can reject any hybrid or changed-file assembly; include that disk-read cost in transfer windows and benchmarks. It streams slices instead of retaining whole parts in RAM, but parallelism still consumes file descriptors, disk bandwidth, gateway connections, and scanner/staging capacity. Benchmark the default four workers, reduce it where links or storage are constrained, and never increase it solely to mask an undersized gateway. Use a new output path for downloads; `--overwrite` is an explicit destructive exception, not a routine flag.

## Offline verification and backup drill

The service holds an exclusive lock on its data directory and refuses a second runtime. Backups deliberately require downtime so SQLite, upload state, payloads, and the audit-chain head are one consistent set.

```sh
systemctl stop sfss
/opt/sfss/venv/bin/sfss-admin verify --data-dir /srv/sfss
/opt/sfss/venv/bin/sfss-admin export-audit --data-dir /srv/sfss --output /secure-staging/sfss-audit-$(date +%F).jsonl
/opt/sfss/venv/bin/sfss-admin backup --data-dir /srv/sfss --output /secure-staging/sfss-$(date +%F).tar
systemctl start sfss
```

The audit export is canonical JSONL: each line contains the exact database event plus its previous and current chain hashes. Record the reported event count, chain head, and file SHA-256, then ingest the file into the approved immutable/WORM audit platform. The local export is evidence for that handoff; it is not itself immutable storage.

On the receiving verification host, using expected values obtained from the approved independent release/evidence channel, run:

```sh
/opt/sfss/venv/bin/sfss-admin verify-audit-export \
  --input /worm-ingest/sfss-audit-YYYY-MM-DD.jsonl \
  --expected-sha256 REPLACE_WITH_RECORDED_64_HEX_SHA256 \
  --expected-head REPLACE_WITH_RECORDED_64_HEX_CHAIN_HEAD \
  --expected-events REPLACE_WITH_RECORDED_EVENT_COUNT
```

Archive the verifier JSON result. The command does not access the source database and detects record/hash/link errors, truncation, unexpected prefixes, file replacement links, and mutation during verification. A value copied only from the same compromised blue host is not a trust anchor: sign the export/summary with the organizational service or retain the expected values in independently controlled WORM/SIEM metadata.

Record the reported backup SHA-256, encrypt the archive using the organization's approved backup/KMS workflow, move it to immutable off-host storage, and remove plaintext staging copies according to policy. `/etc/sfss` certificates, environment/secrets references, YARA rules, Nginx configs, and systemd unit are not inside the data archive and require a separately encrypted configuration backup.

Restore drills must use a new empty target, never overwrite the active data directory:

```sh
/opt/sfss/venv/bin/sfss-admin restore \
  --archive /secure-staging/sfss-YYYY-MM-DD.tar \
  --expected-sha256 REPLACE_WITH_INDEPENDENTLY_RECORDED_BACKUP_SHA256 \
  --target /srv/sfss-restore-test
/opt/sfss/venv/bin/sfss-admin verify --data-dir /srv/sfss-restore-test
```

Validate the restored archive checksum, audit-chain head, object counts, representative downloads, and scanner recovery before deleting the drill target. Production release still requires evidence from the actual backup platform and retention policy.

The runtime scan queue is persisted in SQLite with leases, restart recovery, de-duplication, retry, and fail-closed dead letters. This improves single-node crash safety but is not a multi-node broker. The standard-library HTTP server and SQLite remain release blockers for high-volume/HA production. The blue Nginx layer provides TLS, request limits, and connection handling for a controlled pilot, but a reviewed ASGI/data service, PostgreSQL, and an HA broker are still required for final production acceptance.
