# SFSS foundation

SFSS is a runnable first-phase foundation for a Fabless-oriented controlled file shuttle:

`green upload -> isolated storage -> content detection + asynchronous scanning -> released buffer -> red read-only download`

This repository is **not a production security guarantee**. The default scanner is a development mock and the standard-library HTTP server has no TLS termination. The current SQLite-backed scan queue is restart-durable for a single node, but it is not an HA broker. Deploy default mode only as a development/evaluation service until the controls in “Known limits” are addressed.

## Two-system production split

Production deploys SFSS as two independently operated single-purpose systems, selected with `SFSS_DEPLOYMENT_MODE`:

- **Inbound system (`SFSS_DEPLOYMENT_MODE=inbound`)**: 绿区上传 + 红区下载 — `green upload -> isolated storage -> content detection + asynchronous scanning -> released buffer -> red read-only download`. It serves no outbound route, role, token scope, job kind, or database record; each returns 404/400 or fails startup.
- **Outbound system (`SFSS_DEPLOYMENT_MODE=outbound`)**: 红区上传 + 外发 — `red upload -> outbound isolation -> scanners -> classifier -> approval (WeCom relay) -> released-green buffer -> green download`. It serves no inbound route, role, token scope, job kind, or database record.

Each system has its own data directory (`/srv/sfss-inbound`, `/srv/sfss-outbound`), Unix socket (`/run/sfss-inbound/sfss.sock`, `/run/sfss-outbound/sfss.sock`), database, projects/memberships, service tokens, audit chain, and deployment templates under `deploy/`. Production validation rejects `combined` mode, and startup fails closed if a data directory contains records of the other workflow, so systems cannot share or silently migrate state. The local combined mode (`SFSS_DEPLOYMENT_MODE=combined`, the default) remains a development/evaluation convenience only. See [deploy/README.md](deploy/README.md) for the split placement and per-system drill.

Use the [production acceptance gate](docs/PRODUCTION_ACCEPTANCE.md) to distinguish a tested candidate build from an approved deployment. Missing target-environment evidence is a release blocker, not a documentation exception.

## Run locally

Python 3.9+ remains supported for local/mock evaluation. Production mode rejects branches older than Python 3.12 and also requires an exact patch-version match; the current developer workstation's Python 3.9 runtime is therefore not acceptable production evidence.

```sh
cd /Users/weiwang/workspace/ai/sfss
PYTHONPATH=src python3 -m sfss.server --port 8080
```

The default administrator login is `admin / admin123`. Local mode exposes separate portals:

- `http://127.0.0.1:8080/green`: green upload and approved outbound download only;
- `http://127.0.0.1:8080/red`: released inbound buffer and red outbound upload only;
- `http://127.0.0.1:8080/admin`: platform statistics, configuration, and remediation;
- `http://127.0.0.1:8080/`: compatibility console for local development and local approval testing.

The portal split is a UI and application-policy boundary. In the supplied four-zone template the blue reverse proxy derives `green`, `red`, or `admin` gateway identity from exact mTLS certificate CNs, overwrites all incoming zone/role headers, and the application checks gateway role again. Project/member/policy/audit/approval operations are management-gateway only. Do not treat a browser-provided `X-SFSS-Zone` as a production trust signal.

See [the four-zone architecture](docs/FOUR_ZONE_ARCHITECTURE.md) for component placement, end-to-end flows, and the default-deny firewall matrix. [Security traceability](docs/SECURITY_TRACEABILITY.md) maps each requirement to repository evidence and the target-environment evidence still required for release.

Open `http://127.0.0.1:8080/admin` for the platform administration control plane. Its statistics, system configuration, and security-remediation views are separate. A platform administrator can create/disable local accounts, reset passwords, grant platform-admin status, rename/archive/restore projects, inspect and revoke project roles, configure retention/upload limits and scanner adapters, rescan quarantined inbound or outbound objects, expire objects, and review global events. Development changes take effect immediately. A production change is explicitly returned and displayed as `staged`: it intentionally trips the runtime fingerprint gate and requires approved fingerprint generation, strict preflight, and restart before the data plane can resume. SFSS intentionally has no manual “release” action: quarantine cannot bypass a clean scanner decision.

## Resumable large-file transfer

The browser portals use persistent multipart upload sessions for both directions. The server returns a configurable chunk size (32 MiB by default), accepts up to four parts concurrently from the browser, validates every part with SHA-256, reports received parts after a refresh/restart, and assembles only a complete gap-free upload. Each part record, session update, and chained audit event commits atomically. The final object is hashed again, its registration is audited, the upload session is durably finalized, and only then is scanning enqueued. A partial file is never visible as a released object. Project source-IP policy is rechecked when creating a session, receiving every part, and completing it, so a revoked network range cannot finalize an already-open upload.

The API sequence is:

1. `POST /v1/projects/{project}/uploads` with `direction`, `filename`, and `total_size`;
2. `PUT /v1/uploads/{upload_id}/parts/{number}` with `X-Part-SHA256`;
3. `GET /v1/uploads/{upload_id}` to discover completed parts and resume;
4. `POST /v1/uploads/{upload_id}/complete` to verify, assemble, and submit scanning;
5. `DELETE /v1/uploads/{upload_id}` to cancel an active session.

Downloads support a single standard byte range, `206 Partial Content`, `Content-Range`, `Accept-Ranges`, `ETag`, `If-Range`, and `HEAD`. Released local payloads are sealed read-only. File size, modification time, and change time provide a fast immutable check for repeated range requests; if that fingerprint changes, SFSS performs a full SHA-256 verification and expires a mismatched object. The download path opens the final payload without following a symlink and checks the opened descriptor before sending headers. Green metadata is limited to an uploader's own objects (project administrators retain management visibility), while red metadata exposes only released objects.

Incomplete sessions expire automatically and their staged chunks are removed. Administrators can configure the maximum object size, multipart chunk size, and upload-session lifetime and see active uploads/staged bytes in the statistics view.

Upload authorization is continuous rather than admission-only: SFSS re-evaluates the current project role before session inspection, every part write, and final assembly, and rechecks that the outbound policy is still enabled. Revoking a role or disabling external transfer therefore stops an already-created session; the maintenance worker later removes abandoned chunks.

SFSS also reserves configurable physical disk headroom (`SFSS_MIN_FREE_BYTES`, 1 GiB development default). Direct uploads are rejected before body processing when the declared size would consume that reserve. Multipart admission conservatively accounts for outstanding parts and the temporary full-size assembly copy; every part and completion rechecks current free space. Capacity exhaustion returns `507` and never creates a releasable object. The administrator statistics/configuration page exposes capacity remaining after the reserve. The production template starts at 100 GiB, but storage and scanner scratch sizing must be based on measured target workloads.

The Web portals use the browser File System Access API, when available, to stream downloads directly to disk instead of buffering the entire object in memory. Browsers without that API may download files up to 256 MiB through a memory-backed compatibility path; larger downloads are refused with guidance to use the Agent. Web streaming validates the received length but is deliberately not advertised as interruption-resumable.

Production mode and the supplied zone gateways disable the legacy single-request upload endpoints. All production uploads use resumable multipart sessions with per-part SHA-256, repeated role/IP/policy/capacity checks, and final whole-object hashing. The direct endpoints remain available only in development/test mode for compatibility tests.

For unattended, interruption-resumable, or very large transfers, use the packaged `sfss-agent`. Before creating or resuming a session it opens the source without following links, records device/inode/size/mtime/ctime, streams a full SHA-256, and commits that expected digest to the server's completion plan. Every part is reopened with `O_NOFOLLOW`, identity-checked before/after hashing and upload, and sent with its own SHA-256. The Agent reads only bounded private non-link state files, resumes downloads with `Range`, validates final size/SHA-256, verifies the server manifest HMAC even when a complete partial already exists, and seals the downloaded payload mode `0400`. It requires HTTPS by default, validates paired mTLS certificate/key configuration and private-key permissions, supports a private CA, safely commits partial/final outputs without following links, and deliberately ignores ambient OS proxy settings so bearer credentials are not silently sent to a desktop proxy. Existing final outputs are not overwritten unless `--overwrite` is explicitly supplied. `--timeout`/`SFSS_AGENT_TIMEOUT_SECONDS` controls the bounded 30–86400 second per-request timeout; the default is 3600 seconds for slow cross-zone links.

Agents use dedicated, non-interactive service identities—not a person's LDAP account. In the administrator configuration page, create a service identity, assign only the required project role, then issue a project/zone/direction-scoped token. `SFSS_SERVICE_TOKEN_MAX_TTL_SECONDS` bounds issuance; production rejects a value above 30 days and startup/preflight reject an unexpired historical token whose original lifetime exceeds the accepted bound. The raw token is displayed once; store it in the approved secrets manager and rotate it before expiry. For managed deployment, materialize it as an absolute mode-`0600` file and set `SFSS_AGENT_TOKEN_FILE`; the Agent rejects links, special files, group/other access, and malformed token content. `SFSS_AGENT_TOKEN`/`--token` remain development compatibility inputs, but `--production` (or `SFSS_AGENT_PRODUCTION=true`) rejects them and requires token/manifest files, a private CA, paired mTLS identity, signed downloads, and a new non-overwritten output. Disabling a service identity, revoking a token, or archiving its project immediately invalidates the token. The role/scope mapping is:

- green inbound sender: `uploader` + `green` / `inbound_upload`;
- red inbound receiver: `downloader` + `red` / `inbound_download`;
- red outbound sender: `red_uploader` + `red` / `outbound_upload`;
- green outbound receiver: `green_downloader` + `green` / `outbound_download`.

A token is bound to one project and one zone and cannot access administration, approval, membership, policy, or audit APIs. SFSS stores only its SHA-256 digest. Removing any project role from a service identity atomically revokes all of that identity's tokens for the project, so later role restoration cannot resurrect an old scope. Use separate identities and tokens for each gateway/direction so compromise of one agent does not grant the reverse flow.

```sh
SFSS_AGENT_TOKEN_FILE=/run/credentials/sfss-agent/token sfss-agent \
  --production \
  --server https://green-gateway.example.internal \
  --ca-file /etc/sfss/ca.pem --client-cert /etc/sfss/agent.pem --client-key /etc/sfss/agent.key \
  upload --project chip-a --direction inbound --file ./large-design.tar

SFSS_AGENT_TOKEN_FILE=/run/credentials/sfss-agent/token SFSS_AGENT_MANIFEST_KEY_FILE=/run/credentials/sfss-agent/manifest-hmac sfss-agent \
  --production \
  --server https://red-gateway.example.internal \
  --ca-file /etc/sfss/ca.pem --client-cert /etc/sfss/agent.pem --client-key /etc/sfss/agent.key \
  download --project chip-a --direction inbound --object-id OBJECT_ID --output ./large-design.tar
```

Use `--allow-http` and `--allow-unsigned` only against a local development server. A network proxy is used only when explicitly supplied with `--proxy` or `SFSS_AGENT_PROXY`.

## Red-to-green outbound workflow

Each project has an independent outbound policy in the **红区外发** tab. A project administrator enables the policy, selects allowed `GDS`, `FPGA_BITFILE`, and `GENERAL` classifications, and assigns direction-specific roles in **成员权限**:

- `red_uploader`: submit a file from the red zone;
- `approver`: approve or reject a clean, classified request;
- `green_downloader`: download an approved transfer from the green zone.

The local runnable flow is `red upload -> outbound isolation -> scanners -> content classifier -> local approval -> released-green buffer -> green download`. GDSII and common Xilinx FPGA bitstreams are recognized from binary structures rather than names. Known ordinary content becomes `GENERAL`; unknown binary content and extension/content conflicts are quarantined. The `WeComApprovalProvider` is a fail-closed integration boundary only until real enterprise credentials, API calls, and signed/idempotent callbacks are configured.

Local approval is development-only. `SFSS_ALLOW_LOCAL_APPROVAL=false` prevents a project administrator from selecting it, production validation requires that value, and startup rejects an enabled local-approval policy persisted from an earlier environment.

Production WeCom integration uses a separately deployed internal approval relay. The blue SFSS core holds neither a WeCom CorpSecret nor direct Internet access. It submits canonical metadata over HTTPS with mTLS plus an independent HMAC signature; the relay translates to the organization-approved WeCom API. The relay returns an opaque approval ID and later sends a normalized decision through the yellow management gateway. Callbacks require mTLS at the gateway plus HMAC-SHA256, a bounded timestamp, nonce/payload binding, and durable event idempotency. Local approvers cannot decide a `wecom` transfer. Missing relay TLS files/keys, malformed responses, callback tampering, clock skew, replay conflicts, policy changes, or payload integrity failures all fail closed.

This repository implements and tests the SFSS side of that relay protocol, not Tencent's public API or AES callback codec. The external connector must use the officially approved WeCom SDK/protocol, keep CorpSecret and EncodingAESKey outside blue, validate/decrypt Tencent callbacks, map only final approved/rejected states, and pass real enterprise integration tests before production enablement.

The exact submission, callback, signature, idempotency, retry, and acceptance contract is documented in [docs/APPROVAL_RELAY_PROTOCOL.md](docs/APPROVAL_RELAY_PROTOCOL.md).

Project administrators also configure separate IPv4/IPv6 CIDR allowlists for green-zone inbound uploads and red-zone outbound uploads under **成员权限**. The client address is checked before the request body is read. Individual IPs are normalized to `/32` or `/128`; invalid or empty lists are rejected. Local test defaults permit only `127.0.0.1/32` and `::1/128`. In development SFSS uses the direct peer and ignores forwarding headers. With trusted-proxy enforcement enabled, it accepts only the first `X-Forwarded-For` address set by a peer inside `SFSS_TRUSTED_ZONE_PROXY_CIDRS`; gateway configs overwrite client-supplied forwarding, zone, and scheme headers. Management APIs additionally enforce `SFSS_ADMIN_SOURCE_CIDRS`.

For API testing, local bearer tokens are also available as `dev-admin`, `dev-alice`, and `dev-reader`. They can be disabled with `SFSS_DEV_TOKENS_ENABLED=false`. Create a project and memberships:

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/projects \
  -H 'Authorization: Bearer dev-admin' -H 'Content-Type: application/json' \
  -d '{"id":"chip-a","name":"Chip A"}'
curl -sS -X POST http://127.0.0.1:8080/v1/projects/chip-a/members \
  -H 'Authorization: Bearer dev-admin' -H 'Content-Type: application/json' \
  -d '{"username":"alice","role":"uploader"}'
curl -sS -X POST http://127.0.0.1:8080/v1/projects/chip-a/members \
  -H 'Authorization: Bearer dev-admin' -H 'Content-Type: application/json' \
  -d '{"username":"reader","role":"downloader"}'
```

Upload the raw request body from the green zone. `X-Filename` is metadata; identification uses file bytes.

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/projects/chip-a/objects \
  -H 'Authorization: Bearer dev-alice' -H 'X-SFSS-Zone: green' \
  -H 'X-Filename: netlist.txt' --data-binary @./netlist.txt
```

Poll `GET /v1/projects/chip-a/objects/{id}`. Once state is `released`, download from the red zone:

```sh
curl -OJ http://127.0.0.1:8080/v1/projects/chip-a/objects/OBJECT_ID/download \
  -H 'Authorization: Bearer dev-reader' -H 'X-SFSS-Zone: red'
```

Liveness is unauthenticated at `GET /health` and deliberately returns only `{"status":"ok"}`. Detailed dependency readiness is management-only at `GET /ready`: it actively checks ClamAV PING, YARA executable/rules availability, physical storage reserve, maintenance freshness/errors, and required approval-relay configuration, returning `503 degraded` for a failed dependency. Management-only `GET /metrics` exposes low-cardinality Prometheus text metrics without project, user, object, or filename labels. Project audit is `GET /v1/projects/{project}/audit` for project admins/auditors through the management gateway.

## Tests

```sh
cd /Users/weiwang/workspace/ai/sfss
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Scanner and authentication configuration

The default `SFSS_SCANNERS=mock` recognizes EICAR only and must not be treated as anti-malware protection. The local Compose profile uses the current fixed ClamAV 1.5.3 tag, loopback host publication, bounded resources, and the development container config; it is not the production scanner tier. Run `docker compose up -d clamav`, wait for its database/health, then use:

```sh
SFSS_SCANNERS=clamav PYTHONPATH=src python3 -m sfss.server
```

Multiple adapters are conjunctive: `SFSS_SCANNERS=clamav,yara`. Install the `yara` CLI, set `SFSS_YARA_RULES=/absolute/rules.yar`, and ensure every adapter returns clean. YARA runs as a no-shell child process with an engine timeout and a parent hard timeout, so an engine failure does not execute inside the core Python process. ClamAV accepts only one exact NUL-terminated `stream: OK` response as clean; ambiguous, truncated, oversized, `ERROR`, or unknown replies fail closed. Health also requires `PONG`, a parseable VERSION response, and ClamAV 1.4.5 or 1.5.3/newer. Unknown content, claimed/detected type conflicts, adapter errors, timeouts, or pipeline exceptions remain quarantined. Malware is rejected. No failed or unknown result is automatically released.

`SFSS_CLAMAV_STREAM_MAX_BYTES` is a declared deployment invariant and must equal clamd `StreamMaxLength`; SFSS rejects an upload limit above it at configuration, persisted-state startup, and preflight boundaries. The controlled-pilot template is intentionally 2 GiB. ClamAV documents that INSTREAM has a configured total limit and that files over internal scan limits may otherwise be skipped/assumed clean, so the supplied clamd configs enable `AlertExceedsMax`, encrypted/broken-content alerts, and bounded recursion/files/time. Raising the 2 GiB candidate limit requires `clamconf -n` evidence and clean/infected/limit test files at the new maximum in the isolated target scanner tier. See the official [clamd protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) and [scanning limits](https://docs.clamav.net/manual/Usage/Scanning.html).

`SFSS_AUTH_BACKEND=ldap` selects the LDAP/AD interface. Production-candidate LDAP wheels are exact-version/SHA-256 locked in `requirements-production.txt`; install them from a reviewed internal mirror, then configure `SFSS_LDAP_URI`, `SFSS_LDAP_BASE_DN`, and optionally `SFSS_LDAP_USER_TEMPLATE` (default `uid={username},{base_dn}`). Set `SFSS_BOOTSTRAP_ADMINS` explicitly to the LDAP identities allowed to create projects; LDAP mode has no implicit administrator. Put TLS and trusted proxy zone assertions in front of the service. Local auth is explicitly a development substitute.

Persistent human sessions carry both their issuing authentication backend and logical entrance (`green`, `red`, or `admin`). A session issued at one entrance is rejected at the other entrances without revoking its valid original use. Development login returns a Bearer for local testing. Production login never exposes the opaque human token to JavaScript or the JSON response: it sets a host-only `__Host-sfss_session` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`. Cookie-authenticated mutations additionally require `X-SFSS-CSRF: 1`; the static console adds it, while cross-origin simple requests cannot. Machine/service credentials remain explicit project/zone-scoped Bearers. The browser's zone header is only a development convenience: production trusts the entrance only because blue Nginx derives and overwrites it from the mutually authenticated gateway certificate. Sessions also have absolute and idle deadlines and a per-user concurrent-session cap. The production template permits at most a 1-hour absolute lifetime, 15-minute idle lifetime, and three concurrent sessions; stricter enterprise settings are encouraged.

The management-only security-operations page lists active human sessions by user/backend/entrance and timestamps without returning a token or token hash. A platform administrator can revoke all sessions for one human identity or perform a strongly confirmed global emergency revocation; both actions are append-only audited, and global revocation also invalidates the administrator's current session. Session issue/revocation, password reset, identity disable, project archive, service-token issue/revocation/automatic expiry, membership and policy changes commit with their chained audit event in the same database transaction; an audit failure rolls the security mutation back. Invalid human sessions are retained as revoked until an audited maintenance purge instead of being silently deleted during authentication. Service tokens remain a separate credential class and require their own scoped revocation workflow.

Production LDAP startup revokes non-LDAP, legacy, development, or otherwise unbound sessions and rejects any database containing local password records or enabled platform administrators outside `SFSS_BOOTSTRAP_ADMINS`. Use a fresh production identity database or an independently reviewed identity/role migration; copying a development database into production is intentionally fail-closed. These local session controls do not substitute for AD account-disable propagation, MFA/conditional access, or an enterprise session-revocation design; prove those end to end in the target environment.

Production mode also requires `SFSS_REQUIRE_TRUSTED_PROXY=true`, non-empty `SFSS_TRUSTED_ZONE_PROXY_CIDRS`, `SFSS_REQUIRE_FORWARDED_HTTPS=true`, an absolute data directory, non-mock ClamAV scanning, disabled development tokens, LDAP authentication, and HMAC secrets loaded from private absolute `*_FILE` paths. Unsafe production settings, raw environment HMAC values, unsafe secret files, or startup/file content drift fail during startup.

The accepted effective-configuration fingerprint and secret-file binding are also rechecked while the process is running. Drift keeps minimal liveness, detailed readiness/metrics, login/logout, read-only administrator visibility, configuration rollback, identity disable, token revocation, and human-session revocation available, but all green/red data-plane requests, approval callbacks, new credentials, scans, and approved outbound promotion fail closed. A queued object encountering drift is quarantined with a `runtime-policy` result; an already-approved outbound object stays non-downloadable in `approved` for recovery after the accepted configuration is restored. `/ready` remains degraded until the controlled fingerprint/restart process is completed.

Other settings: `SFSS_DATA_DIR`, `SFSS_RETENTION_SECONDS`, `SFSS_PURGE_GRACE_SECONDS`, `SFSS_MAINTENANCE_INTERVAL_SECONDS`, `SFSS_SCAN_TIMEOUT_SECONDS`, `SFSS_SESSION_TTL_SECONDS`, `SFSS_SESSION_IDLE_SECONDS`, `SFSS_MAX_SESSIONS_PER_USER`, `SFSS_SERVICE_TOKEN_MAX_TTL_SECONDS`, `SFSS_REQUEST_HEADER_TIMEOUT_SECONDS`, `SFSS_REQUEST_IO_TIMEOUT_SECONDS`, `SFSS_MAX_REQUEST_WORKERS`, `SFSS_MAX_UPLOAD_BYTES`, `SFSS_MAX_ACTIVE_UPLOADS_PER_USER`, `SFSS_MAX_STAGED_BYTES_PER_PROJECT`, `SFSS_MIN_FREE_BYTES`, `SFSS_MULTIPART_CHUNK_BYTES`, `SFSS_UPLOAD_SESSION_TTL_SECONDS`, `SFSS_CLAMAV_HOST`, `SFSS_CLAMAV_PORT`, `SFSS_CLAMAV_STREAM_MAX_BYTES`, `SFSS_YARA_RULES_SHA256`, `SFSS_LDAP_CA_SHA256`, `SFSS_JOB_WORKERS`, `SFSS_JOB_LEASE_SECONDS`, `SFSS_JOB_MAX_ATTEMPTS`, and the `SFSS_APPROVAL_RELAY_*` settings shown in the deployment template. Override local test passwords with `SFSS_LOCAL_CREDENTIALS='admin:a-long-test-password,alice:...,reader:...'`; never expose local mode to an untrusted network. The core independently enforces header/I/O timeouts and a bounded request-thread pool; gateway limits remain mandatory and should be sized no higher than the tested downstream capacity.

`sfss-admin verify --data-dir /srv/sfss` performs an offline full audit-chain, payload, part-hash, path-containment, and permission check; every directory/file under the data root must remain private. `sfss-admin export-audit` verifies the chain and writes an exclusive mode-`0600` canonical JSONL file with event/chain hashes plus a reported file SHA-256 and chain head for WORM/SIEM ingestion. `sfss-admin verify-audit-export` independently streams that JSONL without opening the SFSS database, safely rejects links/special files, malformed or oversized records, sequence/link/hash errors, truncation, and concurrent mutation, and can require trusted expected SHA-256, chain head, and event count values. `sfss-admin backup` creates a mode-`0600` uncompressed archive only while the service lock is free; `sfss-admin restore --expected-sha256 ...` opens the archive without following links, checks an externally retained digest before extraction, rejects traversal, duplicate names, links/special entries, broad/set-ID permissions and declared contents larger than available space, ignores archive-supplied ownership, detects concurrent archive mutation, restores only to a new target, rebases stored paths, and verifies the result before success. See [deploy/README.md](deploy/README.md) for the stop/verify/export/backup/restore drill. The trusted expected values or an organizational signature must be carried through a channel independent of the mutable blue host; backup encryption and immutable off-host retention remain infrastructure responsibilities.

`sfss-admin preflight` is a strict, no-listening-port production gate. It consumes the target environment, requires exclusive access to the stopped data directory, uses a genuinely read-only SQLite connection, verifies data/audit/payloads, checks persisted identity and approval downgrade state, probes configured scanner health and disk reserve, and validates the LDAP client plus LDAPS certificate handshake. It emits JSON and exits nonzero on any failed or unknown required check. `--allow-non-production` exists only to exercise the mechanism in a development environment and never reports `production_candidate: true`.

The SQLite candidate records an explicit schema version and refuses to open a database created by a newer SFSS binary, preventing unsafe application rollback writes. Upgrades remain forward-only and must follow stop/backup/verify/upgrade/verify/start. This marker is not a replacement for reviewed migration tooling and HA database change governance in the final PostgreSQL architecture.

## Security behavior and extension points

- Original names never select a filesystem path; objects receive UUID directories with mode `0700`. The local data directory is `0700` and the SQLite database is `0600`.
- SHA-256 is calculated while streaming into isolation. Content signatures and UTF-8/binary heuristics determine type; an extension can only create a conflict, never establish trust.
- Isolation content is fully rehashed immediately before scanning/release, and outbound content is rehashed again before approval release. Post-upload or post-scan modification is quarantined/expired rather than released.
- State transitions are constrained to `pending_scan`, `scanning`, `quarantined`, `released`, `rejected`, and `expired`.
- Project RBAC has separate `admin`, `uploader`, `downloader`, and `auditor` roles. A platform bootstrap admin may create projects but does not bypass project membership for file access. The service exposes no mutation endpoint for red-zone objects.
- Audit rows record actor, request id, zone, address, action, outcome, project/object, and details. Database triggers prevent update/delete through the application database connection.
- Audit rows are also SHA-256 chained. Startup refuses a missing, inserted, deleted, or modified chain record; the admin statistics page reports the verified event count, and exported chains can be independently verified against externally retained expected values. An attacker able to rewrite the whole local database can recompute an unkeyed chain, so this is tamper-evident operational evidence—not a replacement for organizational signing and immutable remote audit storage.
- `JobQueue`, `Authenticator`, `Scanner`, classifier, and approval provider are explicit interfaces. The default runtime uses a persistent SQLite scan queue with active-job de-duplication, renewable worker leases, restart reclamation, bounded retry, and fail-closed dead-letter handling. An HA broker, enterprise AD group adapter, real WeCom adapter, and object storage backend can replace local implementations.
- Red-to-green is a separate transfer aggregate and policy pipeline with `GDS`, `FPGA_BITFILE`, and `GENERAL` classification, independent outbound roles, project policy, approval timeout, green download TTL, and separate released storage. It does not reuse the green-to-red release decision.
- Maintenance expires timed-out approvals/downloads and purges expired payloads after a configurable grace period. Startup recovery requeues pending jobs and quarantines scans interrupted by a restart. Stale scans fail closed after `SFSS_SCAN_TIMEOUT_SECONDS`.
- The transfer design follows mature managed-file-transfer principles also used by systems such as SFTPGo: temporary uploads are isolated from completed objects, authorization is checked before accepting data, storage details are hidden behind object identities, and an interrupted connection never implies a successful transfer. No SFTPGo source or Web UI code is copied; SFTPGo is AGPL-licensed and SFSS has a distinct security workflow.

## Known limits / production hardening

The local multipart implementation assembles filesystem chunks once before scanning. For production-scale multi-gigabyte and HA workloads, add an S3-compatible multipart `StorageBackend`, TLS/mTLS and firewall enforcement from the supplied templates, PostgreSQL, a multi-node durable broker, immutable remote/WORM audit export, object-store encryption/KMS, managed migrations/backups, rate limits/quotas, archive-bomb and parser sandboxing, richer semiconductor formats, LDAP group mapping, the real Tencent-facing WeCom Connector, external metrics collection/alerting/SIEM, performance benchmarks on the real cross-zone links, and independent security review. The included Transfer Agent and SQLite queue close the basic resume/restart gaps, but SQLite, the standard-library HTTP server, and local assembly remain a single-node candidate only.
# sfss
