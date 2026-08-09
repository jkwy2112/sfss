# SFSS security requirement traceability

This table separates repository evidence from target-environment evidence. “Implemented” means the candidate contains an enforceable control with automated coverage; it does not mean the external production gate has passed.

| Requirement | Repository control | Automated evidence | External evidence still required |
|---|---|---|---|
| LDAP/AD with local development mode | `LDAPAuthenticator`, LDAPS production validation; production HttpOnly `__Host-` human-session cookie and CSRF guard; `LocalAuthenticator` rejected in production | LDAP URI/template/basic-auth, cookie/CSRF, credential-generation race and production-mode tests | real AD bind, disable, expiry, lockout, group lifecycle, MFA |
| Project least-privilege RBAC | separate inbound/outbound roles; platform admin does not bypass file roles | role, revocation, last-admin, service-scope tests | named access review and joiner/mover/leaver evidence |
| Green-only upload/download view | gateway allowlist plus core zone/role visibility | portal, metadata visibility, wrong-zone tests | deployed gateway bypass test |
| Red-only buffer/download and outbound upload view | red gateway routes plus core zone/role enforcement | inbound download/outbound upload and zone tests | red graphical path and firewall evidence |
| Upload and outbound IP restrictions | per-project normalized inbound/outbound upload CIDRs, rechecked at completion | IPv4/IPv6, denial, changed-policy completion tests | approved real source ranges and spoof/bypass test |
| Isolation and content type | isolated paths, content magic, extension conflict, unknown quarantine | type conflict, GDS recognition, unknown-content tests | reviewed format corpus and parser fuzzing |
| SHA-256 and resumable large transfer | streaming full/part hashes, pre/post-scan revalidation, crash-recoverable deterministic completion, multipart state, Range download, Agent resume | corrupt part/final hash/scanner-time mutation/completion-crash/resume/range/manifest tests | maximum-size interruption and performance tests |
| Asynchronous fail-closed scanning | durable leased queue; conjunctive adapters; errors quarantine | retry/dead-letter/restart/error tests | HA broker and scanner saturation/failure drill |
| ClamAV and YARA adapters | strict Clam protocol/version gate; bounded YARA subprocess | adapter protocol/version/timeout/output tests | isolated scanner tier, signature/rule governance, sandbox limits |
| Object state machines | explicit inbound/outbound transition maps; no manual release | transition, crash recovery, expiry, approval tests | operational SLO and stuck-state alert evidence |
| Enterprise outbound approval | mTLS relay contract, independent HMACs, replay/idempotency controls | canonical relay, callback forgery/skew/replay/crash tests | real Tencent connector, official callback crypto and credential custody |
| Read-only controlled download | released-state/role/zone checks, immutable mode, Range, signed manifest | tamper, role, expiry, signed-download tests | target KMS/asymmetric signing decision and link tests |
| Audit | append-only local triggers/hash chain; atomic object, identity/session, service-token, membership, project and policy state/event commit; canonical independent export verifier | rollback-on-audit-failure plus identity/membership fault injection and mutation/truncation/order/link/expected-value tests | continuous WORM/SIEM receipt and independent trust anchor |
| Runtime and secret drift | accepted config fingerprint and secret-file binding gate data plane/scans | startup/readiness/live-drift tests | controlled release/change evidence and secret-manager integration |
| Resource exhaustion | upload/session/storage quotas; gateway and core time/connection/thread limits | quota/reserve/framing/timeout/worker tests | target load/soak, alert threshold and capacity evidence |
| Backup and restore | exclusive offline backup, trusted digest, safe extraction, full verification | round-trip/digest/link/duplicate/integrity tests | encrypted off-host retention and RPO/RTO/DR drill |
| Four-zone deployment | mTLS gateways, certificate-derived zone, UDS-only core, route allowlists | deployment-template assertions and listener validation | actual firewall, PKI, CRL, DNS and host-hardening evidence |

The release remains blocked whenever any row has missing required external evidence. See [FOUR_ZONE_ARCHITECTURE.md](FOUR_ZONE_ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [PRODUCTION_ACCEPTANCE.md](PRODUCTION_ACCEPTANCE.md).
