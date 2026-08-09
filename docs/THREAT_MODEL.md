# SFSS threat model and production acceptance boundary

## Protected assets

- Red-zone design data and approved outbound artifacts.
- File integrity, classification, scanner results, approval decisions, and project authorization.
- LDAP credentials, bearer sessions, gateway certificates, and manifest-signing secrets.
- Append-only audit history and the mapping between project, user, object, and transfer.

## Principal threats

1. A compromised green workstation uploads malware, parser exploits, oversized data, or misleading extensions.
2. A client bypasses a zone gateway or forges forwarding/zone headers.
3. An uploader obtains download or approval privileges, or a platform operator bypasses project roles.
4. A partial, corrupted, replayed, or modified large file is treated as complete.
5. A red-zone object is released before clean scanning and approval, or after policy/TTL revocation.
6. A database, queue, or process restart loses security state and accidentally releases an object.
7. A transfer gateway, scanner, LDAP service, or approval provider is unavailable or returns an unknown result.
8. Secrets or sensitive names appear in logs, command lines, URLs, browser storage, or backups.
9. A malicious archive or file exploits ClamAV/YARA/classifier resources and causes denial of service.
10. An administrator or host-level attacker tampers with mutable local audit or payload storage.

## Enforced controls in this repository

- Content-derived type recognition, SHA-256, extension conflict detection, conjunctive scanners, and fail-closed state transitions.
- Separate inbound/outbound aggregates, roles, buffers, policies, approval timeout, download TTL, and IP allowlists.
- Production forbids local outbound approval and rejects persisted enabled downgrade policies; an unavailable enterprise provider fails closed instead of falling back.
- The blue core delegates Tencent-specific processing to an internal mTLS approval relay and holds no WeCom CorpSecret. Canonical submissions and normalized callbacks use independent HMAC keys; callback timestamps, nonces, payload hashes, durable event IDs, provider binding, and local-approval denial prevent tampering, replay, and downgrade.
- Multipart part hashes, full-object verification, resumable state, immutable release files, signed download manifests, and Range downloads. Each part record, session heartbeat, and audit event commit in one transaction. Object identity is persisted before assembly; object registration and its audit commit before session completion and its audit, and scanning is enqueued only after both commits. Recovery binds an already registered object back to its original session or removes the deterministic orphan target and returns intact parts to a retryable state, preventing duplicate objects and stranded `completing` sessions.
- Existing multipart sessions continuously recheck current project roles on read/write/complete and recheck the outbound enable policy, so revocation is not limited to new session admission.
- Trusted-proxy CIDR enforcement, trusted forwarded HTTPS assertion, management source CIDRs, certificate-derived gateway roles, mTLS CRL checks in both directions, disabled TLS session tickets, zone/role consistency checks, management-only route enforcement, and production startup safety validation.
- Request correlation IDs are length/character constrained before response echo or audit persistence; malformed client values are replaced by server UUIDs.
- The core independently bounds header and request/download I/O time, caps concurrent request threads, rejects excess accepted connections before thread allocation, audits I/O timeouts, and exposes a management-only rejected-connection counter. These controls remain active behind the mandatory gateway limits.
- Data zones receive only a minimal liveness response. Detailed readiness and low-cardinality metrics are restricted to the certificate-derived management gateway and management source allowlist, with no sensitive identity/file labels.
- Detailed readiness fails closed for scanner exceptions, exhausted storage reserve, stale/failed maintenance, and missing required approval-relay configuration; scanner metric collection remains available with an explicit down value when a health adapter raises.
- Production configuration/secret drift is enforced beyond readiness: the data plane, callbacks, background scanning, and approved-file promotion stop. Only bounded observability plus management rollback and credential/session containment remain available; drifted scans quarantine and approved outbound files stay non-downloadable.
- Persistent human sessions stored only as hashes; production delivers them only in host-only `Secure`, `HttpOnly`, `SameSite=Strict` cookies and requires a non-simple CSRF header for cookie-authenticated mutations, while service credentials remain Bearers. Logout, account disable, password reset, absolute expiry, idle expiry, and the concurrent-session cap revoke access. Session insertion itself selects only a currently enabled human principal; local mode additionally binds the insertion predicate to the exact verified password hash generation, closing disable/reset-after-verification races. Service-token insertion itself requires a currently enabled service principal, active project, and every role implied by the requested permissions. Session issuance/eviction/revocation, password and identity lifecycle changes, project archive, service-token lifecycle (including maintenance expiry), membership changes, and project policy writes commit atomically with their chained audit event. Invalid sessions remain as revoked forensic records until audited maintenance purge. Removing a service identity's project role revokes every project token in that same transaction, preventing credential resurrection after role restoration.
- Human sessions are bound to their issuing authentication backend and certificate-derived green/red/admin entrance. Cross-entrance replay is rejected without destroying the original session. Production LDAP startup revokes local, legacy, development, and unbound sessions and rejects local password records or platform-admin identities outside the explicit bootstrap allowlist.
- The management plane exposes token-free active-session metadata plus audited per-user and strongly confirmed global emergency revocation. Global revocation intentionally revokes the caller; machine/service credentials are managed separately to prevent accidental scope confusion.
- LDAP login identifiers are bounded to a conservative account/UPN grammar before bind-template expansion; host-only LDAP URIs and restricted template fields prevent user-controlled DN/template structure. The LDAP CA and approval-relay CA/client certificate are SHA-256 locked and runtime identity-bound; LDAP CA drift disables even recovery-plane login so passwords are not sent under changed trust. Failed-login state is time-pruned and globally bounded in addition to gateway rate limiting.
- Transfer agents use separate non-interactive principals. Their one-time-displayed tokens are hash-only at rest and bound to one project, one zone, and explicit directions; role checks remain conjunctive, and identity disable/project archive revokes associated tokens. Agent source, state, partial, key, and final-output handling rejects links and detects file-identity changes; uploads commit a precomputed whole-file digest in addition to every part digest.
- Service-token issuance has a configurable absolute lifetime bound; production permits at most 30 days and rejects active legacy tokens whose original issued lifetime exceeds policy at startup/preflight.
- SQLite-persisted scan jobs with active de-duplication, renewable owner-bound leases, immediate restart reclamation, bounded retries, and fail-closed dead-letter quarantine.
- Explicit `0700` at every data-directory level, `0600` staging/isolation modes, and `0400` released modes; per-user active-upload limits and per-project declared-size staging reservations. Production requires an offline-initialized database and rejects permission drift before mutable startup code can normalize it; verified legacy-mode repair is development-only.
- A physical free-space safety reserve with conservative multipart/assembly admission and repeated part/completion checks rejects uploads with HTTP 507 before capacity exhaustion can create ambiguous state.
- Full-object hash revalidation before scanning, again after every scanner has returned but before inbound release or outbound classification/approval, and again before outbound approval release; any scanner-time mutation is quarantined and scanner dependency readiness fails with HTTP 503.
- YARA executes without a shell, with bounded time and disk-backed bounded-output reading so pathological child output is not accumulated in the blue application process. Production binds the reviewed rules to an expected SHA-256, safely hashes the configured and persisted path, and closes the live data plane on artifact identity drift. Production direct-upload routes are disabled in favor of resumable per-part hashing and authorization checks.
- ClamAV uses strict framed-response parsing: only one exact clean record is accepted, while truncation, ambiguity, errors, stream-limit replies, and unknown records fail closed. Health requires a security-fixed version, and declared upload/INSTREAM limits are checked at configuration, startup, and preflight boundaries; clamd limit/encrypted/broken alerts prevent silent clean treatment at parser limits.
- Approval decisions are durably recorded before the filesystem move. `approved` is a non-downloadable recovery state, and maintenance idempotently retries promotion to the green release buffer after crashes or storage failures. A restart or timeout in the intermediate `classified`/relay-submission window explicitly quarantines the transfer instead of leaving it stranded; controlled rescan uses `transfer_id` as the relay idempotency key.
- An exclusive runtime lock plus offline path-contained backup/restore, full SHA-256/audit-chain verification, and a database-independent streaming audit-export verifier that can require externally retained file hash, chain head, and count. Restore can require an independently retained backup digest before extraction; it opens without following links, rejects duplicate/non-canonical/special members and excessive declared resources, reserves disk headroom, and detects archive mutation during extraction.
- A persisted database schema version prevents an older binary from opening and writing a newer schema; forward upgrades still require the documented offline backup/verification gate.
- SIGTERM initiates non-blocking graceful server shutdown and bounded systemd drain time; interrupted multipart work remains resumable, while interrupted scan work is recovered fail closed rather than released.
- Append-only SQLite audit triggers, atomic state-transition-plus-chain-event transactions (including scan/classification/approval evidence), object integrity revalidation after filesystem fingerprint changes, and automatic expiry/purge. A failed audit append rolls the state mutation back.

## Release blockers outside the current repository

- Independent architecture review and penetration test against the real green/yellow/blue/red network.
- Managed PostgreSQL HA, durable job broker, encrypted/versioned object storage, KMS/HSM-managed secrets, immutable remote audit export, and tested backup restore.
- A sandboxed content-analysis tier with CPU/memory/time limits and archive-bomb controls.
- Real AD group lifecycle, MFA/conditional access, real WeCom signed/idempotent callbacks, certificate issuance/revocation, monitoring, alerting, and incident response.
- Demonstrated firewall rules that prevent direct green/red/yellow-client access to the blue application and prevent blue/red Internet egress.
- Load, soak, interruption, storage-full, scanner-down, database-failover, queue-replay, and disaster-recovery tests at target file sizes and link rates.

SFSS must not be labeled production-secure until every release blocker has an accountable owner, evidence, and approval.
