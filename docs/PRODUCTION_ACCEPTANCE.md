# SFSS production acceptance gate

Passing repository tests makes this build a production **candidate**, not a production security guarantee. Every item below needs an accountable owner, dated evidence from the target green/yellow/blue/red environment, and security/change approval. Any missing or failed item blocks production labeling.

## Candidate build evidence

- Pin the source revision/release ID, exact supported Python 3.12-or-newer patch runtime, accepted effective-configuration SHA-256, hash-locked Python wheels, OS packages, ClamAV signatures, YARA rules, Nginx, and systemd versions in the release record. Install from the approved internal artifact mirror with no blue-zone Internet access. Prove startup and `/ready` reject end-of-life runtime branches, patch mismatch, secret drift, and configuration drift. While running, induce configuration and secret drift and prove data requests, callbacks, queued scans, and approved-file promotion stop while only bounded observation, rollback, and credential/session containment remain available.
- Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`, Python compilation, and `node --check src/sfss/web/app.js` from the sealed build artifact.
- Run `sfss-admin verify`, `sfss-admin export-audit`, and a backup/restore drill while SFSS is stopped. Record object/part counts, audit chain head, and artifact SHA-256 values.
- Generate `sfss-admin release-manifest` from the sealed artifact, sign it with the organizational code-signing service, generate an SBOM, scan dependencies/container images, verify artifact signatures/provenance, and resolve findings under the organization's vulnerability SLA. Explicitly review the age and maintenance status of the pinned LDAP client; a hash proves identity, not safety.

## Identity and administrative plane

- Validate real AD/LDAPS CA, bind format, disabled users, password expiry, lockout, group lifecycle, MFA/conditional-access path, and emergency bootstrap-admin removal.
- Prove local accounts, Basic auth, development tokens, and local approval cannot start in production.
- Prove a session issued through each green/red/admin gateway works only at that entrance; verify login JSON never contains the production human token and the browser receives a host-only `__Host-` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`. Demonstrate cookie mutation rejection without the CSRF header, cross-entrance replay rejection, 15-minute-or-shorter idle expiry, 1-hour-or-shorter absolute expiry, concurrent-session eviction, logout/clearing, account-disable propagation, token-free administrator session inventory, per-user revocation, audited maintenance cleanup, and strongly confirmed emergency global revocation (including the caller). Record the maximum disable-to-denial delay accepted by the security owner.
- Review every platform admin, project role, outbound role, service identity, token scope, expiry, and rotation owner against least privilege. Prove issuance above 30 days is rejected, startup/preflight catch a historical overlong active token, and rotation overlap/revocation works at every zone gateway.
- Demonstrate yellow management source-CIDR restriction and mTLS identity; green/red clients must not reach `/admin`, `/ready`, `/metrics`, audit, policy, membership, approval, or callback routes.

## Network and PKI

- Demonstrate there is no green-to-red route; only zone gateways reach blue mTLS ingress; only blue reaches its scanner/data dependencies; blue and red have no Internet egress.
- Test exact certificate subject mapping, trust depth, expiry monitoring, CRL freshness, emergency revocation, failed-CRL deployment behavior, TLS protocol/cipher policy, HSTS, and disabled session tickets.
- Run `nginx -t` on every target host and `systemd-analyze security sfss.service` on the exact target distribution. Any removed hardening directive requires security approval.

## File and scanner pipeline

- Use a digest/package-pinned security-fixed ClamAV plus reviewed YARA rules. Archive `clamconf -n`, engine/signature versions, SBOM and vulnerability evidence; prove StreamMaxLength/MaxFileSize/MaxScanSize align with SFSS limits and `AlertExceedsMax` is active. Demonstrate clean, EICAR, YARA match, unknown content, extension conflict, encrypted/broken archive, every scanner limit, scanner timeout/down/error, corrupt part, full-hash mismatch, and payload tamper cases; all non-clean outcomes must remain non-downloadable.
- Deploy content analysis in a separate restricted tier with CPU, memory, process, file-count, recursion, decompression-ratio, total-expanded-size, and wall-clock limits. Test archive bombs and parser exploits. The blue application must not unpack untrusted archives.
- Prove production direct upload is rejected and multipart interruption/resume preserves part SHA-256, final SHA-256, authorization/IP policy, quota, and disk reserve.
- Run load/soak tests at approved maximum object size and actual cross-zone bandwidth, including concurrent uploads/downloads, slow clients, disconnects, storage-full, scanner saturation, and recovery. Prove the gateway and core header/I/O timeouts agree, the bounded core worker pool rejects overload without unbounded thread growth, and rejected-connection alerts fire at the approved threshold.

## Outbound approval

- Validate the separately deployed Tencent-facing WeCom Connector with official credentials/SDK, Tencent callback cryptography, mTLS, independent HMAC keys, secret-manager custody, and no Tencent secret in blue.
- Demonstrate duplicate, reordered, delayed, forged, revoked-certificate, API-timeout, callback-loss, policy-disable, expiry, and crash-between-approval-and-move scenarios. Only a normalized final approval may reach `released_to_green`.

## Data, audit, monitoring, and recovery

- Replace the single-node SQLite/filesystem candidate with approved HA PostgreSQL, durable broker, encrypted/versioned object storage, and KMS/HSM-backed secrets for production-scale or HA service. Prove database failover and queue replay do not auto-release files.
- Continuously export audit events to immutable/WORM storage or SIEM. On the receiving side, run `sfss-admin verify-audit-export` and require the event count, chain head, and file SHA-256 carried through an independently controlled channel or organizational signature. Test content mutation, full-line truncation, malformed JSON, reordered events, link replacement, and verification-time mutation. Restrict and monitor access to audit content; an unkeyed chain whose expected values came only from the same compromised host is not an external trust anchor.
- Alert on non-200 `/ready`, `sfss_runtime_accepted != 1`, security-artifact drift, scanner down, queue accumulation/dead letters, storage reserve, rejected core connections, stale/failed maintenance, approval callback errors, certificate/CRL expiry, auth abuse, and intermediate states exceeding SLO.
- Complete encrypted off-host backup retention, restore, RPO/RTO, disaster recovery, and key-loss/revocation drills. Carry the backup SHA-256 or organizational signature through an independent channel and require it with `restore --expected-sha256`; a backup that has not been restored is not accepted evidence.

## Independent acceptance

- Complete threat-model review, secure-code review, penetration test, and remediation verification against the deployed system.
- Obtain sign-off from network security, IAM/AD, PKI, SOC/SIEM, storage/database, application owner, red-data owner, and change authority.
- Record residual risks, compensating controls, owners, expiry dates, rollback plan, incident runbook, and an explicit go/no-go decision.

Release status remains **blocked** until all applicable sections have accepted evidence.
