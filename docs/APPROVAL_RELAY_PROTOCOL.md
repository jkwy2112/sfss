# SFSS internal approval relay protocol v1

This protocol is the security boundary between the blue SFSS core and a separately operated internal WeCom connector. It is **not** Tencent's public API. The connector owns the reviewed official SDK, CorpSecret, EncodingAESKey, Tencent callback validation/decryption, and Internet egress. Blue owns file state and final release authorization.

## Transport and trust

- Submission is `POST` from blue to the configured HTTPS relay URL. Both peers validate mTLS certificates and CRLs. SFSS does not use ambient proxy variables.
- Callback is `POST /v1/integrations/wecom/callback` through the yellow management gateway. The gateway authenticates to blue with the exact admin-gateway certificate; the relay source IP must also pass management allowlists.
- Submission and callback use different random HMAC-SHA256 keys of at least 32 characters. Keys are secret-manager material, never URL parameters or JSON fields.
- All clocks use the approved internal time source. Callback timestamps outside the configured 30–900 second window are rejected.

## Signature

Both directions carry:

```text
X-SFSS-Approval-Timestamp: decimal Unix seconds
X-SFSS-Approval-Nonce: 1–128 characters from A-Z a-z 0-9 . _ -
X-SFSS-Approval-Signature: lowercase hex HMAC-SHA256
```

The exact signed bytes are:

```text
timestamp + "\n" + nonce + "\n" + raw HTTP body
```

Verify signatures with a constant-time comparison before parsing JSON. Do not reserialize JSON before verification.

## Submission

SFSS sends canonical UTF-8 JSON (`sort_keys`, compact separators):

```json
{
  "classification": "GDS",
  "filename": "layout.gds",
  "media_type": "application/octet-stream",
  "project_id": "chip-a",
  "sha256": "64 lowercase hexadecimal characters",
  "size": 123456,
  "transfer_id": "SFSS UUID",
  "uploader": "red-user"
}
```

The relay returns HTTP `200` or `201` and at most 64 KiB of JSON:

```json
{"approval_id":"opaque-safe-id"}
```

`approval_id` is 1–128 characters from `A-Z a-z 0-9 . _ -`. The relay **must** treat `transfer_id` as its idempotency key: a timeout or lost response may cause SFSS to resubmit after a controlled rescan, and this must return the same enterprise request rather than create another approval. A non-2xx response, invalid TLS/signature, timeout, malformed body, or invalid ID fails closed; SFSS never falls back to local approval.

## Normalized callback

After fully validating and decrypting the official Tencent event, the relay sends only a final normalized decision:

```json
{
  "actor": "wecom-user-id",
  "approval_id": "opaque-safe-id",
  "comment": "optional decision comment",
  "event_id": "durable-relay-event-id",
  "status": "approved"
}
```

`status` is exactly `approved` or `rejected`. `event_id` and `approval_id` use the safe ID character set; `actor` additionally permits `@`. Intermediate, withdrawn, cancelled, unknown, partially approved, or ambiguous Tencent states must not be mapped to `approved`; either withhold a final callback or map an organization-approved terminal denial to `rejected`.

SFSS binds the callback to a stored `wecom` approval ID, current project policy, classification allowlist, expiry, and payload SHA-256. It stores event ID and payload hash durably. Exact retries return `200 duplicate`; reuse of an event ID or nonce with different bytes returns `409`. A local approver cannot decide the transfer.

## Failure and recovery semantics

- Approval is recorded as durable `approved` before moving the file. `approved` is not downloadable.
- Promotion to `released_to_green` rechecks policy and full payload integrity and is idempotently retried by maintenance after storage/process failures.
- Rejection never creates a green payload.
- Relay callbacks should retry non-2xx responses with bounded exponential backoff and the same `event_id` and body. Exact nonce reuse is accepted idempotently, but the relay may generate a new nonce/timestamp for a retry.
- The relay must retain the Tencent-to-`event_id` mapping beyond the longest SFSS approval and retry window.

## Acceptance evidence

Production enablement requires captured evidence for: valid approval/rejection, duplicate delivery, response loss, reordered/conflicting events, stale timestamp, body/signature tampering, nonce conflict, unknown approval ID, callback loss/retry, relay restart, Tencent timeout/error, revoked client/server certificate, policy change during approval, payload tampering, and crash during file promotion. Logs and screenshots must redact all secrets and sensitive file content.
