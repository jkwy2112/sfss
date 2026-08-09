"""Approval providers and the internal WeCom relay protocol.

The blue SFSS core never talks to the public WeCom API and never stores a
CorpSecret.  A separately deployed relay translates this small signed protocol
to the enterprise-approved WeCom API and callback implementation.
"""
import hashlib
import hmac
import json
import secrets
import ssl
import time
from pathlib import Path
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


def relay_signature(key: str, timestamp: str, nonce: str, body: bytes) -> str:
    message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


class ApprovalProvider:
    name = "approval"

    def create(self, transfer: dict) -> str:
        raise NotImplementedError


class LocalApprovalProvider(ApprovalProvider):
    name = "local"

    def create(self, transfer: dict) -> str:
        return f"local-{transfer['id']}"


class WeComApprovalProvider(ApprovalProvider):
    """Submit a normalized request to an internal mTLS approval relay."""
    name = "wecom"

    def __init__(self, settings, transport=None):
        self.settings = settings
        self.transport = transport or self._post

    def create(self, transfer: dict) -> str:
        errors = self.settings.approval_relay_errors()
        if errors: raise RuntimeError("approval relay is not safely configured: " + "; ".join(errors))
        body = json.dumps({
            "transfer_id": transfer["id"], "project_id": transfer["project_id"],
            "uploader": transfer["uploader"], "filename": transfer["filename"],
            "size": transfer["size"], "sha256": transfer["sha256"],
            "media_type": transfer["media_type"], "classification": transfer["classification"],
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time())); nonce = secrets.token_urlsafe(18)
        headers = {
            "Content-Type":"application/json", "Content-Length":str(len(body)),
            "X-SFSS-Approval-Timestamp":timestamp, "X-SFSS-Approval-Nonce":nonce,
            "X-SFSS-Approval-Signature":relay_signature(
                self.settings.approval_relay_submit_hmac_key, timestamp, nonce, body),
        }
        raw = self.transport(body, headers)
        if len(raw) > 64 * 1024: raise RuntimeError("approval relay response is too large")
        try: response = json.loads(raw)
        except Exception as exc: raise RuntimeError("approval relay returned invalid JSON") from exc
        approval_id = str(response.get("approval_id", "")).strip()
        if (not 1 <= len(approval_id) <= 128 or
                any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in approval_id)):
            raise RuntimeError("approval relay returned an invalid approval id")
        return approval_id

    def _post(self, body: bytes, headers: dict) -> bytes:
        context = ssl.create_default_context(cafile=self.settings.approval_relay_ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.settings.approval_relay_client_cert,
                                self.settings.approval_relay_client_key)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        request = Request(self.settings.approval_relay_url, data=body, headers=headers, method="POST")
        with opener.open(request, timeout=self.settings.approval_relay_timeout_seconds) as response:
            if response.status not in {200, 201}: raise RuntimeError("approval relay rejected request")
            return response.read(64 * 1024 + 1)
