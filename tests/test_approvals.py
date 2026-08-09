import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sfss.approvals import WeComApprovalProvider, relay_signature
from sfss.config import Settings


class ApprovalRelayTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        files = []
        for name in ("ca.pem", "client.pem", "client-key.pem"):
            path = root / name; path.write_text("test fixture", encoding="utf-8"); files.append(str(path))
        Path(files[2]).chmod(0o600)
        self.settings = replace(
            Settings(data_dir=root), approval_relay_url="https://approval-relay.internal/v1/requests",
            approval_relay_ca_file=files[0], approval_relay_client_cert=files[1],
            approval_relay_client_key=files[2], approval_relay_submit_hmac_key="s" * 32,
            approval_relay_callback_hmac_key="c" * 32,
        )

    def tearDown(self): self.temp.cleanup()

    def test_normalized_submission_is_canonical_and_signed(self):
        captured = {}
        def transport(body, headers):
            captured.update(body=body, headers=headers)
            return b'{"approval_id":"wecom-approval_123"}'
        transfer = {"id":"t1", "project_id":"p1", "uploader":"alice", "filename":"design.gds",
                    "size":42, "sha256":"a" * 64, "media_type":"application/octet-stream",
                    "classification":"GDS"}
        approval_id = WeComApprovalProvider(self.settings, transport).create(transfer)
        self.assertEqual("wecom-approval_123", approval_id)
        timestamp = captured["headers"]["X-SFSS-Approval-Timestamp"]
        nonce = captured["headers"]["X-SFSS-Approval-Nonce"]
        self.assertEqual(relay_signature("s" * 32, timestamp, nonce, captured["body"]),
                         captured["headers"]["X-SFSS-Approval-Signature"])
        self.assertEqual("t1", json.loads(captured["body"])["transfer_id"])

    def test_invalid_relay_response_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "invalid approval id"):
            WeComApprovalProvider(self.settings, lambda _body, _headers: b'{"approval_id":"bad id"}').create(
                {"id":"t1", "project_id":"p1", "uploader":"alice", "filename":"x",
                 "size":1, "sha256":"a" * 64, "media_type":"text/plain", "classification":"GENERAL"})

    def test_relay_configuration_rejects_shared_directional_key(self):
        unsafe = replace(self.settings, approval_relay_callback_hmac_key="s" * 32)
        self.assertIn("must be different", "; ".join(unsafe.approval_relay_errors()))


if __name__ == "__main__": unittest.main()
