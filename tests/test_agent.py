import ssl
import contextlib
import hashlib
import hmac
import os
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.request import ProxyHandler

from sfss.agent import (API, AgentError, FileSliceBody, download, file_identity, hash_file_slice,
                        load_state, read_private_agent_secret, read_token_file, save_state,
                        ssl_context, upload, validate_production_agent_args)


class AgentTest(unittest.TestCase):
    def test_agent_token_file_must_be_private_regular_and_not_a_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); token = root / "token"
            token.write_text("A" * 43 + "\n", encoding="ascii"); token.chmod(0o600)
            self.assertEqual("A" * 43, read_token_file(str(token)))
            token.chmod(0o640)
            with self.assertRaisesRegex(AgentError, "private regular"):
                read_token_file(str(token))
            token.chmod(0o600); link = root / "link"; link.symlink_to(token)
            with self.assertRaisesRegex(AgentError, "unavailable or unsafe"):
                read_token_file(str(link))

    def test_agent_manifest_key_file_accepts_private_printable_secret(self):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "manifest-key"
            key.write_text("manifest-key-" + "x" * 32, encoding="ascii"); key.chmod(0o600)
            self.assertEqual("manifest-key-" + "x" * 32,
                             read_private_agent_secret(str(key), "manifest key"))

    def test_file_slice_body_streams_only_the_planned_range(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "payload.bin"
            source.write_bytes(b"prefix-" + (b"x" * (2 * 1024 * 1024)) + b"-suffix")
            offset, size = 7, 2 * 1024 * 1024
            chunks = list(FileSliceBody(source, offset, size))
            self.assertEqual(size, sum(map(len, chunks)))
            self.assertTrue(all(len(chunk) <= 1024 * 1024 for chunk in chunks))
            self.assertEqual(hash_file_slice(source, offset, size),
                             hashlib.sha256(b"".join(chunks)).hexdigest())

    def test_upload_source_and_state_read_never_follow_symbolic_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "payload"; source.write_bytes(b"payload")
            source_link = root / "payload-link"; source_link.symlink_to(source)
            with self.assertRaisesRegex(AgentError, "unavailable or unsafe"):
                file_identity(source_link)
            state = root / "state"; state.symlink_to(source)
            with self.assertRaisesRegex(AgentError, "unavailable or unsafe"):
                load_state(state)

    def test_agent_mtls_requires_pair_and_private_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); cert = root / "client.pem"; key = root / "client-key.pem"
            cert.write_text("certificate"); key.write_text("private-key"); key.chmod(0o644)
            with self.assertRaisesRegex(AgentError, "configured together"):
                ssl_context(SimpleNamespace(ca_file=None, client_cert=str(cert), client_key=None))
            with self.assertRaisesRegex(AgentError, "must not grant"):
                ssl_context(SimpleNamespace(ca_file=None, client_cert=str(cert), client_key=str(key)))

    def test_ambient_operating_system_proxy_is_not_inherited(self):
        api = API("https://sfss.invalid", "secret", "red", ssl.create_default_context())
        proxy_handlers = [handler for handler in api.opener.handlers if isinstance(handler, ProxyHandler)]
        # urllib omits an explicitly empty ProxyHandler from the final handler
        # list; importantly, it does not install a handler from OS settings.
        self.assertEqual([], proxy_handlers)

    def test_proxy_requires_explicit_configuration(self):
        api = API("https://sfss.invalid", "secret", "red", ssl.create_default_context(),
                  proxy="http://proxy.invalid:8080")
        proxy_handlers = [handler for handler in api.opener.handlers if isinstance(handler, ProxyHandler)]
        self.assertEqual("http://proxy.invalid:8080", proxy_handlers[0].proxies["https"])

    def test_plain_http_is_development_opt_in(self):
        with self.assertRaises(AgentError):
            API("http://127.0.0.1:8080", "secret", "red", ssl.create_default_context())

    def test_agent_timeout_is_bounded(self):
        with self.assertRaises(AgentError):
            API("https://sfss.invalid", "secret", "red", ssl.create_default_context(), timeout=1)

    def test_production_agent_requires_file_secrets_mtls_and_safe_download(self):
        base = dict(production=True, allow_http=False, token="", token_file="/run/token",
                    ca_file="/etc/ca", client_cert="/etc/cert", client_key="/run/key",
                    command="download", manifest_key_file="/run/manifest", allow_unsigned=False,
                    overwrite=False)
        validate_production_agent_args(SimpleNamespace(**base), "")
        cases = (
            ({"token":"raw"}, "token-file"), ({"token_file":""}, "token-file"),
            ({"client_key":None}, "mTLS"), ({"manifest_key_file":""}, "manifest-key-file"),
            ({"allow_unsigned":True}, "unsigned"), ({"overwrite":True}, "overwriting"),
        )
        for changes, message in cases:
            with self.subTest(changes=changes), self.assertRaisesRegex(AgentError, message):
                validate_production_agent_args(SimpleNamespace(**{**base, **changes}), "")
        with self.assertRaisesRegex(AgentError, "raw manifest"):
            validate_production_agent_args(SimpleNamespace(**base), "raw-key")

    def test_state_write_replaces_symlink_without_touching_its_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); sensitive = root / "sensitive"; sensitive.write_text("unchanged")
            state = root / "state.json"; state.symlink_to(sensitive)
            save_state(state, {"safe":True})
            self.assertEqual("unchanged", sensitive.read_text())
            self.assertFalse(state.is_symlink())
            self.assertEqual(0o600, state.stat().st_mode & 0o777)

    def test_complete_partial_still_requires_authorized_signed_head(self):
        with tempfile.TemporaryDirectory() as temp:
            payload = b"complete partial"; digest = hashlib.sha256(payload).hexdigest()
            record = {"id":"o1", "project_id":"p1", "filename":"payload.bin", "size":len(payload),
                      "sha256":digest, "state":"released"}
            output = Path(temp) / "result.bin"; partial = Path(str(output) + ".part"); partial.write_bytes(payload)
            key = "manifest-secret"; manifest = f'o1\np1\n{len(payload)}\n{digest}'
            signature = hmac.new(key.encode(), manifest.encode(), hashlib.sha256).hexdigest()
            calls = []
            class Response:
                status = 200; headers = {"X-SFSS-Manifest-Signature":signature}
                def __enter__(self): return self
                def __exit__(self, *args): return False
            class FakeAPI:
                def json(self, method, path, value=None, headers=None): return record
                def open(self, method, path, body=None, headers=None):
                    calls.append(method); return Response()
            args = SimpleNamespace(direction="inbound", server="https://sfss.invalid", token="token",
                                   allow_http=False, proxy=None, timeout=3600, ca_file=None,
                                   client_cert=None, client_key=None, project="p1", object_id="o1",
                                   output=str(output), overwrite=False, allow_unsigned=False)
            with patch("sfss.agent.API", return_value=FakeAPI()), patch.dict(os.environ, {"SFSS_AGENT_MANIFEST_KEY":key}), contextlib.redirect_stdout(io.StringIO()):
                download(args)
            self.assertEqual(["HEAD"], calls)
            self.assertEqual(payload, output.read_bytes())
            self.assertEqual(0o400, output.stat().st_mode & 0o777)

    def test_completed_upload_response_loss_is_recovered_without_duplicate_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "payload.txt"; source.write_bytes(b"payload")
            state = Path(temp) / "state.json"
            digest = hashlib.sha256(b"payload").hexdigest()
            save_state(state, {"server":"https://sfss.invalid", "project":"p1", "direction":"inbound",
                               "upload_id":"u1", "file":file_identity(source),
                               "expected_sha256":digest})
            calls = []
            class FakeAPI:
                def json(self, method, path, value=None, headers=None):
                    calls.append((method, path, value))
                    if method == "GET": return {"id":"u1", "state":"completed", "object_id":"o1"}
                    if path.endswith("/complete"): return {"id":"o1", "state":"released"}
                    raise AssertionError("a new upload session must not be created")
            args = SimpleNamespace(file=str(source), direction="inbound", server="https://sfss.invalid",
                                   token="token", allow_http=False, proxy=None, state_file=str(state), project="p1",
                                   ca_file=None, client_cert=None, client_key=None, parallel=1)
            with patch("sfss.agent.API", return_value=FakeAPI()), contextlib.redirect_stdout(io.StringIO()):
                upload(args)
            self.assertFalse(state.exists())
            self.assertEqual([("GET", "/v1/uploads/u1", None), ("POST", "/v1/uploads/u1/complete", None)], calls)

    def test_new_upload_commits_full_source_sha256_to_server_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "payload.txt"; payload = b"whole-file-integrity"; source.write_bytes(payload)
            calls = []
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def read(self): return b""
            class FakeAPI:
                def json(self, method, path, value=None, headers=None):
                    calls.append((method, path, value))
                    if path.endswith("/uploads"):
                        return {"id":"u1", "state":"uploading", "chunk_size":len(payload),
                                "part_count":1, "parts":[]}
                    if path.endswith("/complete"): return {"id":"o1", "state":"released"}
                    raise AssertionError(path)
                def open(self, method, path, body=None, headers=None):
                    self.uploaded = b"".join(body); return Response()
            fake = FakeAPI()
            args = SimpleNamespace(file=str(source), direction="inbound", server="https://sfss.invalid",
                                   token="token", allow_http=False, proxy=None, state_file=None, project="p1",
                                   ca_file=None, client_cert=None, client_key=None, parallel=1, timeout=3600)
            with patch("sfss.agent.API", return_value=fake), contextlib.redirect_stdout(io.StringIO()):
                upload(args)
            plan = calls[0][2]
            self.assertEqual(hashlib.sha256(payload).hexdigest(), plan["expected_sha256"])
            self.assertEqual(payload, fake.uploaded)


if __name__ == "__main__": unittest.main()
