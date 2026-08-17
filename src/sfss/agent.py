"""SFSS zone transfer agent for resumable, integrity-checked large-file movement."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import sys
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


class AgentError(RuntimeError):
    pass


def read_private_agent_secret(value: str, label: str, allowed=None) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute(): raise AgentError(f"agent {label} file path must be absolute")
    try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise AgentError(f"agent {label} file is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AgentError(f"agent {label} file must be a private regular file")
        if not 32 <= metadata.st_size <= 4096: raise AgentError(f"agent {label} file size is invalid")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    try: secret = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc: raise AgentError(f"agent {label} file is not ASCII") from exc
    if (not 32 <= len(secret) <= 512 or any(ord(ch) < 33 or ord(ch) > 126 for ch in secret) or
            (allowed is not None and any(ch not in allowed for ch in secret))):
        raise AgentError(f"agent {label} file contains an invalid secret")
    return secret


def read_token_file(value: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    return read_private_agent_secret(value, "token", allowed)


class API:
    def __init__(self, server: str, token: str, zone: str, context: ssl.SSLContext,
                 allow_http: bool = False, proxy: Optional[str] = None, timeout: int = 3600):
        self.server = server.rstrip("/")
        if not allow_http and not self.server.startswith("https://"):
            raise AgentError("HTTPS is required; use --allow-http only for local development")
        if not 30 <= int(timeout) <= 86400: raise AgentError("request timeout must be between 30 and 86400 seconds")
        self.token, self.zone, self.context, self.timeout = token, zone, context, int(timeout)
        # Do not inherit desktop/OS proxy settings: doing so can unexpectedly
        # disclose bearer credentials. A proxy must be explicitly configured.
        proxy_map = {"http": proxy, "https": proxy} if proxy else {}
        self.opener = build_opener(ProxyHandler(proxy_map), HTTPSHandler(context=context))

    def open(self, method: str, path: str, body=None, headers=None):
        request_headers = {"Authorization": f"Bearer {self.token}", "X-SFSS-Zone": self.zone,
                           "User-Agent": "sfss-transfer-agent/0.3"}
        request_headers.update(headers or {})
        request = Request(self.server + path, data=body, headers=request_headers, method=method)
        try:
            return self.opener.open(request, timeout=self.timeout)
        except HTTPError as exc:
            try: detail = json.loads(exc.read().decode()).get("error", exc.reason)
            except Exception: detail = exc.reason
            raise AgentError(f"SFSS returned {exc.code}: {detail}") from exc
        except URLError as exc:
            raise AgentError(f"cannot reach SFSS: {exc.reason}") from exc

    def json(self, method: str, path: str, value=None, headers=None):
        body = None
        request_headers = dict(headers or {})
        if value is not None:
            body = json.dumps(value, separators=(",", ":")).encode()
            request_headers["Content-Type"] = "application/json"
        with self.open(method, path, body, request_headers) as response:
            payload = response.read()
            return json.loads(payload) if payload else None


def ssl_context(args) -> ssl.SSLContext:
    if bool(args.client_cert) != bool(args.client_key):
        raise AgentError("client certificate and private key must be configured together")
    if args.client_key:
        _validate_agent_file(Path(args.client_key), "client private key", private=True, maximum=64 * 1024)
        _validate_agent_file(Path(args.client_cert), "client certificate", maximum=1024 * 1024)
    if args.ca_file:
        _validate_agent_file(Path(args.ca_file), "CA bundle", maximum=4 * 1024 * 1024)
    context = ssl.create_default_context(cafile=args.ca_file)
    if args.client_cert:
        context.load_cert_chain(args.client_cert, args.client_key)
    return context


def _validate_agent_file(path: Path, label: str, private=False, maximum=1024 * 1024):
    if not path.is_absolute(): raise AgentError(f"agent {label} path must be absolute")
    try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise AgentError(f"agent {label} is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= maximum:
            raise AgentError(f"agent {label} must be a bounded regular file")
        if private and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AgentError(f"agent {label} must not grant group or other access")
    finally:
        os.close(descriptor)


def file_identity(path: Path):
    absolute = path.expanduser().absolute()
    try: descriptor = os.open(str(absolute), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise AgentError("source file is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode): raise AgentError("source file must be a regular non-symlink file")
        return _identity_from_stat(absolute, metadata)
    finally:
        os.close(descriptor)


def _identity_from_stat(path: Path, metadata):
    return {"path":str(path.expanduser().absolute()), "device":metadata.st_dev,
            "inode":metadata.st_ino, "size":metadata.st_size,
            "mtime_ns":metadata.st_mtime_ns, "ctime_ns":metadata.st_ctime_ns}


def hash_file_slice(path: Path, offset: int, size: int, expected_identity=None) -> str:
    digest = hashlib.sha256(); remaining = size
    try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise AgentError("source file is unavailable or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode): raise AgentError("source file must be regular")
        if expected_identity and _identity_from_stat(path, before) != expected_identity:
            raise AgentError("source file identity changed before hashing")
        os.lseek(descriptor, offset, os.SEEK_SET)
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block: raise AgentError("source file became shorter while hashing a part")
            digest.update(block); remaining -= len(block)
        after = os.fstat(descriptor)
        if _identity_from_stat(path, before) != _identity_from_stat(path, after):
            raise AgentError("source file changed while hashing a part")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


class FileSliceBody:
    """Re-openable bounded request-body iterator for constant-memory uploads."""
    def __init__(self, path: Path, offset: int, size: int, expected_identity=None):
        self.path, self.offset, self.size = path, offset, size
        self.expected_identity = expected_identity

    def __iter__(self):
        remaining = self.size
        try: descriptor = os.open(str(self.path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc: raise AgentError("source file is unavailable or unsafe") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode): raise AgentError("source file must be regular")
            if self.expected_identity and _identity_from_stat(self.path, before) != self.expected_identity:
                raise AgentError("source file identity changed before upload")
            os.lseek(descriptor, self.offset, os.SEEK_SET)
            while remaining:
                block = os.read(descriptor, min(1024 * 1024, remaining))
                if not block: raise AgentError("source file became shorter during upload")
                remaining -= len(block); yield block
            after = os.fstat(descriptor)
            if _identity_from_stat(self.path, before) != _identity_from_stat(self.path, after):
                raise AgentError("source file changed during upload")
        finally:
            os.close(descriptor)


def save_state(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    payload = json.dumps(value, sort_keys=True).encode("utf-8")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); path.chmod(0o600)
    except Exception:
        temporary.unlink(missing_ok=True); raise


def load_state(path: Path):
    try: descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise AgentError("upload state file is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077 or
                metadata.st_size > 64 * 1024):
            raise AgentError("upload state file must be a bounded private regular file")
        raw = os.read(descriptor, 64 * 1024 + 1)
    finally:
        os.close(descriptor)
    try: return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentError("upload state file is invalid") from exc


def upload(args):
    source = Path(args.file).expanduser().absolute()
    identity = file_identity(source)
    expected_sha256 = hash_file_slice(source, 0, identity["size"], identity)
    if file_identity(source) != identity: raise AgentError("source file changed while calculating SHA-256")
    zone = "green" if args.direction == "inbound" else "red"
    api = API(args.server, args.token, zone, ssl_context(args), args.allow_http, args.proxy,
              getattr(args, "timeout", 3600))
    state_path = Path(args.state_file) if args.state_file else source.with_name(source.name + ".sfss-upload.json")
    session = None
    if state_path.exists():
        try:
            saved = load_state(state_path)
            if (saved.get("file") == identity and saved.get("expected_sha256") == expected_sha256 and
                    saved.get("server") == args.server.rstrip("/") and
                    saved.get("direction") == args.direction):
                session = api.json("GET", f'/v1/uploads/{quote(saved["upload_id"])}')
        except Exception:
            session = None
    if session and session.get("state") == "completed" and session.get("object_id"):
        record = api.json("POST", f'/v1/uploads/{quote(session["id"])}/complete')
        state_path.unlink(missing_ok=True)
        print(json.dumps(record, ensure_ascii=False, sort_keys=True))
        return
    if not session or session.get("state") != "uploading":
        session = api.json("POST", "/v1/uploads", {
            "direction": args.direction, "filename": source.name, "total_size": identity["size"],
            "expected_sha256": expected_sha256,
        })
        save_state(state_path, {"server":args.server.rstrip("/"),
                                "direction":args.direction, "upload_id":session["id"], "file":identity,
                                "expected_sha256":expected_sha256})
    completed = {part["part_number"] for part in session.get("parts", [])}
    missing = [number for number in range(1, session["part_count"] + 1) if number not in completed]

    def send_part(number):
        current = file_identity(source)
        if current != identity: raise AgentError("source file changed during upload")
        offset = (number - 1) * session["chunk_size"]
        size = min(session["chunk_size"], identity["size"] - offset)
        digest = hash_file_slice(source, offset, size, identity)
        if file_identity(source) != identity: raise AgentError("source file changed while hashing a part")
        body = FileSliceBody(source, offset, size, identity)
        with api.open("PUT", f'/v1/uploads/{quote(session["id"])}/parts/{number}', body,
                      {"Content-Type":"application/octet-stream", "Content-Length":str(size),
                       "X-Part-SHA256":digest}) as response:
            response.read()
        if file_identity(source) != identity: raise AgentError("source file changed during upload")
        return number, size

    sent = sum(part["size"] for part in session.get("parts", []))
    with ThreadPoolExecutor(max_workers=max(1, min(args.parallel, 16))) as executor:
        futures = [executor.submit(send_part, number) for number in missing]
        for future in as_completed(futures):
            number, size = future.result(); sent += size
            print(f"uploaded part {number}/{session['part_count']} ({sent}/{identity['size']} bytes)", flush=True)
    if file_identity(source) != identity: raise AgentError("source file changed before completion")
    record = api.json("POST", f'/v1/uploads/{quote(session["id"])}/complete')
    state_path.unlink(missing_ok=True)
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def get_record(api: API, direction: str, object_id: str):
    if direction == "inbound":
        return api.json("GET", f"/v1/objects/{quote(object_id)}")
    rows = api.json("GET", "/v1/outbound")["transfers"]
    for row in rows:
        if row["id"] == object_id: return row
    raise AgentError("outbound object not found or not visible")


def verify_manifest(args, record, signature):
    key = getattr(args, "manifest_key", "") or os.getenv("SFSS_AGENT_MANIFEST_KEY", "")
    if not key:
        if args.allow_unsigned: return
        raise AgentError("SFSS_AGENT_MANIFEST_KEY is required to verify the transfer manifest")
    manifest = f'{record["id"]}\n{record["size"]}\n{record["sha256"]}'
    expected = hmac.new(key.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(signature, expected):
        raise AgentError("download manifest signature verification failed")


def prepare_partial(path: Path):
    if not path.exists(): return None, 0
    try: descriptor = os.open(str(path), os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc: raise AgentError("partial download is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode): raise AgentError("partial download must be a regular file")
        os.fchmod(descriptor, 0o600)
        return _identity_from_stat(path, os.fstat(descriptor)), metadata.st_size
    finally:
        os.close(descriptor)


def open_partial_for_write(path: Path, expected_identity, append: bool):
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    if expected_identity is None: flags |= os.O_CREAT | os.O_EXCL
    try: descriptor = os.open(str(path), flags, 0o600)
    except OSError as exc: raise AgentError("partial download changed before writing") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode): raise AgentError("partial download must be a regular file")
        if expected_identity is not None and _identity_from_stat(path, metadata) != expected_identity:
            raise AgentError("partial download identity changed before writing")
        os.fchmod(descriptor, 0o600)
        if append: os.lseek(descriptor, 0, os.SEEK_END)
        else: os.ftruncate(descriptor, 0)
        return os.fdopen(descriptor, "wb")
    except Exception:
        os.close(descriptor); raise


def download(args):
    zone = "red" if args.direction == "inbound" else "green"
    api = API(args.server, args.token, zone, ssl_context(args), args.allow_http, args.proxy,
              getattr(args, "timeout", 3600))
    record = get_record(api, args.direction, args.object_id)
    output = Path(args.output).expanduser().absolute(); partial = output.with_name(output.name + ".part")
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise AgentError("download output must be a regular non-symlink path")
    if output.exists() and not getattr(args, "overwrite", False):
        raise AgentError("download output already exists; use --overwrite only after verifying the target")
    partial_identity, start = prepare_partial(partial)
    if start > record["size"]: raise AgentError("partial download is larger than the remote object")
    headers = {"If-Range": f'"{record["sha256"]}"'}
    if start: headers["Range"] = f"bytes={start}-"
    kind = "objects" if args.direction == "inbound" else "outbound"
    path = f"/v1/{kind}/{quote(args.object_id)}/download"
    if start < record["size"]:
        with api.open("GET", path, headers=headers) as response:
            verify_manifest(args, record, response.headers.get("X-SFSS-Manifest-Signature"))
            append = bool(response.status == 206 and start)
            with open_partial_for_write(partial, partial_identity, append) as stream:
                while True:
                    block = response.read(1024 * 1024)
                    if not block: break
                    stream.write(block)
                stream.flush(); os.fsync(stream.fileno())
    else:
        # A pre-existing complete partial must not bypass current authorization
        # or manifest authentication.
        with api.open("HEAD", path) as response:
            verify_manifest(args, record, response.headers.get("X-SFSS-Manifest-Signature"))
    completed_identity = file_identity(partial)
    digest = hash_file_slice(partial, 0, completed_identity["size"], completed_identity)
    size = completed_identity["size"]
    if size != record["size"] or digest != record["sha256"]:
        raise AgentError("downloaded file size or SHA-256 does not match the signed record")
    if getattr(args, "overwrite", False):
        os.replace(partial, output)
    else:
        try: os.link(partial, output, follow_symlinks=False)
        except OSError as exc: raise AgentError("download output appeared before final commit") from exc
        partial.unlink()
    output.chmod(0o400)
    manifest_path = output.with_name(output.name + ".sfss-manifest.json")
    save_state(manifest_path, {key:record.get(key) for key in ("id","filename","size","sha256","state")})
    print(json.dumps({"output":str(output), "sha256":record["sha256"], "size":size}, ensure_ascii=False))


def parser():
    root = argparse.ArgumentParser(description="SFSS resumable zone transfer agent")
    root.add_argument("--production", action="store_true",
                      default=os.getenv("SFSS_AGENT_PRODUCTION", "false").lower() in {"1","true","yes"},
                      help="enforce managed-secret, mTLS, and non-destructive production policy")
    root.add_argument("--server", required=True); root.add_argument("--token", default=os.getenv("SFSS_AGENT_TOKEN", ""))
    root.add_argument("--token-file", default=os.getenv("SFSS_AGENT_TOKEN_FILE", ""),
                      help="absolute private token file (recommended for managed deployments)")
    root.add_argument("--manifest-key-file", default=os.getenv("SFSS_AGENT_MANIFEST_KEY_FILE", ""),
                      help="absolute private download-manifest HMAC key file")
    root.add_argument("--ca-file", default=os.getenv("SFSS_AGENT_CA") or None)
    root.add_argument("--client-cert", default=os.getenv("SFSS_AGENT_CLIENT_CERT") or None)
    root.add_argument("--client-key", default=os.getenv("SFSS_AGENT_CLIENT_KEY") or None)
    root.add_argument("--proxy", default=os.getenv("SFSS_AGENT_PROXY") or None,
                      help="explicit HTTP(S) proxy; ambient OS proxy settings are ignored")
    root.add_argument("--timeout", type=int, default=int(os.getenv("SFSS_AGENT_TIMEOUT_SECONDS", "3600")),
                      help="per-request timeout in seconds (30-86400)")
    root.add_argument("--allow-http", action="store_true", help="development only")
    commands = root.add_subparsers(dest="command", required=True)
    up = commands.add_parser("upload")
    up.add_argument("--direction", choices=("inbound","outbound"), required=True); up.add_argument("--file", required=True)
    up.add_argument("--parallel", type=int, default=4); up.add_argument("--state-file"); up.set_defaults(action=upload)
    down = commands.add_parser("download")
    down.add_argument("--direction", choices=("inbound","outbound"), required=True)
    down.add_argument("--object-id", required=True); down.add_argument("--output", required=True)
    down.add_argument("--overwrite", action="store_true")
    down.add_argument("--allow-unsigned", action="store_true", help="development only"); down.set_defaults(action=download)
    return root


def validate_production_agent_args(args, manifest_environment: str):
    if not getattr(args, "production", False): return
    if args.allow_http: raise AgentError("production Agent forbids plain HTTP")
    if args.token or not args.token_file:
        raise AgentError("production Agent requires token-file and forbids raw token arguments/environment")
    if not args.ca_file or not args.client_cert or not args.client_key:
        raise AgentError("production Agent requires a private CA and paired mTLS identity")
    if args.command == "download":
        if manifest_environment or not args.manifest_key_file:
            raise AgentError("production Agent requires manifest-key-file and forbids raw manifest keys")
        if args.allow_unsigned: raise AgentError("production Agent forbids unsigned downloads")
        if args.overwrite: raise AgentError("production Agent forbids overwriting an existing output")


def main():
    args = parser().parse_args()
    try:
        manifest_environment = os.getenv("SFSS_AGENT_MANIFEST_KEY", "")
        validate_production_agent_args(args, manifest_environment)
        if args.token_file:
            if args.token: raise AgentError("configure exactly one of token or token-file")
            args.token = read_token_file(args.token_file)
        if not args.token: raise AgentError("SFSS_AGENT_TOKEN_FILE, SFSS_AGENT_TOKEN, or --token is required")
        if args.manifest_key_file and manifest_environment:
            raise AgentError("configure exactly one of manifest key or manifest-key-file")
        args.manifest_key = (read_private_agent_secret(args.manifest_key_file, "manifest key")
                             if args.manifest_key_file else manifest_environment)
        args.action(args)
    except AgentError as exc: print(f"error: {exc}", file=sys.stderr); raise SystemExit(2)


if __name__ == "__main__": main()
