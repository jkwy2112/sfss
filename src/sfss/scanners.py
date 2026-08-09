from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
import shutil
import re
import socket
import struct
import subprocess
import tempfile
from typing import List


@dataclass(frozen=True)
class ScanResult:
    scanner: str
    status: str  # clean, infected, error
    detail: str


class Scanner(ABC):
    name = "scanner"

    @abstractmethod
    def scan(self, path: Path) -> ScanResult:
        pass

    def health(self) -> ScanResult:
        return ScanResult(self.name, "error", "health check is not implemented")


class MockScanner(Scanner):
    """Local test adapter; EICAR is rejected, all other data is marked clean."""
    name = "mock"

    def health(self) -> ScanResult:
        return ScanResult(self.name, "clean", "development mock available")

    def scan(self, path: Path) -> ScanResult:
        signature = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        tail = b""
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block: break
                combined = tail + block
                if signature in combined:
                    return ScanResult(self.name, "infected", "EICAR test signature")
                tail = combined[-(len(signature) - 1):]
        return ScanResult(self.name, "clean", "development mock result")


class ClamAVScanner(Scanner):
    name = "clamav"

    def __init__(self, host: str, port: int, timeout: float = 15.0):
        self.host, self.port, self.timeout = host, port, timeout

    def scan(self, path: Path) -> ScanResult:
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(b"zINSTREAM\0")
                with path.open("rb") as stream:
                    while True:
                        block = stream.read(1024 * 1024)
                        if not block:
                            break
                        sock.sendall(struct.pack("!I", len(block)) + block)
                sock.sendall(struct.pack("!I", 0))
                reply = bytearray()
                while b"\0" not in reply and len(reply) <= 64 * 1024:
                    block = sock.recv(4096)
                    if not block: break
                    reply.extend(block)
            if len(reply) > 64 * 1024 or not reply.endswith(b"\0"):
                return ScanResult(self.name, "error", "invalid or oversized ClamAV response")
            records = [record for record in bytes(reply).split(b"\0") if record]
            if len(records) != 1:
                return ScanResult(self.name, "error", "ambiguous ClamAV response")
            text = records[0].decode("utf-8", "replace").strip()
            if text == "stream: OK":
                return ScanResult(self.name, "clean", text)
            if text.startswith("stream: ") and text.endswith(" FOUND"):
                return ScanResult(self.name, "infected", text[:500])
            return ScanResult(self.name, "error", text[:500] or "empty response")
        except Exception as exc:
            return ScanResult(self.name, "error", f"unavailable: {type(exc).__name__}")

    def health(self) -> ScanResult:
        try:
            ping = self._command("PING", 64)
            version_text = self._command("VERSION", 512)
            version = self._version_tuple(version_text)
            if ping != "PONG": return ScanResult(self.name, "error", ping or "empty PING response")
            if not version or not self._supported_version(version):
                return ScanResult(self.name, "error", f"unsupported or vulnerable ClamAV version: {version_text[:200]}")
            return ScanResult(self.name, "clean", f"PONG; {version_text[:200]}")
        except Exception as exc:
            return ScanResult(self.name, "error", f"unavailable: {type(exc).__name__}")

    def _command(self, command: str, maximum: int) -> str:
        with socket.create_connection((self.host, self.port), min(self.timeout, 2.0)) as sock:
            sock.settimeout(2.0); sock.sendall(f"z{command}\0".encode("ascii")); reply = bytearray()
            while b"\0" not in reply and len(reply) <= maximum:
                block = sock.recv(min(256, maximum + 1 - len(reply)))
                if not block: break
                reply.extend(block)
        if len(reply) > maximum or not reply.endswith(b"\0") or reply.count(0) != 1:
            raise ValueError("invalid ClamAV command response")
        return bytes(reply[:-1]).decode("utf-8", "replace").strip()

    @staticmethod
    def _version_tuple(text: str):
        match = re.match(r"^ClamAV (\d+)\.(\d+)\.(\d+)(?:/|\s|$)", text)
        return tuple(map(int, match.groups())) if match else None

    @staticmethod
    def _supported_version(version) -> bool:
        return version >= (1, 5, 3) or ((1, 4, 5) <= version < (1, 5, 0))


class YaraScanner(Scanner):
    """YARA CLI adapter; runs untrusted parsing outside the SFSS process."""
    name = "yara"

    def __init__(self, rules_path: str):
        self.rules_path = rules_path

    def scan(self, path: Path) -> ScanResult:
        try:
            # Do not let a pathological rule set or CLI failure accumulate
            # unbounded child output inside the long-running blue process.
            with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
                result = subprocess.run(
                    ["yara", "--timeout=15", self.rules_path, str(path)],
                    stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file,
                    timeout=30, check=False,
                )
                stdout_file.seek(0); stderr_file.seek(0)
                stdout = stdout_file.read(64 * 1024).decode("utf-8", "replace").strip()
                stderr = stderr_file.read(64 * 1024).decode("utf-8", "replace").strip()
            if result.returncode != 0:
                return ScanResult(self.name, "error", (stderr or f"yara exit {result.returncode}")[:500])
            if stdout:
                matches = [line.split(maxsplit=1)[0] for line in stdout.splitlines()[:50]]
                return ScanResult(self.name, "infected", ",".join(matches)[:500])
            return ScanResult(self.name, "clean", "no rule matched")
        except Exception as exc:
            return ScanResult(self.name, "error", f"unavailable: {type(exc).__name__}")

    def health(self) -> ScanResult:
        rules = Path(self.rules_path)
        if not shutil.which("yara"): return ScanResult(self.name, "error", "yara executable not found")
        if not rules.is_absolute() or not rules.is_file(): return ScanResult(self.name, "error", "rules file unavailable")
        return ScanResult(self.name, "clean", "yara executable and rules available")


def build_scanners(names: str, host: str, port: int, yara_rules: str) -> List[Scanner]:
    scanners: List[Scanner] = []
    for name in (part.strip() for part in names.split(",")):
        if name == "mock": scanners.append(MockScanner())
        elif name == "clamav": scanners.append(ClamAVScanner(host, port))
        elif name == "yara": scanners.append(YaraScanner(yara_rules))
        elif name: raise ValueError(f"unknown scanner adapter: {name}")
    if not scanners:
        raise ValueError("at least one scanner is required (fail closed)")
    return scanners
