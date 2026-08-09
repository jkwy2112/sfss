import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sfss.scanners import ClamAVScanner, YaraScanner


class ScannerAdapterTest(unittest.TestCase):
    def clamav_result(self, reply):
        class Socket:
            def __init__(self): self.reply = reply
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def settimeout(self, _value): pass
            def sendall(self, _value): pass
            def recv(self, _size):
                value, self.reply = self.reply, b""; return value
        with tempfile.TemporaryDirectory() as temp:
            payload = Path(temp) / "payload"; payload.write_bytes(b"safe")
            with patch("sfss.scanners.socket.create_connection", return_value=Socket()):
                return ClamAVScanner("127.0.0.1", 3310).scan(payload)

    def test_clamav_accepts_only_one_exact_clean_record(self):
        self.assertEqual("clean", self.clamav_result(b"stream: OK\0").status)
        self.assertEqual("infected", self.clamav_result(b"stream: Eicar-Signature FOUND\0").status)
        for reply in (b"stream: Access denied ERROR\0stream: OK\0",
                      b"stream: INSTREAM size limit exceeded. ERROR\0",
                      b"stream: OK", b"prefix OK suffix\0"):
            with self.subTest(reply=reply):
                self.assertEqual("error", self.clamav_result(reply).status)

    def test_clamav_version_gate_rejects_known_vulnerable_branches(self):
        for text, accepted in (("ClamAV 1.4.4/1/Tue", False), ("ClamAV 1.4.5/1/Tue", True),
                               ("ClamAV 1.5.2/1/Tue", False), ("ClamAV 1.5.3/1/Tue", True),
                               ("ClamAV 2.0.0/1/Tue", True), ("unknown", False)):
            version = ClamAVScanner._version_tuple(text)
            self.assertEqual(accepted, bool(version and ClamAVScanner._supported_version(version)))

    def test_clamav_health_requires_ping_and_supported_version_commands(self):
        class Socket:
            def __init__(self, reply): self.reply = reply
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def settimeout(self, _value): pass
            def sendall(self, _value): pass
            def recv(self, _size): value, self.reply = self.reply, b""; return value
        for version, expected in ((b"ClamAV 1.5.3/1/Tue\0", "clean"),
                                  (b"ClamAV 1.5.2/1/Tue\0", "error")):
            with self.subTest(version=version), patch(
                "sfss.scanners.socket.create_connection",
                side_effect=[Socket(b"PONG\0"), Socket(version)],
            ):
                self.assertEqual(expected, ClamAVScanner("127.0.0.1", 3310).health().status)

    @patch("sfss.scanners.subprocess.run")
    def test_yara_cli_match_is_infected_without_a_shell(self, run):
        def completed(command, **kwargs):
            kwargs["stdout"].write(b"suspicious_rule /tmp/payload\n")
            return subprocess.CompletedProcess(command, 0)
        run.side_effect = completed
        result = YaraScanner("/etc/sfss/rules.yar").scan(Path("/tmp/payload"))
        self.assertEqual("infected", result.status)
        command = run.call_args.args[0]
        self.assertEqual(["yara", "--timeout=15", "/etc/sfss/rules.yar", "/tmp/payload"], command)
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("sfss.scanners.subprocess.run")
    def test_yara_cli_failure_is_fail_closed(self, run):
        def failed(command, **kwargs):
            kwargs["stderr"].write(b"invalid rule")
            return subprocess.CompletedProcess(command, 2)
        run.side_effect = failed
        result = YaraScanner("/etc/sfss/rules.yar").scan(Path("/tmp/payload"))
        self.assertEqual("error", result.status)
        self.assertIn("invalid rule", result.detail)

    @patch("sfss.scanners.subprocess.run")
    def test_yara_cli_output_is_not_captured_in_process_memory(self, run):
        run.return_value = subprocess.CompletedProcess([], 0)
        YaraScanner("/etc/sfss/rules.yar").scan(Path("/tmp/payload"))
        self.assertNotEqual(subprocess.PIPE, run.call_args.kwargs["stdout"])
        self.assertNotEqual(subprocess.PIPE, run.call_args.kwargs["stderr"])


if __name__ == "__main__": unittest.main()
