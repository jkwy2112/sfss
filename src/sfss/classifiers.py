from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Classification:
    category: Optional[str]
    detail: str


class OutboundClassifier:
    name = "builtin-semiconductor"

    def classify(self, path: Path, media_type: str, type_known: bool) -> Classification:
        with path.open("rb") as stream:
            prefix = stream.read(65536)
        if self._is_gdsii(prefix):
            return Classification("GDS", "validated GDSII HEADER and BGNLIB records")
        if self._is_fpga_bitfile(prefix):
            return Classification("FPGA_BITFILE", "recognized FPGA bitstream synchronization structure")
        if type_known:
            return Classification("GENERAL", f"known content type {media_type}")
        return Classification(None, "unknown binary content cannot be classified")

    @staticmethod
    def _is_gdsii(data: bytes) -> bool:
        # Require the mandatory HEADER, BGNLIB and LIBNAME record sequence,
        # including exact fixed-record lengths. Two plausible type bytes alone
        # are not enough to authorize an outbound classification.
        if len(data) < 40 or data[2:4] != b"\x00\x02":
            return False
        first_length = int.from_bytes(data[:2], "big")
        version = int.from_bytes(data[4:6], "big")
        if first_length != 6 or not 1 <= version <= 1000:
            return False
        offset = first_length
        if offset + 28 > len(data):
            return False
        second_length = int.from_bytes(data[offset:offset + 2], "big")
        if second_length != 28 or data[offset + 2:offset + 4] != b"\x01\x02":
            return False
        offset += second_length
        if offset + 6 > len(data): return False
        third_length = int.from_bytes(data[offset:offset + 2], "big")
        return (third_length >= 6 and third_length % 2 == 0 and
                data[offset + 2:offset + 4] == b"\x02\x06" and
                offset + third_length <= len(data))

    @staticmethod
    def _is_fpga_bitfile(data: bytes) -> bool:
        # Xilinx .bit container: fixed magic, ordered metadata fields a-d,
        # followed by field e with a 32-bit payload length. Validate that the
        # payload itself also contains a word-aligned dummy/sync sequence.
        magic = b"\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01"
        if data.startswith(magic):
            offset = len(magic)
            for tag in b"abcd":
                if offset + 3 > len(data) or data[offset] != tag: return False
                length = int.from_bytes(data[offset + 1:offset + 3], "big")
                if not 1 <= length <= 4096 or offset + 3 + length > len(data): return False
                offset += 3 + length
            if offset + 5 > len(data) or data[offset] != ord("e"): return False
            payload_length = int.from_bytes(data[offset + 1:offset + 5], "big")
            payload = data[offset + 5:]
            return payload_length >= 8 and OutboundClassifier._has_xilinx_sync(payload)
        return OutboundClassifier._has_xilinx_sync(data)

    @staticmethod
    def _has_xilinx_sync(data: bytes) -> bool:
        limit = min(len(data), 4096)
        offset = data.find(b"\xff\xff\xff\xff\xaa\x99\x55\x66", 0, limit)
        return offset >= 0 and offset % 4 == 0
