from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class DetectedType:
    media_type: str
    extension: str
    known: bool


SIGNATURES = (
    (b"%PDF-", "application/pdf", ".pdf"),
    (b"PK\x03\x04", "application/zip", ".zip"),
    (b"\x1f\x8b", "application/gzip", ".gz"),
    (b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
    (b"\xff\xd8\xff", "image/jpeg", ".jpg"),
    (b"\x7fELF", "application/x-elf", ""),
)

EXTENSIONS = {
    ".pdf": "application/pdf", ".zip": "application/zip", ".gz": "application/gzip",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".txt": "text/plain", ".csv": "text/plain", ".json": "text/plain",
}


def detect_content(prefix: bytes) -> DetectedType:
    for signature, media_type, extension in SIGNATURES:
        if prefix.startswith(signature):
            return DetectedType(media_type, extension, True)
    if prefix and b"\x00" not in prefix:
        try:
            prefix.decode("utf-8")
            return DetectedType("text/plain", ".txt", True)
        except UnicodeDecodeError:
            pass
    return DetectedType("application/octet-stream", "", False)


def extension_conflicts(filename: str, detected: DetectedType) -> bool:
    suffix = Path(filename).suffix.lower()
    claimed = EXTENSIONS.get(suffix)
    return bool(claimed and claimed != detected.media_type)

