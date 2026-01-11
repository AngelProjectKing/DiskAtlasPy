from __future__ import annotations
from typing import Optional, Tuple

MAGIC = [
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"ID3", "mp3"),
    (b"OggS", "ogg"),
    (b"fLaC", "flac"),
    (b"\x1f\x8b\x08", "gz"),
    (b"MZ", "exe"),
]

EXT_MAP = {
    ".pdf": "pdf",
    ".png": "png",
    ".jpg": "jpg",
    ".jpeg": "jpg",
    ".zip": "zip",
    ".rar": "rar",
    ".7z": "7z",
    ".mp3": "mp3",
    ".ogg": "ogg",
    ".flac": "flac",
    ".gz": "gz",
    ".exe": "exe",
    ".dll": "exe",
}

def detect_kind(head: bytes) -> Optional[str]:
    for sig, kind in MAGIC:
        if head.startswith(sig):
            return kind
    return None

def extension_kind(ext: str) -> Optional[str]:
    return EXT_MAP.get(ext.lower())

def looks_like_extension_mismatch(ext: str, head: bytes) -> Tuple[bool, str]:
    ek = extension_kind(ext)
    hk = detect_kind(head)
    if hk is None:
        return (False, "")
    if ek is None:
        return (True, f"Сигнатура похожа на '{hk}', но расширение неизвестно/не типичное")
    if ek != hk:
        return (True, f"Расширение похоже на '{ek}', а сигнатура — на '{hk}'")
    return (False, "")
