from __future__ import annotations
import os
import struct
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"DATLAS1"
VERSION = 1
DEFAULT_CHUNK = 1024 * 1024  # 1MB

def is_diskatlas_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(len(MAGIC))
        return head == MAGIC
    except OSError:
        return False

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(in_path: str, out_path: str, password: str, chunk_size: int = DEFAULT_CHUNK,
                 progress: Optional[callable] = None, cancel_flag: Optional[callable] = None) -> None:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)

    total = os.path.getsize(in_path)
    written = 0

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack("B", VERSION))
        fout.write(salt)
        fout.write(struct.pack("<I", int(chunk_size)))
        fout.write(struct.pack("<Q", int(total)))

        while True:
            if cancel_flag and cancel_flag():
                raise RuntimeError("Cancelled")
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, chunk, None)
            fout.write(nonce)
            fout.write(struct.pack("<I", len(ct)))
            fout.write(ct)
            written += len(chunk)
            if progress:
                progress(written, total)

def decrypt_file(in_path: str, out_path: str, password: str,
                 progress: Optional[callable] = None, cancel_flag: Optional[callable] = None) -> None:
    with open(in_path, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Это не файл DiskAtlasPy (MAGIC не совпадает).")
        ver = struct.unpack("B", fin.read(1))[0]
        if ver != VERSION:
            raise ValueError(f"Неподдерживаемая версия формата: {ver}")
        salt = fin.read(16)
        chunk_size = struct.unpack("<I", fin.read(4))[0]
        orig_size = struct.unpack("<Q", fin.read(8))[0]

        key = _derive_key(password, salt)
        aes = AESGCM(key)

        read_total = 0
        with open(out_path, "wb") as fout:
            while True:
                if cancel_flag and cancel_flag():
                    raise RuntimeError("Cancelled")
                nonce = fin.read(12)
                if not nonce:
                    break
                ct_len_bytes = fin.read(4)
                if len(ct_len_bytes) < 4:
                    break
                ct_len = struct.unpack("<I", ct_len_bytes)[0]
                ct = fin.read(ct_len)
                if len(ct) != ct_len:
                    raise ValueError("Файл повреждён (недостаточно данных).")
                pt = aes.decrypt(nonce, ct, None)
                fout.write(pt)
                read_total += len(pt)
                if progress:
                    progress(min(read_total, orig_size), orig_size)
            fout.truncate(orig_size)
