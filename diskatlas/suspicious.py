from __future__ import annotations
import os
import time
from typing import Dict, Iterable, List, Optional, Tuple
from .models import SuspiciousFinding
from .utils import shannon_entropy
from .magic import looks_like_extension_mismatch

RANSOM_EXT = {
    ".locked",".lock",".crypt",".encrypted",".enc",".crypto",".crypz",".cryp1",".cryp2",
    ".locky",".zepto",".cerber",".ryuk",".conti",".revil",".sodinokibi",".djvu",".stop",
    ".phobos",".gandcrab",".medusa",".mallox",".pysa",".vault",".wasted",".nuke"
}

RANSOM_NOTES = {
    "readme.txt","readme.html","readme.bmp",
    "how_to_decrypt.txt","how_to_decrypt.html",
    "recover_files.txt","restore_files.txt","decrypt_instructions.txt",
    "!!!readme!!!.txt","!!!readme!!!.html",
}

def _read_head(path: str, n: int = 4096) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""

def _read_sample_for_entropy(path: str, n: int = 65536) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""

def score_file(path: str,
               size: int,
               mtime: float,
               dir_stats: Optional[Dict[str, int]] = None) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path).lower()

    if ext in RANSOM_EXT:
        score += 45
        reasons.append(f"Подозрительное расширение: {ext}")

    if base in RANSOM_NOTES:
        score += 60
        reasons.append("Похоже на ransom note (инструкция выкупа)")

    if size > 0:
        sample = _read_sample_for_entropy(path)
        ent = shannon_entropy(sample) if sample else 0.0
        if ent >= 7.6 and size >= 4096:
            score += 25
            reasons.append(f"Высокая энтропия: {ent:.2f} (шифрование/упаковка)")
        elif ent >= 7.2 and size >= 4096:
            score += 15
            reasons.append(f"Повышенная энтропия: {ent:.2f}")

    head = _read_head(path)
    mismatch, msg = looks_like_extension_mismatch(ext, head)
    if mismatch:
        score += 15
        reasons.append(msg)

    now = time.time()
    age_hours = (now - mtime) / 3600.0 if mtime else 1e9
    if age_hours < 24:
        score += 8
        reasons.append("Изменён < 24 часов назад")
    if age_hours < 3:
        score += 8
        reasons.append("Изменён < 3 часов назад")

    if dir_stats is not None:
        d = os.path.dirname(path)
        cnt = dir_stats.get(d, 0)
        if cnt >= 50:
            score += 10
            reasons.append(f"Много изменённых файлов в каталоге за сутки: {cnt}")

    return min(100, score), reasons

def build_recent_dir_stats(files: Iterable[Tuple[str, float]], hours: float = 24.0) -> Dict[str, int]:
    now = time.time()
    out: Dict[str, int] = {}
    for path, mtime in files:
        if not mtime:
            continue
        if (now - mtime) <= hours * 3600.0:
            d = os.path.dirname(path)
            out[d] = out.get(d, 0) + 1
    return out

def scan_suspicious(files: Iterable[str],
                    progress: Optional[callable] = None,
                    cancel_flag: Optional[callable] = None) -> List[SuspiciousFinding]:
    mtimes: List[Tuple[str, float]] = []
    sizes: Dict[str, int] = {}
    i = 0
    for p in files:
        if cancel_flag and cancel_flag():
            break
        try:
            st = os.stat(p)
            mtimes.append((p, st.st_mtime))
            sizes[p] = int(st.st_size)
        except OSError:
            mtimes.append((p, 0.0))
            sizes[p] = 0
        i += 1
        if progress and i % 2500 == 0:
            progress("collect", i)

    dir_stats = build_recent_dir_stats(mtimes, hours=24.0)

    findings: List[SuspiciousFinding] = []
    total = len(mtimes)
    for idx, (p, mt) in enumerate(mtimes, 1):
        if cancel_flag and cancel_flag():
            break
        sz = sizes.get(p, 0)
        s, reasons = score_file(p, sz, mt, dir_stats=dir_stats)
        if s >= 40:
            findings.append(SuspiciousFinding(path=p, score=s, reasons=reasons, size=sz, mtime=mt))
        if progress and idx % 2500 == 0:
            progress("score", idx, total)

    findings.sort(key=lambda x: x.score, reverse=True)
    return findings
