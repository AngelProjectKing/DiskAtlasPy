from __future__ import annotations
import math

def format_bytes(num: int) -> str:
    if num < 0:
        return str(num)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    x = float(num)
    for u in units:
        if x < 1024.0 or u == units[-1]:
            return f"{x:.2f} {u}" if u != "B" else f"{int(x)} {u}"
        x /= 1024.0
    return f"{x:.2f} PB"

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    n = len(data)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def clamp(v, lo, hi):
    return lo if v < lo else hi if v > hi else v

import os
import sys
import subprocess


def reveal_in_file_manager(path: str) -> bool:
    """Open the system file manager and reveal the given path.

    Works on Windows/macOS/Linux. Returns True if an attempt was made.
    """
    if not path:
        return False
    try:
        ap = os.path.abspath(path)
        if sys.platform.startswith('win'):
            # explorer can reveal files; for folders just open
            if os.path.isdir(ap):
                os.startfile(ap)
            else:
                subprocess.Popen(['explorer', '/select,', ap])
            return True
        if sys.platform == 'darwin':
            subprocess.Popen(['open', '-R', ap])
            return True
        # linux & others
        folder = ap if os.path.isdir(ap) else os.path.dirname(ap)
        subprocess.Popen(['xdg-open', folder])
        return True
    except Exception:
        return False
