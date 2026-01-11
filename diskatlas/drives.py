from __future__ import annotations
import os
import psutil

def list_drives():
    drives = []
    seen = set()
    for p in psutil.disk_partitions(all=False):
        mp = p.mountpoint
        if not mp:
            continue
        mp_norm = os.path.abspath(mp)
        if mp_norm in seen:
            continue
        seen.add(mp_norm)
        try:
            u = psutil.disk_usage(mp_norm)
        except Exception:
            continue
        drives.append({
            "mountpoint": mp_norm,
            "fstype": p.fstype,
            "total": int(u.total),
            "used": int(u.used),
            "free": int(u.free),
            "percent": float(u.percent),
        })
    drives.sort(key=lambda d: d["mountpoint"].lower())
    return drives

def estimate_total_bytes(paths):
    # Для дисков (C:\) берём disk_usage.total.
    # Для папки — берём “used” диска как грубую оценку (иначе точно не узнать заранее).
    total = 0
    for p in paths:
        try:
            u = psutil.disk_usage(p)
            total += int(u.total)
        except Exception:
            pass
    return total
