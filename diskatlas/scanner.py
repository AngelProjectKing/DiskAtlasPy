from __future__ import annotations
import os
import time
import stat as statmod
import heapq
from typing import Callable, Optional, Dict, Tuple, List
from .models import Node, ScanResult

DEFAULT_TOP_FILES_PER_DIR = 80
DEFAULT_GLOBAL_TOP_FILES = 400

# ВАЖНО: bytes_scanned может быть >2GB, поэтому в Qt сигнале НЕ использовать int32.
ProgressCb = Callable[[str, int, int, int], None]  # (current_path, files, dirs, bytes_scanned)

def _push_top(heap: List[Tuple[int, str]], item: Tuple[int, str], limit: int):
    if limit <= 0:
        return
    if len(heap) < limit:
        heapq.heappush(heap, item)
    else:
        if item[0] > heap[0][0]:
            heapq.heapreplace(heap, item)

def scan_paths(paths: List[str],
               progress: Optional[ProgressCb] = None,
               cancel_flag: Optional[Callable[[], bool]] = None,
               follow_symlinks: bool = False,
               top_files_per_dir: int = DEFAULT_TOP_FILES_PER_DIR,
               global_top_files: int = DEFAULT_GLOBAL_TOP_FILES) -> ScanResult:
    t0 = time.time()
    paths = [os.path.abspath(p) for p in paths if p]
    paths = [p.rstrip("\\/") + os.sep if len(p) == 3 and p[1] == ":" else p for p in paths]  # C:\
    name = "Этот компьютер" if len(paths) > 1 else (os.path.basename(paths[0].rstrip("\\/")) or paths[0])
    root = Node(name=name, path=";".join(paths), is_dir=True, size=0, children=[])

    files = 0
    dirs = 0
    bytes_scanned = 0
    ext_stats: Dict[str, Tuple[int, int]] = {}
    global_top: List[Tuple[int, str]] = []

    last_emit = 0.0
    def emit(cur: str):
        nonlocal last_emit
        if not progress:
            return
        now = time.time()
        if now - last_emit >= 0.10:
            last_emit = now
            progress(cur, files, dirs, bytes_scanned)

    def scan_dir(dir_path: str) -> Node:
        nonlocal files, dirs, bytes_scanned
        node = Node(name=os.path.basename(dir_path.rstrip("\\/")) or dir_path,
                    path=dir_path, is_dir=True, size=0, children=[])

        if cancel_flag and cancel_flag():
            return node

        local_top: List[Tuple[int, str, str]] = []
        local_files_count = 0
        local_other_bytes = 0

        try:
            with os.scandir(dir_path) as it:
                for entry in it:
                    if cancel_flag and cancel_flag():
                        break

                    try:
                        if entry.is_symlink() and not follow_symlinks:
                            continue
                    except OSError:
                        continue

                    try:
                        st = entry.stat(follow_symlinks=follow_symlinks)
                    except OSError:
                        continue

                    mode = st.st_mode
                    if statmod.S_ISDIR(mode):
                        dirs += 1
                        child = scan_dir(entry.path)
                        node.children.append(child)
                        node.size += child.size
                    else:
                        files += 1
                        local_files_count += 1
                        sz = int(getattr(st, "st_size", 0) or 0)
                        node.size += sz
                        bytes_scanned += sz

                        ext = os.path.splitext(entry.name)[1].lower() or "<без расширения>"
                        b, c = ext_stats.get(ext, (0, 0))
                        ext_stats[ext] = (b + sz, c + 1)

                        _push_top(global_top, (sz, entry.path), global_top_files)

                        if top_files_per_dir > 0:
                            if len(local_top) < top_files_per_dir:
                                heapq.heappush(local_top, (sz, entry.name, entry.path))
                            else:
                                if sz > local_top[0][0]:
                                    heapq.heapreplace(local_top, (sz, entry.name, entry.path))
                                else:
                                    local_other_bytes += sz
                        else:
                            local_other_bytes += sz

                    emit(dir_path)
        except (PermissionError, FileNotFoundError, OSError):
            return node

        if local_top:
            local_top.sort(key=lambda x: x[0], reverse=True)
            for sz, nm, pth in local_top:
                node.children.append(Node(name=nm, path=pth, is_dir=False, size=sz, children=[]))

        other_count = max(0, local_files_count - len(local_top))
        if other_count > 0 and local_other_bytes > 0:
            node.children.append(Node(
                name=f"… другие файлы ({other_count})",
                path=dir_path,
                is_dir=False,
                size=int(local_other_bytes),
                children=[]
            ))
        return node

    for p in paths:
        if cancel_flag and cancel_flag():
            break
        child = scan_dir(p)
        root.children.append(child)
        root.size += child.size

    top_files_sorted = sorted(global_top, key=lambda x: x[0], reverse=True)
    elapsed = time.time() - t0
    return ScanResult(
        root=root,
        ext_stats=ext_stats,
        top_files=top_files_sorted,
        scanned_paths=paths,
        files=files,
        dirs=dirs,
        bytes_scanned=bytes_scanned,
        elapsed_sec=elapsed
    )

def iter_all_files(paths: List[str], cancel_flag=None):
    for root in paths:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            if cancel_flag and cancel_flag():
                return
            for fn in filenames:
                if cancel_flag and cancel_flag():
                    return
                yield os.path.join(dirpath, fn)
