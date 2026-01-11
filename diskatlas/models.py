from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

@dataclass
class Node:
    name: str
    path: str
    is_dir: bool
    size: int = 0
    children: List["Node"] = field(default_factory=list)

@dataclass
class SuspiciousFinding:
    path: str
    score: int
    reasons: List[str]
    size: int = 0
    mtime: float = 0.0

@dataclass
class ScanResult:
    root: Node
    ext_stats: Dict[str, Tuple[int, int]]  # ext -> (bytes, count)
    top_files: List[Tuple[int, str]]       # (bytes, path) sorted desc
    scanned_paths: List[str]
    files: int
    dirs: int
    bytes_scanned: int
    elapsed_sec: float
