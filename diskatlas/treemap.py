from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
from .models import Node

@dataclass
class Rect:
    x: float
    y: float
    w: float
    h: float

def _normalize_sizes(nodes: List[Node], area: float) -> List[float]:
    total = sum(max(0, n.size) for n in nodes) or 1
    return [max(0, n.size) * area / total for n in nodes]

def _worst(row: List[float], w: float) -> float:
    if not row:
        return float("inf")
    s = sum(row)
    rmax = max(row)
    rmin = min(row)
    w2 = w * w
    return max((w2 * rmax) / (s * s), (s * s) / (w2 * rmin))

def _layout_row(row: List[float], rect: Rect, horizontal: bool) -> Tuple[List[Rect], Rect]:
    out: List[Rect] = []
    s = sum(row)
    if horizontal:
        h = s / rect.w if rect.w > 0 else 0
        x = rect.x
        for a in row:
            w = a / h if h > 0 else 0
            out.append(Rect(x, rect.y, w, h))
            x += w
        rem = Rect(rect.x, rect.y + h, rect.w, max(0.0, rect.h - h))
    else:
        w = s / rect.h if rect.h > 0 else 0
        y = rect.y
        for a in row:
            h = a / w if w > 0 else 0
            out.append(Rect(rect.x, y, w, h))
            y += h
        rem = Rect(rect.x + w, rect.y, max(0.0, rect.w - w), rect.h)
    return out, rem

def squarify(nodes: List[Node], x: float, y: float, w: float, h: float) -> List[Tuple[Rect, Node]]:
    nodes = [n for n in nodes if n.size > 0]
    nodes.sort(key=lambda n: n.size, reverse=True)
    rect = Rect(x, y, w, h)
    areas = _normalize_sizes(nodes, w * h)
    out: List[Tuple[Rect, Node]] = []

    row: List[float] = []
    row_nodes: List[Node] = []
    remaining = rect
    i = 0
    while i < len(nodes):
        a = areas[i]
        n = nodes[i]
        short = min(remaining.w, remaining.h) or 1.0
        new_row = row + [a]
        if row and _worst(new_row, short) > _worst(row, short):
            horizontal = remaining.w >= remaining.h
            laid, remaining = _layout_row(row, remaining, horizontal)
            for r, nn in zip(laid, row_nodes):
                out.append((r, nn))
            row, row_nodes = [], []
        else:
            row.append(a)
            row_nodes.append(n)
            i += 1

    if row:
        horizontal = remaining.w >= remaining.h
        laid, remaining = _layout_row(row, remaining, horizontal)
        for r, nn in zip(laid, row_nodes):
            out.append((r, nn))
    return out

def top_children_for_view(node: Node, limit: int = 450) -> List[Node]:
    kids = [c for c in node.children if c.size > 0]
    kids.sort(key=lambda n: n.size, reverse=True)
    return kids[:limit]
