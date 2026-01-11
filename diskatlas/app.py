from __future__ import annotations

import os
import sys
import json
import heapq
import time
from dataclasses import asdict
from typing import Optional, List, Tuple, Callable, Dict

from PySide6.QtCore import (
    Qt, QThread, Signal, QTimer, QEasingCurve, QPropertyAnimation, QSize
)
from PySide6.QtGui import (
    QFont, QColor, QBrush, QPen, QPainter, QPainterPath, QAction, QKeySequence
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QTreeWidget, QTreeWidgetItem, QSplitter, QLineEdit,
    QProgressBar, QMessageBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextEdit, QHeaderView, QAbstractItemView, QGraphicsView, QGraphicsScene,
    QGraphicsRectItem, QGraphicsTextItem, QFormLayout, QSpinBox,
    QDialog, QDialogButtonBox, QCheckBox, QGraphicsOpacityEffect, QMenu
)

import shiboken6

from .models import Node, SuspiciousFinding, ScanResult
from .scanner import scan_paths, iter_all_files
from .utils import format_bytes, clamp, reveal_in_file_manager
from .treemap import squarify, top_children_for_view
from .suspicious import scan_suspicious
from .crypto_tools import encrypt_file, decrypt_file, DEFAULT_CHUNK, is_diskatlas_file
from .drives import list_drives, estimate_total_bytes

APP_NAME = "DiskAtlasPy"

# -------------------- Style --------------------
DARK_QSS = r"""
* { font-family: "Segoe UI"; font-size: 12px; }

QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #0b0e14, stop:0.6 #0f1220, stop:1 #0b1020);
}

QWidget { color: #dbe6ff; }
QLabel { color: #dbe6ff; }

QLineEdit, QTextEdit, QTreeWidget, QTableWidget, QSpinBox {
    background: #121826;
    border: 1px solid #25314a;
    border-radius: 10px;
    padding: 7px 9px;
    selection-background-color: rgba(47, 107, 255, 0.40);
    selection-color: #ffffff;
}

QTextEdit { padding: 10px; }

QGraphicsView {
    background: #121826;
    border: 1px solid #25314a;
    border-radius: 14px;
}

QTableCornerButton::section {
    background: #0e1320;
    border: none;
}

QPushButton {
    background: #16203a;
    border: 1px solid #2a3a5a;
    border-radius: 12px;
    padding: 8px 12px;
    color: #e7efff;
}

QPushButton:hover {
    background: #1a2a4c;
    border-color: #3a5aa8;
}

QPushButton:pressed {
    background: #0f1930;
}

QPushButton:disabled {
    background: #141a28;
    color: #6a7894;
    border-color: #1d2433;
}

QProgressBar {
    background: #0e1320;
    border: 1px solid #26334d;
    border-radius: 10px;
    text-align: center;
    color: #cfe0ff;
    height: 18px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #2f6bff, stop:1 #38d1c5);
    border-radius: 10px;
}

QTabWidget::pane {
    border: 1px solid #26334d;
    border-radius: 16px;
    top: 0px;
    background: rgba(14,19,32,0.20);
}

QTabBar::tab {
    background: #101624;
    border: 1px solid #26334d;
    border-bottom: none;
    padding: 8px 14px;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    margin-right: 4px;
    color: #bcd0ff;
}

QTabBar::tab:selected {
    background: #121a2d;
    color: #ffffff;
    border-color: #3a5aa8;
}

QHeaderView::section {
    background: #0e1320;
    color: #9fb6ea;
    padding: 7px 8px;
    border: none;
    border-right: 1px solid #1e2a40;
}

QTableWidget {
    gridline-color: #1e2a40;
    alternate-background-color: #0f1526;
}

QTableWidget::item {
    padding: 6px;
    border-radius: 6px;
}

QTableWidget::item:selected {
    background: rgba(47, 107, 255, 0.35);
}

QTreeWidget::item {
    padding: 4px 2px;
}

QTreeWidget::item:selected {
    background: rgba(47, 107, 255, 0.35);
}

QScrollBar:vertical {
    background: #0b0f1a;
    width: 10px;
    margin: 0px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #26334d;
    min-height: 30px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #3a5aa8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QSplitter::handle { background: #0f1526; }
QSplitter::handle:hover { background: #1a2a4c; }
"""


# -------------------- Cancel flag --------------------
class CancelFlag:
    def __init__(self):
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def __call__(self):
        return self._cancel


# -------------------- Worker threads --------------------
class ScanThread(QThread):
    progress = Signal(str, int, int, object)  # path, files, dirs, bytes_scanned (may be int64)
    done = Signal(object)                      # ScanResult
    error = Signal(str)

    def __init__(self, paths: List[str]):
        super().__init__()
        self.paths = paths
        self.cancel_flag = CancelFlag()

    def run(self):
        try:
            def prog(cur: str, files: int, dirs: int, bytes_scanned: int):
                self.progress.emit(cur, files, dirs, bytes_scanned)
            res = scan_paths(self.paths, progress=prog, cancel_flag=self.cancel_flag)
            self.done.emit(res)
        except Exception as e:
            self.error.emit(str(e))


class SuspiciousThread(QThread):
    progress = Signal(str, int, int)  # msg, a, b
    done = Signal(list)              # List[SuspiciousFinding]
    error = Signal(str)

    def __init__(self, root_paths: List[str]):
        super().__init__()
        self.root_paths = root_paths
        self.cancel_flag = CancelFlag()

    def run(self):
        try:
            files_iter = iter_all_files(self.root_paths, cancel_flag=self.cancel_flag)

            def prog(stage: str, a: int, b: int = 0):
                if stage == "collect":
                    self.progress.emit("Сбор метаданных…", a, 0)
                else:
                    self.progress.emit("Оценка подозрительности…", a, b)

            res = scan_suspicious(files_iter, progress=prog, cancel_flag=self.cancel_flag)
            self.done.emit(res)
        except Exception as e:
            self.error.emit(str(e))


class CryptoThread(QThread):
    progress = Signal(int, int)  # a, b
    done = Signal(str)
    error = Signal(str)

    def __init__(self, mode: str, in_path: str, out_path: str, password: str, chunk: int):
        super().__init__()
        self.mode = mode
        self.in_path = in_path
        self.out_path = out_path
        self.password = password
        self.chunk = chunk
        self.cancel_flag = CancelFlag()

    def run(self):
        try:
            def prog(a: int, b: int):
                self.progress.emit(a, b)

            if self.mode == "enc":
                encrypt_file(
                    self.in_path, self.out_path, self.password,
                    chunk_size=self.chunk, progress=prog, cancel_flag=self.cancel_flag
                )
                self.done.emit("✅ Готово: файл зашифрован (формат DiskAtlasPy).")
            else:
                decrypt_file(
                    self.in_path, self.out_path, self.password,
                    progress=prog, cancel_flag=self.cancel_flag
                )
                self.done.emit("✅ Готово: файл расшифрован.")
        except RuntimeError as e:
            # отмена
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(str(e))


# -------------------- Dialogs --------------------
class DrivePicker(QDialog):
    def __init__(self, parent=None, preselected: Optional[List[str]] = None):
        super().__init__(parent)
        self.setWindowTitle("Выбор дисков")
        self.resize(700, 400)
        self.selected: List[str] = preselected[:] if preselected else []

        v = QVBoxLayout(self)
        hint = QLabel("Отметь диски, которые нужно просканировать (можно несколько).")
        hint.setStyleSheet("QLabel{color:#b7c3dd;}")
        v.addWidget(hint)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["", "Диск", "Всего", "Занято", "Свободно"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        v.addWidget(self.table, 1)

        drives = list_drives()
        for d in drives:
            r = self.table.rowCount()
            self.table.insertRow(r)
            cb = QCheckBox()
            cb.setChecked(d["mountpoint"] in self.selected)
            cb.stateChanged.connect(lambda _=None: self._collect())
            self.table.setCellWidget(r, 0, cb)
            self.table.setItem(r, 1, QTableWidgetItem(d["mountpoint"]))
            self.table.setItem(r, 2, QTableWidgetItem(format_bytes(d["total"])))
            self.table.setItem(r, 3, QTableWidgetItem(format_bytes(d["used"])))
            self.table.setItem(r, 4, QTableWidgetItem(format_bytes(d["free"])))

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        v.addWidget(btns)

    def _collect(self):
        out = []
        for r in range(self.table.rowCount()):
            cb = self.table.cellWidget(r, 0)
            if isinstance(cb, QCheckBox) and cb.isChecked():
                mp_item = self.table.item(r, 1)
                if mp_item:
                    out.append(mp_item.text())
        self.selected = out


# -------------------- UI helpers --------------------
class BusySpinner(QWidget):
    """Lightweight spinner (no external deps)."""
    def __init__(self, parent=None, radius: int = 10, line_len: int = 6):
        super().__init__(parent)
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._radius = radius
        self._line_len = line_len
        self.setFixedSize(QSize((radius + line_len + 2) * 2, (radius + line_len + 2) * 2))

    def start(self):
        if not self._timer.isActive():
            self._timer.start(16)

    def stop(self):
        self._timer.stop()
        self.update()

    def _tick(self):
        self._angle = (self._angle + 30) % 360
        self.update()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        c = self.rect().center()

        for i in range(12):
            a = (self._angle + i * 30) % 360
            alpha = int(clamp(255 - i * 18, 30, 255))
            col = QColor(56, 209, 197, alpha) if i < 6 else QColor(47, 107, 255, alpha)
            p.setPen(QPen(col, 2, Qt.SolidLine, Qt.RoundCap))
            p.save()
            p.translate(c)
            p.rotate(a)
            p.drawLine(0, -self._radius, 0, -(self._radius + self._line_len))
            p.restore()


class LoadingOverlay(QWidget):
    """Modal overlay with cancel + subtle animations."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setVisible(False)
        self.setFocusPolicy(Qt.StrongFocus)

        self._cancel_cb: Optional[Callable[[], None]] = None

        self.effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.effect.setOpacity(0.0)

        self.anim = QPropertyAnimation(self.effect, b"opacity", self)
        self.anim.setDuration(180)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)

        # Dim background
        self.setStyleSheet("LoadingOverlay{background: rgba(6,8,14,190);} ")

        # Center card
        self.card = QWidget(self)
        self.card.setObjectName("overlayCard")
        self.card.setStyleSheet("""
            QWidget#overlayCard {
                background: rgba(18,24,38,0.96);
                border: 1px solid #2a3a5a;
                border-radius: 18px;
            }
            QLabel { color: #e7efff; }
        """)

        cv = QVBoxLayout(self.card)
        cv.setContentsMargins(18, 16, 18, 16)
        cv.setSpacing(10)

        top = QHBoxLayout()
        self.spinner = BusySpinner(self.card, radius=10, line_len=6)
        top.addWidget(self.spinner, 0, Qt.AlignTop)

        titles = QVBoxLayout()
        self.title = QLabel("Загрузка")
        f = QFont(); f.setPointSize(13); f.setBold(True)
        self.title.setFont(f)

        self.detail = QLabel("…")
        self.detail.setStyleSheet("QLabel{color:#b7c3dd;}")
        self.detail.setWordWrap(True)

        titles.addWidget(self.title)
        titles.addWidget(self.detail)
        top.addLayout(titles, 1)
        cv.addLayout(top)

        self.prog = QProgressBar()
        self.prog.setRange(0, 100)
        self.prog.setValue(0)
        cv.addWidget(self.prog)

        bottom = QHBoxLayout()
        self.hint = QLabel("Esc — отмена")
        self.hint.setStyleSheet("QLabel{color:#8ea3d6;}")
        bottom.addWidget(self.hint)
        bottom.addStretch(1)

        self.btn_cancel = QPushButton("⏹ Отмена")
        self.btn_cancel.clicked.connect(self._on_cancel)
        bottom.addWidget(self.btn_cancel)
        cv.addLayout(bottom)

        self._relayout()

    def start(self, title: str, detail: str = "", cancellable: bool = True, cancel_cb: Optional[Callable[[], None]] = None):
        self._cancel_cb = cancel_cb
        self.title.setText(title)
        self.detail.setText(detail or "…")
        self.btn_cancel.setVisible(bool(cancellable))
        self.hint.setVisible(bool(cancellable))
        self.btn_cancel.setEnabled(True)
        self.prog.setVisible(True)
        self.prog.setRange(0, 100)
        self.prog.setValue(0)

        self._relayout()
        self.setVisible(True)
        self.raise_()
        self.setFocus(Qt.ActiveWindowFocusReason)

        self.spinner.start()

        self.anim.stop()
        self.anim.setStartValue(self.effect.opacity())
        self.anim.setEndValue(1.0)
        self.anim.start()

    def stop(self):
        self.spinner.stop()
        self.anim.stop()
        self.anim.setStartValue(self.effect.opacity())
        self.anim.setEndValue(0.0)
        self.anim.finished.connect(self._hide_after_anim)
        self.anim.start()

    def _hide_after_anim(self):
        self.anim.finished.disconnect(self._hide_after_anim)
        self.setVisible(False)

    def set_detail(self, text: str):
        self.detail.setText(text)

    def set_progress(self, value: int, maximum: int = 100, indeterminate: bool = False):
        if indeterminate:
            self.prog.setRange(0, 0)
            return
        self.prog.setRange(0, max(1, int(maximum)))
        self.prog.setValue(max(0, min(int(value), int(maximum))))

    def lock_cancel(self, locked_text: str = "Отмена…"):
        if self.btn_cancel.isVisible():
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setText(locked_text)

    def _on_cancel(self):
        self.lock_cancel()
        if self._cancel_cb:
            try:
                self._cancel_cb()
            except Exception:
                pass

    def _relayout(self):
        if not self.parent():
            return
        pr = self.parent().rect()
        self.setGeometry(pr)

        # Card size
        w = min(560, max(360, pr.width() - 120))
        h = 168
        self.card.setFixedSize(w, h)
        x = (pr.width() - w) // 2
        y = (pr.height() - h) // 2
        self.card.move(max(0, x), max(0, y))

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        self._relayout()

    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key_Escape and self.btn_cancel.isVisible() and self.btn_cancel.isEnabled():
            self._on_cancel()
            ev.accept()
            return
        super().keyPressEvent(ev)


class TreemapView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing | QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setViewportUpdateMode(QGraphicsView.BoundingRectViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)

    def wheelEvent(self, ev):
        if ev.modifiers() & Qt.ControlModifier:
            factor = 1.15 if ev.angleDelta().y() > 0 else 1 / 1.15
            self.scale(factor, factor)
            ev.accept()
            return
        super().wheelEvent(ev)

    def mouseDoubleClickEvent(self, ev):
        # double click on empty -> fit
        if not self.itemAt(ev.position().toPoint()):
            sc = self.scene()
            if sc:
                self.fitInView(sc.sceneRect(), Qt.KeepAspectRatio)
            ev.accept()
            return
        super().mouseDoubleClickEvent(ev)


class TreemapTile(QGraphicsRectItem):
    def __init__(self, x: float, y: float, w: float, h: float, node: Node,
                 pct: float,
                 on_click: Callable[[Node], None],
                 on_double: Callable[[Node], None]):
        super().__init__(x, y, w, h)
        self.node = node
        self.pct = pct
        self._on_click = on_click
        self._on_double = on_double
        self._base_pen = QPen(QColor(10, 14, 22, 140), 1)
        self._hover_pen = QPen(QColor(56, 209, 197, 210), 2)
        self._radius = max(4.0, min(12.0, min(w, h) * 0.08))
        self.setPen(self._base_pen)
        self.setAcceptHoverEvents(True)

        tip = f"<b>{self.node.name}</b><br>{format_bytes(self.node.size)} • {self.pct:.2f}%<br><span style='color:#b7c3dd'>{self.node.path}</span>"
        self.setToolTip(tip)

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing, True)
        r = self.rect()
        path = QPainterPath()
        path.addRoundedRect(r, self._radius, self._radius)
        painter.setPen(self.pen())
        painter.setBrush(self.brush())
        painter.drawPath(path)

        # Optional label (only on sufficiently large tiles)
        if r.width() >= 110 and r.height() >= 52:
            pad = 8
            title = self.node.name
            size_s = format_bytes(self.node.size)

            # Title
            font = painter.font()
            font.setBold(True)
            font.setPointSizeF(max(9.0, min(12.0, r.height() * 0.18)))
            painter.setFont(font)
            painter.setPen(QColor(240, 245, 255, 230))
            fm = QFontMetrics(font)
            title_el = fm.elidedText(title, Qt.ElideRight, int(r.width() - 2 * pad))
            painter.drawText(r.adjusted(pad, pad, -pad, -pad), Qt.AlignLeft | Qt.AlignTop, title_el)

            # Size
            font2 = painter.font()
            font2.setBold(False)
            font2.setPointSizeF(max(8.5, min(11.0, r.height() * 0.15)))
            painter.setFont(font2)
            painter.setPen(QColor(185, 197, 221, 230))
            fm2 = QFontMetrics(font2)
            size_el = fm2.elidedText(size_s, Qt.ElideRight, int(r.width() - 2 * pad))
            painter.drawText(r.adjusted(pad, pad + fm.height() + 2, -pad, -pad), Qt.AlignLeft | Qt.AlignTop, size_el)

    def hoverEnterEvent(self, ev):
        self.setPen(self._hover_pen)
        self.setZValue(10)
        super().hoverEnterEvent(ev)

    def hoverLeaveEvent(self, ev):
        self.setPen(self._base_pen)
        self.setZValue(0)
        super().hoverLeaveEvent(ev)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.LeftButton:
            self._on_click(self.node)
            ev.accept()
            return
        super().mousePressEvent(ev)

    def mouseDoubleClickEvent(self, ev):
        if ev.button() == Qt.LeftButton:
            self._on_double(self.node)
            ev.accept()
            return
        super().mouseDoubleClickEvent(ev)


# -------------------- Main window --------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — анализ + подозрительные файлы")
        self.resize(1320, 860)

        self.scan_thread: Optional[ScanThread] = None
        self.susp_thread: Optional[SuspiciousThread] = None
        self.crypto_thread: Optional[CryptoThread] = None

        self.current_scan: Optional[ScanResult] = None
        self.selected_paths: List[str] = []
        self.total_est_bytes = 1

        self._findings: List[SuspiciousFinding] = []
        self._path_to_tree_item: Dict[str, QTreeWidgetItem] = {}

        self._treemap_anim_timer: Optional[QTimer] = None
        self._treemap_anim_seq = 0
        self._info_prev_sizes: Optional[List[int]] = None

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ---------- Top controls
        top = QWidget()
        top.setObjectName("topCard")
        top.setStyleSheet("""
            QWidget#topCard {
                background: rgba(18,24,38,0.72);
                border: 1px solid #25314a;
                border-radius: 16px;
            }
        """)
        top_l = QVBoxLayout(top)
        top_l.setContentsMargins(14, 12, 14, 12)
        top_l.setSpacing(10)

        row = QHBoxLayout()
        title = QLabel("DiskAtlasPy")
        tf = QFont(); tf.setPointSize(16); tf.setBold(True)
        title.setFont(tf)
        subtitle = QLabel("анализ дисков + treemap + подозрительные + защита файлов")
        subtitle.setStyleSheet("QLabel{color:#aabce6;}")
        row.addWidget(title)
        row.addSpacing(10)
        row.addWidget(subtitle, 1)
        top_l.addLayout(row)

        src_row = QHBoxLayout()
        self.paths_view = QLineEdit()
        self.paths_view.setPlaceholderText("Выбери диски или папку…")
        self.paths_view.setReadOnly(True)

        btn_disks = QPushButton("💽 Диски…")
        btn_folder = QPushButton("📁 Папка…")
        btn_scan = QPushButton("▶ Анализ")
        self.btn_cancel_scan = QPushButton("⏹ Отмена")
        self.btn_cancel_scan.setEnabled(False)
        btn_reset = QPushButton("↺ Сброс вида")

        src_row.addWidget(self.paths_view, 1)
        src_row.addWidget(btn_disks)
        src_row.addWidget(btn_folder)
        src_row.addSpacing(6)
        src_row.addWidget(btn_scan)
        src_row.addWidget(self.btn_cancel_scan)
        src_row.addWidget(btn_reset)
        top_l.addLayout(src_row)

        prog_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.summary = QLabel("Готово.")
        self.summary.setStyleSheet("QLabel{color:#b7c3dd;}")
        self.scan_detail = QLabel("")
        self.scan_detail.setStyleSheet("QLabel{color:#8ea3d6;}")
        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.summary)
        top_l.addLayout(prog_row)
        top_l.addWidget(self.scan_detail)

        root.addWidget(top)

        # ---------- Tabs
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # ---------- Analyze tab
        self.tab_an = QWidget()
        self.tabs.addTab(self.tab_an, "Анализ")
        a_lay = QVBoxLayout(self.tab_an)
        a_lay.setContentsMargins(0, 0, 0, 0)
        a_lay.setSpacing(10)

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setHandleWidth(10)
        self.splitter.setChildrenCollapsible(False)
        a_lay.addWidget(self.splitter, 1)

        # left: tree
        left = QWidget()
        left_l = QVBoxLayout(left)
        left_l.setContentsMargins(0, 0, 0, 0)
        left_l.setSpacing(8)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Папка/Файл", "Размер"])
        self.tree.setUniformRowHeights(True)
        self.tree.header().setStretchLastSection(False)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.Fixed)
        self.tree.header().resizeSection(1, 120)
        self.tree.setTextElideMode(Qt.ElideMiddle)
        self.tree.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.tree.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        left_l.addWidget(self.tree, 1)

        self.tree_hint = QLabel("Подсказка: клик по treemap выделяет в дереве. Двойной клик — зайти внутрь. Ctrl+колесо — зум.")
        self.tree_hint.setStyleSheet("QLabel{color:#8ea3d6;}")
        self.tree_hint.setWordWrap(True)
        left_l.addWidget(self.tree_hint)

        self.splitter.addWidget(left)

        # right: treemap + info
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)
        right_l.setSpacing(8)

        tm_head = QHBoxLayout()
        self.btn_up = QPushButton("↑ Вверх")
        self.btn_fit = QPushButton("⤢ Вписать")
        self.btn_info = QPushButton("ℹ Инфо")
        self.btn_shot = QPushButton("📷 Снимок")

        self.tm_path = QLabel("Treemap: —")
        self.tm_path.setStyleSheet("QLabel{color:#b7c3dd;}")
        self.tm_path.setTextInteractionFlags(Qt.TextSelectableByMouse)

        tm_head.addWidget(self.tm_path, 1)
        tm_head.addWidget(self.btn_up)
        tm_head.addWidget(self.btn_fit)
        tm_head.addWidget(self.btn_info)
        tm_head.addWidget(self.btn_shot)
        right_l.addLayout(tm_head)

        self.treemap_view = TreemapView()
        self.treemap_scene = QGraphicsScene()
        self.treemap_view.setScene(self.treemap_scene)

        self.info = QTextEdit()
        self.info.setReadOnly(True)
        self.info.setMinimumHeight(130)

        self.right_split = QSplitter(Qt.Vertical)
        self.right_split.setHandleWidth(10)
        self.right_split.setChildrenCollapsible(False)
        self.right_split.addWidget(self.treemap_view)
        self.right_split.addWidget(self.info)
        self.right_split.setSizes([680, 220])
        right_l.addWidget(self.right_split, 1)

        self.splitter.addWidget(right)
        self.splitter.setSizes([420, 900])

        # ---------- Stats tab
        self.tab_stats = QWidget()
        self.tabs.addTab(self.tab_stats, "Статистика")
        st = QVBoxLayout(self.tab_stats)

        self.stats_hint = QLabel("Сначала сделай сканирование — после этого тут появится понятная статистика.")
        self.stats_hint.setStyleSheet("QLabel{color:#b7c3dd;}")
        st.addWidget(self.stats_hint)

        st.addWidget(QLabel("Использование дисков (по системе):"))
        self.drive_table = QTableWidget(0, 5)
        self.drive_table.setHorizontalHeaderLabels(["Диск", "Всего", "Занято", "Свободно", "Заполнено"])
        self.drive_table.setMaximumHeight(170)
        st.addWidget(self.drive_table, 0)

        self.stats_split = QSplitter(Qt.Horizontal)
        self.stats_split.setHandleWidth(10)
        self.stats_split.setChildrenCollapsible(False)
        st.addWidget(self.stats_split, 1)

        ext_box = QWidget()
        ext_l = QVBoxLayout(ext_box); ext_l.setContentsMargins(0, 0, 0, 0)
        ext_l.addWidget(QLabel("Топ расширений (по размеру скана):"))
        self.ext_table = QTableWidget(0, 4)
        self.ext_table.setHorizontalHeaderLabels(["Расширение", "Размер", "Файлы", "Доля"])
        ext_l.addWidget(self.ext_table, 1)
        self.stats_split.addWidget(ext_box)

        top_box = QWidget()
        top_l = QVBoxLayout(top_box); top_l.setContentsMargins(0, 0, 0, 0)
        top_l.addWidget(QLabel("Топ по размеру:"))

        # tabs: top files + top folders
        self.top_table = QTableWidget(0, 2)
        self.top_table.setHorizontalHeaderLabels(["Размер", "Путь"])

        self.top_dirs_table = QTableWidget(0, 2)
        self.top_dirs_table.setHorizontalHeaderLabels(["Размер", "Путь"])

        self.top_tabs = QTabWidget()
        files_tab = QWidget(); files_l = QVBoxLayout(files_tab); files_l.setContentsMargins(0,0,0,0)
        files_l.addWidget(self.top_table, 1)
        dirs_tab = QWidget(); dirs_l = QVBoxLayout(dirs_tab); dirs_l.setContentsMargins(0,0,0,0)
        dirs_l.addWidget(self.top_dirs_table, 1)
        self.top_tabs.addTab(files_tab, "Файлы")
        self.top_tabs.addTab(dirs_tab, "Папки")
        top_l.addWidget(self.top_tabs, 1)

        self.scan_summary_box = QTextEdit()
        self.scan_summary_box.setReadOnly(True)
        self.scan_summary_box.setFixedHeight(150)
        top_l.addWidget(self.scan_summary_box)

        self.stats_split.addWidget(top_box)
        self.stats_split.setSizes([520, 700])

        # ---------- Suspicious tab
        self.tab_susp = QWidget()
        self.tabs.addTab(self.tab_susp, "Подозрительные")
        s_lay = QVBoxLayout(self.tab_susp)

        s_top = QHBoxLayout()
        self.btn_susp_scan = QPushButton("🧪 Сканировать подозрительные (полный обход)")
        self.btn_susp_cancel = QPushButton("⏹ Отмена")
        self.btn_susp_cancel.setEnabled(False)
        self.btn_export = QPushButton("⬇ Экспорт отчёта…")
        self.btn_export.setEnabled(False)
        s_top.addWidget(self.btn_susp_scan)
        s_top.addWidget(self.btn_susp_cancel)
        s_top.addStretch(1)
        s_top.addWidget(self.btn_export)
        s_lay.addLayout(s_top)

        self.susp_table = QTableWidget(0, 4)
        self.susp_table.setHorizontalHeaderLabels(["Score", "Размер", "Путь", "Причины"])
        s_lay.addWidget(self.susp_table, 1)

        self.susp_progress = QProgressBar()
        self.susp_progress.setRange(0, 100)
        self.susp_progress.setValue(0)
        s_lay.addWidget(self.susp_progress)

        # ---------- Protect tab
        self.tab_protect = QWidget()
        self.tabs.addTab(self.tab_protect, "Защита")
        p_lay = QVBoxLayout(self.tab_protect)

        p_form = QFormLayout()
        self.in_file = QLineEdit()
        self.out_file = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.cb_show_pwd = QCheckBox("Показать пароль")
        self.chunk_spin = QSpinBox()
        self.chunk_spin.setRange(64, 16384)
        self.chunk_spin.setValue(int(DEFAULT_CHUNK // 1024))
        self.chunk_spin.setSuffix(" KB")

        row_in = QHBoxLayout()
        row_in.addWidget(self.in_file, 1)
        btn_in = QPushButton("…")
        row_in.addWidget(btn_in)

        row_out = QHBoxLayout()
        row_out.addWidget(self.out_file, 1)
        btn_out = QPushButton("…")
        row_out.addWidget(btn_out)

        p_form.addRow("Входной файл:", row_in)
        p_form.addRow("Выходной файл:", row_out)
        p_form.addRow("Пароль:", self.password)
        p_form.addRow("", self.cb_show_pwd)
        p_form.addRow("Chunk размер:", self.chunk_spin)

        p_lay.addLayout(p_form)

        self.file_detect = QLabel("Формат: —")
        self.file_detect.setStyleSheet("QLabel{color:#b7c3dd;}")
        p_lay.addWidget(self.file_detect)

        p_btns = QHBoxLayout()
        self.btn_enc = QPushButton("🔒 Зашифровать")
        self.btn_dec = QPushButton("🔓 Расшифровать")
        self.btn_crypto_cancel = QPushButton("⏹ Отмена")
        self.btn_crypto_cancel.setEnabled(False)
        p_btns.addWidget(self.btn_enc)
        p_btns.addWidget(self.btn_dec)
        p_btns.addWidget(self.btn_crypto_cancel)
        p_btns.addStretch(1)
        p_lay.addLayout(p_btns)

        self.crypto_progress = QProgressBar()
        self.crypto_progress.setRange(0, 100)
        self.crypto_progress.setValue(0)
        p_lay.addWidget(self.crypto_progress)

        self.crypto_log = QTextEdit()
        self.crypto_log.setReadOnly(True)
        self.crypto_log.setFixedHeight(180)
        p_lay.addWidget(self.crypto_log)

        # overlay
        self.overlay = LoadingOverlay(central)

        # ---------- Tables common look
        self._init_table(self.drive_table, no_select=True)
        self._init_table(self.ext_table)
        self._init_table(self.top_table)
        self._init_table(self.top_dirs_table)
        self._init_table(self.susp_table)

        for t in (self.top_table, self.top_dirs_table, self.susp_table):
            t.setTextElideMode(Qt.ElideMiddle)

        # Drive table: last column is a compact bar
        self.drive_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for c in [1, 2, 3]:
            self.drive_table.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.drive_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)

        # Ext table: last column is a compact bar
        self.ext_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ext_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.ext_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.ext_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

        self.top_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.top_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)

        self.top_dirs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.top_dirs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)

        self.susp_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.susp_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.susp_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.susp_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

        # wiring
        btn_disks.clicked.connect(self.pick_disks)
        btn_folder.clicked.connect(self.pick_folder)
        btn_scan.clicked.connect(self.start_scan)
        self.btn_cancel_scan.clicked.connect(self.cancel_scan)
        btn_reset.clicked.connect(self.reset_layout)

        self.tree.itemSelectionChanged.connect(self.on_tree_select)

        # tree: context menu
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_path_menu)
        self.btn_up.clicked.connect(self.go_up_tree)
        self.btn_fit.clicked.connect(lambda: self.treemap_view.fitInView(self.treemap_scene.sceneRect(), Qt.KeepAspectRatio))
        self.btn_info.clicked.connect(self.toggle_info_panel)
        self.btn_shot.clicked.connect(self.save_treemap_screenshot)

        self.btn_susp_scan.clicked.connect(self.start_suspicious)
        self.btn_susp_cancel.clicked.connect(self.cancel_suspicious)
        self.btn_export.clicked.connect(self.export_report)

        # tables: context menu + double click reveal
        for _tbl, _col in ((self.top_table, 1), (self.top_dirs_table, 1), (self.susp_table, 2)):
            _tbl.setContextMenuPolicy(Qt.CustomContextMenu)
            _tbl.customContextMenuRequested.connect(lambda pos, t=_tbl, c=_col: self._table_path_menu(t, pos, c))

        self.top_table.itemDoubleClicked.connect(lambda it: self._reveal_path(self.top_table.item(it.row(), 1).text()))
        self.top_dirs_table.itemDoubleClicked.connect(lambda it: self._reveal_path(self.top_dirs_table.item(it.row(), 1).text()))
        self.susp_table.itemDoubleClicked.connect(lambda it: self._reveal_path(self.susp_table.item(it.row(), 2).text()))

        btn_in.clicked.connect(self.pick_in_file)
        btn_out.clicked.connect(self.pick_out_file)
        self.cb_show_pwd.stateChanged.connect(self.toggle_pwd)
        self.in_file.textChanged.connect(self.on_infile_changed)

        self.btn_enc.clicked.connect(lambda: self.start_crypto("enc"))
        self.btn_dec.clicked.connect(lambda: self.start_crypto("dec"))
        self.btn_crypto_cancel.clicked.connect(self.cancel_crypto)

        # ESC to cancel
        act = QAction(self)
        act.setShortcut(QKeySequence(Qt.Key_Escape))
        act.triggered.connect(self._esc_cancel)
        self.addAction(act)

        self.refresh_drive_table()
        self.statusBar().showMessage("Готово.")

    # ---------- helpers
    def _esc_cancel(self):
        # Prefer active long operations
        if self.scan_thread and self.btn_cancel_scan.isEnabled():
            self.cancel_scan()
            self.overlay.lock_cancel()
        elif self.susp_thread and self.btn_susp_cancel.isEnabled():
            self.cancel_suspicious()
            self.overlay.lock_cancel()
        elif self.crypto_thread and self.btn_crypto_cancel.isEnabled():
            self.cancel_crypto()
            self.overlay.lock_cancel()

    def _stop_treemap_anim(self):
        """Stop running treemap fade-in animation (avoids PySide 'C++ object deleted')."""
        try:
            if self._treemap_anim_timer is not None:
                self._treemap_anim_timer.stop()
        except Exception:
            pass
        self._treemap_anim_timer = None
        # bump generation to invalidate any running closures
        self._treemap_anim_seq += 1

    def toggle_info_panel(self):
        if self.info.isVisible():
            self._info_prev_sizes = self.right_split.sizes()
            self.info.hide()
        else:
            self.info.show()
            if self._info_prev_sizes:
                self.right_split.setSizes(self._info_prev_sizes)
            else:
                self.right_split.setSizes([680, 220])

    def save_treemap_screenshot(self):
        if self.treemap_scene.items() == []:
            QMessageBox.information(self, "Снимок treemap", "Treemap пока пуст — сначала сделай сканирование.")
            return
        fn, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить изображение treemap",
            os.path.expanduser("~/treemap.png"),
            "PNG (*.png);;JPEG (*.jpg *.jpeg)"
        )
        if not fn:
            return
        pm = self.treemap_view.grab()  # what user sees
        ok = pm.save(fn)
        if ok:
            self.statusBar().showMessage(f"Сохранено: {fn}")
        else:
            QMessageBox.warning(self, "Снимок treemap", "Не удалось сохранить изображение.")

    def _copy_text(self, text: str):
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("Скопировано в буфер обмена")

    def _reveal_path(self, path: str):
        if not path:
            return
        if not reveal_in_file_manager(path):
            QMessageBox.warning(self, "Открыть", "Не удалось открыть путь в файловом менеджере.")

    def _table_path_menu(self, table: QTableWidget, pos, path_col: int):
        item = table.itemAt(pos)
        if not item:
            return
        row = item.row()
        pitem = table.item(row, path_col)
        if not pitem:
            return
        path = pitem.text().strip()
        if not path:
            return
        m = QMenu(table)
        a_open = m.addAction("Открыть в проводнике")
        a_copy = m.addAction("Копировать путь")
        act = m.exec(table.viewport().mapToGlobal(pos))
        if act == a_open:
            self._reveal_path(path)
        elif act == a_copy:
            self._copy_text(path)

    def _expand_tree_subtree(self, item: QTreeWidgetItem, expand: bool):
        """Expand/collapse a subtree. Bounded to keep UI responsive."""
        if item is None:
            return
        stack = [item]
        limit = 6000
        n = 0
        while stack and n < limit:
            it = stack.pop()
            try:
                it.setExpanded(expand)
            except Exception:
                pass
            n += 1
            # push children
            for i in range(it.childCount() - 1, -1, -1):
                stack.append(it.child(i))

    def _tree_path_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        node = item.data(0, Qt.UserRole)
        if not node:
            return

        menu = QMenu(self.tree)

        a_open = menu.addAction("Открыть в проводнике")
        a_copy = menu.addAction("Копировать путь")
        a_copy_name = menu.addAction("Копировать имя")

        menu.addSeparator()

        a_expand = menu.addAction("Развернуть")
        a_collapse = menu.addAction("Свернуть")
        a_expand_all = menu.addAction("Развернуть всю ветку")
        a_collapse_all = menu.addAction("Свернуть всю ветку")

        menu.addSeparator()

        a_scan_this = menu.addAction("Сканировать только эту папку")

        act = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if not act:
            return

        if act == a_open:
            self._reveal_path(getattr(node, 'path', ''))
            return
        if act == a_copy:
            self._copy_text(getattr(node, 'path', ''))
            return
        if act == a_copy_name:
            self._copy_text(getattr(node, 'name', ''))
            return

        if act == a_expand:
            item.setExpanded(True)
            return
        if act == a_collapse:
            item.setExpanded(False)
            return
        if act == a_expand_all:
            self._expand_tree_subtree(item, True)
            return
        if act == a_collapse_all:
            self._expand_tree_subtree(item, False)
            return

        if act == a_scan_this:
            import os
            pth = getattr(node, 'path', '')
            if not pth:
                return
            if os.path.isfile(pth):
                pth = os.path.dirname(pth)
            self.selected_paths = [pth]
            self.paths_view.setText(pth)
            self.tabs.setCurrentWidget(self.tab_an)
            self.statusBar().showMessage("Выбран источник: " + pth)
            return


    def _init_table(self, t: QTableWidget, no_select: bool = False):
        t.verticalHeader().setVisible(False)   # removes those "black squares"
        t.setShowGrid(False)
        try:
            t.setCornerButtonEnabled(False)
        except Exception:
            pass
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        try:
            t.horizontalHeader().setHighlightSections(False)
        except Exception:
            pass
        t.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        t.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        if no_select:
            t.setSelectionMode(QAbstractItemView.NoSelection)
        else:
            t.setSelectionMode(QAbstractItemView.SingleSelection)

    def reset_layout(self):
        self.splitter.setSizes([420, 900])
        self.stats_split.setSizes([520, 700])
        self.treemap_view.resetTransform()
        self.treemap_view.fitInView(self.treemap_scene.sceneRect(), Qt.KeepAspectRatio)

    # ---------- Source selection
    def pick_disks(self):
        dlg = DrivePicker(self, preselected=self.selected_paths)
        if dlg.exec() == QDialog.Accepted:
            self.selected_paths = dlg.selected
            self.paths_view.setText("; ".join(self.selected_paths))
            self.refresh_drive_table()

    def pick_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Выбор папки", os.path.expanduser("~"))
        if path:
            self.selected_paths = [path]
            self.paths_view.setText(path)

    # ---------- Scan
    def start_scan(self):
        paths = [p.strip() for p in self.selected_paths if p.strip()]
        if not paths:
            QMessageBox.warning(self, "Источник", "Выбери диск(и) или папку.")
            return
        for p in paths:
            if not os.path.exists(p):
                QMessageBox.warning(self, "Не найдено", f"Путь не существует: {p}")
                return

        self.total_est_bytes = estimate_total_bytes(paths) or 1

        self.progress.setValue(0)
        self.summary.setText("Сканирование…")
        self.scan_detail.setText("")
        self.tree.clear()
        self._stop_treemap_anim()
        self.treemap_scene.clear()
        self.info.setHtml("")
        self.current_scan = None
        self._findings = []
        self._path_to_tree_item = {}
        self.susp_table.setRowCount(0)
        self.btn_export.setEnabled(False)

        self.overlay.start("Сканирование", "Идёт обход файловой системы…", cancellable=True, cancel_cb=self.cancel_scan)

        self.scan_thread = ScanThread(paths)
        self.scan_thread.progress.connect(self.on_scan_progress)
        self.scan_thread.done.connect(self.on_scan_done)
        self.scan_thread.error.connect(self.on_scan_error)
        self.btn_cancel_scan.setEnabled(True)
        self.scan_thread.start()
        self.statusBar().showMessage("Сканирование запущено…")

    def cancel_scan(self):
        if self.scan_thread:
            self.scan_thread.cancel_flag.cancel()
            self.overlay.lock_cancel("Отмена…")
            self.statusBar().showMessage("Отмена сканирования…")

    def on_scan_progress(self, cur: str, files: int, dirs: int, bytes_scanned):
        bs = int(bytes_scanned or 0)
        pct = int(clamp((bs / self.total_est_bytes) * 100.0, 0, 100))
        curv = self.progress.value()
        if pct > curv:
            self.progress.setValue(pct)

        # avoid extremely long labels
        cur_show = cur
        if len(cur_show) > 140:
            cur_show = cur_show[:60] + " … " + cur_show[-60:]

        self.scan_detail.setText(f"Файлов: {files} | Папок: {dirs} | Пройдено: {format_bytes(bs)} | Сейчас: {cur_show}")
        self.summary.setText("Сканирование…")
        self.overlay.set_detail(f"Сканирование… {format_bytes(bs)} • {files} файлов • {dirs} папок")
        self.overlay.set_progress(pct)

    def on_scan_done(self, result: ScanResult):
        self.btn_cancel_scan.setEnabled(False)
        self.progress.setValue(100)
        self.overlay.stop()

        self.current_scan = result
        node = result.root

        self.summary.setText(f"Готово. Размер: {format_bytes(node.size)}")
        self.scan_detail.setText(f"Файлов: {result.files} | Папок: {result.dirs} | Время: {result.elapsed_sec:.1f} сек")
        self.statusBar().showMessage("Сканирование завершено.")

        self.populate_tree(node)
        self.tree.setCurrentItem(self.tree.topLevelItem(0))
        self.render_treemap(node)
        self.fill_stats(result)

    def on_scan_error(self, msg: str):
        self.btn_cancel_scan.setEnabled(False)
        self.progress.setValue(0)
        self.overlay.stop()
        QMessageBox.critical(self, "Ошибка сканирования", msg)
        self.statusBar().showMessage("Ошибка.")

    def populate_tree(self, node: Node):
        self.tree.setUpdatesEnabled(False)
        self.tree.clear()
        self._path_to_tree_item = {}

        def add(parent_item: Optional[QTreeWidgetItem], n: Node, depth: int = 0):
            it = QTreeWidgetItem([n.name, format_bytes(n.size)])
            it.setData(0, Qt.UserRole, n)
            it.setToolTip(0, n.path)
            if parent_item is None:
                self.tree.addTopLevelItem(it)
            else:
                parent_item.addChild(it)
            self._path_to_tree_item[n.path] = it

            if n.is_dir and depth < 32:
                for c in sorted(n.children, key=lambda x: x.size, reverse=True)[:650]:
                    add(it, c, depth + 1)

        add(None, node)
        self.tree.expandToDepth(1)
        self.tree.setUpdatesEnabled(True)

    def go_up_tree(self):
        items = self.tree.selectedItems()
        if not items:
            return
        p = items[0].parent()
        if p:
            self.tree.setCurrentItem(p)
            self.tree.scrollToItem(p, QAbstractItemView.PositionAtCenter)

    def on_tree_select(self):
        items = self.tree.selectedItems()
        if not items:
            return
        n: Node = items[0].data(0, Qt.UserRole)
        if not n:
            return
        self.info.setHtml(self.describe_node_html(n))
        self.render_treemap(n)

    def describe_node_html(self, n: Node) -> str:
        kind = "папка" if n.is_dir else "файл"
        top_html = ""
        if n.is_dir and n.children:
            kids = sorted(n.children, key=lambda x: x.size, reverse=True)[:12]
            rows = "".join(
                f"<tr><td style='padding:4px 8px; color:#e7efff;'><b>{c.name}</b></td>"
                f"<td style='padding:4px 8px; color:#b7c3dd; text-align:right;'>{format_bytes(c.size)}</td></tr>"
                for c in kids
            )
            top_html = f"""
            <div style="margin-top:10px; color:#b7c3dd;"><b>Топ внутри:</b></div>
            <table style="margin-top:6px; border-collapse:collapse; width:100%; background: rgba(14,19,32,0.55);
                          border:1px solid #25314a; border-radius:12px;">
              {rows}
            </table>
            """

        return f"""
        <div style="font-size:13px; line-height:1.35;">
          <div style="font-size:14px;"><b>{n.name}</b></div>
          <div style="color:#8ea3d6; margin-top:2px;">{n.path}</div>
          <div style="margin-top:10px;">
            <span style="color:#b7c3dd;">Тип:</span> <b>{kind}</b>
            &nbsp;&nbsp;•&nbsp;&nbsp;
            <span style="color:#b7c3dd;">Размер:</span> <b style="color:#38d1c5;">{format_bytes(n.size)}</b>
          </div>
          {top_html}
        </div>
        """

    # ---------- Treemap
    def _select_in_tree(self, node: Node):
        it = self._path_to_tree_item.get(node.path)
        if it:
            self.tree.setCurrentItem(it)
            self.tree.scrollToItem(it, QAbstractItemView.PositionAtCenter)

    def render_treemap(self, node: Node):
        self._stop_treemap_anim()
        self.treemap_scene.clear()
        self.tm_path.setText(f"Treemap: {node.path if node else '—'}")

        if not node or not node.is_dir:
            return

        kids = top_children_for_view(node, limit=650)
        if not kids:
            return

        vp = self.treemap_view.viewport().size()
        W = max(600, int(vp.width()) - 8)
        H = max(360, int(vp.height()) - 8)

        rects = squarify(kids, 0, 0, W, H)
        total = max(1, int(node.size))

        tiles: List[TreemapTile] = []

        def pick_color(child: Node) -> QColor:
            # Moderately colorful (in measure)
            base = hash(("D:" if child.is_dir else "F:") + child.path) % 360
            if child.is_dir:
                s, v = 140, 220
            else:
                s, v = 90, 210
            col = QColor()
            col.setHsv(int(base), int(s), int(v))
            col.setAlpha(235)
            return col

        def on_click(n: Node):
            self._select_in_tree(n)

        def on_double(n: Node):
            self._select_in_tree(n)
            if n.is_dir:
                # expand a bit for convenience
                it = self._path_to_tree_item.get(n.path)
                if it:
                    it.setExpanded(True)

        # Build items
        for r, child in rects:
            if r.w < 2 or r.h < 2:
                continue

            pct = (child.size / total) * 100.0
            tile = TreemapTile(r.x, r.y, r.w, r.h, child, pct, on_click, on_double)
            tile.setBrush(QBrush(pick_color(child)))
            tile.setOpacity(0.0)
            tiles.append(tile)
            self.treemap_scene.addItem(tile)

            # label if enough space
            area = r.w * r.h
            if area >= 11000 and r.w >= 120 and r.h >= 46:
                label = QGraphicsTextItem()
                label.setDefaultTextColor(QColor("#f4f7ff"))
                label.setTextWidth(r.w - 16)
                label.setHtml(
                    f"<div style='font-size:11px; line-height:1.25;'>"
                    f"<b>{child.name}</b><br>"
                    f"<span style='color:#cfe0ff;'>{format_bytes(child.size)} • {pct:.1f}%</span>"
                    f"</div>"
                )
                label.setPos(r.x + 8, r.y + 6)
                label.setZValue(20)

                # background for readability
                bg = QGraphicsRectItem(r.x + 6, r.y + 4, min(r.w - 12, 280), 40)
                bg.setBrush(QBrush(QColor(0, 0, 0, 110)))
                bg.setPen(QPen(QColor(0, 0, 0, 0)))
                bg.setZValue(15)

                self.treemap_scene.addItem(bg)
                self.treemap_scene.addItem(label)

        self.treemap_scene.setSceneRect(0, 0, W, H)
        self.treemap_view.fitInView(self.treemap_scene.sceneRect(), Qt.KeepAspectRatio)

        # Fade-in animation (robust: no "Internal C++ object ... deleted" spam)
        self._treemap_anim_seq += 1
        _seq = self._treemap_anim_seq
        step = {"v": 0}

        def tick():
            if _seq != self._treemap_anim_seq:
                try:
                    anim_timer.stop()
                except Exception:
                    pass
                return

            step["v"] += 1
            op = min(1.0, step["v"] / 12.0)

            alive = 0
            for t in tiles:
                try:
                    t.setOpacity(op)
                    alive += 1
                except RuntimeError:
                    # tile might already be destroyed by scene.clear()
                    continue

            if alive == 0 or op >= 1.0:
                anim_timer.stop()

        anim_timer = QTimer(self)
        self._treemap_anim_timer = anim_timer
        anim_timer.timeout.connect(tick)
        anim_timer.start(16)

    # ---------- Stats
    def refresh_drive_table(self):
        drives = list_drives()
        self.drive_table.setRowCount(0)
        for d in drives:
            r = self.drive_table.rowCount()
            self.drive_table.insertRow(r)
            self.drive_table.setItem(r, 0, QTableWidgetItem(d["mountpoint"]))
            self.drive_table.setItem(r, 1, QTableWidgetItem(format_bytes(d["total"])))
            self.drive_table.setItem(r, 2, QTableWidgetItem(format_bytes(d["used"])))
            self.drive_table.setItem(r, 3, QTableWidgetItem(format_bytes(d["free"])))

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(int(d["percent"]))
            bar.setTextVisible(True)
            bar.setFormat(f'{d["percent"]:.0f}%')
            bar.setFixedHeight(16)
            self.drive_table.setCellWidget(r, 4, bar)

    def fill_stats(self, result: ScanResult):
        self.stats_hint.setText("Сводка по результатам сканирования:")

        total = result.root.size or 1

        # extensions
        items = [(ext, b, c) for ext, (b, c) in result.ext_stats.items()]
        items.sort(key=lambda x: x[1], reverse=True)
        self.ext_table.setRowCount(0)
        for ext, b, c in items[:80]:
            r = self.ext_table.rowCount()
            self.ext_table.insertRow(r)
            self.ext_table.setItem(r, 0, QTableWidgetItem(ext))
            self.ext_table.setItem(r, 1, QTableWidgetItem(format_bytes(b)))
            self.ext_table.setItem(r, 2, QTableWidgetItem(str(c)))
            pct = int((b / total) * 100)

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(pct)
            bar.setTextVisible(True)
            bar.setFormat(f"{pct}%")
            bar.setFixedHeight(16)
            self.ext_table.setCellWidget(r, 3, bar)

        # top files
        self.top_table.setRowCount(0)
        for sz, pth in result.top_files[:260]:
            r = self.top_table.rowCount()
            self.top_table.insertRow(r)
            it0 = QTableWidgetItem(format_bytes(sz))
            it1 = QTableWidgetItem(pth)
            it1.setToolTip(pth)
            self.top_table.setItem(r, 0, it0)
            self.top_table.setItem(r, 1, it1)

        # top folders
        self.top_dirs_table.setRowCount(0)
        heap: List[tuple[int, str]] = []
        limit = 260
        stack = [result.root]
        while stack:
            n = stack.pop()
            if not n.is_dir:
                continue
            # push children first
            if getattr(n, 'children', None):
                stack.extend(n.children)
            if n is result.root:
                continue
            if n.size <= 0:
                continue
            heapq.heappush(heap, (int(n.size), n.path))
            if len(heap) > limit:
                heapq.heappop(heap)
        top_dirs = sorted(heap, key=lambda x: x[0], reverse=True)
        for sz, pth in top_dirs:
            r = self.top_dirs_table.rowCount()
            self.top_dirs_table.insertRow(r)
            it0 = QTableWidgetItem(format_bytes(sz))
            it1 = QTableWidgetItem(pth)
            it1.setToolTip(pth)
            self.top_dirs_table.setItem(r, 0, it0)
            self.top_dirs_table.setItem(r, 1, it1)
        # summary text
        top_ext = items[:8]
        top_lines = "\n".join([f"• {ext}: {format_bytes(b)} ({int((b/total)*100)}%)" for ext, b, c in top_ext])
        self.scan_summary_box.setPlainText(
            f"Пути: {', '.join(result.scanned_paths)}\n"
            f"Размер скана: {format_bytes(result.root.size)}\n"
            f"Файлов: {result.files} | Папок: {result.dirs} | Время: {result.elapsed_sec:.1f} сек\n"
            f"\nТоп расширений:\n{top_lines}\n"
        )

    # ---------- Suspicious
    def start_suspicious(self):
        if not self.current_scan or not self.current_scan.scanned_paths:
            QMessageBox.information(self, "Сначала анализ", "Сначала сделай анализ диска/папки.")
            return

        self.susp_progress.setValue(0)
        self.btn_susp_cancel.setEnabled(True)
        self.btn_susp_scan.setEnabled(False)
        self.susp_table.setRowCount(0)
        self._findings = []

        self.overlay.start("Проверка подозрительных", "Сбор метаданных…", cancellable=True, cancel_cb=self.cancel_suspicious)

        self.susp_thread = SuspiciousThread(self.current_scan.scanned_paths)
        self.susp_thread.progress.connect(self.on_susp_progress)
        self.susp_thread.done.connect(self.on_susp_done)
        self.susp_thread.error.connect(self.on_susp_error)
        self.susp_thread.start()
        self.statusBar().showMessage("Поиск подозрительных запущен…")

    def cancel_suspicious(self):
        if self.susp_thread:
            self.susp_thread.cancel_flag.cancel()
            self.overlay.lock_cancel("Отмена…")
            self.statusBar().showMessage("Отмена поиска подозрительных…")

    def on_susp_progress(self, msg: str, a: int, b: int):
        if b and b > 0:
            v = int((a / b) * 100)
            self.susp_progress.setValue(max(0, min(100, v)))
            self.overlay.set_progress(v)
        else:
            v = (self.susp_progress.value() + 2) % 100
            self.susp_progress.setValue(v)
            self.overlay.set_progress(0, 0, indeterminate=True)

        self.overlay.set_detail(f"{msg} ({a}/{b if b else '…'})")
        self.statusBar().showMessage(f"{msg} ({a}/{b if b else '…'})")

    def on_susp_done(self, findings: List[SuspiciousFinding]):
        self.btn_susp_cancel.setEnabled(False)
        self.btn_susp_scan.setEnabled(True)
        self.susp_progress.setValue(100)
        self.overlay.stop()

        self._findings = findings
        self.btn_export.setEnabled(bool(findings))
        self.populate_susp_table(findings)
        self.statusBar().showMessage(f"Готово. Подозрительных: {len(findings)}")

    def on_susp_error(self, msg: str):
        self.btn_susp_cancel.setEnabled(False)
        self.btn_susp_scan.setEnabled(True)
        self.overlay.stop()

        # RuntimeError("Cancelled") can be shown as a normal cancel
        if "Cancelled" in msg or "cancel" in msg.lower() or "отмен" in msg.lower():
            self.statusBar().showMessage("Отменено.")
            return

        QMessageBox.critical(self, "Ошибка", msg)
        self.statusBar().showMessage("Ошибка.")

    def populate_susp_table(self, findings: List[SuspiciousFinding]):
        self.susp_table.setRowCount(0)
        for f in findings[:3000]:
            r = self.susp_table.rowCount()
            self.susp_table.insertRow(r)
            it0 = QTableWidgetItem(str(f.score))
            it1 = QTableWidgetItem(format_bytes(f.size))
            it2 = QTableWidgetItem(f.path); it2.setToolTip(f.path)
            it3 = QTableWidgetItem("; ".join(f.reasons))
            self.susp_table.setItem(r, 0, it0)
            self.susp_table.setItem(r, 1, it1)
            self.susp_table.setItem(r, 2, it2)
            self.susp_table.setItem(r, 3, it3)
        self.susp_table.sortItems(0, Qt.DescendingOrder)

    def export_report(self):
        if not self._findings:
            QMessageBox.information(self, "Экспорт", "Нет данных для экспорта.")
            return
        p, _ = QFileDialog.getSaveFileName(self, "Экспорт отчёта", os.path.expanduser("~"), "JSON (*.json)")
        if not p:
            return
        data = [asdict(x) for x in self._findings]
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"created": time.time(), "findings": data}, f, ensure_ascii=False, indent=2)
        QMessageBox.information(self, "Экспорт", "Отчёт сохранён.")

    # ---------- Crypto
    def pick_in_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Выбери файл", os.path.expanduser("~"))
        if p:
            self.in_file.setText(p)

    def pick_out_file(self):
        p, _ = QFileDialog.getSaveFileName(self, "Выбери выходной файл", os.path.expanduser("~"))
        if p:
            self.out_file.setText(p)

    def toggle_pwd(self):
        self.password.setEchoMode(QLineEdit.Normal if self.cb_show_pwd.isChecked() else QLineEdit.Password)

    def on_infile_changed(self):
        p = self.in_file.text().strip()
        if not p or not os.path.exists(p):
            self.file_detect.setText("Формат: —")
            return
        if is_diskatlas_file(p):
            self.file_detect.setText("Формат: DiskAtlasPy (.datlas) — можно расшифровать")
            if not self.out_file.text().strip():
                if p.lower().endswith(".datlas"):
                    self.out_file.setText(p[:-7])
                else:
                    self.out_file.setText(p + ".decrypted")
        else:
            self.file_detect.setText("Формат: обычный файл — можно зашифровать в .datlas")
            if not self.out_file.text().strip():
                self.out_file.setText(p + ".datlas")

    def start_crypto(self, mode: str):
        in_path = self.in_file.text().strip()
        out_path = self.out_file.text().strip()
        pwd = self.password.text()
        chunk_kb = int(self.chunk_spin.value())
        chunk = max(64 * 1024, chunk_kb * 1024)

        if not in_path or not os.path.exists(in_path):
            QMessageBox.warning(self, "Файл", "Укажи входной файл.")
            return
        if not out_path:
            QMessageBox.warning(self, "Файл", "Укажи выходной файл.")
            return
        if not pwd:
            QMessageBox.warning(self, "Пароль", "Укажи пароль.")
            return

        self.crypto_progress.setValue(0)
        self.btn_enc.setEnabled(False)
        self.btn_dec.setEnabled(False)
        self.btn_crypto_cancel.setEnabled(True)
        self.crypto_log.append(f"▶ {('Шифрование' if mode=='enc' else 'Расшифровка')}…")

        self.overlay.start("Защита файлов", "Выполняется операция…", cancellable=True, cancel_cb=self.cancel_crypto)

        self.crypto_thread = CryptoThread(mode, in_path, out_path, pwd, chunk)
        self.crypto_thread.progress.connect(self.on_crypto_progress)
        self.crypto_thread.done.connect(self.on_crypto_done)
        self.crypto_thread.error.connect(self.on_crypto_error)
        self.crypto_thread.start()

    def cancel_crypto(self):
        if self.crypto_thread:
            self.crypto_thread.cancel_flag.cancel()
            self.overlay.lock_cancel("Отмена…")
            self.crypto_log.append("⏹ Отмена…")

    def on_crypto_progress(self, a: int, b: int):
        if b <= 0:
            self.crypto_progress.setRange(0, 0)
            self.overlay.set_progress(0, 0, indeterminate=True)
            return
        self.crypto_progress.setRange(0, 100)
        pct = int(clamp((a / b) * 100.0, 0, 100))
        self.crypto_progress.setValue(pct)
        self.overlay.set_progress(pct)
        self.overlay.set_detail(f"Прогресс: {pct}% • {format_bytes(a)} / {format_bytes(b)}")

    def on_crypto_done(self, msg: str):
        self.btn_crypto_cancel.setEnabled(False)
        self.btn_enc.setEnabled(True)
        self.btn_dec.setEnabled(True)
        self.overlay.stop()
        self.crypto_progress.setValue(100)
        self.crypto_log.append(msg)
        self.statusBar().showMessage("Готово.")

    def on_crypto_error(self, msg: str):
        self.btn_crypto_cancel.setEnabled(False)
        self.btn_enc.setEnabled(True)
        self.btn_dec.setEnabled(True)
        self.overlay.stop()

        if "Cancelled" in msg or "cancel" in msg.lower() or "отмен" in msg.lower():
            self.crypto_log.append("⏹ Отменено.")
            self.statusBar().showMessage("Отменено.")
            return

        self.crypto_log.append("❌ Ошибка: " + msg)
        QMessageBox.critical(self, "Ошибка", msg)
        self.statusBar().showMessage("Ошибка.")


def run():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(DARK_QSS)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())
