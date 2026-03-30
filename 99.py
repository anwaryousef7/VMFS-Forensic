import os
import sys
import subprocess
import time
import re

import psutil
from PyQt5 import QtCore, QtGui, QtWidgets


# ═══════════════════════════ WorkerThread ════════════════════════════

class WorkerThread(QtCore.QThread):
    progress_changed = QtCore.pyqtSignal(int)
    log_message      = QtCore.pyqtSignal(str)
    finished_ok      = QtCore.pyqtSignal()
    finished_error   = QtCore.pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self._target    = target
        self._stop_flag = False

    def run(self):
        try:
            self._target(self)
            self.finished_ok.emit()
        except Exception as exc:
            self.finished_error.emit(str(exc))

    def stop(self):
        self._stop_flag = True

    @property
    def stopped(self):
        return self._stop_flag


# ══════════════════════════ HexViewerDialog ══════════════════════════

MAGIC_SIGNATURES = {
    b"\x4D\x5A":                         "Windows PE/EXE",
    b"\x7FELF":                           "ELF Binary (Linux)",
    b"\x89PNG\r\n\x1a\n":                 "PNG Image",
    b"\xFF\xD8\xFF":                      "JPEG Image",
    b"GIF87a":                            "GIF Image (87a)",
    b"GIF89a":                            "GIF Image (89a)",
    b"PK\x03\x04":                        "ZIP Archive / DOCX / XLSX",
    b"PK\x05\x06":                        "ZIP Archive (empty)",
    b"\x1F\x8B":                          "GZIP Compressed",
    b"BZh":                               "BZIP2 Compressed",
    b"\xFD7zXZ\x00":                      "XZ Compressed",
    b"Rar!\x1A\x07":                      "RAR Archive",
    b"\x7FVMDK":                          "VMDK Disk Image",
    b"KDMV":                              "VMDK Extent",
    b"COWD":                              "VMDK COW Disk",
    b"#extents":                          "VMDK Descriptor",
    b"VMFS":                              "VMFS Filesystem",
    b"%PDF":                              "PDF Document",
    b"\xD0\xCF\x11\xE0":                 "OLE2 (DOC/XLS/PPT)",
    b"\xFF\xFE":                          "UTF-16 LE Text",
    b"\xFE\xFF":                          "UTF-16 BE Text",
    b"\xEF\xBB\xBF":                      "UTF-8 BOM Text",
    b"SQLite format 3":                   "SQLite Database",
    b"\x00\x00\x00\x0CJXL ":             "JPEG XL Image",
    b"RIFF":                              "RIFF (WAV/AVI)",
    b"\x00\x00\x00\x14ftyp":             "MP4 Video",
    b"\x1A\x45\xDF\xA3":                 "Matroska/WebM Video",
    b"OggS":                              "OGG Media",
    b"fLaC":                              "FLAC Audio",
    b"ID3":                               "MP3 Audio (ID3)",
    b"\xFF\xFB":                          "MP3 Audio",
    b"CAFEBABE":                          "Java Class",
    b"\xCE\xFA\xED\xFE":                 "Mach-O 32-bit",
    b"\xCF\xFA\xED\xFE":                 "Mach-O 64-bit",
}


def detect_file_type(data: bytes) -> str:
    for magic, label in MAGIC_SIGNATURES.items():
        if data[:len(magic)] == magic:
            return label
    # Check if mostly printable text
    if len(data) > 0:
        printable = sum(1 for b in data[:512] if 32 <= b < 127 or b in (9, 10, 13))
        if printable / min(len(data), 512) > 0.85:
            return "Text / Script file"
    return "Unknown / Binary"


def extract_strings(data: bytes, min_len: int = 5) -> list:
    """Extract ASCII printable strings of at least min_len characters."""
    results = []
    current = []
    offset  = 0
    start   = 0
    for i, b in enumerate(data):
        if 32 <= b < 127 or b == 9:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append((start, "".join(current)))
            current = []
    if len(current) >= min_len:
        results.append((start, "".join(current)))
    return results


class HexViewerDialog(QtWidgets.QDialog):
    PAGE_SIZE = 65536   # 64 KB per page
    ROW_BYTES = 16

    def __init__(self, filepath, parent=None):
        super().__init__(parent)
        self.filepath  = filepath
        self.page      = 0
        try:
            self.file_size = os.path.getsize(filepath)
        except Exception:
            self.file_size = 0
        self.setWindowTitle(
            f"Hex Viewer  –  {os.path.basename(filepath)}")
        self._build_ui()
        self.showMaximized()
        self._load_page()

    def _build_ui(self):
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)

        # ── Top bar: file info + search ──────────────────────────────
        top = QtWidgets.QHBoxLayout()

        self.filetype_label = QtWidgets.QLabel("Detecting…")
        self.filetype_label.setStyleSheet(
            "background:#1a3a1a;color:#44ff88;"
            "padding:4px 10px;border-radius:4px;font-weight:bold;font-size:13px;")

        self.info_label = QtWidgets.QLabel()
        self.info_label.setStyleSheet("color:#aaddff;font-size:12px;")

        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText(
            "Search:  hex bytes  (4D 5A)  or  ASCII text")
        self.search_edit.setMinimumWidth(300)
        self.search_edit.returnPressed.connect(self._search)
        b_search = QtWidgets.QPushButton("🔍 Search")
        b_search.setStyleSheet("padding:4px 12px;font-weight:bold;")
        b_search.clicked.connect(self._search)

        top.addWidget(self.filetype_label)
        top.addWidget(self.info_label)
        top.addStretch()
        top.addWidget(self.search_edit)
        top.addWidget(b_search)
        lay.addLayout(top)

        # ── Main splitter: hex (left) | interpretation (right) ───────
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Left: hex display
        left_w  = QtWidgets.QWidget()
        left_l  = QtWidgets.QVBoxLayout(left_w)
        left_l.setContentsMargins(0, 0, 0, 0)

        hex_header = QtWidgets.QLabel(
            "  Offset      00 01 02 03 04 05 06 07  "
            "08 09 0A 0B 0C 0D 0E 0F   ASCII")
        hex_header.setStyleSheet(
            "background:#1a1a2a;color:#88aaff;"
            "font-family:Courier New,monospace;font-size:12px;"
            "padding:4px;")
        left_l.addWidget(hex_header)

        self.hex_edit = QtWidgets.QPlainTextEdit()
        self.hex_edit.setReadOnly(True)
        font = QtGui.QFont("Courier New", 11)
        font.setStyleHint(QtGui.QFont.Monospace)
        self.hex_edit.setFont(font)
        self.hex_edit.setStyleSheet(
            "background:#0a0a0a;color:#e8e8e8;border:none;"
            "selection-background-color:#2a4a8a;")
        left_l.addWidget(self.hex_edit)

        # Right: interpretation panel (tabbed)
        right_w = QtWidgets.QWidget()
        right_l = QtWidgets.QVBoxLayout(right_w)
        right_l.setContentsMargins(4, 0, 0, 0)

        right_tabs = QtWidgets.QTabWidget()

        # Tab 1: Extracted strings
        self.strings_edit = QtWidgets.QPlainTextEdit()
        self.strings_edit.setReadOnly(True)
        self.strings_edit.setFont(QtGui.QFont("Courier New", 10))
        self.strings_edit.setStyleSheet(
            "background:#0a0a12;color:#ccffcc;border:none;")
        self.strings_edit.setPlaceholderText("Strings found in current page…")
        right_tabs.addTab(self.strings_edit, "Strings")

        # Tab 2: Decoded text (UTF-8 + Latin-1)
        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QtGui.QFont("Courier New", 10))
        self.text_edit.setStyleSheet(
            "background:#0a0a12;color:#ffffcc;border:none;")
        right_tabs.addTab(self.text_edit, "Decoded Text")

        # Tab 3: File / Offset info
        self.info_edit = QtWidgets.QPlainTextEdit()
        self.info_edit.setReadOnly(True)
        self.info_edit.setFont(QtGui.QFont("Courier New", 10))
        self.info_edit.setStyleSheet(
            "background:#0a0a12;color:#ccccff;border:none;")
        right_tabs.addTab(self.info_edit, "File Info")

        right_l.addWidget(right_tabs)

        splitter.addWidget(left_w)
        splitter.addWidget(right_w)
        splitter.setSizes([700, 340])
        lay.addWidget(splitter)

        # ── Navigation bar ───────────────────────────────────────────
        nav = QtWidgets.QHBoxLayout()

        self.b_prev = QtWidgets.QPushButton("◀  Prev  64 KB")
        self.b_next = QtWidgets.QPushButton("Next  64 KB  ▶")
        self.b_prev.setStyleSheet(
            "padding:5px 16px;background:#222244;color:white;font-weight:bold;")
        self.b_next.setStyleSheet(
            "padding:5px 16px;background:#222244;color:white;font-weight:bold;")

        self.page_label = QtWidgets.QLabel()
        self.page_label.setStyleSheet(
            "color:#ffcc44;font-weight:bold;font-size:13px;padding:0 12px;")

        self.goto_edit = QtWidgets.QLineEdit()
        self.goto_edit.setPlaceholderText("Hex offset  e.g.  0x1A2B")
        self.goto_edit.setMaximumWidth(180)
        self.goto_edit.returnPressed.connect(self._goto_offset)
        b_goto = QtWidgets.QPushButton("Go to offset")
        b_goto.setStyleSheet("padding:5px 10px;")

        self.b_prev.clicked.connect(self._prev_page)
        self.b_next.clicked.connect(self._next_page)
        b_goto.clicked.connect(self._goto_offset)

        nav.addWidget(self.b_prev)
        nav.addWidget(self.page_label)
        nav.addWidget(self.b_next)
        nav.addStretch()
        nav.addWidget(QtWidgets.QLabel("Go to:"))
        nav.addWidget(self.goto_edit)
        nav.addWidget(b_goto)
        lay.addLayout(nav)

    # ─────────────────── page loading ────────────────────────────────

    def _load_page(self):
        offset = self.page * self.PAGE_SIZE
        try:
            with open(self.filepath, "rb") as f:
                f.seek(offset)
                data = f.read(self.PAGE_SIZE)
        except Exception as e:
            self.hex_edit.setPlainText(f"Error reading file:\n{e}")
            return

        # ── Hex display ──────────────────────────────────────────────
        lines = []
        for i in range(0, len(data), self.ROW_BYTES):
            chunk     = data[i:i + self.ROW_BYTES]
            row_off   = offset + i
            h1 = " ".join(f"{b:02X}" for b in chunk[:8])
            h2 = " ".join(f"{b:02X}" for b in chunk[8:])
            hex_str   = f"{h1:<23}  {h2:<23}"
            ascii_str = "".join(
                chr(b) if 32 <= b < 127 else "·" for b in chunk)
            lines.append(f"{row_off:010X}  {hex_str}  |{ascii_str}|")

        self.hex_edit.setPlainText("\n".join(lines))

        # ── Navigation labels ────────────────────────────────────────
        total_pages = max(1, (self.file_size + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.page_label.setText(
            f"Page {self.page + 1} / {total_pages}   |   "
            f"Offset: 0x{offset:08X}")
        self.info_label.setText(
            f"{os.path.basename(self.filepath)}   |   "
            f"Size: {self._fmt_size(self.file_size)}")
        self.b_prev.setEnabled(self.page > 0)
        self.b_next.setEnabled(offset + self.PAGE_SIZE < self.file_size)

        # ── Strings panel ────────────────────────────────────────────
        strings = extract_strings(data, min_len=5)
        if strings:
            str_lines = [
                f"0x{offset+s:08X}  {txt}"
                for s, txt in strings[:500]
            ]
            self.strings_edit.setPlainText("\n".join(str_lines))
        else:
            self.strings_edit.setPlainText("(no printable strings found in this page)")

        # ── Decoded text panel ───────────────────────────────────────
        decoded_parts = []
        decoded_parts.append("── UTF-8 Decoded ──────────────────────────────")
        try:
            utf8 = data.decode("utf-8", errors="replace")
            decoded_parts.append(utf8[:4096])
        except Exception as e:
            decoded_parts.append(f"UTF-8 error: {e}")

        decoded_parts.append("\n── Latin-1 Decoded ────────────────────────────")
        try:
            latin = data.decode("latin-1", errors="replace")
            decoded_parts.append(latin[:2048])
        except Exception as e:
            decoded_parts.append(f"Latin-1 error: {e}")

        self.text_edit.setPlainText("\n".join(decoded_parts))

        # ── File Info panel (only on first page) ─────────────────────
        if self.page == 0:
            ftype = detect_file_type(data)
            self.filetype_label.setText(f"  ✦  {ftype}  ")

            info_lines = [
                f"File        : {self.filepath}",
                f"Size        : {self._fmt_size(self.file_size)} "
                f"({self.file_size:,} bytes)",
                f"Type        : {ftype}",
                f"Total pages : {total_pages}  (64 KB each)",
                "",
                "── First 32 bytes (hex) ─────────────────────────",
                " ".join(f"{b:02X}" for b in data[:32]),
                "",
                "── Magic bytes ──────────────────────────────────",
            ]
            for magic, label in MAGIC_SIGNATURES.items():
                if data[:len(magic)] == magic:
                    info_lines.append(
                        f"  MATCH: {label}  "
                        f"(magic: {magic.hex().upper()[:16]})")
                    break
            else:
                info_lines.append("  No known magic signature matched.")

            # Shannon entropy + byte frequency
            if data:
                import math as _math
                freq  = [0] * 256
                for b in data[:min(len(data), 65536)]:
                    freq[b] += 1
                n       = len(data[:65536])
                entropy = 0.0
                if n > 0:
                    for c in freq:
                        if c > 0:
                            p = c / n
                            entropy -= p * _math.log2(p)
                info_lines += [
                    "",
                    "── Byte analysis (first page) ───────────────────",
                    f"  Shannon entropy : {entropy:.4f} bits/byte  (max 8.0)",
                    f"  Null bytes      : {freq[0]:,}",
                    f"  Printable ASCII : {sum(freq[i] for i in range(32, 127)):,}",
                    f"  High bytes >127 : {sum(freq[i] for i in range(128, 256)):,}",
                    f"  Unique byte vals: {sum(1 for c in freq if c > 0)} / 256",
                ]

            try:
                stat = os.stat(self.filepath)
                info_lines += [
                    "",
                    "── File Metadata ────────────────────────────────",
                    f"  Modified : {time.ctime(stat.st_mtime)}",
                    f"  Accessed : {time.ctime(stat.st_atime)}",
                    f"  Inode    : {stat.st_ino}",
                    f"  Mode     : {oct(stat.st_mode)}",
                ]
            except Exception:
                pass

            self.info_edit.setPlainText("\n".join(info_lines))

    # ─────────────────── navigation ──────────────────────────────────

    def _prev_page(self):
        if self.page > 0:
            self.page -= 1
            self._load_page()

    def _next_page(self):
        if (self.page + 1) * self.PAGE_SIZE < self.file_size:
            self.page += 1
            self._load_page()

    def _goto_offset(self):
        txt = self.goto_edit.text().strip().replace("0x", "").replace("0X", "")
        try:
            offset    = int(txt, 16)
            self.page = offset // self.PAGE_SIZE
            self._load_page()
        except ValueError:
            pass

    def _search(self):
        query = self.search_edit.text().strip()
        if not query:
            return
        try:
            pattern = bytes.fromhex(query.replace(" ", ""))
        except ValueError:
            pattern = query.encode("utf-8", errors="replace")

        try:
            search_mb = 50 * 1024 * 1024  # search up to 50 MB
            with open(self.filepath, "rb") as f:
                for start in [self.page * self.PAGE_SIZE, 0]:
                    f.seek(start)
                    buf = f.read(search_mb)
                    idx = buf.find(pattern)
                    if idx != -1:
                        found     = start + idx
                        self.page = found // self.PAGE_SIZE
                        self._load_page()
                        QtWidgets.QMessageBox.information(
                            self, "Found",
                            f"Pattern found at offset: 0x{found:X} "
                            f"({found:,} bytes)")
                        return
            QtWidgets.QMessageBox.information(
                self, "Not found", "Pattern not found in first 50 MB.")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Search error", str(e))

    @staticmethod
    def _fmt_size(n):
        for u in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"


# ════════════════════════ ExportProgressDialog ════════════════════════

class ExportProgressDialog(QtWidgets.QDialog):
    cancel_requested = QtCore.pyqtSignal()

    def __init__(self, title="Exporting…", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(540, 180)
        self.setWindowFlags(
            self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)

        lay = QtWidgets.QVBoxLayout(self)

        self.file_label = QtWidgets.QLabel("Preparing…")
        self.file_label.setWordWrap(True)
        self.file_label.setStyleSheet("font-size:12px;")
        lay.addWidget(self.file_label)

        self.bar = QtWidgets.QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setTextVisible(True)
        self.bar.setStyleSheet(
            "QProgressBar{height:30px;border-radius:5px;font-size:13px;}"
            "QProgressBar::chunk{background:#1a7a1a;border-radius:5px;}")
        lay.addWidget(self.bar)

        info_row = QtWidgets.QHBoxLayout()
        self.speed_label = QtWidgets.QLabel("Speed: --")
        self.speed_label.setStyleSheet(
            "color:#44ff88;font-weight:bold;font-size:13px;")
        self.copied_label = QtWidgets.QLabel("")
        self.copied_label.setStyleSheet("color:#aaaaaa;font-size:12px;")
        info_row.addWidget(self.speed_label)
        info_row.addStretch()
        info_row.addWidget(self.copied_label)
        lay.addLayout(info_row)

        b_cancel = QtWidgets.QPushButton("Cancel")
        b_cancel.setStyleSheet(
            "background:#7a1a1a;color:white;"
            "font-weight:bold;padding:5px;")
        b_cancel.clicked.connect(self.cancel_requested.emit)
        lay.addWidget(b_cancel)

    # FIXED: plain method (no QMetaObject needed – called from main thread)
    def update_progress(self, pct: int, filename: str = "",
                        speed: str = "", copied_str: str = ""):
        self.bar.setValue(pct)
        if filename:
            name = filename[-60:] if len(filename) > 60 else filename
            self.file_label.setText(f"Copying:  {name}")
        if speed:
            self.speed_label.setText(f"Speed: {speed}")
        if copied_str:
            self.copied_label.setText(copied_str)


# ══════════════════════════════ Main GUI ══════════════════════════════

class VMFSGui(QtWidgets.QMainWindow):

    IS_WIN = (os.name == "nt")
    CHUNK  = 4 * 1024 * 1024   # 4 MB chunks for large file copy

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VMFS6 Forensic Utility")
        self.resize(1200, 820)
        self.worker       = None
        self._export_dlg  = None
        self._hex_viewers = []
        self._build_ui()
        self._populate_devices()

    # ─────────────────────────── UI BUILD ────────────────────────────

    def _build_ui(self):
        central = QtWidgets.QWidget()
        root    = QtWidgets.QVBoxLayout(central)

        self.tabs = QtWidgets.QTabWidget()
        root.addWidget(self.tabs)

        self.tab_src    = QtWidgets.QWidget()
        self.tab_mount  = QtWidgets.QWidget()
        self.tab_dd     = QtWidgets.QWidget()
        self.tab_browse = QtWidgets.QWidget()
        self.tab_wsl    = QtWidgets.QWidget()

        self._build_tab_source()
        self._build_tab_mount()
        self._build_tab_dd()
        self._build_tab_browse()
        self._build_tab_wsl()

        self.tabs.addTab(self.tab_src,    "Sources")
        self.tabs.addTab(self.tab_mount,  "Mount VMFS6")
        self.tabs.addTab(self.tab_dd,     "Imaging (dd)")
        self.tabs.addTab(self.tab_browse, "VMFS Browser")
        self.tabs.addTab(self.tab_wsl,    "WSL Helper")

        root.addWidget(QtWidgets.QLabel("Log:"))
        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(120)
        root.addWidget(self.log_edit)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        root.addWidget(self.progress)

        self.speed_label = QtWidgets.QLabel("Speed: --")
        self.speed_label.setStyleSheet(
            "color:#44ff88;font-size:13px;font-weight:bold;")
        root.addWidget(self.speed_label)

        btn_row = QtWidgets.QHBoxLayout()
        b_clear = QtWidgets.QPushButton("Clear log")
        b_save  = QtWidgets.QPushButton("Save log")
        b_clear.clicked.connect(self.log_edit.clear)
        b_save.clicked.connect(self._save_log)
        btn_row.addWidget(b_clear)
        btn_row.addWidget(b_save)
        btn_row.addStretch()
        root.addLayout(btn_row)

        self.setCentralWidget(central)

    # ── Tab 1: Sources ────────────────────────────────────────────────

    def _build_tab_source(self):
        lay = QtWidgets.QVBoxLayout(self.tab_src)
        toolbar = QtWidgets.QHBoxLayout()
        b_refresh = QtWidgets.QPushButton("Refresh Devices")
        b_scan    = QtWidgets.QPushButton("Scan VMFS6 Candidates")
        b_refresh.clicked.connect(self._populate_devices)
        b_scan.clicked.connect(self._scan_vmfs_candidates)
        toolbar.addWidget(b_refresh)
        toolbar.addWidget(b_scan)
        toolbar.addStretch()
        lay.addLayout(toolbar)

        self.device_table = QtWidgets.QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(
            ["Device", "Size", "Type", "FS Type", "Mountpoint", "Hint"])
        self.device_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SingleSelection)
        self.device_table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.device_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(
            self._device_context_menu)
        self.device_table.doubleClicked.connect(self._on_device_double_click)
        lay.addWidget(self.device_table)

        grp  = QtWidgets.QGroupBox("Use raw image / VMDK file as source")
        glay = QtWidgets.QHBoxLayout(grp)
        self.image_path_edit = QtWidgets.QLineEdit()
        self.image_path_edit.setPlaceholderText(
            "/path/to/disk.dd  or  /path/to/disk.vmdk")
        b_img = QtWidgets.QPushButton("Browse")
        b_img.clicked.connect(self._browse_image_file)
        glay.addWidget(QtWidgets.QLabel("Image file:"))
        glay.addWidget(self.image_path_edit)
        glay.addWidget(b_img)
        lay.addWidget(grp)

    # ── Tab 2: Mount ──────────────────────────────────────────────────

    def _build_tab_mount(self):
        lay = QtWidgets.QVBoxLayout(self.tab_mount)

        src_grp  = QtWidgets.QGroupBox("Mount Source")
        src_form = QtWidgets.QFormLayout(src_grp)
        self.mount_source_cb = QtWidgets.QComboBox()
        self.mount_source_cb.addItems(
            ["Selected device (from table)", "Image file"])
        self.mount_dev_override = QtWidgets.QLineEdit()
        self.mount_dev_override.setPlaceholderText(
            "Leave empty to use table selection  or  /dev/sdc1")
        src_form.addRow("Source type:", self.mount_source_cb)
        src_form.addRow("Device path override:", self.mount_dev_override)
        lay.addWidget(src_grp)

        opt_grp  = QtWidgets.QGroupBox("Mount Options")
        opt_form = QtWidgets.QFormLayout(opt_grp)
        self.mount_point_edit = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_mp = QtWidgets.QPushButton("Browse")
        b_mp.clicked.connect(self._browse_mount_point)
        mp_row = QtWidgets.QHBoxLayout()
        mp_row.addWidget(self.mount_point_edit)
        mp_row.addWidget(b_mp)
        self.mount_opts_edit = QtWidgets.QLineEdit()
        self.mount_opts_edit.setPlaceholderText("Extra fuse flags (optional)")
        self.mount_sudo_chk = QtWidgets.QCheckBox(
            "Use sudo  (required if not root)")
        self.mount_sudo_chk.setChecked(True)
        self.allow_other_chk = QtWidgets.QCheckBox(
            "Add -o allow_other  (fixes permission denied)")
        self.allow_other_chk.setChecked(True)
        self.nonempty_chk = QtWidgets.QCheckBox(
            "Add -o nonempty  (fixes mountpoint is not empty)")
        self.nonempty_chk.setChecked(True)
        opt_form.addRow("Mount point:", mp_row)
        opt_form.addRow("Extra flags:", self.mount_opts_edit)
        opt_form.addRow("", self.mount_sudo_chk)
        opt_form.addRow("", self.allow_other_chk)
        opt_form.addRow("", self.nonempty_chk)
        lay.addWidget(opt_grp)

        fuse_note = QtWidgets.QLabel(
            "If allow_other fails, run once:\n"
            "   echo 'user_allow_other' | sudo tee -a /etc/fuse.conf")
        fuse_note.setStyleSheet(
            "color:#aaddff;background:#1a2a3a;padding:6px;border-radius:4px;")
        lay.addWidget(fuse_note)

        btn_row = QtWidgets.QHBoxLayout()
        b_mount  = QtWidgets.QPushButton("Mount VMFS6")
        b_umount = QtWidgets.QPushButton("Unmount")
        b_mount.setStyleSheet(
            "background:#1a7a1a;color:white;font-weight:bold;padding:6px;")
        b_umount.setStyleSheet(
            "background:#7a1a1a;color:white;font-weight:bold;padding:6px;")
        b_mount.clicked.connect(self._mount_vmfs6)
        b_umount.clicked.connect(self._umount_vmfs)
        btn_row.addWidget(b_mount)
        btn_row.addWidget(b_umount)
        lay.addLayout(btn_row)
        lay.addStretch()

    # ── Tab 3: DD Imaging ─────────────────────────────────────────────

    def _build_tab_dd(self):
        lay = QtWidgets.QVBoxLayout(self.tab_dd)
        src_grp  = QtWidgets.QGroupBox("Source")
        src_form = QtWidgets.QFormLayout(src_grp)
        self.dd_source_cb = QtWidgets.QComboBox()
        self.dd_source_cb.addItems(
            ["Selected device (from table)", "Image file"])
        self.dd_dev_override = QtWidgets.QLineEdit()
        self.dd_dev_override.setPlaceholderText(
            "Leave empty or type e.g.  /dev/sdc1")
        src_form.addRow("Source:", self.dd_source_cb)
        src_form.addRow("Device override:", self.dd_dev_override)
        lay.addWidget(src_grp)

        out_grp  = QtWidgets.QGroupBox("Destination")
        out_form = QtWidgets.QFormLayout(out_grp)
        self.dd_output_edit = QtWidgets.QLineEdit()
        self.dd_output_edit.setPlaceholderText(
            "/home/user/vmfs6.dd  or  /mnt/c/forensics/vmfs6.dd")
        b_out = QtWidgets.QPushButton("Browse")
        b_out.clicked.connect(self._browse_dd_output)
        out_row = QtWidgets.QHBoxLayout()
        out_row.addWidget(self.dd_output_edit)
        out_row.addWidget(b_out)
        out_form.addRow("Output file:", out_row)
        lay.addWidget(out_grp)

        speed_grp  = QtWidgets.QGroupBox(
            "Performance Options  (O_DIRECT = constant high speed)")
        speed_form = QtWidgets.QFormLayout(speed_grp)
        self.dd_bs_combo = QtWidgets.QComboBox()
        self.dd_bs_combo.addItems(["1M", "4M", "8M", "16M", "64M", "128M"])
        self.dd_bs_combo.setCurrentText("4M")
        self.dd_direct_in_chk = QtWidgets.QCheckBox(
            "iflag=direct  (bypass read cache)")
        self.dd_direct_in_chk.setChecked(True)
        self.dd_direct_out_chk = QtWidgets.QCheckBox(
            "oflag=direct  (bypass write cache)")
        self.dd_direct_out_chk.setChecked(True)
        self.dd_noerror_chk = QtWidgets.QCheckBox(
            "conv=noerror,sync  (continue on bad sectors)")
        self.dd_noerror_chk.setChecked(True)
        self.dd_sudo_chk = QtWidgets.QCheckBox("Use sudo")
        self.dd_sudo_chk.setChecked(True)
        speed_form.addRow("Block size:", self.dd_bs_combo)
        speed_form.addRow("", self.dd_direct_in_chk)
        speed_form.addRow("", self.dd_direct_out_chk)
        speed_form.addRow("", self.dd_noerror_chk)
        speed_form.addRow("", self.dd_sudo_chk)
        lay.addWidget(speed_grp)

        b_dd = QtWidgets.QPushButton("Start High-Speed Imaging")
        b_dd.setStyleSheet(
            "background:#1a4a8a;color:white;"
            "font-weight:bold;padding:10px;font-size:14px;")
        b_dd.clicked.connect(self._start_dd)
        lay.addWidget(b_dd)
        lay.addStretch()

    # ── Tab 4: VMFS Browser ───────────────────────────────────────────

    def _build_tab_browse(self):
        lay = QtWidgets.QVBoxLayout(self.tab_browse)

        top = QtWidgets.QHBoxLayout()
        self.browse_root_edit = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_set  = QtWidgets.QPushButton("Browse")
        b_load = QtWidgets.QPushButton("Load Tree")
        b_set.clicked.connect(self._browse_vmfs_root)
        b_load.clicked.connect(self._load_vmfs_tree)
        top.addWidget(QtWidgets.QLabel("VMFS mount root:"))
        top.addWidget(self.browse_root_edit)
        top.addWidget(b_set)
        top.addWidget(b_load)
        lay.addLayout(top)

        self.file_tree = QtWidgets.QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Type", "Full Path"])
        self.file_tree.header().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch)
        self.file_tree.setColumnWidth(1, 90)
        self.file_tree.setColumnWidth(2, 60)
        self.file_tree.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection)
        self.file_tree.itemExpanded.connect(self._on_tree_expand)
        self.file_tree.itemDoubleClicked.connect(self._on_tree_double_click)
        self.file_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(
            self._tree_context_menu)
        lay.addWidget(self.file_tree)

        act_row = QtWidgets.QHBoxLayout()

        b_export_sel = QtWidgets.QPushButton(
            "⬇  Export Selected  (files & folders)")
        b_export_sel.setStyleSheet(
            "background:#1a5a1a;color:white;font-weight:bold;padding:7px;")
        b_export_sel.clicked.connect(self._export_selected)

        b_tree_report = QtWidgets.QPushButton("📄  Save Tree Report  (.txt)")
        b_tree_report.setStyleSheet(
            "background:#3a3a1a;color:white;font-weight:bold;padding:7px;")
        b_tree_report.clicked.connect(self._save_tree_report)

        b_hex = QtWidgets.QPushButton("🔬  Open in Hex Viewer")
        b_hex.setStyleSheet(
            "background:#1a1a5a;color:white;font-weight:bold;padding:7px;")
        b_hex.clicked.connect(self._open_hex_viewer)

        b_sel_all = QtWidgets.QPushButton("Select All")
        b_sel_all.setStyleSheet("padding:7px;")
        b_sel_all.clicked.connect(self.file_tree.selectAll)

        act_row.addWidget(b_export_sel)
        act_row.addWidget(b_tree_report)
        act_row.addWidget(b_hex)
        act_row.addWidget(b_sel_all)
        act_row.addStretch()
        lay.addLayout(act_row)

        self.browse_status = QtWidgets.QLabel(
            "Ctrl+Click = multi-select  |  "
            "Double-click file = Hex Viewer  |  "
            "Right-click = context menu")
        self.browse_status.setStyleSheet("color:#888;font-size:11px;")
        lay.addWidget(self.browse_status)

        self.file_tree.itemSelectionChanged.connect(
            self._on_selection_changed)

    # ── Tab 5: WSL Helper ─────────────────────────────────────────────

    def _build_tab_wsl(self):
        lay = QtWidgets.QVBoxLayout(self.tab_wsl)
        info = QtWidgets.QLabel(
            "Generate PowerShell commands to pass a physical disk into WSL2.\n"
            "Run these in an elevated PowerShell on the Windows host.\n\n"
            "Workflow:\n"
            "  1. Elevated PowerShell -> Get-Disk  (find PHYSICALDRIVE N)\n"
            "  2. Run the generated wsl --mount command\n"
            "  3. Refresh Sources -> disk appears as /dev/sdX\n"
            "  4. Double-click disk to auto-mount.")
        info.setWordWrap(True)
        lay.addWidget(info)

        form = QtWidgets.QFormLayout()
        self.wsl_disk_edit = QtWidgets.QLineEdit()
        self.wsl_disk_edit.setPlaceholderText("e.g.  2")
        self.wsl_part_edit = QtWidgets.QLineEdit()
        self.wsl_part_edit.setPlaceholderText(
            "e.g.  1  (leave empty for whole disk)")
        form.addRow("PHYSICALDRIVE number (N):", self.wsl_disk_edit)
        form.addRow("Partition number:", self.wsl_part_edit)
        lay.addLayout(form)

        btn_row = QtWidgets.QHBoxLayout()
        b_gen  = QtWidgets.QPushButton("Generate commands")
        b_copy = QtWidgets.QPushButton("Copy to clipboard")
        b_gen.clicked.connect(self._gen_wsl_cmds)
        b_copy.clicked.connect(self._copy_wsl_cmds)
        btn_row.addWidget(b_gen)
        btn_row.addWidget(b_copy)
        lay.addLayout(btn_row)

        self.wsl_out_edit = QtWidgets.QPlainTextEdit()
        self.wsl_out_edit.setReadOnly(True)
        lay.addWidget(self.wsl_out_edit)

    # ═══════════════════════ DEVICE DETECTION ════════════════════════

    def _populate_devices(self):
        self.device_table.setRowCount(0)
        if self.IS_WIN:
            self._populate_windows()
        else:
            self._populate_linux()

    def _populate_linux(self):
        try:
            raw = subprocess.check_output(
                ["lsblk", "-rno", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"],
                text=True, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            self._log("lsblk not found – using /sys/block fallback.")
            self._populate_sysblock()
            return
        except subprocess.CalledProcessError as e:
            self._log(f"lsblk error: {e}")
            return

        for line in raw.strip().splitlines():
            cols  = line.split()
            if not cols:
                continue
            name  = cols[0]
            size  = cols[1] if len(cols) > 1 else "?"
            dtype = cols[2] if len(cols) > 2 else "?"
            fst   = cols[3] if len(cols) > 3 else ""
            mnt   = cols[4] if len(cols) > 4 else ""
            if dtype in ("loop", "rom", "ram"):
                continue
            hint = ""
            fg   = None
            if "vmfs" in fst.lower():
                hint = "VMFS detected"
                fg   = QtGui.QColor("#44ff88")
            elif fst == "" and dtype in ("disk", "part"):
                hint = "Unknown FS – possible VMFS"
                fg   = QtGui.QColor("#ffcc44")
            self._add_device_row(
                f"/dev/{name}", size, dtype, fst, mnt, hint, fg)
        self._log(
            f"Scan done – {self.device_table.rowCount()} device(s) listed.")

    def _populate_sysblock(self):
        try:
            devs = sorted(os.listdir("/sys/block"))
        except Exception as e:
            self._log(f"/sys/block error: {e}")
            return
        for name in devs:
            if name.startswith(("loop", "ram", "sr")):
                continue
            size = self._sysblock_size(name)
            self._add_device_row(
                f"/dev/{name}", size, "disk", "", "",
                "possible VMFS", QtGui.QColor("#ffcc44"))
            try:
                for entry in sorted(os.listdir(f"/sys/block/{name}")):
                    if entry.startswith(name):
                        ps = self._sysblock_size(name, entry)
                        self._add_device_row(
                            f"/dev/{entry}", ps, "part", "", "",
                            "possible VMFS", QtGui.QColor("#ffcc44"))
            except Exception:
                pass

    @staticmethod
    def _sysblock_size(disk, part=None):
        try:
            p = (f"/sys/block/{disk}/{part}/size"
                 if part else f"/sys/block/{disk}/size")
            with open(p) as f:
                return f"{int(f.read().strip()) * 512 / 1024**3:.1f}G"
        except Exception:
            return "?"

    def _populate_windows(self):
        seen = set()
        for part in psutil.disk_partitions(all=True):
            if part.device in seen:
                continue
            seen.add(part.device)
            try:
                sz = f"{psutil.disk_usage(part.mountpoint).total/1024**3:.1f}G"
            except Exception:
                sz = "?"
            self._add_device_row(
                part.device, sz, "Volume", part.fstype, part.mountpoint, "")
        for i in range(8):
            self._add_device_row(
                f"\\\\.\\PhysicalDrive{i}", "?", "Physical", "", "", "Raw device")
        self._log("Windows device scan complete.")

    def _add_device_row(self, path, size, dtype, fstype, mnt, hint, fg=None):
        r = self.device_table.rowCount()
        self.device_table.insertRow(r)
        for c, txt in enumerate([path, size, dtype, fstype, mnt, hint]):
            item = QtWidgets.QTableWidgetItem(str(txt))
            if fg:
                item.setForeground(fg)
            self.device_table.setItem(r, c, item)

    def _scan_vmfs_candidates(self):
        hits = 0
        for row in range(self.device_table.rowCount()):
            fs  = self.device_table.item(row, 3)
            mnt = self.device_table.item(row, 4)
            hnt = self.device_table.item(row, 5)
            tp  = self.device_table.item(row, 2)
            if not (fs and hnt and tp):
                continue
            if (fs.text().strip() == ""
                    and tp.text().strip() in ("disk", "part", "Physical")
                    and (not mnt or mnt.text().strip() in ("", "-"))):
                hnt.setText("Possible VMFS6 candidate")
                for c in range(self.device_table.columnCount()):
                    it = self.device_table.item(row, c)
                    if it:
                        it.setForeground(QtGui.QColor("#ffcc44"))
                hits += 1
        self._log(f"Scan complete – {hits} VMFS6 candidate(s) highlighted.")

    # ═════════════════ CONTEXT MENUS & EVENTS ════════════════════════

    def _device_context_menu(self, pos):
        row = self.device_table.rowAt(pos.y())
        if row < 0:
            return
        self.device_table.selectRow(row)
        dev  = self.device_table.item(row, 0).text()
        menu = QtWidgets.QMenu(self)
        a_mount = menu.addAction("Mount VMFS6  (vmfs6-fuse)")
        a_dd    = menu.addAction("Create dd image  (high speed)")
        a_copy  = menu.addAction("Copy device path")
        menu.addSeparator()
        a_fill  = menu.addAction("Fill mount device field")
        action  = menu.exec_(self.device_table.viewport().mapToGlobal(pos))
        if action == a_mount:
            self._quick_mount(dev)
        elif action == a_dd:
            self.dd_dev_override.setText(dev)
            self.tabs.setCurrentIndex(2)
        elif action == a_copy:
            QtWidgets.QApplication.clipboard().setText(dev)
            self._log(f"Copied: {dev}")
        elif action == a_fill:
            self.mount_dev_override.setText(dev)
            self.tabs.setCurrentIndex(1)

    def _on_device_double_click(self, index):
        row = index.row()
        if row >= 0:
            self._quick_mount(self.device_table.item(row, 0).text())

    def _quick_mount(self, device: str):
        self.mount_dev_override.setText(device)
        self.mount_source_cb.setCurrentIndex(0)
        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"
        self.mount_point_edit.setText(mp)
        self.tabs.setCurrentIndex(1)
        self._log(f"Quick-mount: {device} -> {mp}")
        self._mount_vmfs6()

    # ═══════════════════ SOURCE RESOLVER ═════════════════════════════

    def _resolve_source(self, cb, override_edit):
        ov = override_edit.text().strip() if override_edit else ""
        if ov:
            return ov
        if "device" in cb.currentText().lower():
            dev = self._get_selected_device()
            if not dev:
                raise RuntimeError(
                    "No device selected.\n"
                    "Click a row in Sources tab or use the override field.")
            return dev
        img = self.image_path_edit.text().strip()
        if not img:
            raise RuntimeError("No image file specified in the Sources tab.")
        if not os.path.exists(img):
            raise RuntimeError(f"Image file not found:\n{img}")
        return img

    def _get_selected_device(self):
        row = self.device_table.currentRow()
        if row < 0:
            return ""
        item = self.device_table.item(row, 0)
        return item.text().strip() if item else ""

    # ═══════════════════ MOUNT POINT HELPER ══════════════════════════

    def _ensure_mount_point(self, mp: str) -> bool:
        if os.path.isdir(mp):
            self._log(f"Mount point exists: {mp}")
            return True
        if os.path.exists(mp):
            QtWidgets.QMessageBox.critical(
                self, "Mount point error",
                f"'{mp}' exists but is NOT a directory.\n"
                f"Delete it:  sudo rm '{mp}'")
            return False
        try:
            os.makedirs(mp)
            self._log(f"Created: {mp}")
            return True
        except PermissionError:
            self._log(f"Need sudo to create {mp} ...")
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self, "Mount point error", f"Cannot create '{mp}':\n{e}")
            return False
        try:
            r = subprocess.run(
                ["sudo", "mkdir", "-p", mp], capture_output=True, text=True)
            if r.returncode != 0:
                QtWidgets.QMessageBox.critical(
                    self, "Mount point error",
                    f"sudo mkdir failed:\n{r.stderr}")
                return False
            subprocess.run(["sudo", "chmod", "755", mp], capture_output=True)
            self._log(f"Created with sudo: {mp}")
            return True
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self, "Mount point error", f"sudo mkdir failed: {e}")
            return False

    @staticmethod
    def _is_mounted(mp: str) -> bool:
        try:
            r = subprocess.run(["mountpoint", "-q", mp], capture_output=True)
            return r.returncode == 0
        except FileNotFoundError:
            try:
                with open("/proc/mounts") as f:
                    return any(mp in line for line in f)
            except Exception:
                return False

    # ═══════════════════════ MOUNT / UNMOUNT ═════════════════════════

    def _mount_vmfs6(self):
        if self.IS_WIN:
            QtWidgets.QMessageBox.warning(
                self, "Not supported", "vmfs6-fuse requires Linux or WSL.")
            return
        try:
            source = self._resolve_source(
                self.mount_source_cb, self.mount_dev_override)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source error", str(exc))
            return

        mp          = self.mount_point_edit.text().strip() or "/mnt/vmfs6"
        extra       = self.mount_opts_edit.text().strip()
        use_sudo    = self.mount_sudo_chk.isChecked()
        allow_other = self.allow_other_chk.isChecked()
        nonempty    = self.nonempty_chk.isChecked()

        if not self._ensure_mount_point(mp):
            return
        if self._is_mounted(mp):
            ans = QtWidgets.QMessageBox.question(
                self, "Already mounted",
                f"'{mp}' is already mounted.\nUnmount and remount?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if ans == QtWidgets.QMessageBox.Yes:
                self._do_umount_sync(mp)
            else:
                return

        def task(worker: WorkerThread):
            cmd = (["sudo"] if use_sudo else []) + ["vmfs6-fuse"]
            fuse_opts = []
            if allow_other:
                fuse_opts.append("allow_other")
            if nonempty:
                fuse_opts.append("nonempty")
            if extra:
                parts = extra.split()
                i = 0
                while i < len(parts):
                    if parts[i] == "-o" and i + 1 < len(parts):
                        fuse_opts.append(parts[i + 1])
                        i += 2
                    else:
                        cmd.append(parts[i])
                        i += 1
            if fuse_opts:
                cmd += ["-o", ",".join(fuse_opts)]
            cmd += [source, mp]
            worker.log_message.emit("CMD: " + " ".join(cmd))

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True)
            except FileNotFoundError:
                raise RuntimeError(
                    "vmfs6-fuse not found.\n"
                    "Install:  sudo apt install vmfs6-tools")

            output_lines = []
            for line in iter(proc.stdout.readline, ""):
                if worker.stopped:
                    proc.terminate()
                    return
                line = line.rstrip()
                if line:
                    worker.log_message.emit(line)
                    output_lines.append(line)
            proc.wait()
            if proc.returncode not in (0, None):
                raise RuntimeError(
                    f"vmfs6-fuse exited with code {proc.returncode}\n\n"
                    "Output:\n" + "\n".join(output_lines) + "\n\n"
                    "Fixes:\n"
                    "  1. Use /dev/sdc1 not /dev/sdc\n"
                    "  2. sudo dmesg | tail -20\n"
                    "  3. echo 'user_allow_other' | sudo tee -a /etc/fuse.conf")
            worker.progress_changed.emit(100)
            worker.log_message.emit(
                f"SUCCESS – Mounted at {mp}\n"
                "-> Go to VMFS Browser tab and click Load Tree.")
            QtCore.QMetaObject.invokeMethod(
                self.browse_root_edit, "setText",
                QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, mp))

        self._run_worker(task)

    def _do_umount_sync(self, mp: str):
        self._log(f"Unmounting {mp} ...")
        for cmd in [["fusermount", "-u", mp], ["sudo", "umount", mp]]:
            if subprocess.run(cmd, capture_output=True).returncode == 0:
                self._log("Unmounted.")
                return
        self._log("Warning: unmount failed. Proceeding anyway.")

    def _umount_vmfs(self):
        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"

        def task(worker: WorkerThread):
            worker.log_message.emit(f"Unmounting {mp} ...")
            r = subprocess.run(
                ["fusermount", "-u", mp], capture_output=True, text=True)
            if r.returncode != 0:
                worker.log_message.emit("Trying sudo umount ...")
                r2 = subprocess.run(
                    ["sudo", "umount", mp], capture_output=True, text=True)
                if r2.returncode != 0:
                    raise RuntimeError(f"umount failed:\n{r2.stderr}")
            worker.progress_changed.emit(100)
            worker.log_message.emit(f"Unmounted: {mp}")

        self._run_worker(task)

    # ═══════════════════ DD IMAGING – HIGH SPEED ═════════════════════

    def _start_dd(self):
        try:
            source = self._resolve_source(self.dd_source_cb, self.dd_dev_override)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source error", str(exc))
            return
        out_path = self.dd_output_edit.text().strip()
        if not out_path:
            QtWidgets.QMessageBox.warning(
                self, "No output", "Please specify an output file path.")
            return
        bs             = self.dd_bs_combo.currentText()
        use_direct_in  = self.dd_direct_in_chk.isChecked()
        use_direct_out = self.dd_direct_out_chk.isChecked()
        use_noerror    = self.dd_noerror_chk.isChecked()
        use_sudo       = self.dd_sudo_chk.isChecked()

        if QtWidgets.QMessageBox.question(
            self, "Confirm",
            f"Source:\n  {source}\n\nDestination:\n  {out_path}\n\nContinue?"
        ) != QtWidgets.QMessageBox.Yes:
            return

        def task(worker: WorkerThread):
            cmd = (["sudo"] if use_sudo else []) + [
                "dd", f"if={source}", f"of={out_path}",
                f"bs={bs}", "status=progress"]
            iflags, oflags, conv = [], [], []
            if use_direct_in:
                iflags.append("direct")
            if use_direct_out:
                oflags.append("direct")
            if use_noerror:
                conv += ["noerror", "sync"]
            if iflags:
                cmd.append("iflag=" + ",".join(iflags))
            if oflags:
                cmd.append("oflag=" + ",".join(oflags))
            if conv:
                cmd.append("conv=" + ",".join(conv))

            worker.log_message.emit("CMD: " + " ".join(cmd))

            total_bytes = None
            try:
                r = subprocess.check_output(
                    ["sudo", "blockdev", "--getsize64", source], text=True)
                total_bytes = int(r.strip())
                worker.log_message.emit(
                    f"Disk size: {total_bytes/1024**3:.2f} GB")
            except Exception:
                pass

            out_dir = os.path.dirname(os.path.abspath(out_path))
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, text=True, bufsize=1)

            buf, last_speed, copied = "", "", 0
            while True:
                if worker.stopped:
                    proc.terminate()
                    break
                ch = proc.stderr.read(1)
                if not ch:
                    break
                if ch in ("\r", "\n"):
                    line = buf.strip()
                    buf  = ""
                    if not line:
                        continue
                    m_bytes = re.search(r"^(\d+)\s+bytes", line)
                    m_speed = re.search(r"([\d.,]+\s*[KMGT]?B/s)\s*$", line)
                    if m_bytes:
                        copied = int(m_bytes.group(1))
                        if total_bytes:
                            worker.progress_changed.emit(
                                min(int(copied * 100 / total_bytes), 99))
                    if m_speed:
                        spd = m_speed.group(1).strip()
                        if spd != last_speed:
                            last_speed = spd
                            QtCore.QMetaObject.invokeMethod(
                                self.speed_label, "setText",
                                QtCore.Qt.QueuedConnection,
                                QtCore.Q_ARG(str, f"Speed: {spd}"))
                            worker.log_message.emit(
                                f"  {copied/1024**3:.2f} GB  –  {spd}")
                else:
                    buf += ch

            proc.wait()
            if proc.returncode not in (0, None):
                raise RuntimeError(
                    f"dd exited with code {proc.returncode}\n"
                    "  - Uncheck iflag=direct if source is an image file\n"
                    "  - Check disk space / permissions")
            worker.progress_changed.emit(100)
            QtCore.QMetaObject.invokeMethod(
                self.speed_label, "setText",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, "Speed: done ✓"))
            worker.log_message.emit("Imaging completed.")

        self._run_worker(task)

    # ═══════════════════════ FILE TREE ═══════════════════════════════

    def _browse_vmfs_root(self):
        p = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select mounted VMFS6 directory")
        if p:
            self.browse_root_edit.setText(p)

    def _load_vmfs_tree(self):
        root = self.browse_root_edit.text().strip()
        if not root or not os.path.isdir(root):
            QtWidgets.QMessageBox.warning(
                self, "Invalid path",
                "Mount the VMFS6 disk first, then click Load Tree.")
            return
        self.file_tree.clear()
        self._log(f"Loading tree from {root}")
        root_item = QtWidgets.QTreeWidgetItem(
            [os.path.basename(root) or "/", "", "DIR", root])
        root_item.setIcon(
            0, self.style().standardIcon(QtWidgets.QStyle.SP_DriveHDIcon))
        self.file_tree.addTopLevelItem(root_item)
        self._fill_tree_level(root_item, root)
        root_item.setExpanded(True)
        self._log("Tree loaded. Expand folders for deeper levels.")

    def _fill_tree_level(self, parent, dir_path):
        try:
            entries = sorted(
                os.scandir(dir_path),
                key=lambda e: (not e.is_dir(follow_symlinks=False), e.name))
        except PermissionError:
            err = QtWidgets.QTreeWidgetItem(
                ["[Permission denied]", "", "", dir_path])
            err.setForeground(0, QtGui.QColor("#ff4444"))
            parent.addChild(err)
            self._log(f"Permission denied: {dir_path}")
            return
        except OSError as exc:
            self._log(f"Cannot read {dir_path}: {exc}")
            return

        for entry in entries:
            is_dir = entry.is_dir(follow_symlinks=False)
            ext    = os.path.splitext(entry.name)[1].upper() or "FILE"
            if is_dir:
                icon  = self.style().standardIcon(QtWidgets.QStyle.SP_DirIcon)
                child = QtWidgets.QTreeWidgetItem(
                    [entry.name, "", "DIR", entry.path])
                child.setIcon(0, icon)
                child.addChild(QtWidgets.QTreeWidgetItem(["...", "", "", ""]))
            else:
                try:
                    sz       = entry.stat(follow_symlinks=False).st_size
                    size_txt = self._fmt_size(sz)
                except Exception:
                    size_txt = "?"
                icon  = self.style().standardIcon(QtWidgets.QStyle.SP_FileIcon)
                child = QtWidgets.QTreeWidgetItem(
                    [entry.name, size_txt, ext, entry.path])
                child.setIcon(0, icon)
            parent.addChild(child)

    def _on_tree_expand(self, item):
        if item.childCount() == 1 and item.child(0).text(0) == "...":
            item.removeChild(item.child(0))
            self._fill_tree_level(item, item.text(3))

    def _on_tree_double_click(self, item, col):
        path = item.text(3)
        if path and os.path.isfile(path):
            self._open_hex_viewer_for(path)

    def _on_selection_changed(self):
        items = self.file_tree.selectedItems()
        n     = len(items)
        total = 0
        for it in items:
            p = it.text(3)
            if os.path.isfile(p):
                try:
                    total += os.path.getsize(p)
                except Exception:
                    pass
        self.browse_status.setText(
            f"{n} item(s) selected  |  "
            f"Estimated file size: {self._fmt_size(total)}  |  "
            "Ctrl+Click = multi-select  |  Double-click file = Hex Viewer")

    def _tree_context_menu(self, pos):
        items = self.file_tree.selectedItems()
        if not items:
            return
        menu   = QtWidgets.QMenu(self)
        a_exp  = menu.addAction("⬇  Export selected  (files & folders)")
        a_hex  = menu.addAction("🔬  Open in Hex Viewer")
        a_copy = menu.addAction("📋  Copy path(s) to clipboard")
        menu.addSeparator()
        a_rep  = menu.addAction("📄  Save Tree Report (.txt)")
        action = menu.exec_(self.file_tree.viewport().mapToGlobal(pos))
        if action == a_exp:
            self._export_selected()
        elif action == a_hex:
            self._open_hex_viewer()
        elif action == a_copy:
            paths = "\n".join(it.text(3) for it in items if it.text(3))
            QtWidgets.QApplication.clipboard().setText(paths)
            self._log(f"Copied {len(items)} path(s) to clipboard.")
        elif action == a_rep:
            self._save_tree_report()

    # ═══════════════════════ HEX VIEWER ══════════════════════════════

    def _open_hex_viewer(self):
        items = [it for it in self.file_tree.selectedItems()
                 if os.path.isfile(it.text(3))]
        if not items:
            QtWidgets.QMessageBox.information(
                self, "Hex Viewer",
                "Select one or more files in the tree.\n"
                "(Tip: double-click a file to open it directly.)")
            return
        for it in items[:3]:
            self._open_hex_viewer_for(it.text(3))

    def _open_hex_viewer_for(self, path: str):
        dlg = HexViewerDialog(path, parent=self)
        dlg.setModal(False)
        dlg.show()
        self._hex_viewers.append(dlg)

    # ═══════════════ EXPORT – FIXED (direct call, no invokeMethod) ═══

    def _export_selected(self):
        items = self.file_tree.selectedItems()
        paths = [it.text(3) for it in items
                 if it.text(3) and os.path.exists(it.text(3))]
        if not paths:
            QtWidgets.QMessageBox.warning(
                self, "Nothing selected",
                "Select at least one file or folder in the tree.")
            return

        dest_dir = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select destination folder for export")
        if not dest_dir:
            return

        # Build copy plan: list of (src_file, dst_file)
        copy_plan = []
        for src in paths:
            if os.path.isfile(src):
                copy_plan.append(
                    (src, os.path.join(dest_dir, os.path.basename(src))))
            elif os.path.isdir(src):
                base_parent = os.path.dirname(src)
                for dirpath, _, filenames in os.walk(src):
                    for fname in filenames:
                        sf = os.path.join(dirpath, fname)
                        df = os.path.join(
                            dest_dir,
                            os.path.relpath(sf, base_parent))
                        copy_plan.append((sf, df))

        if not copy_plan:
            QtWidgets.QMessageBox.information(
                self, "Empty", "No files found to export.")
            return

        # Total size
        total_bytes = 0
        for sf, _ in copy_plan:
            try:
                total_bytes += os.path.getsize(sf)
            except Exception:
                pass

        self._log(
            f"Export: {len(copy_plan)} file(s)  |  "
            f"Total: {self._fmt_size(total_bytes)}  ->  {dest_dir}")

        # Progress dialog (shown modally but GUI still processes events)
        dlg = ExportProgressDialog(
            f"Exporting {len(copy_plan)} file(s)…", parent=self)

        stop_flag = [False]
        dlg.cancel_requested.connect(lambda: stop_flag.__setitem__(0, True))
        dlg.show()

        chunk  = self.CHUNK
        copied = 0
        t0     = time.time()
        errors = []

        for sf, df in copy_plan:
            if stop_flag[0]:
                self._log("Export cancelled.")
                break

            try:
                os.makedirs(os.path.dirname(os.path.abspath(df)), exist_ok=True)
            except Exception as e:
                errors.append(f"mkdir: {df}: {e}")
                continue

            try:
                with open(sf, "rb") as fin, open(df, "wb") as fout:
                    while True:
                        if stop_flag[0]:
                            break
                        data = fin.read(chunk)
                        if not data:
                            break
                        fout.write(data)
                        copied += len(data)

                        # ─── FIXED: direct call (export runs on main thread) ───
                        pct     = min(int(copied * 100 / total_bytes), 99) \
                                  if total_bytes else 0
                        elapsed = time.time() - t0
                        speed   = (f"{copied/elapsed/1024**2:.1f} MB/s"
                                   if elapsed > 0.5 else "--")
                        copied_str = (
                            f"{self._fmt_size(copied)} / "
                            f"{self._fmt_size(total_bytes)}")

                        dlg.update_progress(
                            pct, os.path.basename(sf),
                            speed, copied_str)
                        QtWidgets.QApplication.processEvents()

            except Exception as e:
                errors.append(f"{sf}: {e}")
                self._log(f"  Error: {sf}: {e}")

        # Final update
        dlg.update_progress(100, "Done ✓", "", self._fmt_size(copied))
        QtWidgets.QApplication.processEvents()
        dlg.close()

        self.progress.setValue(100)
        elapsed = time.time() - t0
        self._log(
            f"Export complete – {self._fmt_size(copied)}  "
            f"in {elapsed:.1f} s  |  {len(errors)} error(s)")

        if errors:
            QtWidgets.QMessageBox.warning(
                self, "Export errors",
                f"{len(errors)} file(s) failed:\n\n"
                + "\n".join(errors[:10]))
        else:
            QtWidgets.QMessageBox.information(
                self, "Export complete ✓",
                f"Exported {self._fmt_size(copied)}\n"
                f"Files: {len(copy_plan)}\n"
                f"Destination: {dest_dir}\n"
                f"Time: {elapsed:.1f} s")

    # ═══════════════════════ TREE REPORT ═════════════════════════════

    def _save_tree_report(self):
        root = self.browse_root_edit.text().strip()
        if not root or not os.path.isdir(root):
            QtWidgets.QMessageBox.warning(
                self, "No tree", "Load the VMFS tree first.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save Tree Report", "vmfs6_tree_report.txt",
            "Text files (*.txt);;All (*)")
        if not path:
            return

        self._log(f"Generating tree report for {root} ...")

        total_files, total_dirs, total_size = [0], [0], [0]
        lines = [
            "VMFS6 Tree Report",
            "=" * 70,
            f"Root   : {root}",
            f"Date   : {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70, ""]

        def walk(dirpath, prefix=""):
            try:
                entries = sorted(
                    os.scandir(dirpath),
                    key=lambda e: (not e.is_dir(follow_symlinks=False), e.name))
            except PermissionError:
                lines.append(f"{prefix}[Permission denied]")
                return
            except OSError as exc:
                lines.append(f"{prefix}[Error: {exc}]")
                return

            for i, entry in enumerate(entries):
                is_last   = (i == len(entries) - 1)
                connector = "└── " if is_last else "├── "
                ext_pfx   = "    " if is_last else "│   "
                if entry.is_dir(follow_symlinks=False):
                    total_dirs[0] += 1
                    lines.append(f"{prefix}{connector}{entry.name}/")
                    walk(entry.path, prefix + ext_pfx)
                else:
                    total_files[0] += 1
                    try:
                        sz = entry.stat(follow_symlinks=False).st_size
                        total_size[0] += sz
                        sz_str = self._fmt_size(sz)
                    except Exception:
                        sz_str = "?"
                    lines.append(
                        f"{prefix}{connector}{entry.name}  [{sz_str}]")

        walk(root)
        lines += [
            "", "─" * 70,
            f"Total directories : {total_dirs[0]}",
            f"Total files       : {total_files[0]}",
            f"Total size        : {self._fmt_size(total_size[0])}"]

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            self._log(
                f"Tree report saved -> {path}  "
                f"({total_files[0]} files, {self._fmt_size(total_size[0])})")
            QtWidgets.QMessageBox.information(
                self, "Report saved ✓",
                f"Saved to:\n{path}\n\n"
                f"Directories: {total_dirs[0]}\n"
                f"Files: {total_files[0]}\n"
                f"Total size: {self._fmt_size(total_size[0])}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Save failed", str(e))

    # ═══════════════════ WSL HELPER ══════════════════════════════════

    def _gen_wsl_cmds(self):
        n = self.wsl_disk_edit.text().strip()
        p = self.wsl_part_edit.text().strip()
        if not n:
            QtWidgets.QMessageBox.warning(
                self, "Input required", "Enter the PHYSICALDRIVE number.")
            return
        lines = [
            "# Run in elevated PowerShell on Windows host", "",
            "# List all disks:",
            "Get-CimInstance -ClassName Win32_DiskDrive | "
            "Select-Object DeviceID, Model, Size",
            "",
            "# Take disk offline:",
            "diskpart",
            f"  select disk {n}",
            "  offline disk", "  exit", "",
        ]
        if p:
            lines += [
                f"# Attach partition {p} of PHYSICALDRIVE{n}:",
                f"wsl --mount \\\\.\\PHYSICALDRIVE{n} --partition {p} --bare",
            ]
        else:
            lines += [
                f"# Attach full disk PHYSICALDRIVE{n}:",
                f"wsl --mount \\\\.\\PHYSICALDRIVE{n} --bare",
            ]
        lines += ["", "# Refresh Sources tab in this tool."]
        self.wsl_out_edit.setPlainText("\n".join(lines))
        self._log("Commands generated.")

    def _copy_wsl_cmds(self):
        text = self.wsl_out_edit.toPlainText()
        if not text:
            return
        try:
            proc = subprocess.Popen(
                ["xclip", "-selection", "clipboard"],
                stdin=subprocess.PIPE, text=True)
            proc.communicate(text)
            self._log("Copied via xclip.")
        except Exception:
            QtWidgets.QApplication.clipboard().setText(text)
            self._log("Copied via Qt clipboard.")

    # ═══════════════════ WORKER MANAGEMENT ═══════════════════════════

    def _run_worker(self, target):
        if self.worker and self.worker.isRunning():
            QtWidgets.QMessageBox.warning(
                self, "Busy", "Another operation is already running.")
            return
        self.progress.setValue(0)
        self.speed_label.setText("Speed: --")
        self.worker = WorkerThread(target)
        self.worker.progress_changed.connect(self.progress.setValue)
        self.worker.log_message.connect(self._log)
        self.worker.finished_ok.connect(
            lambda: self._log("Operation completed successfully."))
        self.worker.finished_error.connect(self._on_error)
        self.worker.start()

    def _on_error(self, msg: str):
        self._log(f"ERROR: {msg}")
        QtWidgets.QMessageBox.critical(self, "Operation failed", msg)

    # ═══════════════════ HELPERS ══════════════════════════════════════

    def _log(self, text: str):
        ts = time.strftime("%H:%M:%S")
        self.log_edit.appendPlainText(f"[{ts}]  {text}")

    def _save_log(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save log", "vmfs6_log.txt", "Text (*.txt);;All (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_edit.toPlainText())
            self._log(f"Log saved -> {path}")

    def _browse_image_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select disk image", "",
            "Disk images (*.dd *.img *.raw *.vmdk *.bin);;All (*)")
        if path:
            self.image_path_edit.setText(path)

    def _browse_mount_point(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select mount point directory")
        if path:
            self.mount_point_edit.setText(path)

    def _browse_dd_output(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "DD output file", "vmfs6_disk.dd")
        if path:
            self.dd_output_edit.setText(path)

    @staticmethod
    def _fmt_size(n):
        for u in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"


# ═════════════════════════ Entry Point ═══════════════════════════════

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    pal = QtGui.QPalette()
    pal.setColor(QtGui.QPalette.Window,          QtGui.QColor(38, 38, 38))
    pal.setColor(QtGui.QPalette.WindowText,      QtCore.Qt.white)
    pal.setColor(QtGui.QPalette.Base,            QtGui.QColor(22, 22, 22))
    pal.setColor(QtGui.QPalette.AlternateBase,   QtGui.QColor(38, 38, 38))
    pal.setColor(QtGui.QPalette.Text,            QtCore.Qt.white)
    pal.setColor(QtGui.QPalette.Button,          QtGui.QColor(50, 50, 50))
    pal.setColor(QtGui.QPalette.ButtonText,      QtCore.Qt.white)
    pal.setColor(QtGui.QPalette.Highlight,       QtGui.QColor(0, 120, 215))
    pal.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
    pal.setColor(QtGui.QPalette.ToolTipBase,     QtGui.QColor(50, 50, 50))
    pal.setColor(QtGui.QPalette.ToolTipText,     QtCore.Qt.white)
    app.setPalette(pal)

    win = VMFSGui()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
