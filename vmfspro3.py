import os
import sys
import subprocess
import time
import re
import struct
import csv
import hashlib
import psutil
from PyQt5 import QtCore, QtGui, QtWidgets

# ═══════════════════════════ Workers & Threads ════════════════════════════

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


class ExportWorker(QtCore.QThread):
    """ محرك النسخ الجنائي المسرع متعدد الخيوط (16MB Buffer) """
    update_ui = QtCore.pyqtSignal(int, str, str, str, str, str, str)
    finished_export = QtCore.pyqtSignal(int, float)
    error_export = QtCore.pyqtSignal(str)

    def __init__(self, copy_plan, total_bytes):
        super().__init__()
        self.copy_plan = copy_plan
        self.total_bytes = total_bytes
        self._stop_flag = False
        self.CHUNK_SIZE = 16 * 1024 * 1024  

    def run(self):
        copied = 0
        t0 = time.time()
        for sf, df in self.copy_plan:
            if self._stop_flag: break
            try:
                os.makedirs(os.path.dirname(os.path.abspath(df)), exist_ok=True)
                md5, sha256 = hashlib.md5(), hashlib.sha256()
                with open(sf, "rb", buffering=0) as fin, open(df, "wb", buffering=0) as fout:
                    while True:
                        if self._stop_flag: break
                        data = fin.read(self.CHUNK_SIZE)
                        if not data: break
                        fout.write(data)
                        md5.update(data)
                        sha256.update(data)
                        copied += len(data)

                        elapsed = time.time() - t0
                        if elapsed > 0.5:
                            speed_bps = copied / elapsed
                            speed_str = f"{speed_bps / 1024**2:.1f} MB/s"
                            eta_sec = (self.total_bytes - copied) / speed_bps if speed_bps > 0 else 0
                            m, s = divmod(int(eta_sec), 60)
                            h, m = divmod(m, 60)
                            eta_str = f"{h:02d}:{m:02d}:{s:02d}"
                            pct = min(int(copied * 100 / self.total_bytes), 99) if self.total_bytes else 0
                            copied_str = f"{copied/1024**3:.2f} GB / {self.total_bytes/1024**3:.2f} GB"
                            
                            self.update_ui.emit(pct, os.path.basename(sf), speed_str, copied_str, eta_str, md5.hexdigest(), sha256.hexdigest())
            except Exception as e:
                self.error_export.emit(f"Error copying {sf}: {e}")
                continue
        self.finished_export.emit(copied, time.time() - t0)

    def stop(self):
        self._stop_flag = True


# ══════════════════════════ Modern Export Dialog ══════════════════════════

class ModernExportDialog(QtWidgets.QDialog):
    cancel_requested = QtCore.pyqtSignal()
    
    def __init__(self, title="Forensic Extraction", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(600, 320)
        self.setWindowFlags(QtCore.Qt.Dialog | QtCore.Qt.CustomizeWindowHint | QtCore.Qt.WindowTitleHint)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI', sans-serif; }
            QLabel { font-size: 13px; }
            QProgressBar { height: 25px; border-radius: 6px; background-color: #313244; text-align: center; color: white; font-weight: bold; }
            QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #89b4fa, stop:1 #a6e3a1); border-radius: 6px; }
            QPushButton { background-color: #f38ba8; color: #11111b; font-weight: bold; border-radius: 6px; padding: 8px; }
            QPushButton:hover { background-color: #eba0ac; }
            QGroupBox { border: 1px solid #45475a; border-radius: 4px; margin-top: 10px; } 
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #cba6f7; }
        """)

        lay = QtWidgets.QVBoxLayout(self)
        
        head_lbl = QtWidgets.QLabel("🚀 High-Speed Forensic Extraction")
        head_lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #89b4fa;")
        lay.addWidget(head_lbl)
        
        self.file_lbl = QtWidgets.QLabel("Preparing files...")
        self.file_lbl.setStyleSheet("color: #bac2de; font-style: italic;")
        lay.addWidget(self.file_lbl)

        self.bar = QtWidgets.QProgressBar()
        lay.addWidget(self.bar)

        grid = QtWidgets.QGridLayout()
        self.lbl_speed = QtWidgets.QLabel("Speed: 0.0 MB/s")
        self.lbl_speed.setStyleSheet("color: #a6e3a1; font-weight: bold;")
        self.lbl_eta = QtWidgets.QLabel("ETA: --:--:--")
        self.lbl_eta.setStyleSheet("color: #fab387; font-weight: bold;")
        self.lbl_copied = QtWidgets.QLabel("Copied: 0 GB / 0 GB")
        
        grid.addWidget(QtWidgets.QLabel("⚡ Current Speed:"), 0, 0)
        grid.addWidget(self.lbl_speed, 0, 1)
        grid.addWidget(QtWidgets.QLabel("⏳ Time Remaining:"), 0, 2)
        grid.addWidget(self.lbl_eta, 0, 3)
        grid.addWidget(QtWidgets.QLabel("📦 Transferred:"), 1, 0)
        grid.addWidget(self.lbl_copied, 1, 1, 1, 3)
        lay.addLayout(grid)

        hash_box = QtWidgets.QGroupBox("Live Integrity Hashes")
        hl = QtWidgets.QVBoxLayout(hash_box)
        self.lbl_md5 = QtWidgets.QLabel("MD5: Calculating...")
        self.lbl_md5.setStyleSheet("font-family: Courier New; color: #f9e2af;")
        self.lbl_sha = QtWidgets.QLabel("SHA256: Calculating...")
        self.lbl_sha.setStyleSheet("font-family: Courier New; color: #f9e2af;")
        hl.addWidget(self.lbl_md5)
        hl.addWidget(self.lbl_sha)
        lay.addWidget(hash_box)

        b_cancel = QtWidgets.QPushButton("🛑 Cancel Extraction")
        b_cancel.clicked.connect(self.cancel_requested.emit)
        lay.addWidget(b_cancel, alignment=QtCore.Qt.AlignCenter)

    @QtCore.pyqtSlot(int, str, str, str, str, str, str)
    def update_ui(self, pct, fname, speed, copied, eta, md5, sha):
        self.bar.setValue(pct)
        self.file_lbl.setText(f"Extracting: {fname[-50:]}")
        self.lbl_speed.setText(speed)
        self.lbl_copied.setText(copied)
        self.lbl_eta.setText(eta)
        self.lbl_md5.setText(f"MD5: {md5}")
        self.lbl_sha.setText(f"SHA256: {sha}")


# ══════════════════════════ HexViewerDialog ══════════════════════════

MAGIC_SIGNATURES = {
    b"\x4D\x5A": "Windows PE/EXE", b"\x7FELF": "ELF Binary (Linux)",
    b"\x89PNG\r\n\x1a\n": "PNG Image", b"\xFF\xD8\xFF": "JPEG Image",
    b"GIF87a": "GIF Image (87a)", b"GIF89a": "GIF Image (89a)",
    b"PK\x03\x04": "ZIP Archive / DOCX / XLSX", b"PK\x05\x06": "ZIP Archive (empty)",
    b"\x1F\x8B": "GZIP Compressed", b"BZh": "BZIP2 Compressed",
    b"\xFD7zXZ\x00": "XZ Compressed", b"Rar!\x1A\x07": "RAR Archive",
    b"\x7FVMDK": "VMDK Disk Image", b"KDMV": "VMDK Extent",
    b"COWD": "VMDK COW Disk", b"#extents": "VMDK Descriptor",
    b"VMFS": "VMFS Filesystem", b"%PDF": "PDF Document",
    b"\xD0\xCF\x11\xE0": "OLE2 (DOC/XLS/PPT)", b"\xFF\xFE": "UTF-16 LE Text",
    b"\xFE\xFF": "UTF-16 BE Text", b"\xEF\xBB\xBF": "UTF-8 BOM Text",
    b"SQLite format 3": "SQLite Database", b"\x00\x00\x00\x0CJXL ": "JPEG XL Image",
    b"RIFF": "RIFF (WAV/AVI)", b"\x00\x00\x00\x14ftyp": "MP4 Video",
    b"\x1A\x45\xDF\xA3": "Matroska/WebM Video", b"OggS": "OGG Media",
    b"fLaC": "FLAC Audio", b"ID3": "MP3 Audio (ID3)",
    b"\xFF\xFB": "MP3 Audio", b"CAFEBABE": "Java Class",
    b"\xCE\xFA\xED\xFE": "Mach-O 32-bit", b"\xCF\xFA\xED\xFE": "Mach-O 64-bit",
}

def detect_file_type(data: bytes) -> str:
    for magic, label in MAGIC_SIGNATURES.items():
        if data[:len(magic)] == magic: return label
    if len(data) > 0:
        printable = sum(1 for b in data[:512] if 32 <= b < 127 or b in (9, 10, 13))
        if printable / min(len(data), 512) > 0.85: return "Text / Script file"
    return "Unknown / Binary"

def extract_strings(data: bytes, min_len: int = 5) -> list:
    results, current, start = [], [], 0
    for i, b in enumerate(data):
        if 32 <= b < 127 or b == 9:
            if not current: start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len: results.append((start, "".join(current)))
            current = []
    if len(current) >= min_len: results.append((start, "".join(current)))
    return results

class HexViewerDialog(QtWidgets.QDialog):
    PAGE_SIZE = 65536
    ROW_BYTES = 16

    def __init__(self, filepath, parent=None):
        super().__init__(parent)
        self.filepath = filepath
        self.page = 0
        try: self.file_size = os.path.getsize(filepath)
        except Exception: self.file_size = 0
        self.setWindowTitle(f"Hex Viewer  –  {os.path.basename(filepath)}")
        self._build_ui()
        self.showMaximized()
        self._load_page()

    def _build_ui(self):
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)

        top = QtWidgets.QHBoxLayout()
        self.filetype_label = QtWidgets.QLabel("Detecting…")
        self.filetype_label.setStyleSheet("background:#1a3a1a;color:#44ff88;padding:4px 10px;border-radius:4px;font-weight:bold;font-size:13px;")
        self.info_label = QtWidgets.QLabel()
        self.info_label.setStyleSheet("color:#aaddff;font-size:12px;")
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Search:  hex bytes  (4D 5A)  or  ASCII text")
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

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        left_w  = QtWidgets.QWidget(); left_l  = QtWidgets.QVBoxLayout(left_w); left_l.setContentsMargins(0, 0, 0, 0)
        hex_header = QtWidgets.QLabel("  Offset      00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII")
        hex_header.setStyleSheet("background:#1a1a2a;color:#88aaff;font-family:Courier New,monospace;font-size:12px;padding:4px;")
        left_l.addWidget(hex_header)

        self.hex_edit = QtWidgets.QPlainTextEdit()
        self.hex_edit.setReadOnly(True)
        font = QtGui.QFont("Courier New", 11)
        font.setStyleHint(QtGui.QFont.Monospace)
        self.hex_edit.setFont(font)
        self.hex_edit.setStyleSheet("background:#0a0a0a;color:#e8e8e8;border:none;selection-background-color:#2a4a8a;")
        left_l.addWidget(self.hex_edit)

        right_w = QtWidgets.QWidget(); right_l = QtWidgets.QVBoxLayout(right_w); right_l.setContentsMargins(4, 0, 0, 0)
        right_tabs = QtWidgets.QTabWidget()

        self.strings_edit = QtWidgets.QPlainTextEdit()
        self.strings_edit.setReadOnly(True)
        self.strings_edit.setFont(QtGui.QFont("Courier New", 10))
        self.strings_edit.setStyleSheet("background:#0a0a12;color:#ccffcc;border:none;")
        right_tabs.addTab(self.strings_edit, "Strings")

        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QtGui.QFont("Courier New", 10))
        self.text_edit.setStyleSheet("background:#0a0a12;color:#ffffcc;border:none;")
        right_tabs.addTab(self.text_edit, "Decoded Text")

        self.info_edit = QtWidgets.QPlainTextEdit()
        self.info_edit.setReadOnly(True)
        self.info_edit.setFont(QtGui.QFont("Courier New", 10))
        self.info_edit.setStyleSheet("background:#0a0a12;color:#ccccff;border:none;")
        right_tabs.addTab(self.info_edit, "File Info")

        right_l.addWidget(right_tabs)
        splitter.addWidget(left_w)
        splitter.addWidget(right_w)
        splitter.setSizes([700, 340])
        lay.addWidget(splitter)

        nav = QtWidgets.QHBoxLayout()
        self.b_prev = QtWidgets.QPushButton("◀  Prev  64 KB"); self.b_next = QtWidgets.QPushButton("Next  64 KB  ▶")
        self.b_prev.setStyleSheet("padding:5px 16px;background:#222244;color:white;font-weight:bold;")
        self.b_next.setStyleSheet("padding:5px 16px;background:#222244;color:white;font-weight:bold;")

        self.page_label = QtWidgets.QLabel()
        self.page_label.setStyleSheet("color:#ffcc44;font-weight:bold;font-size:13px;padding:0 12px;")

        self.goto_edit = QtWidgets.QLineEdit()
        self.goto_edit.setPlaceholderText("Hex offset  e.g.  0x1A2B")
        self.goto_edit.setMaximumWidth(180)
        self.goto_edit.returnPressed.connect(self._goto_offset)
        b_goto = QtWidgets.QPushButton("Go to offset")
        b_goto.setStyleSheet("padding:5px 10px;")

        self.b_prev.clicked.connect(self._prev_page)
        self.b_next.clicked.connect(self._next_page)
        b_goto.clicked.connect(self._goto_offset)

        nav.addWidget(self.b_prev); nav.addWidget(self.page_label); nav.addWidget(self.b_next)
        nav.addStretch()
        nav.addWidget(QtWidgets.QLabel("Go to:")); nav.addWidget(self.goto_edit); nav.addWidget(b_goto)
        lay.addLayout(nav)

    def _load_page(self):
        offset = self.page * self.PAGE_SIZE
        try:
            with open(self.filepath, "rb") as f:
                f.seek(offset)
                data = f.read(self.PAGE_SIZE)
        except Exception as e:
            self.hex_edit.setPlainText(f"Error reading file:\n{e}")
            return

        lines = []
        for i in range(0, len(data), self.ROW_BYTES):
            chunk     = data[i:i + self.ROW_BYTES]
            row_off   = offset + i
            h1 = " ".join(f"{b:02X}" for b in chunk[:8])
            h2 = " ".join(f"{b:02X}" for b in chunk[8:])
            hex_str   = f"{h1:<23}  {h2:<23}"
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)
            lines.append(f"{row_off:010X}  {hex_str}  |{ascii_str}|")

        self.hex_edit.setPlainText("\n".join(lines))

        total_pages = max(1, (self.file_size + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.page_label.setText(f"Page {self.page + 1} / {total_pages}   |   Offset: 0x{offset:08X}")
        self.info_label.setText(f"{os.path.basename(self.filepath)}   |   Size: {self._fmt_size(self.file_size)}")
        self.b_prev.setEnabled(self.page > 0)
        self.b_next.setEnabled(offset + self.PAGE_SIZE < self.file_size)

        strings = extract_strings(data, min_len=5)
        if strings:
            str_lines = [f"0x{offset+s:08X}  {txt}" for s, txt in strings[:500]]
            self.strings_edit.setPlainText("\n".join(str_lines))
        else: self.strings_edit.setPlainText("(no printable strings found in this page)")

        decoded_parts = ["── UTF-8 Decoded ──────────────────────────────"]
        try: decoded_parts.append(data.decode("utf-8", errors="replace")[:4096])
        except Exception as e: decoded_parts.append(f"UTF-8 error: {e}")
        decoded_parts.append("\n── Latin-1 Decoded ────────────────────────────")
        try: decoded_parts.append(data.decode("latin-1", errors="replace")[:2048])
        except Exception as e: decoded_parts.append(f"Latin-1 error: {e}")
        self.text_edit.setPlainText("\n".join(decoded_parts))

        if self.page == 0:
            ftype = detect_file_type(data)
            self.filetype_label.setText(f"  ✦  {ftype}  ")
            info_lines = [
                f"File        : {self.filepath}",
                f"Size        : {self._fmt_size(self.file_size)} ({self.file_size:,} bytes)",
                f"Type        : {ftype}",
                f"Total pages : {total_pages}  (64 KB each)",
                "", "── First 32 bytes (hex) ─────────────────────────",
                " ".join(f"{b:02X}" for b in data[:32]),
                "", "── Magic bytes ──────────────────────────────────"
            ]
            for magic, label in MAGIC_SIGNATURES.items():
                if data[:len(magic)] == magic:
                    info_lines.append(f"  MATCH: {label}  (magic: {magic.hex().upper()[:16]})")
                    break
            else: info_lines.append("  No known magic signature matched.")

            if data:
                freq  = [0] * 256
                for b in data[:min(len(data), 65536)]: freq[b] += 1
                n = len(data[:65536])
                entropy = -sum((c/n) * (c/n).bit_length() for c in freq if c > 0) / 8 if n else 0
                info_lines += [
                    "", f"── Byte frequency & Entropy (first page) ────────",
                    f"  Calculated Entropy: {entropy:.4f} " + ("(High - Possibly Encrypted/Compressed!)" if entropy > 7.5 else ""),
                    f"  Null bytes  : {freq[0]:,}",
                    f"  Printable   : {sum(freq[i] for i in range(32, 127)):,}",
                    f"  High bytes  : {sum(freq[i] for i in range(128, 256)):,}",
                ]

            try:
                stat = os.stat(self.filepath)
                info_lines += [
                    "", "── File Metadata ────────────────────────────────",
                    f"  Modified : {time.ctime(stat.st_mtime)}",
                    f"  Accessed : {time.ctime(stat.st_atime)}",
                    f"  Inode    : {stat.st_ino}",
                    f"  Mode     : {oct(stat.st_mode)}",
                ]
            except Exception: pass
            self.info_edit.setPlainText("\n".join(info_lines))

    def _prev_page(self):
        if self.page > 0: self.page -= 1; self._load_page()

    def _next_page(self):
        if (self.page + 1) * self.PAGE_SIZE < self.file_size: self.page += 1; self._load_page()

    def _goto_offset(self):
        txt = self.goto_edit.text().strip().replace("0x", "").replace("0X", "")
        try:
            offset    = int(txt, 16)
            self.page = offset // self.PAGE_SIZE
            self._load_page()
        except ValueError: pass

    def _search(self):
        query = self.search_edit.text().strip()
        if not query: return
        try: pattern = bytes.fromhex(query.replace(" ", ""))
        except ValueError: pattern = query.encode("utf-8", errors="replace")

        try:
            search_mb = 50 * 1024 * 1024 
            with open(self.filepath, "rb") as f:
                for start in [self.page * self.PAGE_SIZE, 0]:
                    f.seek(start)
                    buf = f.read(search_mb)
                    idx = buf.find(pattern)
                    if idx != -1:
                        found     = start + idx
                        self.page = found // self.PAGE_SIZE
                        self._load_page()
                        QtWidgets.QMessageBox.information(self, "Found", f"Pattern found at offset: 0x{found:X} ({found:,} bytes)")
                        return
            QtWidgets.QMessageBox.information(self, "Not found", "Pattern not found in first 50 MB.")
        except Exception as e: QtWidgets.QMessageBox.warning(self, "Search error", str(e))

    @staticmethod
    def _fmt_size(n):
        for u in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"


# ══════════════════════════════ Main GUI ══════════════════════════════

class VMFSGui(QtWidgets.QMainWindow):
    IS_WIN = (os.name == "nt")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VMFS6 Advanced Forensic Framework Ultra")
        self.resize(1350, 850)
        self.worker = None
        self._export_worker = None
        self._export_dlg = None
        self._hex_viewers = []
        self._build_ui()
        self._populate_devices()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        root = QtWidgets.QVBoxLayout(central)
        self.tabs = QtWidgets.QTabWidget()
        root.addWidget(self.tabs)

        self.tab_src = QtWidgets.QWidget(); self.tab_mount = QtWidgets.QWidget(); self.tab_dd = QtWidgets.QWidget()
        self.tab_browse = QtWidgets.QWidget(); self.tab_wsl = QtWidgets.QWidget()
        self.tab_forensics = QtWidgets.QWidget(); self.tab_intel = QtWidgets.QWidget()

        self._build_tab_source(); self._build_tab_mount(); self._build_tab_dd()
        self._build_tab_browse(); self._build_tab_wsl(); self._build_tab_forensics(); self._build_tab_intel()

        self.tabs.addTab(self.tab_src, "Sources")
        self.tabs.addTab(self.tab_mount, "Mount VMFS")
        self.tabs.addTab(self.tab_dd, "Forensic Imaging")
        self.tabs.addTab(self.tab_browse, "VMFS Browser")
        self.tabs.addTab(self.tab_wsl, "WSL Helper")
        self.tabs.addTab(self.tab_forensics, "Adv. Forensics (Carve/YARA)")
        self.tabs.addTab(self.tab_intel, "⚡ VMFS Intelligence")

        root.addWidget(QtWidgets.QLabel("Forensic Log:"))
        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(130)
        root.addWidget(self.log_edit)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        root.addWidget(self.progress)

        self.speed_label = QtWidgets.QLabel("Status: Idle")
        self.speed_label.setStyleSheet("color:#a6e3a1;font-size:13px;font-weight:bold;")
        root.addWidget(self.speed_label)

        btn_row = QtWidgets.QHBoxLayout()
        b_clear = QtWidgets.QPushButton("Clear log"); b_clear.clicked.connect(self.log_edit.clear)
        b_save  = QtWidgets.QPushButton("Save log"); b_save.clicked.connect(self._save_log)
        btn_row.addWidget(b_clear); btn_row.addWidget(b_save); btn_row.addStretch()
        root.addLayout(btn_row)

        self.setCentralWidget(central)

    # ── TAB 1: Sources ──
    def _build_tab_source(self):
        lay = QtWidgets.QVBoxLayout(self.tab_src)
        toolbar = QtWidgets.QHBoxLayout()
        b_refresh = QtWidgets.QPushButton("Refresh Devices"); b_refresh.clicked.connect(self._populate_devices)
        b_scan    = QtWidgets.QPushButton("Scan VMFS6 Candidates"); b_scan.clicked.connect(self._scan_vmfs_candidates)
        toolbar.addWidget(b_refresh); toolbar.addWidget(b_scan); toolbar.addStretch()
        lay.addLayout(toolbar)

        self.device_table = QtWidgets.QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(["Device", "Size", "Type", "FS Type", "Mountpoint", "Hint"])
        self.device_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.device_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.device_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self._device_context_menu)
        self.device_table.doubleClicked.connect(self._on_device_double_click)
        lay.addWidget(self.device_table)

        grp  = QtWidgets.QGroupBox("Use raw image / VMDK file as source")
        glay = QtWidgets.QHBoxLayout(grp)
        self.image_path_edit = QtWidgets.QLineEdit()
        self.image_path_edit.setPlaceholderText("/path/to/disk.dd  or  /path/to/disk.vmdk")
        b_img = QtWidgets.QPushButton("Browse"); b_img.clicked.connect(self._browse_image_file)
        glay.addWidget(QtWidgets.QLabel("Image file:")); glay.addWidget(self.image_path_edit); glay.addWidget(b_img)
        lay.addWidget(grp)

    # ── TAB 2: Mount ──
    def _build_tab_mount(self):
        lay = QtWidgets.QVBoxLayout(self.tab_mount)
        src_grp  = QtWidgets.QGroupBox("Mount Source"); src_form = QtWidgets.QFormLayout(src_grp)
        self.mount_source_cb = QtWidgets.QComboBox(); self.mount_source_cb.addItems(["Selected device (from table)", "Image file"])
        self.mount_dev_override = QtWidgets.QLineEdit(); self.mount_dev_override.setPlaceholderText("Leave empty to use table selection  or  /dev/sdc1")
        src_form.addRow("Source type:", self.mount_source_cb); src_form.addRow("Device override:", self.mount_dev_override)
        lay.addWidget(src_grp)

        opt_grp  = QtWidgets.QGroupBox("Mount Options"); opt_form = QtWidgets.QFormLayout(opt_grp)
        self.mount_point_edit = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_mp = QtWidgets.QPushButton("Browse"); b_mp.clicked.connect(self._browse_mount_point)
        mp_row = QtWidgets.QHBoxLayout(); mp_row.addWidget(self.mount_point_edit); mp_row.addWidget(b_mp)
        
        self.mount_opts_edit = QtWidgets.QLineEdit()
        self.mount_sudo_chk = QtWidgets.QCheckBox("Use sudo"); self.mount_sudo_chk.setChecked(True)
        self.allow_other_chk = QtWidgets.QCheckBox("Add -o allow_other"); self.allow_other_chk.setChecked(True)
        self.nonempty_chk = QtWidgets.QCheckBox("Add -o nonempty"); self.nonempty_chk.setChecked(True)
        
        opt_form.addRow("Mount point:", mp_row); opt_form.addRow("Extra flags:", self.mount_opts_edit)
        opt_form.addRow("", self.mount_sudo_chk); opt_form.addRow("", self.allow_other_chk); opt_form.addRow("", self.nonempty_chk)
        lay.addWidget(opt_grp)

        fuse_note = QtWidgets.QLabel("If allow_other fails, run: echo 'user_allow_other' | sudo tee -a /etc/fuse.conf")
        fuse_note.setStyleSheet("color:#aaddff;background:#313244;padding:6px;border-radius:4px;")
        lay.addWidget(fuse_note)

        btn_row = QtWidgets.QHBoxLayout()
        b_mount  = QtWidgets.QPushButton("Mount VMFS6")
        b_umount = QtWidgets.QPushButton("Unmount")
        b_mount.setStyleSheet("background:#a6e3a1;color:#11111b;font-weight:bold;padding:10px;")
        b_umount.setStyleSheet("background:#f38ba8;color:#11111b;font-weight:bold;padding:10px;")
        b_mount.clicked.connect(self._mount_vmfs6)
        b_umount.clicked.connect(self._umount_vmfs)
        btn_row.addWidget(b_mount); btn_row.addWidget(b_umount)
        lay.addLayout(btn_row); lay.addStretch()

    # ── TAB 3: DD & Forensic Imaging ──
    def _build_tab_dd(self):
        lay = QtWidgets.QVBoxLayout(self.tab_dd)
        src_grp  = QtWidgets.QGroupBox("Source"); src_form = QtWidgets.QFormLayout(src_grp)
        self.dd_source_cb = QtWidgets.QComboBox(); self.dd_source_cb.addItems(["Selected device (from table)", "Image file"])
        self.dd_dev_override = QtWidgets.QLineEdit(); self.dd_dev_override.setPlaceholderText("Leave empty or type e.g.  /dev/sdc1")
        src_form.addRow("Source:", self.dd_source_cb); src_form.addRow("Device override:", self.dd_dev_override)
        lay.addWidget(src_grp)

        out_grp  = QtWidgets.QGroupBox("Destination"); out_form = QtWidgets.QFormLayout(out_grp)
        self.dd_output_edit = QtWidgets.QLineEdit(); self.dd_output_edit.setPlaceholderText("/mnt/evidence/image.e01")
        b_out = QtWidgets.QPushButton("Browse"); b_out.clicked.connect(self._browse_dd_output)
        out_row = QtWidgets.QHBoxLayout(); out_row.addWidget(self.dd_output_edit); out_row.addWidget(b_out)
        out_form.addRow("Output file:", out_row)
        lay.addWidget(out_grp)

        speed_grp  = QtWidgets.QGroupBox("Forensic Tool & Options"); speed_form = QtWidgets.QFormLayout(speed_grp)
        self.dd_tool_combo = QtWidgets.QComboBox()
        self.dd_tool_combo.addItems(["dd (Fast Raw Image)", "dc3dd (Hashed Raw Image)", "ewfacquire (E01 Compressed Forensic Image)"])
        self.dd_bs_combo = QtWidgets.QComboBox(); self.dd_bs_combo.addItems(["1M", "4M", "8M", "16M", "64M", "128M"])
        self.dd_bs_combo.setCurrentText("4M")
        
        self.dd_direct_in_chk = QtWidgets.QCheckBox("iflag=direct (bypass read cache - dd only)"); self.dd_direct_in_chk.setChecked(True)
        self.dd_direct_out_chk = QtWidgets.QCheckBox("oflag=direct (bypass write cache - dd only)"); self.dd_direct_out_chk.setChecked(True)
        self.dd_noerror_chk = QtWidgets.QCheckBox("conv=noerror,sync (continue on bad sectors)"); self.dd_noerror_chk.setChecked(True)
        self.dd_sudo_chk = QtWidgets.QCheckBox("Use sudo"); self.dd_sudo_chk.setChecked(True)
        
        speed_form.addRow("Tool:", self.dd_tool_combo); speed_form.addRow("Block size:", self.dd_bs_combo)
        speed_form.addRow("", self.dd_direct_in_chk); speed_form.addRow("", self.dd_direct_out_chk)
        speed_form.addRow("", self.dd_noerror_chk); speed_form.addRow("", self.dd_sudo_chk)
        lay.addWidget(speed_grp)

        b_dd = QtWidgets.QPushButton("Start Forensic Acquisition")
        b_dd.setStyleSheet("background:#89b4fa;color:#11111b;font-weight:bold;padding:12px;font-size:14px;border-radius:6px;")
        b_dd.clicked.connect(self._start_dd)
        lay.addWidget(b_dd); lay.addStretch()

    # ── TAB 4: VMFS Browser ──
    def _build_tab_browse(self):
        lay = QtWidgets.QVBoxLayout(self.tab_browse)
        top = QtWidgets.QHBoxLayout()
        self.browse_root_edit = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_set  = QtWidgets.QPushButton("Browse"); b_set.clicked.connect(self._browse_vmfs_root)
        b_load = QtWidgets.QPushButton("Load Tree"); b_load.clicked.connect(self._load_vmfs_tree)
        top.addWidget(QtWidgets.QLabel("VMFS root:")); top.addWidget(self.browse_root_edit); top.addWidget(b_set); top.addWidget(b_load)
        lay.addLayout(top)

        self.file_tree = QtWidgets.QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Type", "Full Path"])
        self.file_tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.file_tree.setColumnWidth(1, 100); self.file_tree.setColumnWidth(2, 60)
        self.file_tree.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.file_tree.itemExpanded.connect(self._on_tree_expand)
        self.file_tree.itemDoubleClicked.connect(self._on_tree_double_click)
        self.file_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self._tree_context_menu)
        lay.addWidget(self.file_tree)

        act_row = QtWidgets.QHBoxLayout()
        b_export_sel = QtWidgets.QPushButton("⚡ Export & Hash (Ultra Speed)")
        b_export_sel.setStyleSheet("background:#a6e3a1;color:#11111b;font-weight:bold;padding:8px;border-radius:4px;")
        b_export_sel.clicked.connect(self._export_selected)

        b_tree_report = QtWidgets.QPushButton("📄 Tree Report")
        b_tree_report.setStyleSheet("background:#313244;color:white;font-weight:bold;padding:8px;")
        b_tree_report.clicked.connect(self._save_tree_report)
        
        b_timeline = QtWidgets.QPushButton("🕒 MAC Timeline (.csv)")
        b_timeline.setStyleSheet("background:#fab387;color:#11111b;font-weight:bold;padding:8px;")
        b_timeline.clicked.connect(self._generate_timeline)

        b_hex = QtWidgets.QPushButton("🔬 Hex Viewer")
        b_hex.setStyleSheet("background:#cba6f7;color:#11111b;font-weight:bold;padding:8px;")
        b_hex.clicked.connect(self._open_hex_viewer)

        b_sel_all = QtWidgets.QPushButton("Select All"); b_sel_all.clicked.connect(self.file_tree.selectAll)

        act_row.addWidget(b_export_sel); act_row.addWidget(b_tree_report); act_row.addWidget(b_timeline)
        act_row.addWidget(b_hex); act_row.addWidget(b_sel_all); act_row.addStretch()
        lay.addLayout(act_row)

        self.browse_status = QtWidgets.QLabel("Ctrl+Click = multi-select  |  Right-click = context menu")
        self.browse_status.setStyleSheet("color:#a6adc8;font-size:11px;")
        lay.addWidget(self.browse_status)
        self.file_tree.itemSelectionChanged.connect(self._on_selection_changed)

    # ── TAB 5: WSL Helper ──
    def _build_tab_wsl(self):
        lay = QtWidgets.QVBoxLayout(self.tab_wsl)
        info = QtWidgets.QLabel(
            "Generate PowerShell commands to pass a physical disk into WSL2.\n"
            "Run these in an elevated PowerShell on the Windows host.\n\n"
            "Workflow:\n  1. Elevated PowerShell -> Get-Disk\n  2. Run the generated wsl --mount command\n"
            "  3. Refresh Sources -> disk appears as /dev/sdX\n  4. Double-click disk to auto-mount.")
        info.setWordWrap(True)
        lay.addWidget(info)

        form = QtWidgets.QFormLayout()
        self.wsl_disk_edit = QtWidgets.QLineEdit(); self.wsl_disk_edit.setPlaceholderText("e.g. 2")
        self.wsl_part_edit = QtWidgets.QLineEdit(); self.wsl_part_edit.setPlaceholderText("e.g. 1 (leave empty for whole disk)")
        form.addRow("PHYSICALDRIVE number (N):", self.wsl_disk_edit)
        form.addRow("Partition number:", self.wsl_part_edit)
        lay.addLayout(form)

        btn_row = QtWidgets.QHBoxLayout()
        b_gen  = QtWidgets.QPushButton("Generate commands"); b_gen.clicked.connect(self._gen_wsl_cmds)
        b_copy = QtWidgets.QPushButton("Copy to clipboard"); b_copy.clicked.connect(self._copy_wsl_cmds)
        btn_row.addWidget(b_gen); btn_row.addWidget(b_copy)
        lay.addLayout(btn_row)

        self.wsl_out_edit = QtWidgets.QPlainTextEdit()
        self.wsl_out_edit.setReadOnly(True)
        lay.addWidget(self.wsl_out_edit)

    # ── TAB 6: Advanced Forensics ──
    def _build_tab_forensics(self):
        lay = QtWidgets.QVBoxLayout(self.tab_forensics)
        
        grp_carve = QtWidgets.QGroupBox("Data Carving (PhotoRec) - Recover from Raw Device")
        form_carve = QtWidgets.QFormLayout(grp_carve)
        self.carve_src = QtWidgets.QLineEdit(); self.carve_src.setPlaceholderText("Raw device /dev/sdX or .dd file")
        self.carve_out = QtWidgets.QLineEdit(); self.carve_out.setPlaceholderText("/mnt/recovery_output")
        b_carve = QtWidgets.QPushButton("Start Carving"); b_carve.clicked.connect(self._start_carving)
        form_carve.addRow("Target:", self.carve_src); form_carve.addRow("Output Dir:", self.carve_out); form_carve.addRow("", b_carve)
        lay.addWidget(grp_carve)

        grp_yara = QtWidgets.QGroupBox("Ransomware Hunting (YARA Scan)")
        form_yara = QtWidgets.QFormLayout(grp_yara)
        self.yara_rule = QtWidgets.QLineEdit(); self.yara_rule.setPlaceholderText("/path/to/ransomware.yar")
        self.yara_target = QtWidgets.QLineEdit(); self.yara_target.setPlaceholderText("Directory or VMDK file to scan")
        b_yara = QtWidgets.QPushButton("Run YARA Scan"); b_yara.clicked.connect(self._start_yara)
        form_yara.addRow("YARA Ruleset (.yar):", self.yara_rule); form_yara.addRow("Target to Scan:", self.yara_target); form_yara.addRow("", b_yara)
        lay.addWidget(grp_yara); lay.addStretch()

    # ── TAB 7: VMFS Intelligence ──
    def _build_tab_intel(self):
        lay = QtWidgets.QVBoxLayout(self.tab_intel)
        
        b_scan_intel = QtWidgets.QPushButton("🔍 Run Automated VMFS6 Intelligence Deep Scan")
        b_scan_intel.setStyleSheet("background:#f38ba8;color:#11111b;font-weight:bold;padding:12px;font-size:14px;border-radius:6px;")
        b_scan_intel.clicked.connect(self._run_vmfs_intel)
        lay.addWidget(b_scan_intel)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        
        w_top = QtWidgets.QWidget(); l_top = QtWidgets.QVBoxLayout(w_top); l_top.setContentsMargins(0,0,0,0)
        self.snap_tree = QtWidgets.QTreeWidget()
        self.snap_tree.setHeaderLabels(["VM Name / Snapshot Chain", "CID / Guest OS", "Path"])
        self.snap_tree.setColumnWidth(0, 350)
        l_top.addWidget(QtWidgets.QLabel("🖥️ VMs and Snapshot Chains:"))
        l_top.addWidget(self.snap_tree)
        splitter.addWidget(w_top)

        w_bot = QtWidgets.QWidget(); l_bot = QtWidgets.QVBoxLayout(w_bot); l_bot.setContentsMargins(0,0,0,0)
        self.intel_log = QtWidgets.QPlainTextEdit()
        self.intel_log.setReadOnly(True)
        self.intel_log.setStyleSheet("background:#11111b;color:#a6e3a1;font-family:Courier New, monospace;")
        l_bot.addWidget(QtWidgets.QLabel("⚙️ Forensic Analysis (USB Events, Mounts, Heartbeats, System Files):"))
        l_bot.addWidget(self.intel_log)
        splitter.addWidget(w_bot)
        
        lay.addWidget(splitter)


    # ═══════════════════════ DEVICE DETECTION ════════════════════════

    def _populate_devices(self):
        self.device_table.setRowCount(0)
        if self.IS_WIN: self._populate_windows()
        else: self._populate_linux()

    def _populate_linux(self):
        try:
            raw = subprocess.check_output(["lsblk", "-rno", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            self._log("lsblk not found – using /sys/block fallback.")
            self._populate_sysblock()
            return

        for line in raw.strip().splitlines():
            cols  = line.split()
            if not cols: continue
            name  = cols[0]
            size  = cols[1] if len(cols) > 1 else "?"
            dtype = cols[2] if len(cols) > 2 else "?"
            fst   = cols[3] if len(cols) > 3 else ""
            mnt   = cols[4] if len(cols) > 4 else ""
            if dtype in ("loop", "rom", "ram"): continue
            hint = ""
            fg   = None
            if "vmfs" in fst.lower():
                hint = "VMFS detected"
                fg   = QtGui.QColor("#a6e3a1")
            elif fst == "" and dtype in ("disk", "part"):
                hint = "Unknown FS – possible VMFS"
                fg   = QtGui.QColor("#fab387")
            self._add_device_row(f"/dev/{name}", size, dtype, fst, mnt, hint, fg)
        self._log(f"Scan done – {self.device_table.rowCount()} device(s) listed.")

    def _populate_sysblock(self):
        try: devs = sorted(os.listdir("/sys/block"))
        except Exception as e: self._log(f"/sys/block error: {e}"); return
        for name in devs:
            if name.startswith(("loop", "ram", "sr")): continue
            size = self._sysblock_size(name)
            self._add_device_row(f"/dev/{name}", size, "disk", "", "", "possible VMFS", QtGui.QColor("#fab387"))
            try:
                for entry in sorted(os.listdir(f"/sys/block/{name}")):
                    if entry.startswith(name):
                        ps = self._sysblock_size(name, entry)
                        self._add_device_row(f"/dev/{entry}", ps, "part", "", "", "possible VMFS", QtGui.QColor("#fab387"))
            except Exception: pass

    @staticmethod
    def _sysblock_size(disk, part=None):
        try:
            p = (f"/sys/block/{disk}/{part}/size" if part else f"/sys/block/{disk}/size")
            with open(p) as f: return f"{int(f.read().strip()) * 512 / 1024**3:.1f}G"
        except Exception: return "?"

    def _populate_windows(self):
        seen = set()
        for part in psutil.disk_partitions(all=True):
            if part.device in seen: continue
            seen.add(part.device)
            try: sz = f"{psutil.disk_usage(part.mountpoint).total/1024**3:.1f}G"
            except Exception: sz = "?"
            self._add_device_row(part.device, sz, "Volume", part.fstype, part.mountpoint, "")
        for i in range(8):
            self._add_device_row(f"\\\\.\\PhysicalDrive{i}", "?", "Physical", "", "", "Raw device")
        self._log("Windows device scan complete.")

    def _add_device_row(self, path, size, dtype, fstype, mnt, hint, fg=None):
        r = self.device_table.rowCount()
        self.device_table.insertRow(r)
        for c, txt in enumerate([path, size, dtype, fstype, mnt, hint]):
            item = QtWidgets.QTableWidgetItem(str(txt))
            if fg: item.setForeground(fg)
            self.device_table.setItem(r, c, item)

    def _scan_vmfs_candidates(self):
        hits = 0
        for row in range(self.device_table.rowCount()):
            fs, mnt, hnt, tp = [self.device_table.item(row, i) for i in (3, 4, 5, 2)]
            if not (fs and hnt and tp): continue
            if (fs.text().strip() == "" and tp.text().strip() in ("disk", "part", "Physical") and (not mnt or mnt.text().strip() in ("", "-"))):
                hnt.setText("Possible VMFS6 candidate")
                for c in range(self.device_table.columnCount()):
                    it = self.device_table.item(row, c)
                    if it: it.setForeground(QtGui.QColor("#fab387"))
                hits += 1
        self._log(f"Scan complete – {hits} VMFS6 candidate(s) highlighted.")

    # ═════════════════ CONTEXT MENUS & EVENTS ════════════════════════

    def _device_context_menu(self, pos):
        row = self.device_table.rowAt(pos.y())
        if row < 0: return
        self.device_table.selectRow(row)
        dev  = self.device_table.item(row, 0).text()
        menu = QtWidgets.QMenu(self)
        a_mount = menu.addAction("Mount VMFS6  (vmfs6-fuse)")
        a_dd    = menu.addAction("Create dd image  (high speed)")
        a_copy  = menu.addAction("Copy device path")
        menu.addSeparator()
        a_fill  = menu.addAction("Fill mount device field")
        action  = menu.exec_(self.device_table.viewport().mapToGlobal(pos))
        if action == a_mount: self._quick_mount(dev)
        elif action == a_dd: self.dd_dev_override.setText(dev); self.tabs.setCurrentIndex(2)
        elif action == a_copy: QtWidgets.QApplication.clipboard().setText(dev); self._log(f"Copied: {dev}")
        elif action == a_fill: self.mount_dev_override.setText(dev); self.tabs.setCurrentIndex(1)

    def _on_device_double_click(self, index):
        row = index.row()
        if row >= 0: self._quick_mount(self.device_table.item(row, 0).text())

    def _quick_mount(self, device: str):
        self.mount_dev_override.setText(device)
        self.mount_source_cb.setCurrentIndex(0)
        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"
        self.mount_point_edit.setText(mp)
        self.tabs.setCurrentIndex(1)
        self._log(f"Quick-mount: {device} -> {mp}")
        self._mount_vmfs6()

    def _resolve_source(self, cb, override_edit):
        ov = override_edit.text().strip() if override_edit else ""
        if ov: return ov
        if "device" in cb.currentText().lower():
            row = self.device_table.currentRow()
            if row < 0: raise RuntimeError("No device selected.")
            return self.device_table.item(row, 0).text().strip()
        img = self.image_path_edit.text().strip()
        if not img or not os.path.exists(img): raise RuntimeError("Valid image file not found in Sources tab.")
        return img

    def _ensure_mount_point(self, mp: str) -> bool:
        if os.path.isdir(mp): return True
        try:
            subprocess.run(["sudo", "mkdir", "-p", mp], capture_output=True, text=True, check=True)
            subprocess.run(["sudo", "chmod", "755", mp], capture_output=True)
            return True
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Mount point error", f"mkdir failed: {e}")
            return False

    def _is_mounted(self, mp: str) -> bool:
        try: return subprocess.run(["mountpoint", "-q", mp], capture_output=True).returncode == 0
        except Exception: return False

    # ═══════════════════════ MOUNT / UNMOUNT ═════════════════════════

    def _mount_vmfs6(self):
        if self.IS_WIN:
            QtWidgets.QMessageBox.warning(self, "Not supported", "vmfs6-fuse requires Linux or WSL.")
            return
        try: source = self._resolve_source(self.mount_source_cb, self.mount_dev_override)
        except Exception as exc: QtWidgets.QMessageBox.warning(self, "Source error", str(exc)); return

        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"
        if not self._ensure_mount_point(mp): return
        if self._is_mounted(mp):
            if QtWidgets.QMessageBox.question(self, "Already mounted", f"'{mp}' is mounted. Unmount and remount?") == QtWidgets.QMessageBox.Yes:
                subprocess.run(["sudo", "umount", mp], capture_output=True)
            else: return

        def task(worker: WorkerThread):
            cmd = (["sudo"] if self.mount_sudo_chk.isChecked() else []) + ["vmfs6-fuse"]
            opts = []
            if self.allow_other_chk.isChecked(): opts.append("allow_other")
            if self.nonempty_chk.isChecked(): opts.append("nonempty")
            if opts: cmd += ["-o", ",".join(opts)]
            cmd += [source, mp]
            worker.log_message.emit("CMD: " + " ".join(cmd))
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(proc.stdout.readline, ""):
                if worker.stopped: proc.terminate(); return
                if line.rstrip(): worker.log_message.emit(line.rstrip())
            proc.wait()
            if proc.returncode not in (0, None): raise RuntimeError(f"vmfs6-fuse exited with code {proc.returncode}")
            worker.progress_changed.emit(100)
            worker.log_message.emit(f"SUCCESS – Mounted at {mp}")
            QtCore.QMetaObject.invokeMethod(self.browse_root_edit, "setText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, mp))

        self._run_worker(task)

    def _umount_vmfs(self):
        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"
        def task(worker: WorkerThread):
            worker.log_message.emit(f"Unmounting {mp} ...")
            if subprocess.run(["sudo", "umount", mp], capture_output=True).returncode != 0: raise RuntimeError("umount failed")
            worker.progress_changed.emit(100)
            worker.log_message.emit(f"Unmounted: {mp}")
        self._run_worker(task)

    # ═══════════════════ DD & FORENSIC IMAGING ═════════════════════

    def _start_dd(self):
        try: source = self._resolve_source(self.dd_source_cb, self.dd_dev_override)
        except Exception as exc: QtWidgets.QMessageBox.warning(self, "Source error", str(exc)); return
        out_path = self.dd_output_edit.text().strip()
        if not out_path: QtWidgets.QMessageBox.warning(self, "No output", "Please specify an output file path."); return
        
        tool = self.dd_tool_combo.currentText()
        bs   = self.dd_bs_combo.currentText()
        
        if QtWidgets.QMessageBox.question(self, "Confirm", f"Source: {source}\nDest: {out_path}\nContinue?") != QtWidgets.QMessageBox.Yes: return

        def task(worker: WorkerThread):
            cmd = []
            if "ewfacquire" in tool:
                cmd = ["sudo", "ewfacquire", "-t", out_path, "-c", "fast", "-f", "encase6", "-S", "1.4G", "-u", source]
            elif "dc3dd" in tool:
                cmd = ["sudo", "dc3dd", f"if={source}", f"of={out_path}", "hash=md5", "hash=sha256"]
            else:
                cmd = (["sudo"] if self.dd_sudo_chk.isChecked() else []) + ["dd", f"if={source}", f"of={out_path}", f"bs={bs}", "status=progress"]
                iflags, oflags, conv = [], [], []
                if self.dd_direct_in_chk.isChecked(): iflags.append("direct")
                if self.dd_direct_out_chk.isChecked(): oflags.append("direct")
                if self.dd_noerror_chk.isChecked(): conv += ["noerror", "sync"]
                if iflags: cmd.append("iflag=" + ",".join(iflags))
                if oflags: cmd.append("oflag=" + ",".join(oflags))
                if conv: cmd.append("conv=" + ",".join(conv))

            worker.log_message.emit("CMD: " + " ".join(cmd))
            os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in iter(proc.stdout.readline, ""):
                if worker.stopped: proc.terminate(); break
                if line.strip(): worker.log_message.emit(line.strip()[:150]) 
            
            proc.wait()
            if proc.returncode not in (0, None): raise RuntimeError(f"Imaging exited with code {proc.returncode}")
            worker.progress_changed.emit(100)
            worker.log_message.emit("Imaging completed successfully.")

        self._run_worker(task)

    # ═══════════════════════ FILE TREE & BROWSER ═════════════════════

    def _browse_vmfs_root(self):
        p = QtWidgets.QFileDialog.getExistingDirectory(self, "Select mounted VMFS6 directory")
        if p: self.browse_root_edit.setText(p)

    def _load_vmfs_tree(self):
        root = self.browse_root_edit.text().strip()
        if not root or not os.path.isdir(root):
            QtWidgets.QMessageBox.warning(self, "Invalid path", "Mount the VMFS6 disk first.")
            return
        self.file_tree.clear()
        self._log(f"Loading tree from {root}")
        root_item = QtWidgets.QTreeWidgetItem([os.path.basename(root) or "/", "", "DIR", root])
        self.file_tree.addTopLevelItem(root_item)
        self._fill_tree_level(root_item, root)
        root_item.setExpanded(True)

    def _fill_tree_level(self, parent, dir_path):
        try: entries = sorted(os.scandir(dir_path), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name))
        except Exception as exc: self._log(f"Cannot read {dir_path}: {exc}"); return

        for entry in entries:
            is_dir = entry.is_dir(follow_symlinks=False)
            ext    = os.path.splitext(entry.name)[1].upper() or "FILE"
            if is_dir:
                child = QtWidgets.QTreeWidgetItem([entry.name, "", "DIR", entry.path])
                child.addChild(QtWidgets.QTreeWidgetItem(["...", "", "", ""]))
            else:
                try: sz = self._fmt_size(entry.stat(follow_symlinks=False).st_size)
                except: sz = "?"
                child = QtWidgets.QTreeWidgetItem([entry.name, sz, ext, entry.path])
            parent.addChild(child)

    def _on_tree_expand(self, item):
        if item.childCount() == 1 and item.child(0).text(0) == "...":
            item.removeChild(item.child(0))
            self._fill_tree_level(item, item.text(3))

    def _on_tree_double_click(self, item, col):
        path = item.text(3)
        if path and os.path.isfile(path): self._open_hex_viewer_for(path)

    def _on_selection_changed(self):
        items = self.file_tree.selectedItems()
        total = sum(os.path.getsize(it.text(3)) for it in items if os.path.isfile(it.text(3)))
        self.browse_status.setText(f"{len(items)} item(s) selected | Estimated size: {self._fmt_size(total)}")

    def _tree_context_menu(self, pos):
        items = self.file_tree.selectedItems()
        if not items: return
        menu   = QtWidgets.QMenu(self)
        a_exp  = menu.addAction("⚡ Export & Hash (High Speed)")
        a_hex  = menu.addAction("🔬 Open in Hex Viewer")
        a_frag = menu.addAction("🧩 Check File Fragmentation (filefrag)")
        a_guest = menu.addAction("🖥 Mount VMDK inside VMFS (GuestFS)")
        a_copy = menu.addAction("📋 Copy path(s)")
        action = menu.exec_(self.file_tree.viewport().mapToGlobal(pos))
        
        if action == a_exp: self._export_selected()
        elif action == a_hex: self._open_hex_viewer()
        elif action == a_copy: QtWidgets.QApplication.clipboard().setText("\n".join(it.text(3) for it in items))
        elif action == a_frag:
            path = items[0].text(3)
            try:
                res = subprocess.check_output(["filefrag", path], text=True)
                QtWidgets.QMessageBox.information(self, "Fragmentation Check", f"Path: {path}\n\n{res}")
            except Exception as e: QtWidgets.QMessageBox.warning(self, "Error", f"Failed to run filefrag: {e}")
        elif action == a_guest:
            vmdk_path = items[0].text(3)
            if vmdk_path.endswith(".vmdk"):
                mnt_pt = f"/mnt/guest_{os.path.basename(vmdk_path)}"
                os.makedirs(mnt_pt, exist_ok=True)
                self._log(f"Mounting VMDK via GuestFS to {mnt_pt}...")
                subprocess.Popen(["sudo", "guestmount", "-a", vmdk_path, "-i", "--ro", mnt_pt])
                self._log("Guestmount initiated. Check folder in few seconds.")

    def _open_hex_viewer(self):
        for it in [i for i in self.file_tree.selectedItems() if os.path.isfile(i.text(3))][:3]:
            self._open_hex_viewer_for(it.text(3))

    def _open_hex_viewer_for(self, path: str):
        dlg = HexViewerDialog(path, parent=self)
        dlg.setModal(False)
        dlg.show()
        self._hex_viewers.append(dlg)

    # ═══════════════════════ EXPORT ENGINE (ULTRA SPEED) ══════════════════════
    
    def _export_selected(self):
        items = self.file_tree.selectedItems()
        paths = [it.text(3) for it in items if it.text(3) and os.path.exists(it.text(3))]
        if not paths: return

        dest_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Select destination folder")
        if not dest_dir: return

        copy_plan = []
        for src in paths:
            if os.path.isfile(src): copy_plan.append((src, os.path.join(dest_dir, os.path.basename(src))))
            elif os.path.isdir(src):
                base = os.path.dirname(src)
                for dp, _, fns in os.walk(src):
                    for fn in fns:
                        sf = os.path.join(dp, fn)
                        copy_plan.append((sf, os.path.join(dest_dir, os.path.relpath(sf, base))))

        if not copy_plan: return
        total_bytes = sum(os.path.getsize(sf) for sf, _ in copy_plan if os.path.isfile(sf))
        
        self.export_dlg = ModernExportDialog(f"Forensic Extraction ({len(copy_plan)} items)", self)
        self._export_worker = ExportWorker(copy_plan, total_bytes)
        
        self._export_worker.update_ui.connect(self.export_dlg.update_ui)
        self._export_worker.finished_export.connect(self._on_export_finished)
        self._export_worker.error_export.connect(self._log)
        self.export_dlg.cancel_requested.connect(self._export_worker.stop)

        self._export_worker.start()
        self.export_dlg.exec_() 

    def _on_export_finished(self, copied, elapsed):
        self.export_dlg.update_ui(100, "Done ✓", "0 MB/s", f"{copied/1024**3:.2f} GB", "00:00:00", "Matched", "Matched")
        speed = (copied/elapsed)/1024**2 if elapsed > 0 else 0
        self._log(f"Extraction Complete: {copied/1024**3:.2f} GB copied in {elapsed:.1f} seconds. Average Speed: {speed:.1f} MB/s")

    # ═══════════════════════ TREE REPORT & TIMELINE ══════════════════
    
    def _save_tree_report(self):
        root = self.browse_root_edit.text().strip()
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Tree Report", "vmfs6_tree.txt", "Text (*.txt)")
        if not path or not os.path.isdir(root): return
        
        lines = [f"VMFS6 Tree Report | Root: {root} | Date: {time.strftime('%Y-%m-%d %H:%M:%S')}", "="*70]
        def walk(dp, pfx=""):
            try: entries = sorted(os.scandir(dp), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name))
            except: return
            for i, e in enumerate(entries):
                is_last = (i == len(entries) - 1)
                conn = "└── " if is_last else "├── "
                if e.is_dir(follow_symlinks=False):
                    lines.append(f"{pfx}{conn}{e.name}/")
                    walk(e.path, pfx + ("    " if is_last else "│   "))
                else:
                    lines.append(f"{pfx}{conn}{e.name}  [{self._fmt_size(e.stat(follow_symlinks=False).st_size)}]")
        walk(root)
        with open(path, "w", encoding="utf-8") as f: f.write("\n".join(lines))
        self._log(f"Tree report saved to {path}")

    def _generate_timeline(self):
        root = self.browse_root_edit.text().strip()
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save MAC Timeline", "vmfs_timeline.csv", "CSV (*.csv)")
        if not path or not os.path.isdir(root): return
        def task(w):
            w.log_message.emit("Generating MAC Timeline...")
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Path", "Size", "Modified (mtime)", "Accessed (atime)", "Created (ctime)"])
                for dp, _, fns in os.walk(root):
                    for name in fns:
                        full = os.path.join(dp, name)
                        try:
                            st = os.stat(full)
                            writer.writerow([full, st.st_size, time.ctime(st.st_mtime), time.ctime(st.st_atime), time.ctime(st.st_ctime)])
                        except: pass
            w.progress_changed.emit(100)
            w.log_message.emit(f"Timeline saved to {path}")
        self._run_worker(task)

    # ═══════════════════════ WSL HELPER ══════════════════════════════
    
    def _gen_wsl_cmds(self):
        n, p = self.wsl_disk_edit.text().strip(), self.wsl_part_edit.text().strip()
        lines = [
            "# Run in elevated PowerShell on Windows host",
            "Get-CimInstance -ClassName Win32_DiskDrive | Select-Object DeviceID, Model, Size",
            "diskpart", f"  select disk {n}", "  offline disk", "  exit",
            f"wsl --mount \\\\.\\PHYSICALDRIVE{n}" + (f" --partition {p} --bare" if p else " --bare")
        ]
        self.wsl_out_edit.setPlainText("\n".join(lines))

    def _copy_wsl_cmds(self):
        QtWidgets.QApplication.clipboard().setText(self.wsl_out_edit.toPlainText())

    # ═══════════════════════ ADVANCED FORENSICS ══════════════════════
    
    def _start_carving(self):
        src, out = self.carve_src.text().strip(), self.carve_out.text().strip()
        os.makedirs(out, exist_ok=True)
        def task(w):
            cmd = ["sudo", "photorec", "/d", out, "/cmd", src, "partition_none,search"]
            w.log_message.emit("Starting Data Carving (PhotoRec)...")
            subprocess.run(cmd)
            w.progress_changed.emit(100)
            w.log_message.emit(f"Carving finished. Check {out}")
        self._run_worker(task)

    def _start_yara(self):
        rule, target = self.yara_rule.text().strip(), self.yara_target.text().strip()
        def task(w):
            cmd = ["yara", "-r", rule, target]
            w.log_message.emit(f"Running YARA Scan with rule: {os.path.basename(rule)}")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            for line in iter(proc.stdout.readline, ""): w.log_message.emit(f"🔴 YARA HIT: {line.strip()}")
            proc.wait()
            w.progress_changed.emit(100)
            w.log_message.emit("YARA Scan Complete.")
        self._run_worker(task)

    # ═══════════════════════ VMFS INTELLIGENCE SCAN ═══════════════════════
    
    def _run_vmfs_intel(self):
        root = self.browse_root_edit.text().strip()
        if not os.path.isdir(root):
            QtWidgets.QMessageBox.warning(self, "Error", "Mount VMFS and set the path in VMFS Browser first.")
            return

        self.snap_tree.clear()
        self.intel_log.clear()

        def task(worker):
            worker.log_message.emit("Starting VMFS Intelligence Deep Scan...")
            vmdk_descriptors = {}
            lock_macs = set()
            total_logical = total_physical = total_hidden_sf = vm_logs_found = 0

            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    filepath = os.path.join(dirpath, fname)
                    
                    if fname.endswith(".sf"):
                        total_hidden_sf += 1
                        sz = os.path.getsize(filepath)
                        worker.log_message.emit(f"[SYSTEM FILE] Found VMFS6 Metadata File: {fname} (Size: {sz/1024**2:.2f} MB)")
                        if "sbc.sf" in fname: worker.log_message.emit("  -> This is the Space Bitmap Cache (SBC). Analyzable for unmapped blocks.")
                        if "fdc.sf" in fname: worker.log_message.emit("  -> This is the File Descriptor Cache (FDC).")

                    elif fname.endswith(".log") and "vmware" in fname.lower():
                        vm_logs_found += 1
                        try:
                            usb_events, iso_events, power_events = [], [], []
                            with open(filepath, 'r', errors='ignore') as f:
                                lines = f.readlines()[-5000:]
                                for line in lines:
                                    if "USB: Found device" in line: usb_events.append(line.strip())
                                    elif "CDROM" in line and ".iso" in line.lower(): iso_events.append(line.strip())
                                    elif "PowerOn" in line: power_events.append(line.strip())
                            
                            if usb_events or iso_events:
                                worker.log_message.emit(f"\n[FORENSIC LOG] Found sensitive events in {filepath}:")
                                for u in usb_events: worker.log_message.emit(f"  🔴 USB Event: {u}")
                                for i in iso_events: worker.log_message.emit(f"  💿 ISO Mount: {i}")
                                for p in power_events: worker.log_message.emit(f"  ⚡ Power Event: {p}")
                        except Exception: pass

                    elif fname.endswith(".vmx"):
                        vm_name, guest_os, mac_addr = "Unknown", "Unknown", "Unknown"
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                for line in f:
                                    if 'displayName' in line: vm_name = line.split('=')[1].strip().strip('"')
                                    elif 'guestOS' in line: guest_os = line.split('=')[1].strip().strip('"')
                                    elif 'generatedAddress' in line: mac_addr = line.split('=')[1].strip().strip('"')
                            QtCore.QMetaObject.invokeMethod(self, "_add_tree_item", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, f"{vm_name} (VM)"), QtCore.Q_ARG(str, guest_os), QtCore.Q_ARG(str, filepath))
                        except: pass

                    elif fname.endswith(".vmdk") and not fname.endswith("-flat.vmdk") and not fname.endswith("-sesparse.vmdk"):
                        cid, parent_cid = None, None
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                head = f.read(1024)
                                if 'CID=' in head:
                                    for line in head.splitlines():
                                        if line.startswith('CID='): cid = line.split('=')[1].strip()
                                        elif line.startswith('parentCID='): parent_cid = line.split('=')[1].strip()
                            if cid: vmdk_descriptors[cid] = {'name': fname, 'path': filepath, 'parent': parent_cid}
                        except: pass

                    elif fname.endswith("-flat.vmdk") or fname.endswith("-sesparse.vmdk"):
                        try:
                            st = os.stat(filepath)
                            logical, physical = st.st_size, st.st_blocks * 512
                            total_logical += logical; total_physical += physical
                            if logical > 0 and physical < logical:
                                worker.log_message.emit(f"[Thin Prov] {fname} - Provisioned: {logical/1024**3:.1f}GB | Actual used: {physical/1024**3:.1f}GB")
                        except: pass

                    elif ".lck" in fname:
                        try:
                            with open(filepath, 'rb') as f:
                                data = f.read(4096)
                                macs = re.findall(rb'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', data)
                                for m in macs: lock_macs.add(m.decode('utf-8'))
                        except: pass

            worker.log_message.emit("\n--- Volume Metadata ---")
            worker.log_message.emit(f"Total Logical VMDK Size : {total_logical/1024**4:.2f} TB")
            worker.log_message.emit(f"Total Physical Size on Disk: {total_physical/1024**4:.2f} TB")

            if lock_macs:
                worker.log_message.emit("\n--- Heartbeat/Lock Analysis ---")
                worker.log_message.emit("Found following ESXi Host MAC Addresses holding locks:")
                for mac in lock_macs: worker.log_message.emit(f"  -> {mac}")

            QtCore.QMetaObject.invokeMethod(self, "_build_snap_tree", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(dict, vmdk_descriptors))
            worker.progress_changed.emit(100)
            worker.log_message.emit(f"\nScan Summary: Processed {vm_logs_found} VM Logs and {total_hidden_sf} VMFS6 System Files.")
            worker.log_message.emit("VMFS Intelligence Scan Complete!")

        self._run_worker(task)

    @QtCore.pyqtSlot(str, str, str)
    def _add_tree_item(self, col1, col2, col3):
        self.snap_tree.addTopLevelItem(QtWidgets.QTreeWidgetItem([col1, col2, col3]))

    @QtCore.pyqtSlot(dict)
    def _build_snap_tree(self, descriptors):
        items = {}
        for cid, info in descriptors.items():
            items[cid] = QtWidgets.QTreeWidgetItem([info['name'], cid, "Delta/Snapshot" if info['parent'] != "ffffffff" else "Base Disk", info['path']])
        for cid, info in descriptors.items():
            if info['parent'] in items: items[info['parent']].addChild(items[cid])
            else: self.snap_tree.addTopLevelItem(items[cid])
        self.snap_tree.expandAll()

    # ═══════════════════ WORKER MANAGEMENT & HELPERS ═════════════════
    
    def _run_worker(self, target):
        if self.worker and self.worker.isRunning(): return
        self.progress.setValue(0)
        self.worker = WorkerThread(target)
        self.worker.progress_changed.connect(self.progress.setValue)
        self.worker.log_message.connect(self._log)
        self.worker.start()

    def _log(self, text: str):
        ts = time.strftime("%H:%M:%S")
        self.log_edit.appendPlainText(f"[{ts}]  {text}")
        if any(kw in text for kw in ["Thin Prov", "Volume Metadata", "MAC", "Heartbeat", "SYSTEM FILE", "FORENSIC LOG", "USB Event", "ISO Mount"]):
            self.intel_log.appendPlainText(f"[{ts}]  {text}")

    def _save_log(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save log", "vmfs_forensics_log.txt", "Text (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f: f.write(self.log_edit.toPlainText())

    def _browse_image_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select disk image", "", "Images (*.dd *.img *.raw *.vmdk *.e01);;All (*)")
        if path: self.image_path_edit.setText(path)

    def _browse_mount_point(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select mount point directory")
        if path: self.mount_point_edit.setText(path)

    def _browse_dd_output(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Output file", "image.dd")
        if path: self.dd_output_edit.setText(path)

    @staticmethod
    def _fmt_size(n):
        for u in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"

# ═════════════════════════ Entry Point ═══════════════════════════════

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    # تطبيق سمة داكنة متطورة (Catppuccin Macchiato style)
    pal = QtGui.QPalette()
    pal.setColor(QtGui.QPalette.Window,          QtGui.QColor(36, 39, 58))
    pal.setColor(QtGui.QPalette.WindowText,      QtGui.QColor(202, 211, 245))
    pal.setColor(QtGui.QPalette.Base,            QtGui.QColor(30, 32, 48))
    pal.setColor(QtGui.QPalette.AlternateBase,   QtGui.QColor(36, 39, 58))
    pal.setColor(QtGui.QPalette.Text,            QtGui.QColor(202, 211, 245))
    pal.setColor(QtGui.QPalette.Button,          QtGui.QColor(54, 58, 79))
    pal.setColor(QtGui.QPalette.ButtonText,      QtGui.QColor(202, 211, 245))
    pal.setColor(QtGui.QPalette.Highlight,       QtGui.QColor(138, 173, 244))
    pal.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor(36, 39, 58))
    pal.setColor(QtGui.QPalette.ToolTipBase,     QtGui.QColor(54, 58, 79))
    pal.setColor(QtGui.QPalette.ToolTipText,     QtGui.QColor(202, 211, 245))
    app.setPalette(pal)

    win = VMFSGui()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
