import os
import sys
import subprocess
import time

import psutil
from PyQt5 import QtCore, QtGui, QtWidgets


# ─────────────────────────── Worker Thread ───────────────────────────

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


# ─────────────────────────── Main Window ─────────────────────────────

class VMFSGui(QtWidgets.QMainWindow):

    IS_WINDOWS = (os.name == "nt")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VMFS6 Forensic Utility")
        self.resize(1100, 720)
        self.worker   = None
        self._vmfs_fs = None          # reserved for future dissect integration

        self._build_ui()
        self._populate_devices()

    # ═══════════════════════ UI CONSTRUCTION ═════════════════════════

    def _build_ui(self):
        central = QtWidgets.QWidget()
        root    = QtWidgets.QVBoxLayout(central)

        self.tabs = QtWidgets.QTabWidget()
        root.addWidget(self.tabs)

        # ── Tab 1: device / image source ──
        self.tab_src = QtWidgets.QWidget()
        self._build_tab_source()
        self.tabs.addTab(self.tab_src, "📀  Sources")

        # ── Tab 2: VMFS mount ──
        self.tab_mount = QtWidgets.QWidget()
        self._build_tab_mount()
        self.tabs.addTab(self.tab_mount, "🔗  Mount VMFS6")

        # ── Tab 3: dd imaging ──
        self.tab_dd = QtWidgets.QWidget()
        self._build_tab_dd()
        self.tabs.addTab(self.tab_dd, "💾  Imaging (dd)")

        # ── Tab 4: file browser (post-mount) ──
        self.tab_browse = QtWidgets.QWidget()
        self._build_tab_browse()
        self.tabs.addTab(self.tab_browse, "📂  VMFS Browser")

        # ── Tab 5: WSL / Windows helper ──
        self.tab_wsl = QtWidgets.QWidget()
        self._build_tab_wsl()
        self.tabs.addTab(self.tab_wsl, "⚙  WSL Helper")

        # ── Log + progress ──
        root.addWidget(QtWidgets.QLabel("Log:"))
        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(140)
        root.addWidget(self.log_edit)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        root.addWidget(self.progress)

        row = QtWidgets.QHBoxLayout()
        btn_clear = QtWidgets.QPushButton("Clear log")
        btn_save  = QtWidgets.QPushButton("Save log…")
        btn_clear.clicked.connect(self.log_edit.clear)
        btn_save.clicked.connect(self._save_log)
        row.addWidget(btn_clear)
        row.addWidget(btn_save)
        row.addStretch()
        root.addLayout(row)

        self.setCentralWidget(central)

    # ── Tab 1: Sources ────────────────────────────────────────────────

    def _build_tab_source(self):
        lay = QtWidgets.QVBoxLayout(self.tab_src)

        # toolbar
        toolbar = QtWidgets.QHBoxLayout()
        btn_refresh = QtWidgets.QPushButton("🔄  Refresh devices")
        btn_scan    = QtWidgets.QPushButton("🔍  Scan VMFS candidates")
        btn_refresh.clicked.connect(self._populate_devices)
        btn_scan.clicked.connect(self._scan_vmfs_candidates)
        toolbar.addWidget(btn_refresh)
        toolbar.addWidget(btn_scan)
        toolbar.addStretch()
        lay.addLayout(toolbar)

        # device table
        self.device_table = QtWidgets.QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(
            ["Device Path", "Size", "Type", "FS Type", "Mountpoint", "Hint"])
        self.device_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SingleSelection)
        lay.addWidget(self.device_table)

        # image file source
        grp = QtWidgets.QGroupBox("Use raw image / VMDK file as source instead of a device")
        glay = QtWidgets.QHBoxLayout(grp)
        self.image_path_edit = QtWidgets.QLineEdit()
        self.image_path_edit.setPlaceholderText("/path/to/disk.dd   or   /path/to/disk.vmdk")
        btn_img = QtWidgets.QPushButton("Browse…")
        btn_img.clicked.connect(self._browse_image_file)
        glay.addWidget(QtWidgets.QLabel("Image file:"))
        glay.addWidget(self.image_path_edit)
        glay.addWidget(btn_img)
        lay.addWidget(grp)

    # ── Tab 2: Mount ──────────────────────────────────────────────────

    def _build_tab_mount(self):
        form = QtWidgets.QFormLayout(self.tab_mount)

        self.mount_source_cb = QtWidgets.QComboBox()
        self.mount_source_cb.addItems(["Selected device (from table)", "Image file"])

        self.mount_point_edit = QtWidgets.QLineEdit()
        self.mount_point_edit.setPlaceholderText("/mnt/vmfs6")

        self.mount_opts_edit = QtWidgets.QLineEdit()
        self.mount_opts_edit.setPlaceholderText("e.g.  -o allow_other  (optional)")

        btn_browse_mp = QtWidgets.QPushButton("Browse mount point…")
        btn_browse_mp.clicked.connect(self._browse_mount_point)

        btn_mount   = QtWidgets.QPushButton("▶  Mount VMFS6  (vmfs6-fuse)")
        btn_umount  = QtWidgets.QPushButton("⏹  Unmount  (fusermount -u)")
        btn_mount.setStyleSheet("background:#1a7a1a;color:white;")
        btn_umount.setStyleSheet("background:#7a1a1a;color:white;")
        btn_mount.clicked.connect(self._mount_vmfs6)
        btn_umount.clicked.connect(self._umount_vmfs)

        note = QtWidgets.QLabel(
            "⚠  vmfs6-fuse is only available on Linux / WSL.\n"
            "Install with:  sudo apt install vmfs6-tools")
        note.setStyleSheet("color:#ffcc44;")

        form.addRow("Source:", self.mount_source_cb)
        form.addRow("Mount point:", self.mount_point_edit)
        form.addRow("", btn_browse_mp)
        form.addRow("Extra options:", self.mount_opts_edit)
        form.addRow("", btn_mount)
        form.addRow("", btn_umount)
        form.addRow("", note)

    # ── Tab 3: DD imaging ────────────────────────────────────────────

    def _build_tab_dd(self):
        form = QtWidgets.QFormLayout(self.tab_dd)

        self.dd_source_cb = QtWidgets.QComboBox()
        self.dd_source_cb.addItems(["Selected device (from table)", "Image file"])

        self.dd_output_edit = QtWidgets.QLineEdit()
        self.dd_output_edit.setPlaceholderText("/mnt/c/forensics/vmfs6.dd")

        btn_out = QtWidgets.QPushButton("Browse output…")
        btn_out.clicked.connect(self._browse_dd_output)

        self.dd_bs_edit = QtWidgets.QLineEdit("1048576")   # 1 MiB
        self.dd_limit_edit = QtWidgets.QLineEdit()
        self.dd_limit_edit.setPlaceholderText("optional – limit in bytes, e.g. 10737418240 for 10 GB")

        btn_dd = QtWidgets.QPushButton("💾  Create bit‑for‑bit image")
        btn_dd.setStyleSheet("background:#1a4a8a;color:white;font-weight:bold;")
        btn_dd.clicked.connect(self._start_dd)

        form.addRow("Source:", self.dd_source_cb)
        form.addRow("Output file:", self.dd_output_edit)
        form.addRow("", btn_out)
        form.addRow("Block size (bytes):", self.dd_bs_edit)
        form.addRow("Limit bytes:", self.dd_limit_edit)
        form.addRow("", btn_dd)

    # ── Tab 4: VMFS Browser ──────────────────────────────────────────

    def _build_tab_browse(self):
        lay = QtWidgets.QVBoxLayout(self.tab_browse)

        top = QtWidgets.QHBoxLayout()
        self.browse_root_edit = QtWidgets.QLineEdit()
        self.browse_root_edit.setPlaceholderText(
            "Path to mounted VMFS6  (same as mount point above)")
        btn_set   = QtWidgets.QPushButton("Browse…")
        btn_load  = QtWidgets.QPushButton("📂  Load tree")
        btn_set.clicked.connect(self._browse_vmfs_root)
        btn_load.clicked.connect(self._load_vmfs_tree)
        top.addWidget(QtWidgets.QLabel("Root:"))
        top.addWidget(self.browse_root_edit)
        top.addWidget(btn_set)
        top.addWidget(btn_load)
        lay.addLayout(top)

        self.file_tree = QtWidgets.QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Full Path"])
        self.file_tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.file_tree.setColumnWidth(1, 100)
        self.file_tree.itemExpanded.connect(self._on_tree_expand)
        lay.addWidget(self.file_tree)

        bot = QtWidgets.QHBoxLayout()
        self.selected_path_edit = QtWidgets.QLineEdit()
        self.selected_path_edit.setReadOnly(True)
        btn_export = QtWidgets.QPushButton("Export file…")
        btn_export.clicked.connect(self._export_file)
        bot.addWidget(QtWidgets.QLabel("Selected:"))
        bot.addWidget(self.selected_path_edit)
        bot.addWidget(btn_export)
        lay.addLayout(bot)

        self.file_tree.itemSelectionChanged.connect(
            lambda: self._on_file_selected())

    # ── Tab 5: WSL helper ────────────────────────────────────────────

    def _build_tab_wsl(self):
        lay = QtWidgets.QVBoxLayout(self.tab_wsl)

        info = QtWidgets.QLabel(
            "Generate PowerShell commands to attach a physical disk to WSL2.\n"
            "Run those commands in an elevated PowerShell on the Windows host.\n\n"
            "Workflow:\n"
            "  1. Open elevated PowerShell → run Get-Disk to find PHYSICALDRIVE N\n"
            "  2. Run wsl --mount command below\n"
            "  3. Inside WSL, open this tool → the disk appears as /dev/sdX\n"
            "  4. Use Mount / dd tabs normally."
        )
        info.setWordWrap(True)
        lay.addWidget(info)

        form = QtWidgets.QFormLayout()
        self.wsl_disk_edit = QtWidgets.QLineEdit()
        self.wsl_disk_edit.setPlaceholderText("e.g. 1")
        self.wsl_part_edit = QtWidgets.QLineEdit()
        self.wsl_part_edit.setPlaceholderText("leave empty for whole disk")
        form.addRow("PHYSICALDRIVE number (N):", self.wsl_disk_edit)
        form.addRow("Partition number (optional):", self.wsl_part_edit)
        lay.addLayout(form)

        btn_gen  = QtWidgets.QPushButton("⚙  Generate PowerShell commands")
        btn_copy = QtWidgets.QPushButton("📋  Copy to clipboard")
        btn_gen.clicked.connect(self._gen_wsl_cmds)
        btn_copy.clicked.connect(self._copy_wsl_cmds)
        lay.addWidget(btn_gen)
        lay.addWidget(btn_copy)

        self.wsl_out_edit = QtWidgets.QPlainTextEdit()
        self.wsl_out_edit.setReadOnly(True)
        lay.addWidget(self.wsl_out_edit)

    # ═══════════════════════ DEVICE DETECTION ════════════════════════

    def _populate_devices(self):
        self.device_table.setRowCount(0)

        if self.IS_WINDOWS:
            self._populate_windows()
        else:
            self._populate_linux()

    def _populate_linux(self):
        """
        Use lsblk to enumerate ALL block devices including unmounted ones.
        psutil only shows mounted partitions – useless for VMFS6.
        """
        try:
            out = subprocess.check_output(
                ["lsblk", "-rno", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"],
                text=True, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            self._append_log("lsblk not found – falling back to psutil (may miss VMFS).")
            self._populate_linux_fallback()
            return
        except subprocess.CalledProcessError as exc:
            self._append_log(f"lsblk error: {exc}")
            return

        for line in out.strip().splitlines():
            cols = line.split()
            if not cols:
                continue
            name       = cols[0]
            size       = cols[1]  if len(cols) > 1 else "?"
            dev_type   = cols[2]  if len(cols) > 2 else "?"
            fstype     = cols[3]  if len(cols) > 3 else ""
            mountpoint = cols[4]  if len(cols) > 4 else ""

            # skip loop, rom, ram devices
            if dev_type in ("loop", "rom", "ram"):
                continue

            dev_path = f"/dev/{name}"
            hint = ""
            if fstype == "" and dev_type in ("disk", "part"):
                hint = "⚠ No known FS – possible VMFS"
            elif "vmfs" in fstype.lower():
                hint = "✔ VMFS detected"

            self._add_device_row(dev_path, size, dev_type, fstype, mountpoint, hint)

        self._append_log(f"Device scan complete – {self.device_table.rowCount()} entries found.")

    def _populate_linux_fallback(self):
        """Read /sys/block directly when lsblk is unavailable."""
        try:
            block_devs = os.listdir("/sys/block")
        except Exception as exc:
            self._append_log(f"/sys/block not accessible: {exc}")
            return

        for name in sorted(block_devs):
            if name.startswith("loop") or name.startswith("ram"):
                continue
            dev_path = f"/dev/{name}"
            size = "?"
            try:
                with open(f"/sys/block/{name}/size") as f:
                    sectors = int(f.read().strip())
                    gb = sectors * 512 / 1024**3
                    size = f"{gb:.1f}G"
            except Exception:
                pass
            self._add_device_row(dev_path, size, "disk", "", "", "⚠ possible VMFS")

            # partitions
            for entry in sorted(os.listdir(f"/sys/block/{name}")):
                if entry.startswith(name):
                    psize = "?"
                    try:
                        with open(f"/sys/block/{name}/{entry}/size") as f:
                            sec = int(f.read().strip())
                            psize = f"{sec*512/1024**3:.1f}G"
                    except Exception:
                        pass
                    self._add_device_row(f"/dev/{entry}", psize, "part",
                                         "", "", "⚠ possible VMFS")

    def _populate_windows(self):
        """
        On Windows: list visible volumes (psutil) +
        enumerate PhysicalDrive0-7 for raw access.
        """
        seen = set()
        for part in psutil.disk_partitions(all=True):
            dev = part.device
            if dev in seen:
                continue
            seen.add(dev)
            size = "?"
            try:
                size = f"{psutil.disk_usage(part.mountpoint).total/1024**3:.1f}G"
            except Exception:
                pass
            self._add_device_row(dev, size, "Volume", part.fstype,
                                  part.mountpoint, "")

        # raw physical drives
        for idx in range(8):
            raw = f"\\\\.\\PhysicalDrive{idx}"
            self._add_device_row(raw, "unknown", "Physical", "", "",
                                  "Raw – use dd to image")

        self._append_log("Windows device scan complete.")

    def _add_device_row(self, path, size, dtype, fstype, mountpoint, hint):
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        for col, text in enumerate([path, size, dtype, fstype, mountpoint, hint]):
            item = QtWidgets.QTableWidgetItem(str(text))
            if "VMFS" in str(hint):
                item.setForeground(QtGui.QColor("#ffcc44"))
            self.device_table.setItem(row, col, item)

    def _scan_vmfs_candidates(self):
        """Mark rows with empty FS type as VMFS candidates."""
        hits = 0
        for row in range(self.device_table.rowCount()):
            fstype_item    = self.device_table.item(row, 3)
            mnt_item       = self.device_table.item(row, 4)
            hint_item      = self.device_table.item(row, 5)
            dev_type_item  = self.device_table.item(row, 2)

            if not (fstype_item and hint_item and dev_type_item):
                continue

            fstype     = fstype_item.text().strip()
            mnt        = mnt_item.text().strip() if mnt_item else ""
            dev_type   = dev_type_item.text().strip()

            if fstype == "" and dev_type in ("disk", "part", "Physical") \
                    and (mnt == "" or mnt == "-"):
                hint_item.setText("⚠ Possible VMFS6 candidate")
                for col in range(self.device_table.columnCount()):
                    it = self.device_table.item(row, col)
                    if it:
                        it.setForeground(QtGui.QColor("#ffcc44"))
                hits += 1

        self._append_log(f"Scan complete – {hits} VMFS candidate(s) highlighted.")

    # ═══════════════════════ HELPERS ═════════════════════════════════

    def _append_log(self, text: str):
        self.log_edit.appendPlainText(f"[{time.strftime('%H:%M:%S')}]  {text}")

    def _save_log(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save log", "vmfs6_log.txt", "Text (*.txt);;All (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_edit.toPlainText())
            self._append_log(f"Log saved → {path}")

    def _get_selected_device(self) -> str:
        row = self.device_table.currentRow()
        if row < 0:
            return ""
        item = self.device_table.item(row, 0)
        return item.text().strip() if item else ""

    def _resolve_source(self, combo: QtWidgets.QComboBox) -> str:
        if "device" in combo.currentText().lower():
            dev = self._get_selected_device()
            if not dev:
                raise RuntimeError("No device selected in the Sources table.")
            return dev
        else:
            img = self.image_path_edit.text().strip()
            if not img:
                raise RuntimeError("No image file specified in Sources tab.")
            if not os.path.exists(img):
                raise RuntimeError(f"Image file not found:\n{img}")
            return img

    # ── Browse dialogs ────────────────────────────────────────────────

    def _browse_image_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select image", "",
            "Disk images (*.dd *.img *.raw *.vmdk *.bin);;All (*)")
        if path:
            self.image_path_edit.setText(path)

    def _browse_mount_point(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select empty mount point directory")
        if path:
            self.mount_point_edit.setText(path)

    def _browse_dd_output(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "DD output file", "vmfs6_disk.dd")
        if path:
            self.dd_output_edit.setText(path)

    def _browse_vmfs_root(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select VMFS6 mount root")
        if path:
            self.browse_root_edit.setText(path)

    # ═══════════════════════ MOUNT / UNMOUNT ═════════════════════════

    def _mount_vmfs6(self):
        if self.IS_WINDOWS:
            QtWidgets.QMessageBox.warning(
                self, "Not supported",
                "vmfs6-fuse is not available on Windows.\n"
                "Use WSL/Ubuntu and run this tool there.")
            return

        try:
            source = self._resolve_source(self.mount_source_cb)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source error", str(exc))
            return

        mp = self.mount_point_edit.text().strip()
        if not mp:
            QtWidgets.QMessageBox.warning(self, "Mount point",
                                          "Please set a mount point directory.")
            return

        os.makedirs(mp, exist_ok=True)
        extra = self.mount_opts_edit.text().strip()

        def task(worker: WorkerThread):
            cmd = ["vmfs6-fuse"]
            if extra:
                cmd += extra.split()
            cmd += [source, mp]
            self._append_log("CMD: " + " ".join(cmd))

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True)
            except FileNotFoundError:
                raise RuntimeError(
                    "vmfs6-fuse not found.\n"
                    "Install:  sudo apt install vmfs6-tools")

            for line in iter(proc.stdout.readline, ""):
                if worker.stopped:
                    proc.terminate()
                    return
                self._append_log(line.rstrip())
            proc.wait()

            if proc.returncode not in (0, None):
                raise RuntimeError(f"vmfs6-fuse exited with code {proc.returncode}")

            worker.progress_changed.emit(100)
            # auto-fill browser tab
            self.browse_root_edit.setText(mp)

        self._run_worker(task)

    def _umount_vmfs(self):
        mp = self.mount_point_edit.text().strip()
        if not mp:
            QtWidgets.QMessageBox.warning(self, "Mount point", "Please set a mount point.")
            return

        def task(worker: WorkerThread):
            cmd = ["fusermount", "-u", mp]
            self._append_log("CMD: " + " ".join(cmd))
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            out, _ = proc.communicate()
            if out:
                self._append_log(out.strip())
            if proc.returncode != 0:
                raise RuntimeError(f"fusermount failed (code {proc.returncode})")
            worker.progress_changed.emit(100)

        self._run_worker(task)

    # ═══════════════════════ DD IMAGING ══════════════════════════════

    def _start_dd(self):
        try:
            source = self._resolve_source(self.dd_source_cb)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source error", str(exc))
            return

        out_path = self.dd_output_edit.text().strip()
        if not out_path:
            QtWidgets.QMessageBox.warning(self, "No output", "Please set an output file.")
            return

        try:
            bs = int(self.dd_bs_edit.text().strip())
            assert bs > 0
        except Exception:
            QtWidgets.QMessageBox.warning(self, "Block size", "Block size must be a positive integer.")
            return

        limit = None
        if self.dd_limit_edit.text().strip():
            try:
                limit = int(self.dd_limit_edit.text().strip())
                assert limit > 0
            except Exception:
                QtWidgets.QMessageBox.warning(self, "Limit", "Limit must be a positive integer.")
                return

        if QtWidgets.QMessageBox.question(
            self, "Confirm imaging",
            f"Source:\n  {source}\n\nDestination:\n  {out_path}\n\nContinue?"
        ) != QtWidgets.QMessageBox.Yes:
            return

        def task(worker: WorkerThread):
            self._append_log(f"Imaging  {source}  →  {out_path}")

            # detect total size on Linux
            total = None
            if not self.IS_WINDOWS and source.startswith("/dev/"):
                try:
                    r = subprocess.check_output(
                        ["blockdev", "--getsize64", source], text=True)
                    total = int(r.strip())
                    self._append_log(f"Device size: {total/1024**3:.2f} GB")
                except Exception as exc:
                    self._append_log(f"Size detection failed: {exc}")

            # ensure output directory exists
            out_dir = os.path.dirname(os.path.abspath(out_path))
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            copied = 0
            t0 = time.time()

            with open(source, "rb", buffering=0) as src, \
                 open(out_path,  "wb") as dst:

                while True:
                    if worker.stopped:
                        self._append_log("Imaging cancelled.")
                        break

                    to_read = bs
                    if limit is not None:
                        remaining = limit - copied
                        if remaining <= 0:
                            break
                        to_read = min(to_read, remaining)

                    chunk = src.read(to_read)
                    if not chunk:
                        break
                    dst.write(chunk)
                    copied += len(chunk)

                    # emit progress – NOTE: must use worker.progress_changed, not self
                    if total:
                        denom = min(total, limit or total)
                        worker.progress_changed.emit(
                            min(int(copied * 100 / denom), 100))
                    else:
                        worker.progress_changed.emit(
                            (copied // (bs * 100)) % 100)

            elapsed = time.time() - t0
            self._append_log(
                f"Done – {copied/1024**3:.3f} GB copied in {elapsed:.1f} s")
            worker.progress_changed.emit(100)

        self._run_worker(task)

    # ═══════════════════════ VMFS FILE BROWSER ═══════════════════════

    def _load_vmfs_tree(self):
        root_path = self.browse_root_edit.text().strip()
        if not root_path or not os.path.isdir(root_path):
            QtWidgets.QMessageBox.warning(
                self, "Invalid path",
                "Please set a valid mounted VMFS6 directory.")
            return

        self.file_tree.clear()
        self._append_log(f"Loading VMFS tree from: {root_path}")

        root_item = QtWidgets.QTreeWidgetItem(
            [os.path.basename(root_path) or "/", "", root_path])
        root_item.setIcon(0, self.style().standardIcon(
            QtWidgets.QStyle.SP_DriveHDIcon))
        self.file_tree.addTopLevelItem(root_item)

        self._fill_tree_level(root_item, root_path)
        root_item.setExpanded(True)
        self._append_log("Tree loaded (top level). Expand folders to load deeper.")

    def _fill_tree_level(self, parent_item: QtWidgets.QTreeWidgetItem, dir_path: str):
        try:
            entries = sorted(os.scandir(dir_path), key=lambda e: (not e.is_dir(), e.name))
        except PermissionError as exc:
            self._append_log(f"Permission denied: {exc}")
            return
        except OSError as exc:
            self._append_log(f"Error reading {dir_path}: {exc}")
            return

        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                size_txt = ""
                icon = self.style().standardIcon(QtWidgets.QStyle.SP_DirIcon)
                child = QtWidgets.QTreeWidgetItem([entry.name, size_txt, entry.path])
                child.setIcon(0, icon)
                # placeholder so expand arrow appears
                dummy = QtWidgets.QTreeWidgetItem(["…", "", ""])
                child.addChild(dummy)
                parent_item.addChild(child)
            else:
                try:
                    sz = entry.stat(follow_symlinks=False).st_size
                    size_txt = self._fmt_size(sz)
                except Exception:
                    size_txt = "?"
                icon = self.style().standardIcon(QtWidgets.QStyle.SP_FileIcon)
                child = QtWidgets.QTreeWidgetItem([entry.name, size_txt, entry.path])
                child.setIcon(0, icon)
                parent_item.addChild(child)

    def _on_tree_expand(self, item: QtWidgets.QTreeWidgetItem):
        """Lazy-load directory contents on expand."""
        if item.childCount() == 1 and item.child(0).text(0) == "…":
            item.removeChild(item.child(0))
            self._fill_tree_level(item, item.text(2))

    def _on_file_selected(self):
        sel = self.file_tree.selectedItems()
        if sel:
            self.selected_path_edit.setText(sel[0].text(2))

    def _export_file(self):
        path = self.selected_path_edit.text().strip()
        if not path or not os.path.isfile(path):
            QtWidgets.QMessageBox.warning(
                self, "No file", "Select a file in the tree first.")
            return

        dest, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export file", os.path.basename(path))
        if not dest:
            return

        try:
            with open(path, "rb") as src, open(dest, "wb") as dst:
                while chunk := src.read(1024 * 1024):
                    dst.write(chunk)
            self._append_log(f"Exported:  {path}  →  {dest}")
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, "Export failed", str(exc))

    @staticmethod
    def _fmt_size(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"

    # ═══════════════════════ WSL HELPER ══════════════════════════════

    def _gen_wsl_cmds(self):
        n = self.wsl_disk_edit.text().strip()
        p = self.wsl_part_edit.text().strip()
        if not n:
            QtWidgets.QMessageBox.warning(
                self, "Missing", "Enter PHYSICALDRIVE number.")
            return

        dev = f"\\\\.\\PHYSICALDRIVE{n}"
        lines = [
            "# ── Run in elevated PowerShell on Windows host ──",
            "",
            "# List all physical disks to confirm the right number:",
            "Get-CimInstance -ClassName Win32_DiskDrive |"
            " Select-Object DeviceID, Model, Size",
            "",
            "# Optional: take the disk offline so Windows doesn't lock it:",
            "diskpart",
            f"  select disk {n}",
            "  offline disk",
            "",
        ]
        if p:
            lines += [
                f"# Attach partition {p} of PHYSICALDRIVE{n} to WSL2:",
                f"wsl --mount {dev} --partition {p} --bare",
            ]
        else:
            lines += [
                f"# Attach entire PHYSICALDRIVE{n} to WSL2:",
                f"wsl --mount {dev} --bare",
            ]
        lines += [
            "",
            "# ── Inside WSL, run this tool and look for /dev/sdX ──",
        ]
        self.wsl_out_edit.setPlainText("\n".join(lines))
        self._append_log("PowerShell commands generated.")

    def _copy_wsl_cmds(self):
        text = self.wsl_out_edit.toPlainText()
        if not text:
            return
        try:
            proc = subprocess.Popen(
                ["xclip", "-selection", "clipboard"],
                stdin=subprocess.PIPE, text=True)
            proc.communicate(text)
            self._append_log("Copied to clipboard via xclip.")
        except Exception:
            QtWidgets.QApplication.clipboard().setText(text)
            self._append_log("Copied to clipboard (Qt fallback).")

    # ═══════════════════════ WORKER MANAGEMENT ═══════════════════════

    def _run_worker(self, target):
        if self.worker and self.worker.isRunning():
            QtWidgets.QMessageBox.warning(
                self, "Busy", "Another operation is already running.\n"
                "Wait for it to finish or restart the app.")
            return

        self.progress.setValue(0)
        self.worker = WorkerThread(target)
        self.worker.progress_changed.connect(self.progress.setValue)
        self.worker.finished_ok.connect(
            lambda: self._append_log("✔ Operation completed successfully."))
        self.worker.finished_error.connect(self._on_error)
        self.worker.start()

    def _on_error(self, msg: str):
        self._append_log(f"✘ Error: {msg}")
        QtWidgets.QMessageBox.critical(self, "Error", msg)


# ─────────────────────────── Entry Point ─────────────────────────────

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
