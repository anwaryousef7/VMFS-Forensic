import os
import sys
import subprocess
import time

import psutil
from PyQt5 import QtCore, QtGui, QtWidgets


# ═══════════════════════════════════════════════════════════
#  Worker Thread  –  ALL log calls via signal (no direct UI)
# ═══════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════
#  Main Window
# ═══════════════════════════════════════════════════════════

class VMFSGui(QtWidgets.QMainWindow):

    IS_WIN = (os.name == "nt")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VMFS6 Forensic Utility")
        self.resize(1150, 740)
        self.worker = None

        self._build_ui()
        self._populate_devices()

    # ──────────────────────── UI ────────────────────────────

    def _build_ui(self):
        central = QtWidgets.QWidget()
        root    = QtWidgets.QVBoxLayout(central)

        tabs = QtWidgets.QTabWidget()
        root.addWidget(tabs)

        # Tab 1 – Sources
        self.tab_src = QtWidgets.QWidget()
        self._build_tab_source()
        tabs.addTab(self.tab_src, "📀  Sources")

        # Tab 2 – Mount
        self.tab_mount = QtWidgets.QWidget()
        self._build_tab_mount()
        tabs.addTab(self.tab_mount, "🔗  Mount VMFS6")

        # Tab 3 – DD imaging
        self.tab_dd = QtWidgets.QWidget()
        self._build_tab_dd()
        tabs.addTab(self.tab_dd, "💾  Imaging (dd)")

        # Tab 4 – File browser
        self.tab_browse = QtWidgets.QWidget()
        self._build_tab_browse()
        tabs.addTab(self.tab_browse, "📂  VMFS Browser")

        # Tab 5 – WSL Helper
        self.tab_wsl = QtWidgets.QWidget()
        self._build_tab_wsl()
        tabs.addTab(self.tab_wsl, "⚙  WSL Helper")

        # ── Log + progress bar ──
        root.addWidget(QtWidgets.QLabel("Log:"))
        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(130)
        root.addWidget(self.log_edit)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        root.addWidget(self.progress)

        btn_row = QtWidgets.QHBoxLayout()
        b_clear = QtWidgets.QPushButton("Clear log")
        b_save  = QtWidgets.QPushButton("Save log…")
        b_clear.clicked.connect(self.log_edit.clear)
        b_save.clicked.connect(self._save_log)
        btn_row.addWidget(b_clear)
        btn_row.addWidget(b_save)
        btn_row.addStretch()
        root.addLayout(btn_row)

        self.setCentralWidget(central)

    # ── Tab 1 : Sources ──────────────────────────────────────

    def _build_tab_source(self):
        lay = QtWidgets.QVBoxLayout(self.tab_src)

        toolbar = QtWidgets.QHBoxLayout()
        b_refresh = QtWidgets.QPushButton("🔄  Refresh")
        b_scan    = QtWidgets.QPushButton("🔍  Scan VMFS candidates")
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
        hdr = self.device_table.horizontalHeader()
        hdr.setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SingleSelection)
        self.device_table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)

        # Right-click context menu
        self.device_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(
            self._device_context_menu)

        # Double-click → auto mount
        self.device_table.doubleClicked.connect(self._on_device_double_click)

        lay.addWidget(self.device_table)

        # Image file
        grp  = QtWidgets.QGroupBox("Use raw image / VMDK as source")
        glay = QtWidgets.QHBoxLayout(grp)
        self.image_path_edit = QtWidgets.QLineEdit()
        self.image_path_edit.setPlaceholderText(
            "/path/to/disk.dd  or  /path/to/disk.vmdk")
        b_img = QtWidgets.QPushButton("Browse…")
        b_img.clicked.connect(self._browse_image_file)
        glay.addWidget(QtWidgets.QLabel("Image file:"))
        glay.addWidget(self.image_path_edit)
        glay.addWidget(b_img)
        lay.addWidget(grp)

    # ── Tab 2 : Mount ────────────────────────────────────────

    def _build_tab_mount(self):
        lay = QtWidgets.QVBoxLayout(self.tab_mount)

        # Source selection
        src_grp  = QtWidgets.QGroupBox("Mount source")
        src_form = QtWidgets.QFormLayout(src_grp)

        self.mount_source_cb = QtWidgets.QComboBox()
        self.mount_source_cb.addItems(
            ["Selected device (from table)", "Image file"])

        src_form.addRow("Source type:", self.mount_source_cb)

        # Manually override device path
        self.mount_dev_override = QtWidgets.QLineEdit()
        self.mount_dev_override.setPlaceholderText(
            "Leave empty to use table selection  –  or type e.g.  /dev/sdc1")
        src_form.addRow("Device override:", self.mount_dev_override)
        lay.addWidget(src_grp)

        # Mount options
        opt_grp  = QtWidgets.QGroupBox("Mount options")
        opt_form = QtWidgets.QFormLayout(opt_grp)

        self.mount_point_edit = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_mp = QtWidgets.QPushButton("Browse…")
        b_mp.clicked.connect(self._browse_mount_point)

        self.mount_opts_edit = QtWidgets.QLineEdit()
        self.mount_opts_edit.setPlaceholderText(
            "Optional extra flags, e.g.  -o allow_other")

        self.mount_sudo_chk = QtWidgets.QCheckBox(
            "Use sudo  (required if not root)")
        self.mount_sudo_chk.setChecked(True)

        mp_row = QtWidgets.QHBoxLayout()
        mp_row.addWidget(self.mount_point_edit)
        mp_row.addWidget(b_mp)

        opt_form.addRow("Mount point:", mp_row)
        opt_form.addRow("Extra flags:", self.mount_opts_edit)
        opt_form.addRow("", self.mount_sudo_chk)
        lay.addWidget(opt_grp)

        # Buttons
        btn_row = QtWidgets.QHBoxLayout()
        b_mount  = QtWidgets.QPushButton("▶  Mount VMFS6")
        b_umount = QtWidgets.QPushButton("⏹  Unmount")
        b_mount.setStyleSheet(
            "background:#1a7a1a;color:white;font-weight:bold;padding:6px;")
        b_umount.setStyleSheet(
            "background:#7a1a1a;color:white;font-weight:bold;padding:6px;")
        b_mount.clicked.connect(self._mount_vmfs6)
        b_umount.clicked.connect(self._umount_vmfs)
        btn_row.addWidget(b_mount)
        btn_row.addWidget(b_umount)
        lay.addLayout(btn_row)

        note = QtWidgets.QLabel(
            "ℹ  vmfs6-fuse is Linux/WSL only.\n"
            "Install:  sudo apt install vmfs6-tools\n"
            "Tip: double-click a device in Sources tab to auto-fill and mount.")
        note.setStyleSheet("color:#ffcc44;margin-top:8px;")
        lay.addWidget(note)
        lay.addStretch()

    # ── Tab 3 : DD imaging ───────────────────────────────────

    def _build_tab_dd(self):
        lay = QtWidgets.QVBoxLayout(self.tab_dd)

        grp  = QtWidgets.QGroupBox("Bit-for-bit imaging")
        form = QtWidgets.QFormLayout(grp)

        self.dd_source_cb = QtWidgets.QComboBox()
        self.dd_source_cb.addItems(
            ["Selected device (from table)", "Image file"])

        self.dd_dev_override = QtWidgets.QLineEdit()
        self.dd_dev_override.setPlaceholderText(
            "Leave empty to use table selection  –  or type e.g.  /dev/sdc1")

        self.dd_output_edit = QtWidgets.QLineEdit()
        self.dd_output_edit.setPlaceholderText(
            "/home/user/vmfs6_backup.dd  or  /mnt/c/forensics/vmfs6.dd")
        b_out = QtWidgets.QPushButton("Browse…")
        b_out.clicked.connect(self._browse_dd_output)

        self.dd_bs_edit    = QtWidgets.QLineEdit("1048576")
        self.dd_limit_edit = QtWidgets.QLineEdit()
        self.dd_limit_edit.setPlaceholderText(
            "optional  –  limit in bytes (leave empty = full disk)")

        out_row = QtWidgets.QHBoxLayout()
        out_row.addWidget(self.dd_output_edit)
        out_row.addWidget(b_out)

        form.addRow("Source:",          self.dd_source_cb)
        form.addRow("Device override:", self.dd_dev_override)
        form.addRow("Output file:",     out_row)
        form.addRow("Block size (B):",  self.dd_bs_edit)
        form.addRow("Limit bytes:",     self.dd_limit_edit)
        lay.addWidget(grp)

        b_dd = QtWidgets.QPushButton("💾  Start imaging")
        b_dd.setStyleSheet(
            "background:#1a4a8a;color:white;"
            "font-weight:bold;padding:8px;")
        b_dd.clicked.connect(self._start_dd)
        lay.addWidget(b_dd)
        lay.addStretch()

    # ── Tab 4 : File browser ─────────────────────────────────

    def _build_tab_browse(self):
        lay = QtWidgets.QVBoxLayout(self.tab_browse)

        top = QtWidgets.QHBoxLayout()
        self.browse_root_edit = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_set  = QtWidgets.QPushButton("Browse…")
        b_load = QtWidgets.QPushButton("📂  Load tree")
        b_set.clicked.connect(self._browse_vmfs_root)
        b_load.clicked.connect(self._load_vmfs_tree)
        top.addWidget(QtWidgets.QLabel("VMFS root:"))
        top.addWidget(self.browse_root_edit)
        top.addWidget(b_set)
        top.addWidget(b_load)
        lay.addLayout(top)

        self.file_tree = QtWidgets.QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Full Path"])
        self.file_tree.header().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch)
        self.file_tree.setColumnWidth(1, 90)
        self.file_tree.itemExpanded.connect(self._on_tree_expand)
        lay.addWidget(self.file_tree)

        bot = QtWidgets.QHBoxLayout()
        self.selected_path_edit = QtWidgets.QLineEdit()
        self.selected_path_edit.setReadOnly(True)
        b_export = QtWidgets.QPushButton("Export selected file…")
        b_export.clicked.connect(self._export_file)
        bot.addWidget(QtWidgets.QLabel("Selected:"))
        bot.addWidget(self.selected_path_edit)
        bot.addWidget(b_export)
        lay.addLayout(bot)

        self.file_tree.itemSelectionChanged.connect(
            self._on_file_selected)

    # ── Tab 5 : WSL Helper ───────────────────────────────────

    def _build_tab_wsl(self):
        lay = QtWidgets.QVBoxLayout(self.tab_wsl)

        info = QtWidgets.QLabel(
            "Generate PowerShell commands to pass a physical disk into WSL2.\n"
            "Run these commands in an elevated PowerShell on the Windows host.\n\n"
            "Workflow:\n"
            "  1. Elevated PowerShell → Get-Disk  (find PHYSICALDRIVE N)\n"
            "  2. Run the generated wsl --mount command\n"
            "  3. Inside WSL, refresh Sources – disk appears as /dev/sdX\n"
            "  4. Double-click the disk to mount, or use dd tab."
        )
        info.setWordWrap(True)
        lay.addWidget(info)

        form = QtWidgets.QFormLayout()
        self.wsl_disk_edit = QtWidgets.QLineEdit()
        self.wsl_disk_edit.setPlaceholderText("e.g.  2")
        self.wsl_part_edit = QtWidgets.QLineEdit()
        self.wsl_part_edit.setPlaceholderText("e.g.  1  (leave empty for whole disk)")
        form.addRow("PHYSICALDRIVE number (N):", self.wsl_disk_edit)
        form.addRow("Partition number:", self.wsl_part_edit)
        lay.addLayout(form)

        btn_row = QtWidgets.QHBoxLayout()
        b_gen  = QtWidgets.QPushButton("⚙  Generate commands")
        b_copy = QtWidgets.QPushButton("📋  Copy to clipboard")
        b_gen.clicked.connect(self._gen_wsl_cmds)
        b_copy.clicked.connect(self._copy_wsl_cmds)
        btn_row.addWidget(b_gen)
        btn_row.addWidget(b_copy)
        lay.addLayout(btn_row)

        self.wsl_out_edit = QtWidgets.QPlainTextEdit()
        self.wsl_out_edit.setReadOnly(True)
        lay.addWidget(self.wsl_out_edit)

    # ═══════════════════ DEVICE DETECTION ═══════════════════

    def _populate_devices(self):
        self.device_table.setRowCount(0)
        if self.IS_WIN:
            self._populate_windows()
        else:
            self._populate_linux()

    def _populate_linux(self):
        """Use lsblk to list ALL block devices, mounted or not."""
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
                hint = "✔ VMFS detected"
                fg   = QtGui.QColor("#44ff88")
            elif fst == "" and dtype in ("disk", "part"):
                hint = "⚠ Unknown FS – possible VMFS"
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
                "⚠ possible VMFS", QtGui.QColor("#ffcc44"))
            # partitions
            for entry in sorted(os.listdir(f"/sys/block/{name}")):
                if entry.startswith(name):
                    ps = self._sysblock_size(name, entry)
                    self._add_device_row(
                        f"/dev/{entry}", ps, "part", "", "",
                        "⚠ possible VMFS", QtGui.QColor("#ffcc44"))

    @staticmethod
    def _sysblock_size(disk, part=None):
        try:
            p = (f"/sys/block/{disk}/{part}/size"
                 if part else f"/sys/block/{disk}/size")
            with open(p) as f:
                sec = int(f.read().strip())
            return f"{sec*512/1024**3:.1f}G"
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
                part.device, sz, "Volume",
                part.fstype, part.mountpoint, "")
        for i in range(8):
            raw = f"\\\\.\\PhysicalDrive{i}"
            self._add_device_row(
                raw, "?", "Physical", "", "", "Raw device – use dd")
        self._log("Windows device scan complete.")

    def _add_device_row(self, path, size, dtype,
                        fstype, mnt, hint, fg=None):
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
                hnt.setText("⚠ Possible VMFS6 candidate")
                for c in range(self.device_table.columnCount()):
                    it = self.device_table.item(row, c)
                    if it:
                        it.setForeground(QtGui.QColor("#ffcc44"))
                hits += 1
        self._log(f"Scan: {hits} VMFS6 candidate(s) highlighted.")

    # ═══════════════════ CONTEXT MENU & DOUBLE-CLICK ════════

    def _device_context_menu(self, pos):
        row = self.device_table.rowAt(pos.y())
        if row < 0:
            return
        self.device_table.selectRow(row)
        dev = self.device_table.item(row, 0).text()

        menu = QtWidgets.QMenu(self)
        a_mount = menu.addAction("▶  Mount VMFS6  (vmfs6-fuse)")
        a_dd    = menu.addAction("💾  Create dd image")
        a_copy  = menu.addAction("📋  Copy device path")
        menu.addSeparator()
        a_fill  = menu.addAction("✏  Fill mount device field")

        action = menu.exec_(self.device_table.viewport().mapToGlobal(pos))

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
        dev = self.device_table.item(row, 0).text() if row >= 0 else ""
        if dev:
            self._quick_mount(dev)

    def _quick_mount(self, device: str):
        """Auto-fill mount tab and start mount immediately."""
        self.mount_dev_override.setText(device)
        self.mount_source_cb.setCurrentIndex(0)
        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"
        self.mount_point_edit.setText(mp)
        self.tabs.setCurrentIndex(1)
        self._log(f"Quick-mount triggered for  {device}  →  {mp}")
        self._mount_vmfs6()

    # ═══════════════════ MOUNT / UNMOUNT ════════════════════

    def _resolve_source(self, cb: QtWidgets.QComboBox,
                        override_edit: QtWidgets.QLineEdit) -> str:
        # manual override takes priority
        ov = override_edit.text().strip() if override_edit else ""
        if ov:
            return ov
        if "device" in cb.currentText().lower():
            dev = self._get_selected_device()
            if not dev:
                raise RuntimeError(
                    "No device selected in Sources table.\n"
                    "Click a row there, or type a device path in the override field.")
            return dev
        img = self.image_path_edit.text().strip()
        if not img:
            raise RuntimeError("No image file specified in Sources tab.")
        if not os.path.exists(img):
            raise RuntimeError(f"Image file not found:\n{img}")
        return img

    def _mount_vmfs6(self):
        if self.IS_WIN:
            QtWidgets.QMessageBox.warning(
                self, "Not supported",
                "vmfs6-fuse requires Linux or WSL.\n"
                "Run this tool inside WSL Ubuntu.")
            return

        try:
            source = self._resolve_source(
                self.mount_source_cb, self.mount_dev_override)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source error", str(exc))
            return

        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"
        os.makedirs(mp, exist_ok=True)
        extra  = self.mount_opts_edit.text().strip()
        use_sudo = self.mount_sudo_chk.isChecked()

        def task(worker: WorkerThread):
            cmd = []
            if use_sudo:
                cmd.append("sudo")
            cmd.append("vmfs6-fuse")
            if extra:
                cmd += extra.split()
            cmd += [source, mp]

            worker.log_message.emit("CMD:  " + " ".join(cmd))

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True)
            except FileNotFoundError:
                raise RuntimeError(
                    "vmfs6-fuse not found.\n"
                    "Fix:  sudo apt install vmfs6-tools")

            for line in iter(proc.stdout.readline, ""):
                if worker.stopped:
                    proc.terminate()
                    worker.log_message.emit("Mount cancelled.")
                    return
                if line.strip():
                    worker.log_message.emit(line.rstrip())

            proc.wait()
            if proc.returncode not in (0, None):
                raise RuntimeError(
                    f"vmfs6-fuse exited with code {proc.returncode}\n"
                    "Possible fixes:\n"
                    "  • Make sure you selected the right partition (e.g. /dev/sdc1, not /dev/sdc)\n"
                    "  • Check: sudo dmesg | tail\n"
                    "  • Try with sudo if not already enabled")

            worker.progress_changed.emit(100)
            worker.log_message.emit(
                f"✔ Mounted successfully at  {mp}\n"
                "→ Switch to VMFS Browser tab to browse files.")
            # auto-fill browser root
            QtCore.QMetaObject.invokeMethod(
                self.browse_root_edit, "setText",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, mp))

        self._run_worker(task)

    def _umount_vmfs(self):
        mp = self.mount_point_edit.text().strip() or "/mnt/vmfs6"

        def task(worker: WorkerThread):
            cmd = ["fusermount", "-u", mp]
            worker.log_message.emit("CMD:  " + " ".join(cmd))
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            out, _ = proc.communicate()
            if out.strip():
                worker.log_message.emit(out.strip())
            if proc.returncode != 0:
                raise RuntimeError(
                    f"fusermount failed (code {proc.returncode})")
            worker.progress_changed.emit(100)

        self._run_worker(task)

    # ═══════════════════ DD IMAGING ═════════════════════════

    def _start_dd(self):
        try:
            source = self._resolve_source(
                self.dd_source_cb, self.dd_dev_override)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source error", str(exc))
            return

        out_path = self.dd_output_edit.text().strip()
        if not out_path:
            QtWidgets.QMessageBox.warning(
                self, "No output", "Please set an output file path.")
            return

        try:
            bs = int(self.dd_bs_edit.text().strip())
            assert bs > 0
        except Exception:
            QtWidgets.QMessageBox.warning(
                self, "Block size", "Must be a positive integer.")
            return

        limit = None
        if self.dd_limit_edit.text().strip():
            try:
                limit = int(self.dd_limit_edit.text().strip())
                assert limit > 0
            except Exception:
                QtWidgets.QMessageBox.warning(
                    self, "Limit", "Must be a positive integer or empty.")
                return

        if QtWidgets.QMessageBox.question(
            self, "Confirm imaging",
            f"Source:\n  {source}\n\nDestination:\n  {out_path}\n\n"
            "This is a read-only operation on the source. Continue?"
        ) != QtWidgets.QMessageBox.Yes:
            return

        def task(worker: WorkerThread):
            worker.log_message.emit(f"Imaging  {source}  →  {out_path}")

            total = None
            if not self.IS_WIN and source.startswith("/dev/"):
                try:
                    r = subprocess.check_output(
                        ["blockdev", "--getsize64", source], text=True)
                    total = int(r.strip())
                    worker.log_message.emit(
                        f"Device size: {total/1024**3:.2f} GB")
                except Exception as exc:
                    worker.log_message.emit(f"Size detection failed: {exc}")

            out_dir = os.path.dirname(os.path.abspath(out_path))
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            copied = 0
            t0 = time.time()

            with open(source, "rb", buffering=0) as src, \
                 open(out_path, "wb") as dst:

                while True:
                    if worker.stopped:
                        worker.log_message.emit("Imaging cancelled.")
                        break

                    to_read = bs
                    if limit is not None:
                        rem = limit - copied
                        if rem <= 0:
                            break
                        to_read = min(to_read, rem)

                    chunk = src.read(to_read)
                    if not chunk:
                        break
                    dst.write(chunk)
                    copied += len(chunk)

                    # ← FIXED: worker.progress_changed, not self.progress_changed
                    if total:
                        denom = min(total, limit or total)
                        worker.progress_changed.emit(
                            min(int(copied * 100 / denom), 100))
                    else:
                        worker.progress_changed.emit(
                            (copied // (bs * 100)) % 100)

            elapsed = time.time() - t0
            worker.log_message.emit(
                f"✔ Done – {copied/1024**3:.3f} GB in {elapsed:.1f} s")
            worker.progress_changed.emit(100)

        self._run_worker(task)

    # ═══════════════════ FILE BROWSER ═══════════════════════

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
                "Please enter the path to the mounted VMFS6 directory.\n"
                "Mount it first using the Mount tab.")
            return
        self.file_tree.clear()
        self._log(f"Loading tree from  {root}")
        root_item = QtWidgets.QTreeWidgetItem(
            [os.path.basename(root) or "/", "", root])
        root_item.setIcon(
            0, self.style().standardIcon(QtWidgets.QStyle.SP_DriveHDIcon))
        self.file_tree.addTopLevelItem(root_item)
        self._fill_tree_level(root_item, root)
        root_item.setExpanded(True)
        self._log("Top-level tree loaded. Expand folders to go deeper.")

    def _fill_tree_level(self, parent: QtWidgets.QTreeWidgetItem,
                         dir_path: str):
        try:
            entries = sorted(
                os.scandir(dir_path),
                key=lambda e: (not e.is_dir(follow_symlinks=False), e.name))
        except (PermissionError, OSError) as exc:
            self._log(f"Cannot read  {dir_path}:  {exc}")
            return
