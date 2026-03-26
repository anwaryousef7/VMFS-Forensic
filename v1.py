import os
import sys
import subprocess
import threading
import time
from pathlib import Path

import psutil
from PyQt5 import QtCore, QtGui, QtWidgets


# ---------- Worker infrastructure ----------

class WorkerThread(QtCore.QThread):
    progress_changed = QtCore.pyqtSignal(int)
    log_message = QtCore.pyqtSignal(str)
    finished_ok = QtCore.pyqtSignal()
    finished_error = QtCore.pyqtSignal(str)

    def __init__(self, target, *args, **kwargs):
        super().__init__()
        self._target = target
        self._args = args
        self._kwargs = kwargs
        self._stop_flag = False

    def run(self):
        try:
            self._target(self)
            self.finished_ok.emit()
        except Exception as e:
            self.finished_error.emit(str(e))

    def stop(self):
        self._stop_flag = True

    @property
    def stopped(self):
        return self._stop_flag


# ---------- Main GUI ----------

class VMFS6Tool(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced VMFS6 Forensic Utility (WSL / Linux)")
        self.resize(1100, 700)
        self.worker = None

        self._build_ui()
        self._populate_devices()

    # ---------- UI ----------

    def _build_ui(self):
        central = QtWidgets.QWidget()
        main_layout = QtWidgets.QVBoxLayout(central)

        tabs = QtWidgets.QTabWidget()
        main_layout.addWidget(tabs)

        # Tab 1: Devices & Images
        self.devices_tab = QtWidgets.QWidget()
        self._build_devices_tab()
        tabs.addTab(self.devices_tab, "Sources (Devices / Images)")

        # Tab 2: Mount VMFS6
        self.mount_tab = QtWidgets.QWidget()
        self._build_mount_tab()
        tabs.addTab(self.mount_tab, "Mount VMFS6")

        # Tab 3: Imaging (dd)
        self.dd_tab = QtWidgets.QWidget()
        self._build_dd_tab()
        tabs.addTab(self.dd_tab, "Imaging (dd)")

        # Tab 4: WSL / Windows helper
        self.wsl_tab = QtWidgets.QWidget()
        self._build_wsl_tab()
        tabs.addTab(self.wsl_tab, "WSL / Windows Helper")

        # Bottom: log & progress
        bottom_layout = QtWidgets.QVBoxLayout()
        bottom_layout.addWidget(QtWidgets.QLabel("Log:"))

        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        bottom_layout.addWidget(self.log_edit, stretch=1)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        bottom_layout.addWidget(self.progress)

        # Save log button
        save_log_btn = QtWidgets.QPushButton("Save log to file")
        save_log_btn.clicked.connect(self._save_log)
        bottom_layout.addWidget(save_log_btn)

        main_layout.addLayout(bottom_layout)
        self.setCentralWidget(central)

    def _build_devices_tab(self):
        layout = QtWidgets.QVBoxLayout(self.devices_tab)

        top_layout = QtWidgets.QHBoxLayout()
        refresh_btn = QtWidgets.QPushButton("Refresh devices")
        refresh_btn.clicked.connect(self._populate_devices)
        scan_vmfs_btn = QtWidgets.QPushButton("Scan likely VMFS partitions")
        scan_vmfs_btn.clicked.connect(self._scan_vmfs_candidates)
        top_layout.addWidget(refresh_btn)
        top_layout.addWidget(scan_vmfs_btn)
        top_layout.addStretch(1)

        layout.addLayout(top_layout)

        self.device_table = QtWidgets.QTableWidget()
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels(
            ["Device", "Size (GB)", "Type", "Mountpoint", "Hint"]
        )
        self.device_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        layout.addWidget(self.device_table)

        # Image file selector
        img_group = QtWidgets.QGroupBox("Image file as source (dd / VMFS6 image)")
        img_layout = QtWidgets.QHBoxLayout(img_group)
        self.image_path_edit = QtWidgets.QLineEdit()
        self.image_path_edit.setPlaceholderText("/path/to/image.dd or .img")
        browse_img_btn = QtWidgets.QPushButton("Browse...")
        browse_img_btn.clicked.connect(self._browse_image_file)
        img_layout.addWidget(QtWidgets.QLabel("Image file:"))
        img_layout.addWidget(self.image_path_edit)
        img_layout.addWidget(browse_img_btn)

        layout.addWidget(img_group)

    def _build_mount_tab(self):
        layout = QtWidgets.QFormLayout(self.mount_tab)

        self.mount_source_type = QtWidgets.QComboBox()
        self.mount_source_type.addItems(["Selected device (from table)", "Image file"])

        self.mount_point_edit = QtWidgets.QLineEdit()
        self.mount_point_edit.setPlaceholderText("/mnt/vmfs6")

        self.mount_options_edit = QtWidgets.QLineEdit()
        self.mount_options_edit.setPlaceholderText("Extra options (e.g. -o allow_other)")

        browse_mount_btn = QtWidgets.QPushButton("Browse mount point")
        browse_mount_btn.clicked.connect(self._browse_mount_point)

        self.mount_btn = QtWidgets.QPushButton("Mount VMFS6 (vmfs6-fuse)")
        self.mount_btn.clicked.connect(self._mount_vmfs6)

        self.umount_btn = QtWidgets.QPushButton("Unmount (fusermount -u)")
        self.umount_btn.clicked.connect(self._umount_vmfs)

        layout.addRow("Mount source:", self.mount_source_type)
        layout.addRow("Mount point:", self.mount_point_edit)
        layout.addRow("", browse_mount_btn)
        layout.addRow("Extra vmfs6-fuse options:", self.mount_options_edit)
        layout.addRow("", self.mount_btn)
        layout.addRow("", self.umount_btn)

    def _build_dd_tab(self):
        layout = QtWidgets.QFormLayout(self.dd_tab)

        self.dd_source_type = QtWidgets.QComboBox()
        self.dd_source_type.addItems(["Selected device (from table)", "Image file"])

        self.dd_output_edit = QtWidgets.QLineEdit()
        self.dd_output_edit.setPlaceholderText("/mnt/c/forensics/vmfs6_disk.dd (to access from Windows)")

        browse_dd_btn = QtWidgets.QPushButton("Browse output")
        browse_dd_btn.clicked.connect(self._browse_dd_output)

        self.dd_block_size_edit = QtWidgets.QLineEdit("1048576")  # 1 MiB
        self.dd_limit_edit = QtWidgets.QLineEdit()
        self.dd_limit_edit.setPlaceholderText("Optional: limit bytes (empty = full device)")

        self.dd_btn = QtWidgets.QPushButton("Create bit‑for‑bit image (dd-like)")
        self.dd_btn.clicked.connect(self._start_dd)

        layout.addRow("Source:", self.dd_source_type)
        layout.addRow("Output file:", self.dd_output_edit)
        layout.addRow("", browse_dd_btn)
        layout.addRow("Block size (bytes):", self.dd_block_size_edit)
        layout.addRow("Limit bytes (optional):", self.dd_limit_edit)
        layout.addRow("", self.dd_btn)

    def _build_wsl_tab(self):
        layout = QtWidgets.QVBoxLayout(self.wsl_tab)

        info = QtWidgets.QLabel(
            "This tab helps you generate PowerShell commands to attach a physical disk\n"
            "to WSL2 using `wsl --mount` on Windows. Run these commands in an elevated\n"
            "PowerShell window on the Windows host, not inside WSL.\n\n"
            "Typical flow:\n"
            " 1. Identify the disk on Windows (PHYSICALDRIVE N).\n"
            " 2. Run: wsl --mount \\\\.\\PHYSICALDRIVEN --bare\n"
            " 3. Inside WSL, use this GUI on /dev/sdX for VMFS6 and dd operations."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        form = QtWidgets.QFormLayout()
        self.win_disk_number_edit = QtWidgets.QLineEdit()
        self.win_partition_number_edit = QtWidgets.QLineEdit()
        self.win_partition_number_edit.setPlaceholderText("(optional, for a specific partition)")

        form.addRow("Windows PHYSICALDRIVE number (N):", self.win_disk_number_edit)
        form.addRow("Partition number:", self.win_partition_number_edit)

        layout.addLayout(form)

        self.generated_ps_edit = QtWidgets.QPlainTextEdit()
        self.generated_ps_edit.setReadOnly(True)

        gen_btn = QtWidgets.QPushButton("Generate PowerShell commands")
        gen_btn.clicked.connect(self._generate_ps_commands)

        copy_btn = QtWidgets.QPushButton("Copy commands to clipboard (WSL xclip)")
        copy_btn.clicked.connect(self._copy_ps_to_clipboard)

        layout.addWidget(gen_btn)
        layout.addWidget(copy_btn)
        layout.addWidget(QtWidgets.QLabel("Generated PowerShell / cmd commands:"))
        layout.addWidget(self.generated_ps_edit)

    # ---------- Helpers & logging ----------

    def _append_log(self, text: str):
        ts = time.strftime("%H:%M:%S")
        self.log_edit.appendPlainText(f"[{ts}] {text}")

    def _save_log(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save log", "vmfs6_log.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.log_edit.toPlainText())
        self._append_log(f"Log saved to {path}")

    def _get_selected_device(self) -> str:
        row = self.device_table.currentRow()
        if row < 0:
            return ""
        item = self.device_table.item(row, 0)
        return item.text().strip() if item else ""

    # ---------- Devices & VMFS scan ----------

    def _populate_devices(self):
        self.device_table.setRowCount(0)

        if os.name == "nt":
            # In practice, this GUI is meant to run inside WSL/Linux,
            # but we keep this branch for completeness.
            for part in psutil.disk_partitions(all=True):
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                self.device_table.setItem(row, 0, QtWidgets.QTableWidgetItem(part.device))
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    size_gb = f"{usage.total / 1024**3:.2f}"
                except Exception:
                    size_gb = "unknown"
                self.device_table.setItem(row, 1, QtWidgets.QTableWidgetItem(size_gb))
                self.device_table.setItem(row, 2, QtWidgets.QTableWidgetItem("Volume"))
                self.device_table.setItem(row, 3, QtWidgets.QTableWidgetItem(part.mountpoint))
                self.device_table.setItem(row, 4, QtWidgets.QTableWidgetItem(""))
            return

        # Linux / WSL
        # Collect block devices via lsblk (gives better info than psutil alone)
        try:
            lsblk_out = subprocess.check_output(
                ["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"], text=True
            )
            lines = lsblk_out.strip().splitlines()[1:]
            for line in lines:
                parts = line.split()
                if not parts:
                    continue
                name = parts[0]
                size = parts[1] if len(parts) > 1 else "?"
                dev_type = parts[2] if len(parts) > 2 else "?"
                mountpoint = parts[3] if len(parts) > 3 else ""
                device_path = f"/dev/{name}"

                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                self.device_table.setItem(row, 0, QtWidgets.QTableWidgetItem(device_path))
                self.device_table.setItem(row, 1, QtWidgets.QTableWidgetItem(size))
                self.device_table.setItem(row, 2, QtWidgets.QTableWidgetItem(dev_type))
                self.device_table.setItem(row, 3, QtWidgets.QTableWidgetItem(mountpoint))
                self.device_table.setItem(row, 4, QtWidgets.QTableWidgetItem(""))
        except Exception as e:
            self._append_log(f"lsblk failed: {e}")

    def _scan_vmfs_candidates(self):
        # Very lightweight heuristic: mark large unmounted partitions as possible VMFS
        for row in range(self.device_table.rowCount()):
            dev_type_item = self.device_table.item(row, 2)
            mnt_item = self.device_table.item(row, 3)
            hint_item = self.device_table.item(row, 4)

            if not dev_type_item or not hint_item:
                continue

            dev_type = dev_type_item.text().strip()
            mountpoint = mnt_item.text().strip() if mnt_item else ""

            if dev_type in ("disk", "part") and (mountpoint == "" or mountpoint == "-"):
                hint_item.setText("Possible VMFS (unmounted block)")
            else:
                # leave others as is
                pass

        self._append_log("VMFS candidate scan completed (basic heuristic).")

    # ---------- File dialog helpers ----------

    def _browse_image_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select image file", filter="Images (*.dd *.img *.raw *.bin *.*)"
        )
        if path:
            self.image_path_edit.setText(path)

    def _browse_mount_point(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select mount point directory")
        if path:
            self.mount_point_edit.setText(path)

    def _browse_dd_output(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Select dd output file", "vmfs6_disk.dd"
        )
        if path:
            self.dd_output_edit.setText(path)

    # ---------- Mount / Unmount ----------

    def _resolve_mount_source(self) -> str:
        source_mode = self.mount_source_type.currentText()
        if "device" in source_mode.lower():
            dev = self._get_selected_device()
            if not dev:
                raise RuntimeError("No device selected in table.")
            return dev
        else:
            img = self.image_path_edit.text().strip()
            if not img:
                raise RuntimeError("No image file selected.")
            if not os.path.exists(img):
                raise RuntimeError(f"Image file does not exist: {img}")
            return img

    def _mount_vmfs6(self):
        try:
            source = self._resolve_mount_source()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Invalid source", str(e))
            return

        mount_point = self.mount_point_edit.text().strip()
        if not mount_point:
            QtWidgets.QMessageBox.warning(self, "No mount point", "Please set a mount point directory.")
            return

        if not os.path.exists(mount_point):
            try:
                os.makedirs(mount_point)
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to create mount point: {e}")
                return

        extra_opts = self.mount_options_edit.text().strip()

        def do_mount(worker: WorkerThread):
            cmd = ["vmfs6-fuse"]
            if extra_opts:
                # naive split; advanced parsing left to user
                cmd.extend(extra_opts.split())
            cmd.extend([source, mount_point])

            self._append_log("Executing: " + " ".join(cmd))
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except FileNotFoundError:
                raise RuntimeError("vmfs6-fuse not found. Install vmfs6-tools package.")

            while True:
                if worker.stopped:
                    proc.terminate()
                    self._append_log("Mount operation cancelled.")
                    return
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break
                if line:
                    self._append_log(line.rstrip())
                self.progress_changed.emit(40)

            rc = proc.returncode
            if rc != 0:
                raise RuntimeError(f"vmfs6-fuse failed with code {rc}")
            self.progress_changed.emit(100)

        self._run_worker(do_mount)

    def _umount_vmfs(self):
        mount_point = self.mount_point_edit.text().strip()
        if not mount_point:
            QtWidgets.QMessageBox.warning(self, "No mount point", "Please set a mount point directory.")
            return

        def do_umount(worker: WorkerThread):
            cmd = ["fusermount", "-u", mount_point]
            self._append_log("Executing: " + " ".join(cmd))
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            out, _ = proc.communicate()
            if out:
                self._append_log(out.strip())
            if proc.returncode != 0:
                raise RuntimeError(f"fusermount failed with code {proc.returncode}")
            self.progress_changed.emit(100)

        self._run_worker(do_umount)

    # ---------- Imaging (dd-like) ----------

    def _resolve_dd_source(self) -> str:
        source_mode = self.dd_source_type.currentText()
        if "device" in source_mode.lower():
            dev = self._get_selected_device()
            if not dev:
                raise RuntimeError("No device selected in table.")
            return dev
        else:
            img = self.image_path_edit.text().strip()
            if not img:
                raise RuntimeError("No image file selected.")
            if not os.path.exists(img):
                raise RuntimeError(f"Image file does not exist: {img}")
            return img

    def _start_dd(self):
        try:
            source = self._resolve_dd_source()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Invalid source", str(e))
            return

        out_path = self.dd_output_edit.text().strip()
        if not out_path:
            QtWidgets.QMessageBox.warning(self, "No output", "Please set an output file path.")
            return

        try:
            block_size = int(self.dd_block_size_edit.text().strip())
            if block_size <= 0:
                raise ValueError
        except Exception:
            QtWidgets.QMessageBox.warning(self, "Invalid block size", "Block size must be a positive integer.")
            return

        limit_bytes = None
        limit_text = self.dd_limit_edit.text().strip()
        if limit_text:
            try:
                limit_bytes = int(limit_text)
                if limit_bytes <= 0:
                    raise ValueError
            except Exception:
                QtWidgets.QMessageBox.warning(self, "Invalid limit", "Limit must be a positive integer or empty.")
                return

        msg = (
            f"This will read from source:\n  {source}\n"
            f"and write a bit‑for‑bit image to:\n  {out_path}\n\n"
            "Make sure you selected the correct source.\n"
            "Continue?"
        )
        if QtWidgets.QMessageBox.question(self, "Confirm imaging", msg) != QtWidgets.QMessageBox.Yes:
            return

        def do_dd(worker: WorkerThread):
            self._append_log(f"Starting imaging from {source} to {out_path}")
            total_size = None

            # Try to detect size if source is a block device
            if os.name != "nt" and source.startswith("/dev/"):
                try:
                    # use blockdev --getsize64 if available
                    res = subprocess.check_output(["blockdev", "--getsize64", source], text=True)
                    total_size = int(res.strip())
                    self._append_log(f"Detected device size: {total_size / 1024**3:.2f} GB")
                except Exception as e:
                    self._append_log(f"Could not detect device size: {e}")

            bytes_copied = 0
            start = time.time()

            # Ensure target dir exists
            out_dir =
