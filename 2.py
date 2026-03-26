import os
import sys
import subprocess
import time

import psutil
from PyQt5 import QtCore, QtGui, QtWidgets

# dissect.vmfs imports
from dissect.vmfs import VMFS, LVM  # type: ignore
from dissect.target import container  # type: ignore


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
        self.setWindowTitle("VMFS6 Forensic Utility (Linux / WSL)")
        self.resize(1200, 750)
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

        # Tab 2: Mount VMFS6 (FUSE)
        self.mount_tab = QtWidgets.QWidget()
        self._build_mount_tab()
        tabs.addTab(self.mount_tab, "Mount VMFS6 (vmfs6-fuse)")

        # Tab 3: Imaging (dd)
        self.dd_tab = QtWidgets.QWidget()
        self._build_dd_tab()
        tabs.addTab(self.dd_tab, "Imaging (dd)")

        # Tab 4: VMFS Browser (dissect.vmfs)
        self.vmfs_tab = QtWidgets.QWidget()
        self._build_vmfs_tab()
        tabs.addTab(self.vmfs_tab, "VMFS Browser (dissect.vmfs)")

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
        scan_vmfs_btn = QtWidgets.QPushButton("Scan likely VMFS6 partitions")
        scan_vmfs_btn.clicked.connect(self._scan_vmfs_candidates)
        top_layout.addWidget(refresh_btn)
        top_layout.addWidget(scan_vmfs_btn)
        top_layout.addStretch(1)

        layout.addLayout(top_layout)

        self.device_table = QtWidgets.QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(
            ["Device", "Size", "Type", "Mountpoint", "Hint", "Detected FS"]
        )
        self.device_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        layout.addWidget(self.device_table)

        # Image file selector
        img_group = QtWidgets.QGroupBox("Image file as source (dd / VMFS6 image / VMDK)")
        img_layout = QtWidgets.QHBoxLayout(img_group)
        self.image_path_edit = QtWidgets.QLineEdit()
        self.image_path_edit.setPlaceholderText("/path/to/image.dd or .img or .vmdk")
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
        self.mount_options_edit.setPlaceholderText("Extra options to vmfs6-fuse (e.g. -o allow_other)")

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
        self.dd_output_edit.setPlaceholderText("/mnt/c/forensics/vmfs6_disk.dd (or any path)")

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

    def _build_vmfs_tab(self):
        layout = QtWidgets.QVBoxLayout(self.vmfs_tab)

        top_layout = QtWidgets.QHBoxLayout()
        self.vmfs_source_type = QtWidgets.QComboBox()
        self.vmfs_source_type.addItems(["Selected device (from table)", "Image file"])
        open_btn = QtWidgets.QPushButton("Open VMFS (dissect)")
        open_btn.clicked.connect(self._open_vmfs_dissect)
        top_layout.addWidget(QtWidgets.QLabel("Source:"))
        top_layout.addWidget(self.vmfs_source_type)
        top_layout.addWidget(open_btn)
        top_layout.addStretch(1)

        layout.addLayout(top_layout)

        # Tree for directory listing
        self.vmfs_tree = QtWidgets.QTreeWidget()
        self.vmfs_tree.setHeaderLabels(["Path", "Type", "Size"])
        layout.addWidget(self.vmfs_tree)

        # File preview / export
        bottom_layout = QtWidgets.QHBoxLayout()
        self.vmfs_selected_path = QtWidgets.QLineEdit()
        self.vmfs_selected_path.setReadOnly(True)
        export_btn = QtWidgets.QPushButton("Export selected file...")
        export_btn.clicked.connect(self._export_vmfs_file)

        bottom_layout.addWidget(QtWidgets.QLabel("Selected VMFS path:"))
        bottom_layout.addWidget(self.vmfs_selected_path)
        bottom_layout.addWidget(export_btn)
        layout.addLayout(bottom_layout)

        self.vmfs_tree.itemSelectionChanged.connect(self._on_vmfs_selection_changed)

        self._vmfs_fs = None  # will hold VMFS object

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

        # Linux / WSL expected
        try:
            lsblk_out = subprocess.check_output(
                ["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"], text=True
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
                fstype = parts[4] if len(parts) > 4 else ""
                device_path = f"/dev/{name}"

                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                self.device_table.setItem(row, 0, QtWidgets.QTableWidgetItem(device_path))
                self.device_table.setItem(row, 1, QtWidgets.QTableWidgetItem(size))
                self.device_table.setItem(row, 2, QtWidgets.QTableWidgetItem(dev_type))
                self.device_table.setItem(row, 3, QtWidgets.QTableWidgetItem(mountpoint))
                self.device_table.setItem(row, 4, QtWidgets.QTableWidgetItem(""))
                self.device_table.setItem(row, 5, QtWidgets.QTableWidgetItem(fstype))
        except Exception as e:
            self._append_log(f"lsblk failed: {e}")

    def _scan_vmfs_candidates(self):
        # ضع "Possible VMFS" على بارتشنات غير مركات و FSTYPE فاضية
        for row in range(self.device_table.rowCount()):
            dev_type_item = self.device_table.item(row, 2)
            mnt_item = self.device_table.item(row, 3)
            fs_item = self.device_table.item(row, 5)
            hint_item = self.device_table.item(row, 4)

            if not dev_type_item or not hint_item:
                continue

            dev_type = dev_type_item.text().strip()
            mountpoint = mnt_item.text().strip() if mnt_item else ""
            fstype = fs_item.text().strip() if fs_item else ""

            if dev_type in ("disk", "part") and (mountpoint == "" or mountpoint == "-") and fstype == "":
                hint_item.setText("Possible VMFS (unmounted block)")

        self._append_log("VMFS candidate scan completed (basic heuristic).")

    # ---------- File dialog helpers ----------

    def _browse_image_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select image file", filter="Images (*.dd *.img *.raw *.bin *.vmdk *.*)"
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

    # ---------- Source resolvers ----------

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

    def _resolve_vmfs_source(self) -> str:
        source_mode = self.vmfs_source_type.currentText()
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

    # ---------- Mount / Unmount via FUSE ----------

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

            if os.name != "nt" and source.startswith("/dev/"):
                try:
                    res = subprocess.check_output(["blockdev", "--getsize64", source], text=True)
                    total_size = int(res.strip())
                    self._append_log(f"Detected device size: {total_size / 1024**3:.2f} GB")
                except Exception as e:
                    self._append_log(f"Could not detect device size: {e}")

            bytes_copied = 0
            start = time.time()

            out_dir = os.path.dirname(os.path.abspath(out_path))
            if out_dir and not os.path.exists(out_dir):
                os.makedirs(out_dir, exist_ok=True)

            with open(source, "rb", buffering=0) as src, open(out_path, "wb") as dst:
                while True:
                    if worker.stopped:
                        self._append_log("Imaging cancelled by user.")
                        break

                    if limit_bytes is not None and bytes_copied >= limit_bytes:
                        break

                    to_read = block_size
                    if limit_bytes is not None:
                        remaining = limit_bytes - bytes_copied
                        if remaining <= 0:
                            break
                        to_read = min(to_read, remaining)

                    chunk = src.read(to_read)
                    if not chunk:
                        break

                    dst.write(chunk)
                    bytes_copied += len(chunk)

                    if total_size:
                        denom = min(total_size, limit_bytes or total_size)
                        progress = int((bytes_copied / denom) * 100)
                        self.progress_changed.emit(min(progress, 100))
                    else:
                        progress = (bytes_copied // (block_size * 100)) % 100
                        self.progress_changed.emit(progress)

            elapsed = time.time() - start
            self._append_log(
                f"Imaging completed: {bytes_copied / 1024**3:.2f} GB in {elapsed:.1f} seconds"
            )
            self.progress_changed.emit(100)

        self._run_worker(do_dd)

    # ---------- VMFS Browser (dissect.vmfs) ----------

    def _open_vmfs_dissect(self):
        try:
            source = self._resolve_vmfs_source()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Invalid source", str(e))
            return

        try:
            # open via dissect.target.container to handle raw, qcow, vmdk... [web:42][web:46]
            fh = container.open(source)
            lvm = LVM([fh])
            fs = VMFS(lvm)  # supports VMFS5/VMFS6 read-only [web:40][web:48]
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "VMFS error", f"Failed to open VMFS: {e}")
            self._append_log(f"dissect.vmfs open failed: {e}")
            return

        self._vmfs_fs = fs
        self._append_log("VMFS opened via dissect.vmfs. Building directory tree...")
        self.vmfs_tree.clear()

        root_desc = fs.get("/")  # root directory [web:40][web:48]
        root_item = QtWidgets.QTreeWidgetItem(["/", "dir", ""])
        self.vmfs_tree.addTopLevelItem(root_item)

        def add_children(parent_item, path_prefix, desc):
            try:
                entries = desc.listdir()  # returns dict name->FileDescriptor [web:48]
            except Exception as e:
                self._append_log(f"Failed to list {path_prefix}: {e}")
                return

            for name, fd in entries.items():
                child_path = os.path.join(path_prefix, name)
                ftype = "dir" if fd.is_dir() else "file"
                size = ""
                try:
                    if fd.is_file():
                        size = str(fd.size)
                except Exception:
                    size = ""
                item = QtWidgets.QTreeWidgetItem([child_path, ftype, size])
                parent_item.addChild(item)
                # Lazy load dirs: we can add a dummy child
                if fd.is_dir():
                    dummy = QtWidgets.QTreeWidgetItem(["(loading...)", "", ""])
                    item.addChild(dummy)

        add_children(root_item, "/", root_desc)
        self.vmfs_tree.expandItem(root_item)
        self._append_log("VMFS directory tree (top level) loaded.")

        # connect lazy loader
        self.vmfs_tree.itemExpanded.connect(self._on_vmfs_item_expanded)

    def _on_vmfs_item_expanded(self, item: QtWidgets.QTreeWidgetItem):
        if not self._vmfs_fs:
            return
        path = item.text(0)
        # إذا عنده طفل واحد اسمه (loading...) نحذفه ونحمّل children الحقيقيين
        if item.childCount() == 1 and item.child(0).text(0) == "(loading...)":
            item.removeChild(item.child(0))
            try:
                desc = self._vmfs_fs.get(path)
                self._append_log(f"Loading children of {path}")
            except Exception as e:
                self._append_log(f"Failed to get descriptor for {path}: {e}")
                return

            try:
                entries = desc.listdir()
            except Exception as e:
                self._append_log(f"Failed to list {path}: {e}")
                return

            for name, fd in entries.items():
                child_path = os.path.join(path, name)
                ftype = "dir" if fd.is_dir() else "file"
                size = ""
                try:
                    if fd.is_file():
                        size = str(fd.size)
                except Exception:
                    size = ""
                child_item = QtWidgets.QTreeWidgetItem([child_path, ftype, size])
                item.addChild(child_item)
                if fd.is_dir():
                    dummy = QtWidgets.QTreeWidgetItem(["(loading...)", "", ""])
                    child_item.addChild(dummy)

    def _on_vmfs_selection_changed(self):
        items = self.vmfs_tree.selectedItems()
        if not items:
            self.vmfs_selected_path.setText("")
            return
        self.vmfs_selected_path.setText(items[0].text(0))

    def _export_vmfs_file(self):
        if not self._vmfs_fs:
            QtWidgets.QMessageBox.warning(self, "No VMFS open", "Open a VMFS source first.")
            return
        path = self.vmfs_selected_path.text().strip()
        if not path:
            QtWidgets.QMessageBox.warning(self, "No file selected", "Select a file in the VMFS tree.")
            return

        try:
            desc = self._vmfs_fs.get(path)
            if not desc.is_file():
                QtWidgets.QMessageBox.warning(self, "Not a file", "Selected path is not a regular file.")
                return
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to get file descriptor: {e}")
            return

        out_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export VMFS file", os.path.basename(path)
        )
        if not out_path:
            return

        try:
            fh = desc.open()  # returns file-like object [web:40][web:48]
            with fh, open(out_path, "wb") as dst:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
            self._append_log(f"Exported VMFS file {path} -> {out_path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Export error", f"Failed to export: {e}")
            self._append_log(f"Export error: {e}")

    # ---------- Worker management ----------

    def _run_worker(self, target):
        if self.worker and self.worker.isRunning():
            QtWidgets.QMessageBox.warning(self, "Busy", "Another operation is already running.")
            return

        self.progress.setValue(0)
        self.worker = WorkerThread(target)
        self.worker.progress_changed.connect(self.progress.setValue)
        self.worker.finished_ok.connect(lambda: self._append_log("Operation finished successfully."))
        self.worker.finished_error.connect(self._on_worker_error)
        self.worker.start()

    def _on_worker_error(self, msg: str):
        self._append_log(f"Operation failed: {msg}")
        QtWidgets.QMessageBox.critical(self, "Error", msg)


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(40, 40, 40))
    palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(20, 20, 20))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(40, 40, 40))
    palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(40, 40, 40))
    palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(0, 120, 215))
    palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
    app.setPalette(palette)

    win = VMFS6Tool()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
