import os
import sys
import subprocess
import threading
import time
from pathlib import Path

import psutil
from PyQt5 import QtCore, QtGui, QtWidgets


class WorkerThread(QtCore.QThread):
    progress_changed = QtCore.pyqtSignal(int)
    log_message = QtCore.pyqtSignal(str)
    finished_ok = QtCore.pyqtSignal()
    finished_error = QtCore.pyqtSignal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self._stop_flag = False

    def run(self):
        try:
            self.func(self)
            self.finished_ok.emit()
        except Exception as e:
            self.finished_error.emit(str(e))

    def stop(self):
        self._stop_flag = True

    @property
    def stopped(self):
        return self._stop_flag


class VMFSGui(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VMFS6 Disk Utility")
        self.resize(900, 600)
        self.worker = None

        self._build_ui()
        self._populate_devices()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        # Top: device list
        dev_group = QtWidgets.QGroupBox("Available Block Devices / Physical Drives")
        dev_layout = QtWidgets.QVBoxLayout(dev_group)

        self.device_table = QtWidgets.QTableWidget()
        self.device_table.setColumnCount(4)
        self.device_table.setHorizontalHeaderLabels(["Name", "Size (GB)", "Type", "Mountpoint"])
        self.device_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        refresh_btn = QtWidgets.QPushButton("Refresh Devices")
        refresh_btn.clicked.connect(self._populate_devices)

        dev_layout.addWidget(self.device_table)
        dev_layout.addWidget(refresh_btn)

        # Middle: mount and dd options
        ops_group = QtWidgets.QGroupBox("Operations")
        ops_layout = QtWidgets.QGridLayout(ops_group)

        self.mount_point_edit = QtWidgets.QLineEdit()
        self.mount_point_edit.setPlaceholderText("/mnt/vmfs6 or any empty directory")

        browse_mount_btn = QtWidgets.QPushButton("Browse...")
        browse_mount_btn.clicked.connect(self._browse_mount_point)

        self.mount_btn = QtWidgets.QPushButton("Mount VMFS6 (Linux only)")
        self.mount_btn.clicked.connect(self._mount_vmfs6)

        self.umount_btn = QtWidgets.QPushButton("Unmount (Linux only)")
        self.umount_btn.clicked.connect(self._umount_vmfs)

        self.dd_output_edit = QtWidgets.QLineEdit()
        self.dd_output_edit.setPlaceholderText("/path/to/output.img")
        browse_dd_btn = QtWidgets.QPushButton("Browse...")
        browse_dd_btn.clicked.connect(self._browse_dd_output)

        self.dd_btn = QtWidgets.QPushButton("Create bit‑for‑bit image (dd)")
        self.dd_btn.clicked.connect(self._start_dd)

        ops_layout.addWidget(QtWidgets.QLabel("Mount point:"), 0, 0)
        ops_layout.addWidget(self.mount_point_edit, 0, 1)
        ops_layout.addWidget(browse_mount_btn, 0, 2)
        ops_layout.addWidget(self.mount_btn, 1, 1)
        ops_layout.addWidget(self.umount_btn, 1, 2)

        ops_layout.addWidget(QtWidgets.QLabel("DD output file:"), 2, 0)
        ops_layout.addWidget(self.dd_output_edit, 2, 1)
        ops_layout.addWidget(browse_dd_btn, 2, 2)
        ops_layout.addWidget(self.dd_btn, 3, 1)

        # Bottom: log + progress
        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        layout.addWidget(dev_group)
        layout.addWidget(ops_group)
        layout.addWidget(QtWidgets.QLabel("Log:"))
        layout.addWidget(self.log_edit)
        layout.addWidget(self.progress)

        self.setCentralWidget(central)

    def _append_log(self, text: str):
        ts = time.strftime("%H:%M:%S")
        self.log_edit.appendPlainText(f"[{ts}] {text}")

    def _populate_devices(self):
        self.device_table.setRowCount(0)

        if os.name == "nt":
            # Windows: enumerate physical drives by number with psutil
            # psutil.disk_partitions() only sees volumes, not raw drives,
            # but we still add visible volumes for reference.
            seen = set()
            for part in psutil.disk_partitions(all=True):
                device = part.device
                if device in seen:
                    continue
                seen.add(device)
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                size = 0
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    size = usage.total
                except Exception:
                    size = 0
                self.device_table.setItem(row, 0, QtWidgets.QTableWidgetItem(device))
                self.device_table.setItem(row, 1, QtWidgets.QTableWidgetItem(f"{size/1024**3:.2f}"))
                self.device_table.setItem(row, 2, QtWidgets.QTableWidgetItem("Volume"))
                self.device_table.setItem(row, 3, QtWidgets.QTableWidgetItem(part.mountpoint))

            # Additionally show \\.\PhysicalDriveN guess for N in range(0, 8)
            for idx in range(0, 8):
                dev_name = f"\\\\.\\PhysicalDrive{idx}"
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                self.device_table.setItem(row, 0, QtWidgets.QTableWidgetItem(dev_name))
                self.device_table.setItem(row, 1, QtWidgets.QTableWidgetItem("unknown"))
                self.device_table.setItem(row, 2, QtWidgets.QTableWidgetItem("Physical"))
                self.device_table.setItem(row, 3, QtWidgets.QTableWidgetItem(""))
        else:
            # Linux / Unix: use psutil
            added = set()
            for disk in psutil.disk_partitions(all=True):
                dev = disk.device
                if dev in added:
                    continue
                added.add(dev)
                try:
                    stat = os.stat(dev)
                except Exception:
                    continue
                # Filter only block devices heuristically
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                # Try to get size from /sys/block
                size_gb = "unknown"
                try:
                    base = os.path.basename(dev)
                    # handle /dev/sda1 -> sda
                    while base and base[-1].isdigit():
                        base = base[:-1]
                    size_path = f"/sys/block/{base}/size"
                    if os.path.exists(size_path):
                        with open(size_path, "r") as f:
                            sectors = int(f.read().strip())
                            size_bytes = sectors * 512
                            size_gb = f"{size_bytes/1024**3:.2f}"
                except Exception:
                    pass

                self.device_table.setItem(row, 0, QtWidgets.QTableWidgetItem(dev))
                self.device_table.setItem(row, 1, QtWidgets.QTableWidgetItem(size_gb))
                self.device_table.setItem(row, 2, QtWidgets.QTableWidgetItem("Block/Partition"))
                self.device_table.setItem(row, 3, QtWidgets.QTableWidgetItem(disk.mountpoint))

    def _get_selected_device(self) -> str:
        row = self.device_table.currentRow()
        if row < 0:
            return ""
        item = self.device_table.item(row, 0)
        if not item:
            return ""
        return item.text().strip()

    def _browse_mount_point(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select mount point directory")
        if path:
            self.mount_point_edit.setText(path)

    def _browse_dd_output(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Select output image file")
        if path:
            self.dd_output_edit.setText(path)

    # ---------- Mount / Unmount ----------
    def _mount_vmfs6(self):
        if os.name == "nt":
            QtWidgets.QMessageBox.warning(self, "Not supported",
                                          "Direct VMFS6 mount is not supported on Windows.\n"
                                          "Use a Linux system with vmfs6-tools installed.")
            return

        device = self._get_selected_device()
        mount_point = self.mount_point_edit.text().strip()

        if not device:
            QtWidgets.QMessageBox.warning(self, "No device", "Please select a block device.")
            return
        if not mount_point:
            QtWidgets.QMessageBox.warning(self, "No mount point", "Please set a mount point directory.")
            return

        if not os.path.exists(mount_point):
            try:
                os.makedirs(mount_point)
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to create mount point: {e}")
                return

        def do_mount(worker: WorkerThread):
            self._append_log(f"Running vmfs6-fuse on {device} -> {mount_point}")
            cmd = ["vmfs6-fuse", device, mount_point]
            self._append_log("Command: " + " ".join(cmd))
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

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
                self.progress.setValue(50)
            self.progress.setValue(100)
            if proc.returncode != 0:
                raise RuntimeError(f"vmfs6-fuse failed with code {proc.returncode}")

        self._run_worker(do_mount)

    def _umount_vmfs(self):
        if os.name == "nt":
            QtWidgets.QMessageBox.warning(self, "Not supported",
                                          "Unmount is only relevant on Linux.")
            return
        mount_point = self.mount_point_edit.text().strip()
        if not mount_point:
            QtWidgets.QMessageBox.warning(self, "No mount point", "Please set a mount point directory.")
            return

        def do_umount(worker: WorkerThread):
            self._append_log(f"Unmounting {mount_point}")
            cmd = ["fusermount", "-u", mount_point]
            self._append_log("Command: " + " ".join(cmd))
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            out, _ = proc.communicate()
            if out:
                self._append_log(out.strip())
            if proc.returncode != 0:
                raise RuntimeError(f"fusermount failed with code {proc.returncode}")
            self.progress.setValue(100)

        self._run_worker(do_umount)

    # ---------- DD imaging ----------
    def _start_dd(self):
        device = self._get_selected_device()
        out_path = self.dd_output_edit.text().strip()

        if not device:
            QtWidgets.QMessageBox.warning(self, "No device", "Please select a device or physical drive.")
            return
        if not out_path:
            QtWidgets.QMessageBox.warning(self, "No output", "Please select an output image path.")
            return

        # Confirm destructive read warning
        msg = ("This will read the selected device bit‑for‑bit and write it to:\n"
               f"{out_path}\n\nMake sure you selected the correct source device.\n"
               "Continue?")
        res = QtWidgets.QMessageBox.question(self, "Confirm dd imaging", msg)
        if res != QtWidgets.QMessageBox.Yes:
            return

        def do_dd(worker: WorkerThread):
            self._append_log(f"Starting bit‑for‑bit copy from {device} to {out_path}")
            block_size = 1024 * 1024  # 1 MiB
            total_size = None

            # Try to detect size on Linux
            if os.name != "nt" and device.startswith("/dev/"):
                try:
                    base = os.path.basename(device)
                    while base and base[-1].isdigit():
                        base = base[:-1]
                    size_path = f"/sys/block/{base}/size"
                    if os.path.exists(size_path):
                        with open(size_path, "r") as f:
                            sectors = int(f.read().strip())
                            total_size = sectors * 512
                            self._append_log(f"Detected device size: {total_size / 1024**3:.2f} GB")
                except Exception as e:
                    self._append_log(f"Could not detect device size: {e}")

            # On Windows, try psutil for volumes; PhysicalDriveN remains unknown
            if os.name == "nt":
                self._append_log("On Windows, device size may be unknown. Progress is approximate.")

            bytes_copied = 0
            start_time = time.time()

            # Open source device raw
            mode = "rb"
            if os.name == "nt":
                # Windows raw device; Python can open \\.\PhysicalDriveN with rb
                src = open(device, mode, buffering=0)
            else:
                src = open(device, mode)

            # Ensure target directory exists
            out_dir = os.path.dirname(os.path.abspath(out_path))
            if out_dir and not os.path.exists(out_dir):
                os.makedirs(out_dir, exist_ok=True)

            with src, open(out_path, "wb") as dst:
                while True:
                    if worker.stopped:
                        self._append_log("DD imaging cancelled by user.")
                        break
                    chunk = src.read(block_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    bytes_copied += len(chunk)

                    if total_size:
                        progress = int(bytes_copied * 100 / total_size)
                        self.progress_changed.emit(min(progress, 100))
                    else:
                        # No total size: show spinning-ish progress
                        progress = (bytes_copied // (block_size * 100)) % 100
                        self.progress_changed.emit(progress)

            elapsed = time.time() - start_time
            self._append_log(f"Completed dd imaging. Copied {bytes_copied / 1024**3:.2f} GB in {elapsed:.1f} s")
            self.progress_changed.emit(100)

        self._run_worker(do_dd)

    # ---------- Worker handling ----------
    def _run_worker(self, func):
        if self.worker and self.worker.isRunning():
            QtWidgets.QMessageBox.warning(self, "Busy", "An operation is already running.")
            return

        self.progress.setValue(0)
        self.worker = WorkerThread(func)
        self.worker.progress_changed.connect(self.progress.setValue)
        self.worker.log_message.connect(self._append_log)
        self.worker.finished_ok.connect(self._on_worker_ok)
        self.worker.finished_error.connect(self._on_worker_error)
        self.worker.start()

    def _on_worker_ok(self):
        self._append_log("Operation finished successfully.")

    def _on_worker_error(self, msg: str):
        self._append_log("Operation failed: " + msg)
        QtWidgets.QMessageBox.critical(self, "Error", msg)


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    # Optional: dark palette
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
    palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(25, 25, 25))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53, 53, 53))
    palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
    palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(142, 45, 197).lighter())
    palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
    app.setPalette(palette)

    win = VMFSGui()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
