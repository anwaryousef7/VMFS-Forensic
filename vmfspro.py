import os
import sys
import subprocess
import time
import re
import csv
import hashlib
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
        self._target, self._stop_flag = target, False
    def run(self):
        try: self._target(self); self.finished_ok.emit()
        except Exception as exc: self.finished_error.emit(str(exc))
    def stop(self): self._stop_flag = True
    @property
    def stopped(self): return self._stop_flag

# ══════════════════════════ HexViewerDialog ══════════════════════════
MAGIC_SIGNATURES = {
    b"\x4D\x5A": "Windows PE", b"\x7FELF": "ELF Binary", b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xFF\xD8\xFF": "JPEG", b"PK\x03\x04": "ZIP/DOCX", b"%PDF": "PDF", b"KDMV": "VMDK Extent",
    b"COWD": "VMDK COW", b"#extents": "VMDK Descriptor", b"VMFS": "VMFS Filesystem"
}

class HexViewerDialog(QtWidgets.QDialog):
    PAGE_SIZE, ROW_BYTES = 65536, 16
    def __init__(self, filepath, parent=None):
        super().__init__(parent)
        self.filepath, self.page = filepath, 0
        self.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        self.setWindowTitle(f"Hex Viewer – {os.path.basename(filepath)}")
        self._build_ui()
        self.showMaximized()
        self._load_page()

    def _build_ui(self):
        lay = QtWidgets.QVBoxLayout(self)
        self.hex_edit = QtWidgets.QPlainTextEdit()
        self.hex_edit.setFont(QtGui.QFont("Courier New", 11))
        self.hex_edit.setStyleSheet("background:#0a0a0a;color:#44ff88;")
        lay.addWidget(self.hex_edit)

    def _load_page(self):
        try:
            with open(self.filepath, "rb") as f:
                f.seek(self.page * self.PAGE_SIZE)
                data = f.read(self.PAGE_SIZE)
            lines = []
            for i in range(0, len(data), self.ROW_BYTES):
                chunk = data[i:i + self.ROW_BYTES]
                h = " ".join(f"{b:02X}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)
                lines.append(f"{self.page * self.PAGE_SIZE + i:08X}  {h:<47}  |{ascii_str}|")
            self.hex_edit.setPlainText("\n".join(lines))
        except Exception as e: self.hex_edit.setPlainText(str(e))

# ════════════════════════ ExportProgressDialog ════════════════════════
class ExportProgressDialog(QtWidgets.QDialog):
    cancel_requested = QtCore.pyqtSignal()
    def __init__(self, title="Exporting…", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(540, 200)
        lay = QtWidgets.QVBoxLayout(self)
        self.file_label = QtWidgets.QLabel("Preparing…")
        self.bar = QtWidgets.QProgressBar()
        self.hash_label = QtWidgets.QLabel("MD5: Calculating...")
        self.hash_label.setStyleSheet("color:#ffcc44; font-weight:bold;")
        lay.addWidget(self.file_label)
        lay.addWidget(self.bar)
        lay.addWidget(self.hash_label)
        b_cancel = QtWidgets.QPushButton("Cancel")
        b_cancel.clicked.connect(self.cancel_requested.emit)
        lay.addWidget(b_cancel)

    def update_progress(self, pct, filename="", h_md5="", h_sha256=""):
        self.bar.setValue(pct)
        if filename: self.file_label.setText(f"Copying: {filename}")
        if h_md5: self.hash_label.setText(f"MD5: {h_md5} | SHA256: {h_sha256[:16]}...")

# ══════════════════════════════ Main GUI ══════════════════════════════
class VMFSGui(QtWidgets.QMainWindow):
    CHUNK = 4 * 1024 * 1024

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VMFS6 Advanced Forensic Framework Pro")
        self.resize(1350, 850)
        self.worker = None
        self._build_ui()
        self._populate_devices()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        root = QtWidgets.QVBoxLayout(central)
        self.tabs = QtWidgets.QTabWidget()
        root.addWidget(self.tabs)

        self.tab_src = QtWidgets.QWidget()
        self.tab_mount = QtWidgets.QWidget()
        self.tab_dd = QtWidgets.QWidget()
        self.tab_browse = QtWidgets.QWidget()
        self.tab_forensics = QtWidgets.QWidget()
        self.tab_intel = QtWidgets.QWidget() # تبويب الاستخبارات الجنائية الجديد

        self._build_tab_source()
        self._build_tab_mount()
        self._build_tab_imaging()
        self._build_tab_browse()
        self._build_tab_forensics()
        self._build_tab_intel() # بناء واجهة VMFS Intelligence

        self.tabs.addTab(self.tab_src, "Sources")
        self.tabs.addTab(self.tab_mount, "Mount VMFS")
        self.tabs.addTab(self.tab_dd, "Forensic Imaging")
        self.tabs.addTab(self.tab_browse, "VMFS Browser")
        self.tabs.addTab(self.tab_forensics, "Carving & YARA")
        self.tabs.addTab(self.tab_intel, "⚡ VMFS Intelligence")

        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(130)
        self.progress = QtWidgets.QProgressBar()
        root.addWidget(QtWidgets.QLabel("Forensic Log:"))
        root.addWidget(self.log_edit)
        root.addWidget(self.progress)
        self.setCentralWidget(central)

    # --- Basic Tabs (Sources, Mount, Imaging, Browse) ---
    def _build_tab_source(self):
        lay = QtWidgets.QVBoxLayout(self.tab_src)
        self.device_table = QtWidgets.QTableWidget(0, 4)
        self.device_table.setHorizontalHeaderLabels(["Device", "Size", "Type", "Mountpoint"])
        self.device_table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.device_table)
        b_ref = QtWidgets.QPushButton("Refresh Devices")
        b_ref.clicked.connect(self._populate_devices)
        lay.addWidget(b_ref)

    def _build_tab_mount(self):
        lay = QtWidgets.QVBoxLayout(self.tab_mount)
        self.mount_src = QtWidgets.QLineEdit()
        self.mount_src.setPlaceholderText("Device e.g., /dev/sdc1")
        self.mount_dst = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_mnt = QtWidgets.QPushButton("Mount VMFS6 (vmfs6-fuse)")
        b_mnt.clicked.connect(self._mount_vmfs)
        lay.addWidget(QtWidgets.QLabel("Source Device:"))
        lay.addWidget(self.mount_src)
        lay.addWidget(QtWidgets.QLabel("Mount Point:"))
        lay.addWidget(self.mount_dst)
        lay.addWidget(b_mnt)
        lay.addStretch()

    def _build_tab_imaging(self):
        lay = QtWidgets.QVBoxLayout(self.tab_dd)
        form = QtWidgets.QFormLayout()
        self.dd_src = QtWidgets.QLineEdit()
        self.dd_dst = QtWidgets.QLineEdit()
        self.dd_tool = QtWidgets.QComboBox()
        self.dd_tool.addItems(["dc3dd (Hashed Raw)", "ewfacquire (E01 Image)", "dd (Fast Raw)"])
        form.addRow("Source:", self.dd_src)
        form.addRow("Destination:", self.dd_dst)
        form.addRow("Tool:", self.dd_tool)
        lay.addLayout(form)
        b_start = QtWidgets.QPushButton("Start Acquisition")
        b_start.clicked.connect(self._start_imaging)
        lay.addWidget(b_start)
        lay.addStretch()

    def _build_tab_browse(self):
        lay = QtWidgets.QVBoxLayout(self.tab_browse)
        top = QtWidgets.QHBoxLayout()
        self.browse_root = QtWidgets.QLineEdit("/mnt/vmfs6")
        b_load = QtWidgets.QPushButton("Load Tree")
        b_load.clicked.connect(self._load_tree)
        top.addWidget(self.browse_root)
        top.addWidget(b_load)
        lay.addLayout(top)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size", "Type", "Path"])
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        lay.addWidget(self.tree)

        act = QtWidgets.QHBoxLayout()
        b_exp = QtWidgets.QPushButton("⬇ Export & Hash")
        b_csv = QtWidgets.QPushButton("🕒 MAC Timeline (CSV)")
        b_exp.clicked.connect(self._export_selected)
        b_csv.clicked.connect(self._gen_timeline)
        act.addWidget(b_exp)
        act.addWidget(b_csv)
        lay.addLayout(act)

    def _build_tab_forensics(self):
        lay = QtWidgets.QVBoxLayout(self.tab_forensics)
        grp_carve = QtWidgets.QGroupBox("Data Carving (PhotoRec)")
        form_c = QtWidgets.QFormLayout(grp_carve)
        self.carve_src = QtWidgets.QLineEdit()
        self.carve_dst = QtWidgets.QLineEdit()
        b_carve = QtWidgets.QPushButton("Start Carving")
        b_carve.clicked.connect(self._start_carving)
        form_c.addRow("Raw Target:", self.carve_src)
        form_c.addRow("Output Dir:", self.carve_dst)
        form_c.addRow("", b_carve)
        lay.addWidget(grp_carve)

        grp_yara = QtWidgets.QGroupBox("Ransomware Hunting (YARA)")
        form_y = QtWidgets.QFormLayout(grp_yara)
        self.yara_rule = QtWidgets.QLineEdit()
        self.yara_tgt = QtWidgets.QLineEdit()
        b_yara = QtWidgets.QPushButton("Run YARA Scan")
        b_yara.clicked.connect(self._start_yara)
        form_y.addRow("YARA Rule (.yar):", self.yara_rule)
        form_y.addRow("Target (File/Dir):", self.yara_tgt)
        form_y.addRow("", b_yara)
        lay.addWidget(grp_yara)
        lay.addStretch()

    # ── Tab 6: VMFS Intelligence (NEW 5 FEATURES) ─────────────────────
    def _build_tab_intel(self):
        lay = QtWidgets.QVBoxLayout(self.tab_intel)
        
        b_scan_intel = QtWidgets.QPushButton("🔍 Run Automated VMFS Intelligence Scan")
        b_scan_intel.setStyleSheet("background:#7a1a1a;color:white;font-weight:bold;padding:10px;")
        b_scan_intel.clicked.connect(self._run_vmfs_intel)
        lay.addWidget(b_scan_intel)

        # 1. VMX Parser Table
        self.vmx_table = QtWidgets.QTableWidget(0, 4)
        self.vmx_table.setHorizontalHeaderLabels(["VM Name", "Guest OS", "MAC Address", "Config File Path"])
        self.vmx_table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(QtWidgets.QLabel("📄 1. VMX Configurations (Virtual Machines):"))
        lay.addWidget(self.vmx_table)

        # 2. Snapshot Chain Tree
        self.snap_tree = QtWidgets.QTreeWidget()
        self.snap_tree.setHeaderLabels(["VMDK Snapshot Chain (Parent -> Child)", "CID", "Type", "Path"])
        self.snap_tree.setColumnWidth(0, 350)
        lay.addWidget(QtWidgets.QLabel("⛓️ 2. Snapshot Chains (Delta/SEsparse):"))
        lay.addWidget(self.snap_tree)

        # 3. Logs area for Metadata, Thin Provisioning, and Locks
        self.intel_log = QtWidgets.QPlainTextEdit()
        self.intel_log.setReadOnly(True)
        self.intel_log.setStyleSheet("background:#0f151f;color:#88ccff;font-family:monospace;")
        lay.addWidget(QtWidgets.QLabel("⚙️ 3. Metadata, Thin Provisioning & Heartbeat Locks:"))
        lay.addWidget(self.intel_log)

    # ══════════════════════ NEW INTEL SCANNER LOGIC ══════════════════
    def _run_vmfs_intel(self):
        root = self.browse_root.text().strip()
        if not os.path.isdir(root):
            QtWidgets.QMessageBox.warning(self, "Error", "Mount VMFS and set the path in VMFS Browser first.")
            return

        self.vmx_table.setRowCount(0)
        self.snap_tree.clear()
        self.intel_log.clear()

        def task(worker):
            worker.log_message.emit("Starting VMFS Intelligence Deep Scan...")
            vmdk_descriptors = {}
            lock_macs = set()
            total_logical = 0
            total_physical = 0

            # Walk through the VMFS mount
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    filepath = os.path.join(dirpath, fname)
                    
                    # Feature 3: VMX Parser
                    if fname.endswith(".vmx"):
                        vm_name, guest_os, mac_addr = "Unknown", "Unknown", "Unknown"
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                for line in f:
                                    if 'displayName' in line: vm_name = line.split('=')[1].strip().strip('"')
                                    elif 'guestOS' in line: guest_os = line.split('=')[1].strip().strip('"')
                                    elif 'generatedAddress' in line: mac_addr = line.split('=')[1].strip().strip('"')
                            # Update UI Safely
                            QtCore.QMetaObject.invokeMethod(self, "_add_vmx_row", 
                                QtCore.Qt.QueuedConnection, 
                                QtCore.Q_ARG(str, vm_name), QtCore.Q_ARG(str, guest_os), 
                                QtCore.Q_ARG(str, mac_addr), QtCore.Q_ARG(str, filepath))
                        except Exception: pass

                    # Feature 2: Snapshot Chain Analyzer (Descriptor Parser)
                    elif fname.endswith(".vmdk") and not fname.endswith("-flat.vmdk") and not fname.endswith("-sesparse.vmdk"):
                        cid, parent_cid = None, None
                        try:
                            # Read first 1KB to find descriptor text
                            with open(filepath, 'r', errors='ignore') as f:
                                head = f.read(1024)
                                if 'CID=' in head:
                                    for line in head.splitlines():
                                        if line.startswith('CID='): cid = line.split('=')[1].strip()
                                        elif line.startswith('parentCID='): parent_cid = line.split('=')[1].strip()
                            if cid:
                                vmdk_descriptors[cid] = {'name': fname, 'path': filepath, 'parent': parent_cid}
                        except Exception: pass

                    # Feature 5: Thin Provisioning Analysis
                    elif fname.endswith("-flat.vmdk") or fname.endswith("-sesparse.vmdk"):
                        try:
                            st = os.stat(filepath)
                            logical = st.st_size
                            physical = st.st_blocks * 512 # 512-byte blocks in Linux stat
                            total_logical += logical
                            total_physical += physical
                            if logical > 0 and physical < logical:
                                ratio = (physical / logical) * 100
                                worker.log_message.emit(f"[Thin Prov] {fname} - Provisioned: {logical/1024**3:.1f}GB | Actual used: {physical/1024**3:.1f}GB ({ratio:.1f}%)")
                        except Exception: pass

                    # Feature 1: Heartbeat & Lock Analysis (Searching .lck folders/files)
                    elif ".lck" in fname or fname.endswith(".sf"):
                        try:
                            with open(filepath, 'rb') as f:
                                data = f.read(4096) # Read chunk
                                # Regex to find MAC Addresses in raw binary lock data
                                macs = re.findall(rb'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', data)
                                for m in macs: lock_macs.add(m.decode('utf-8'))
                        except Exception: pass

            # Feature 4: Volume Metadata
            worker.log_message.emit("\n--- Volume Metadata ---")
            worker.log_message.emit(f"Total Logical VMDK Size : {total_logical/1024**4:.2f} TB")
            worker.log_message.emit(f"Total Physical Size on Disk: {total_physical/1024**4:.2f} TB")
            worker.log_message.emit("UUIDs and Volume info usually require 'vmkfstools' or block dumps.")

            if lock_macs:
                worker.log_message.emit("\n--- Heartbeat/Lock Analysis ---")
                worker.log_message.emit("Found following ESXi Host MAC Addresses holding locks:")
                for mac in lock_macs: worker.log_message.emit(f"  -> {mac}")

            # Build Snapshot Tree
            QtCore.QMetaObject.invokeMethod(self, "_build_snap_tree", 
                QtCore.Qt.QueuedConnection, QtCore.Q_ARG(dict, vmdk_descriptors))

            worker.progress_changed.emit(100)
            worker.log_message.emit("\nVMFS Intelligence Scan Complete!")

        self._run_worker(task)

    @QtCore.pyqtSlot(str, str, str, str)
    def _add_vmx_row(self, name, os_name, mac, path):
        r = self.vmx_table.rowCount()
        self.vmx_table.insertRow(r)
        self.vmx_table.setItem(r, 0, QtWidgets.QTableWidgetItem(name))
        self.vmx_table.setItem(r, 1, QtWidgets.QTableWidgetItem(os_name))
        self.vmx_table.setItem(r, 2, QtWidgets.QTableWidgetItem(mac))
        self.vmx_table.setItem(r, 3, QtWidgets.QTableWidgetItem(path))

    @QtCore.pyqtSlot(dict)
    def _build_snap_tree(self, descriptors):
        # Build hierarchy
        items = {}
        for cid, info in descriptors.items():
            item = QtWidgets.QTreeWidgetItem([info['name'], cid, "Delta/Snapshot" if info['parent'] != "ffffffff" else "Base Disk", info['path']])
            items[cid] = item

        for cid, info in descriptors.items():
            parent_cid = info['parent']
            if parent_cid in items:
                items[parent_cid].addChild(items[cid])
            else:
                self.snap_tree.addTopLevelItem(items[cid])
        self.snap_tree.expandAll()

    # ══════════════════════ CORE FUNCTIONS ═══════════════════════════
    def _populate_devices(self):
        self.device_table.setRowCount(0)
        try:
            raw = subprocess.check_output(["lsblk", "-rno", "NAME,SIZE,TYPE,MOUNTPOINT"], text=True)
            for line in raw.strip().splitlines():
                cols = line.split()
                if len(cols) >= 3 and cols[2] in ("disk", "part"):
                    r = self.device_table.rowCount()
                    self.device_table.insertRow(r)
                    for i, val in enumerate(cols[:4]):
                        self.device_table.setItem(r, i, QtWidgets.QTableWidgetItem(val))
        except: pass

    def _mount_vmfs(self):
        src, dst = self.mount_src.text().strip(), self.mount_dst.text().strip()
        os.makedirs(dst, exist_ok=True)
        def task(w):
            w.log_message.emit(f"Mounting {src} to {dst}...")
            subprocess.run(["sudo", "vmfs6-fuse", src, dst])
            w.log_message.emit("Mounted successfully.")
            w.progress_changed.emit(100)
        self._run_worker(task)

    def _start_imaging(self):
        src, dst, tool = self.dd_src.text().strip(), self.dd_dst.text().strip(), self.dd_tool.currentText()
        def task(w):
            if "ewfacquire" in tool: cmd = ["sudo", "ewfacquire", "-t", dst, "-u", src]
            elif "dc3dd" in tool: cmd = ["sudo", "dc3dd", f"if={src}", f"of={dst}", "hash=sha256"]
            else: cmd = ["sudo", "dd", f"if={src}", f"of={dst}", "status=progress"]
            w.log_message.emit(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd)
            w.progress_changed.emit(100)
            w.log_message.emit("Imaging Complete.")
        self._run_worker(task)

    def _start_carving(self):
        src, dst = self.carve_src.text().strip(), self.carve_dst.text().strip()
        os.makedirs(dst, exist_ok=True)
        def task(w):
            w.log_message.emit("Starting PhotoRec...")
            subprocess.run(["sudo", "photorec", "/d", dst, "/cmd", src, "partition_none,search"])
            w.progress_changed.emit(100)
            w.log_message.emit("Carving Complete.")
        self._run_worker(task)

    def _start_yara(self):
        rule, tgt = self.yara_rule.text().strip(), self.yara_tgt.text().strip()
        def task(w):
            w.log_message.emit("Running YARA...")
            proc = subprocess.Popen(["yara", "-r", rule, tgt], stdout=subprocess.PIPE, text=True)
            for line in iter(proc.stdout.readline, ""): w.log_message.emit(f"HIT: {line.strip()}")
            w.progress_changed.emit(100)
            w.log_message.emit("YARA Complete.")
        self._run_worker(task)

    def _load_tree(self):
        root = self.browse_root.text().strip()
        if not os.path.isdir(root): return
        self.tree.clear()
        r_item = QtWidgets.QTreeWidgetItem([os.path.basename(root) or "/", "", "DIR", root])
        self.tree.addTopLevelItem(r_item)
        for e in os.scandir(root):
            r_item.addChild(QtWidgets.QTreeWidgetItem([e.name, str(e.stat().st_size), "FILE", e.path]))
        r_item.setExpanded(True)

    def _tree_menu(self, pos):
        items = self.tree.selectedItems()
        if not items: return
        m = QtWidgets.QMenu()
        a_exp = m.addAction("⬇ Export & Hash")
        a_hex = m.addAction("🔬 Hex Viewer")
        act = m.exec_(self.tree.viewport().mapToGlobal(pos))
        if act == a_exp: self._export_selected()
        elif act == a_hex: HexViewerDialog(items[0].text(3), self).show()

    def _export_selected(self):
        items = self.tree.selectedItems()
        if not items: return
        src = items[0].text(3)
        dst = os.path.join("/tmp", os.path.basename(src))
        dlg = ExportProgressDialog("Exporting...", self)
        dlg.show()
        t = os.path.getsize(src)
        copied, md5, sha = 0, hashlib.md5(), hashlib.sha256()
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                d = fin.read(self.CHUNK)
                if not d: break
                fout.write(d)
                md5.update(d)
                sha.update(d)
                copied += len(d)
                dlg.update_progress(int(copied*100/t) if t else 100, os.path.basename(src), md5.hexdigest(), sha.hexdigest())
                QtWidgets.QApplication.processEvents()
        dlg.close()
        self._log(f"Exported: {dst} | SHA256: {sha.hexdigest()}")

    def _gen_timeline(self):
        root = self.browse_root.text().strip()
        if not os.path.isdir(root): return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Timeline", "timeline.csv", "CSV (*.csv)")
        if not path: return
        def task(w):
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Path", "Size", "mtime", "atime", "ctime"])
                for d, _, files in os.walk(root):
                    for name in files:
                        p = os.path.join(d, name)
                        try:
                            st = os.stat(p)
                            writer.writerow([p, st.st_size, time.ctime(st.st_mtime), time.ctime(st.st_atime), time.ctime(st.st_ctime)])
                        except: pass
            w.progress_changed.emit(100)
            w.log_message.emit("Timeline generated.")
        self._run_worker(task)

    def _log(self, text):
        # Override to send regular intel logs to main log or intel log based on context.
        self.log_edit.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {text}")
        if "Thin Prov" in text or "Volume Metadata" in text or "MAC" in text:
            self.intel_log.appendPlainText(text)

    def _run_worker(self, target):
        self.progress.setValue(0)
        self.worker = WorkerThread(target)
        self.worker.progress_changed.connect(self.progress.setValue)
        self.worker.log_message.connect(self._log)
        self.worker.start()

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    p = QtGui.QPalette()
    p.setColor(QtGui.QPalette.Window, QtGui.QColor(30, 30, 30))
    p.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
    p.setColor(QtGui.QPalette.Base, QtGui.QColor(15, 20, 30))
    p.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
    p.setColor(QtGui.QPalette.Button, QtGui.QColor(50, 50, 50))
    p.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
    app.setPalette(p)
    win = VMFSGui()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
