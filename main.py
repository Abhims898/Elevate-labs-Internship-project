import sys, os, base64
from pathlib import Path
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from crypto import generate_master_key, save_master_key, load_master_key, encrypt_file_bytes, decrypt_file_bytes

APP_DIR = Path.home() / ".sfs_gui"
APP_DIR.mkdir(parents=True, exist_ok=True)
STORAGE = APP_DIR / "storage"
STORAGE.mkdir(parents=True, exist_ok=True)
KEY_FILE = APP_DIR / "master.key"

def ensure_key():
    if not KEY_FILE.exists():
        key = generate_master_key()
        save_master_key(str(KEY_FILE), key)
    return load_master_key(str(KEY_FILE))

class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Storage - AES-256-GCM")
        self.resize(800, 480)
        layout = QtWidgets.QVBoxLayout(self)

        # top controls
        top = QtWidgets.QHBoxLayout()
        self.select_btn = QtWidgets.QPushButton("Select File")
        self.select_label = QtWidgets.QLabel("No file selected")
        self.encrypt_btn = QtWidgets.QPushButton("Encrypt & Save (.enc)")
        top.addWidget(self.select_btn)
        top.addWidget(self.select_label)
        top.addWidget(self.encrypt_btn)
        layout.addLayout(top)

        # file list
        self.list_widget = QtWidgets.QListWidget()
        layout.addWidget(self.list_widget)

        # bottom controls
        bottom = QtWidgets.QHBoxLayout()
        self.decrypt_btn = QtWidgets.QPushButton("Decrypt Selected")
        self.verify_btn = QtWidgets.QPushButton("Verify Selected")
        self.refresh_btn = QtWidgets.QPushButton("Refresh List")
        bottom.addWidget(self.decrypt_btn)
        bottom.addWidget(self.verify_btn)
        bottom.addWidget(self.refresh_btn)
        layout.addLayout(bottom)

        # connections
        self.select_btn.clicked.connect(self.select_file)
        self.encrypt_btn.clicked.connect(self.encrypt_selected)
        self.refresh_btn.clicked.connect(self.load_list)
        self.decrypt_btn.clicked.connect(self.decrypt_selected)
        self.verify_btn.clicked.connect(self.verify_selected)
        self.list_widget.itemDoubleClicked.connect(self.decrypt_selected)

        self.current_file = None
        self.key = None
        try:
            self.key = ensure_key()
        except Exception as e:
            QMessageBox.critical(self, "Key Error", f"Failed to load/generate master key: {e}")
        self.load_list()

    def select_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Select a file to encrypt")
        if fn:
            self.current_file = fn
            self.select_label.setText(fn)

    def encrypt_selected(self):
        if not self.current_file:
            QMessageBox.warning(self, "No file", "Please select a file first.")
            return
        try:
            with open(self.current_file, "rb") as f:
                data = f.read()
            package = encrypt_file_bytes(self.key, Path(self.current_file).name, data)
            out_name = Path(self.current_file).name + ".enc"
            out_path = STORAGE / out_name
            with open(out_path, "wb") as f:
                f.write(package)
            QMessageBox.information(self, "Saved", f"Encrypted file saved as:\n{out_path}")
            self.load_list()
        except Exception as e:
            QMessageBox.critical(self, "Encrypt Error", str(e))

    def load_list(self):
        self.list_widget.clear()
        files = sorted(STORAGE.glob("*.enc"))
        for p in files:
            self.list_widget.addItem(p.name)

    def get_selected_path(self):
        it = self.list_widget.currentItem()
        if not it:
            QMessageBox.warning(self, "No selection", "Please select an encrypted file from the list.")
            return None
        return STORAGE / it.text()

    def decrypt_selected(self):
        p = self.get_selected_path()
        if not p:
            return
        try:
            with open(p, "rb") as f:
                pkg = f.read()
            res = decrypt_file_bytes(self.key, pkg)
            meta = res["metadata"]
            plaintext = res["plaintext"]
            # ask where to save
            fn, _ = QFileDialog.getSaveFileName(self, "Save decrypted file as", meta.get("orig_filename"))
            if not fn:
                return
            with open(fn, "wb") as f:
                f.write(plaintext)
            QMessageBox.information(self, "Decrypted", f"File decrypted and saved to:\n{fn}")
        except Exception as e:
            QMessageBox.critical(self, "Decrypt Error", str(e))

    def verify_selected(self):
        p = self.get_selected_path()
        if not p:
            return
        try:
            with open(p, "rb") as f:
                pkg = f.read()
            res = decrypt_file_bytes(self.key, pkg)
            meta = res["metadata"]
            QMessageBox.information(self, "Verified", f"Integrity OK\n\nFilename: {meta.get('orig_filename')}\nSize: {meta.get('size')} bytes\nSHA-256: {meta.get('sha256')}\nTimestamp: {meta.get('timestamp')}")
        except Exception as e:
            QMessageBox.critical(self, "Verify Error", str(e))

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
