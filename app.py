import sys
import os
import datetime
import subprocess
from PySide6.QtWidgets import ( QApplication, QWidget, QVBoxLayout, QPushButton, QMessageBox,QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
)

def parse_keys(colon_output: str):
    keys = []
    current_key = None

    for line in colon_output.splitlines():
        parts = line.split(":")
        rtype = parts[0]
        if rtype == "pub":
            current_key = {
                "status": parts[1],
                "keyid": parts[4],
                "from": parts[5],
                "until": parts[6] if parts[6] else "Never",
                "uids": [],
                "fingerprint": ""
            }
            keys.append(current_key)
        elif rtype == "fpr" and current_key:
            current_key["fingerprint"] = parts[9]
        elif rtype == "uid" and current_key:
            current_key["uids"].append(parts[9])
    return keys

class PGP_APP(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aether")

        self.decrypt_btn = QPushButton("Decrypt File")
        self.decrypt_btn.clicked.connect(self.decrypt_file)

        self.encrypt_btn = QPushButton("Encrypt File")
        self.encrypt_btn.clicked.connect(self.encrypt_file)

        self.key_list = QTableWidget()
        self.key_list.setColumnCount(6)
        self.key_list.setHorizontalHeaderLabels([
        "Name", "E-Mail", "Status", "Valid From", "Valid Until", "Key ID"
        ])

        self.key_list.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.key_list.setSelectionBehavior(QTableWidget.SelectRows)

        self.btn = QPushButton("Check GPG")
        self.btn.clicked.connect(self.check_gpg)

        self.list_keys_btn = QPushButton("List Keys")
        self.list_keys_btn.clicked.connect(self.list_keys)

        layout = QVBoxLayout()
        layout.addWidget(self.key_list)
        layout.addWidget(self.btn)
        layout.addWidget(self.list_keys_btn)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.decrypt_btn)
        self.setLayout(layout)

    def on_key_clicked(self, item):
        index = self.key_list.currentRow() // 3
        
        if index >= len(self.keys):
            return

        key = self.keys[index]
        keyid = key["keyid"]
        fpr = key["fingerprint"]
        uids = key["uids"]

        info = f"Key ID: {keyid}\n"
        info += f"Fingerprint: {fpr}\n"
        info += "-" * 20 + "\n"
        for uid in uids:
            info += f"User: {uid}\n"

        QMessageBox.information(self, "Key Details", info)

    def check_gpg(self):
        try:
            result = subprocess.run(["gpg", "--version"], capture_output=True, text=True)
            version_info = result.stdout.splitlines()[0]
            QMessageBox.information(self, "GPG Status", f"System GPG Found:\n{version_info}")
        except Exception as e:
            QMessageBox.critical(self, "GPG Error", f"Error: {str(e)}")

    def list_keys(self):
        try:
            result = subprocess.run(["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True)
            self.keys = parse_keys(result.stdout)
            
            self.key_list.setRowCount(len(self.keys))
            for row, k in enumerate(self.keys):
                self.key_list.insertRow(row)

                created_raw = k["from"]
                expires_raw = k["until"]

                try:
                    valid_from = datetime.fromtimestamp(int(created_raw)).strftime('%Y-%m-%d')
                except:
                    valid_from = created_raw

                try:
                    if expires_raw.isdigit():
                        valid_until = datetime.fromtimestamp(int(expires_raw)).strftime('%Y-%m-%d')
                    else:
                        valid_until = "Never"
                except:
                    valid_until = expires_raw

                full_uid = k["uids"][0] if k["uids"] else "Unknown <unknown>"
                name = full_uid.split("<")[0].strip()
                email = full_uid.split("<")[-1].replace(">", "").strip()

                self.key_list.setItem(row, 0, QTableWidgetItem(name))
                self.key_list.setItem(row, 1, QTableWidgetItem(email))
                self.key_list.setItem(row, 2, QTableWidgetItem(k["status"]))
                self.key_list.setItem(row, 3, QTableWidgetItem(k["from"]))
                self.key_list.setItem(row, 4, QTableWidgetItem(k["until"]))
                self.key_list.setItem(row, 5, QTableWidgetItem(k["keyid"]))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def encrypt_file(self):
        index = self.key_list.currentRow() // 3
        if index < 0 or index >= len(self.keys):
            QMessageBox.warning(self, "Error", "Please select a key from the list first!")
            return
        
        recipient_id = self.keys[index]["keyid"]

        file_pth, _ = QFileDialog.getOpenFileName(self, "Select file to Encrypt")
        if not file_pth:
            return

        try:
            subprocess.run([
                "gpg", "--batch", "--yes",
                "--encrypt",
                "--recipient", recipient_id,
                file_pth
            ], check=True)

            QMessageBox.information(self, "Success", f"Encrypted file created:\n{file_pth}.gpg")
        except Exception  as e:
            QMessageBox.critical(self, 'Error', f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select file to Decrypt", "", "GPG Files (*.gpg *.asc)"
        )

        if not file_path:
            return

        output_path, ext = os.path.splitext(file_path)

        if os.path.exists(output_path):
            name, extension = os.path.splitext(output_path)
            output_path = f"{name}_decrypted{extension}"

        try:
            result = subprocess.run([
                "gpg", "--batch", "--yes",
                "--output", output_path,
                "--decrypt", file_path
            ], capture_output=True, text=True)

            if result.returncode == 0:
                QMessageBox.information(self,"Success", f"File decrypted to:\n{output_path}")
            else:
                QMessageBox.critical(self, "Decryption Failed", result.stderr)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PGP_APP()
    window.show()
    sys.exit(app.exec())
