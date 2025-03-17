import sys
import subprocess
import time  
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem

class SignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Import file
        self.import_button = QPushButton("Import a file", self)
        self.import_button.clicked.connect(self.import_document)
        layout.addWidget(self.import_button)

        self.file_label = QLabel("No file selected", self)
        layout.addWidget(self.file_label)

        # Select Traditional sign
        self.traditional_label = QLabel("Select the traditional signature algorithm", self)
        layout.addWidget(self.traditional_label)

        self.traditional_combo = QComboBox(self)
        self.traditional_combo.addItems(["RSA", "DSA", "ECDSA"])
        layout.addWidget(self.traditional_combo)

        # Select post-quantum sign
        self.hybrid_label = QLabel("Select the post-quantum signature algorithm:", self)
        layout.addWidget(self.hybrid_label)

        self.hybrid_combo = QComboBox(self)
        self.hybrid_combo.addItems(["Dilithium", "Falcon", "Phinics"])
        layout.addWidget(self.hybrid_combo)

        # Button sign
        self.sign_button = QPushButton("Hybrid Sign a file", self)
        self.sign_button.clicked.connect(self.sign_document)
        layout.addWidget(self.sign_button)

        # Button for verification
        self.verify_button = QPushButton("Verify Hybrid Signature", self)
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.verify_button)


        # Table for benchmark results
        self.table = QTableWidget(self)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Algorithm", "Time (s)"])
        layout.addWidget(self.table)

        self.setLayout(layout)
        self.setWindowTitle("Hybrid Signature")
        self.resize(400, 300)

        self.file_path = None  
        self.signed_file_path = None

    def import_document(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import a document", "", "All Files (*)", options=options)
        if file_name:
            self.file_path = file_name
            self.file_label.setText(f"Selected: {file_name}")

    def sign_document(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please import a file first!")
            return

        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()

        output_file = self.file_path + ".signed"
        self.signed_file_path = output_file

        command = ["./hybrid_signature", self.file_path, traditional_algo, hybrid_algo, output_file]
        
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip().split("\n")

            # Parsing des temps d'exécution
            times = []
            for line in output:
                parts = line.split(": ")
                if len(parts) == 2:
                    algo, time_str = parts
                    try:
                        times.append((algo, float(time_str)))
                    except ValueError:
                        continue  # Ignore erreurs de conversion

            self.update_table(times)
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"Signature process failed!\n{e.stderr}")

    def update_table(self, times):
        self.table.setRowCount(len(times))
        
        for row, (algo, time) in enumerate(times):
            self.table.setItem(row, 0, QTableWidgetItem(algo))
            self.table.setItem(row, 1, QTableWidgetItem(f"{time:.6f} s"))
    
    def verify_signature(self):
        if not self.signed_file_path:
            QMessageBox.warning(self, "Error", "Please sign a file first!")
            return

        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()
        if not os.path.exists(self.signed_file_path):        
            QMessageBox.critical(self, "Error", "The signed file does not exist. Please check the signing process.")
            return
    
        # Suppose the verification is done with the same executable, passing the signed file path and algorithms
        command = ["./hybrid_verify", self.signed_file_path, traditional_algo, hybrid_algo]

        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip()

            # Display the result of verification
            QMessageBox.information(self, "Verification Result", output)
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"Verification process failed!")



if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())
