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

        # Security Level Selection
        self.security_label = QLabel("Select Security Level:")
        layout.addWidget(self.security_label)

        self.security_combo = QComboBox(self)
        self.security_combo.addItems(["2 (Standard)", "3 (High)", "5 (Highest)"])
        layout.addWidget(self.security_combo)

        # Select Traditional sign
        self.traditional_label = QLabel("Select the traditional signature algorithm:")
        layout.addWidget(self.traditional_label)

        self.traditional_combo = QComboBox(self)
        self.traditional_combo.addItems(["RSA", "DSA", "ECDSA"])
        layout.addWidget(self.traditional_combo)

        # Select post-quantum sign
        self.hybrid_label = QLabel("Select the post-quantum signature algorithm:")
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

        # Table for benchmark results with new column structure - updated to use ms
        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Algorithm", "Security Level", 
            "Setup (ms)", "Sign (ms)", "Verify (ms)",
            "Total Time (ms)"
        ])
        layout.addWidget(self.table)

        self.setLayout(layout)
        self.setWindowTitle("Hybrid Signature")
        self.resize(600, 400)  # Increased width to accommodate more columns

        self.file_path = None
        self.signed_file_path = None

    def import_document(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import a document", "", "All Files (*)", options=options)
        if file_name:
            self.file_path = file_name
            self.file_label.setText(f"Selected: {file_name}")

    def is_valid_combination(self, traditional_algo, hybrid_algo, security_level):
        """ Vérifie si la combinaison est autorisée au niveau de sécurité sélectionné. """
        valid_combinations = {
            "2 (Standard)": [("DSA", "Dilithium"), ("RSA", "Falcon")],
            "3 (High)": [("ECDSA", "Dilithium"), ("DSA", "Phinics")],
            "5 (Highest)": [("RSA", "Phinics"), ("ECDSA", "Falcon")]
        }
        return (traditional_algo, hybrid_algo) in valid_combinations[security_level]

    def sign_document(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please import a file first!")
            return

        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()
        security_level = self.security_combo.currentText()

        if not self.is_valid_combination(traditional_algo, hybrid_algo, security_level):
            QMessageBox.critical(self, "Error", f"Selected algorithms are not supported for {security_level}!")
            return

        output_file = self.file_path + ".signed"
        self.signed_file_path = output_file

        command = ["./hybrid_signature", self.file_path, traditional_algo, hybrid_algo, output_file, "sign"]
        
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip().split("\n")

            # Parse timing results according to the format you're using
            # Format example: "Dilithium Setup: 0.123456"
            traditional_data = {"setup": 0, "sign": 0, "verify": 0}
            hybrid_data = {"setup": 0, "sign": 0, "verify": 0}
            
            for line in output:
                # Parse lines like "Dilithium Setup: 0.123456" or "RSA Setup: 0.123456"
                for algo in [traditional_algo, hybrid_algo]:
                    for phase in ["Setup", "Sign", "Verify"]:
                        prefix = f"{algo} {phase}:"
                        if prefix in line:
                            try:
                                # Convert from seconds to milliseconds (multiply by 1000)
                                time_value = float(line.split(prefix)[1].strip()) * 1000
                                if algo == traditional_algo:
                                    traditional_data[phase.lower()] = time_value
                                else:
                                    hybrid_data[phase.lower()] = time_value
                            except (ValueError, IndexError):
                                continue

            # Add data to the table
            timing_data = [
                (traditional_algo, traditional_data, security_level),
                (hybrid_algo, hybrid_data, security_level)
            ]
            
            self.update_table(timing_data)
            QMessageBox.information(self, "Success", "File signed successfully!")
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"Signature process failed!\n{e.stderr}")

    def update_table(self, timing_data):
        # Clear table and set new row count
        self.table.setRowCount(len(timing_data))
        
        for row, (algo, times, security_level) in enumerate(timing_data):
            # Calculate total time
            total_time = times.get('setup', 0) + times.get('sign', 0) + times.get('verify', 0)
            
            # Set values in table - note we're using integers for ms display
            self.table.setItem(row, 0, QTableWidgetItem(algo))
            self.table.setItem(row, 1, QTableWidgetItem(security_level))
            
            # Format with 2 decimal places for milliseconds
            self.table.setItem(row, 2, QTableWidgetItem(f"{times.get('setup', 0):.2f}"))
            self.table.setItem(row, 3, QTableWidgetItem(f"{times.get('sign', 0):.2f}"))
            self.table.setItem(row, 4, QTableWidgetItem(f"{times.get('verify', 0):.2f}"))
            
            self.table.setItem(row, 5, QTableWidgetItem(f"{total_time:.2f}"))
            

    def verify_signature(self):
        if not self.signed_file_path:
            QMessageBox.warning(self, "Error", "Please sign a file first!")
            return

        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()
        if not os.path.exists(self.signed_file_path):        
            QMessageBox.critical(self, "Error", "The signed file does not exist. Please check the signing process.")
            return
    
        # Verification command
        command = ["./hybrid_verify", self.signed_file_path, traditional_algo, hybrid_algo, "verify"]

        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip()
            
            # Parse verification results
            traditional_verify_time = 0
            hybrid_verify_time = 0
            traditional_status = "Success"
            hybrid_status = "Success"
            
            for line in output.split("\n"):
                # Extract verification times and convert to milliseconds
                if f"{traditional_algo} Verify:" in line:
                    try:
                        # Convert from seconds to milliseconds
                        traditional_verify_time = float(line.split(f"{traditional_algo} Verify:")[1].strip()) * 1000
                    except (ValueError, IndexError):
                        pass
                elif f"{hybrid_algo} Verify:" in line:
                    try:
                        # Convert from seconds to milliseconds
                        hybrid_verify_time = float(line.split(f"{hybrid_algo} Verify:")[1].strip()) * 1000
                    except (ValueError, IndexError):
                        pass
                
            # Update the table with verification results
            for row in range(self.table.rowCount()):
                algo = self.table.item(row, 0).text()
                if algo == traditional_algo:
                    self.table.setItem(row, 4, QTableWidgetItem(f"{traditional_verify_time:.2f}"))
                    self.table.setItem(row, 6, QTableWidgetItem(traditional_status))
                    
                    # Recalculate total time
                    setup_time = float(self.table.item(row, 2).text())
                    sign_time = float(self.table.item(row, 3).text())
                    total_time = setup_time + sign_time + traditional_verify_time
                    self.table.setItem(row, 5, QTableWidgetItem(f"{total_time:.2f}"))
                    
                elif algo == hybrid_algo:
                    self.table.setItem(row, 4, QTableWidgetItem(f"{hybrid_verify_time:.2f}"))
                    self.table.setItem(row, 6, QTableWidgetItem(hybrid_status))
                    
                    # Recalculate total time
                    setup_time = float(self.table.item(row, 2).text())
                    sign_time = float(self.table.item(row, 3).text())
                    total_time = setup_time + sign_time + hybrid_verify_time
                    self.table.setItem(row, 5, QTableWidgetItem(f"{total_time:.2f}"))
                
            QMessageBox.information(self, "Verification Result", "Verification completed. See results in the table.")
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"Verification process failed!")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())