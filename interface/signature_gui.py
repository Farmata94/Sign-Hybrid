import sys
import subprocess
import os
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, 
                             QComboBox, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem, 
                             QTabWidget, QHBoxLayout, QFrame)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt

class SignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):

        layout = QVBoxLayout()
        self.tabs = QTabWidget(self)

        self.combination_tab = QWidget()
        self.setup_combination_tab()
        self.tabs.addTab(self.combination_tab, "📘 Combination")

        # 🟡  Signature
        self.signature_tab = QWidget()
        self.setup_signature_tab()
        self.tabs.addTab(self.signature_tab, "🔏 Signature")

        # 🟡 Verification
        self.verify_tab = QWidget()
        self.setup_verification_tab()
        self.tabs.addTab(self.verify_tab, "✔️ Verification")

        # 🟡  Result
        self.results_tab = QWidget()
        self.setup_results_tab()
        self.tabs.addTab(self.results_tab, "📊 Results")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

        
        title = QLabel(" Hybrid Digital Signature Tool", self)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2E86C1; text-align: center;")
        layout.insertWidget(0, title)

        description = QLabel("This tool allows you to sign and verify files using hybrid digital signatures.\n"
                             "Choose a traditional and a post-quantum algorithm, sign your file, and verify it.", self)
        description.setAlignment(Qt.AlignCenter)
        layout.insertWidget(1, description)

        self.setWindowTitle("Hybrid Signature System")
        self.resize(700, 500)

    def setup_combination_tab(self):
        layout = QVBoxLayout()

        icon_label = QLabel(self)
        pixmap = QPixmap("icons/contract.png")
        icon_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio))
        layout.addWidget(icon_label, alignment=Qt.AlignCenter)

        explanation = QLabel(self)
        explanation.setWordWrap(True)
        explanation.setText(
            "<h3>How Hybrid Signature Works</h3>"
            "<p>This tool combines two digital signatures: one from a traditional algorithm "
            "(e.g., RSA, DSA, ECDSA) and one from a post-quantum algorithm (e.g., Dilithium, Falcon).</p>"
            "<p><b>Why?</b> Combining both ensures that even if one algorithm is broken "
            "in the future (e.g., by quantum computers), the other may still be secure. This offers "
            "a transition path to post-quantum cryptography while maintaining compatibility.</p>"
            "<p><b>Steps:</b></p>"
            "<ol>"
            "<li>The file is signed using the traditional algorithm.</li>"
            "<li>The same file is signed again using the post-quantum algorithm.</li>"
            "<li>Both signatures are bundled together into a single signed file.</li>"
            "</ol>"
            "<p>During verification, both signatures are separately verified to ensure the integrity and "
            "authenticity of the file.</p>"
        )
        layout.addWidget(explanation)
        self.combination_tab.setLayout(layout)


    # Signature
    def setup_signature_tab(self):
        layout = QVBoxLayout()

        icon_label = QLabel(self)
        pixmap = QPixmap("icons/contract.png") 
        icon_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio))
        layout.addWidget(icon_label, alignment=Qt.AlignCenter)

        self.import_button = QPushButton("📂 Import a File", self)
        self.import_button.setStyleSheet("background-color: #5DADE2; color: white; padding: 5px;")
        self.import_button.clicked.connect(self.import_document)
        layout.addWidget(self.import_button)

        self.file_label = QLabel("No file selected", self)
        layout.addWidget(self.file_label)

        # Level security
        self.security_label = QLabel("🔒 Security Level:")
        layout.addWidget(self.security_label)
        self.security_combo = QComboBox(self)
        self.security_combo.addItems(["2 (Standard)", "3 (High)", "5 (Highest)"])
        layout.addWidget(self.security_combo)

        # Select algo
        self.traditional_combo = QComboBox(self)
        self.traditional_combo.addItems(["RSA", "DSA", "ECDSA"])
        layout.addWidget(QLabel("📝 Traditional Algorithm:"))
        layout.addWidget(self.traditional_combo)

        self.hybrid_combo = QComboBox(self)
        self.hybrid_combo.addItems(["Dilithium", "Falcon"])
        layout.addWidget(QLabel("🛡 Post-Quantum Algorithm:"))
        layout.addWidget(self.hybrid_combo)

        # Info security level
        self.security_info = QLabel(self)
        self.security_info.setWordWrap(True)
        self.security_info.setStyleSheet("color: #555;")
        self.security_info.setText(
            "<b>Supported Security Levels:</b><br>"
            "🔹 RSA: Levels 2 & 3<br>"
            "🔹 DSA: Levels 2<br>"
            "🔹 ECDSA: Levels 3 & 5<br>"
            "🔹 Dilithium: Levels 2 & 3<br>"
            "🔹 Falcon: Levels 2 & 5"
        )
        layout.addWidget(self.security_info)

        self.compatibility_msg = QLabel("")
        self.compatibility_msg.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(self.compatibility_msg)

        self.traditional_combo.currentTextChanged.connect(self.update_compatibility_message)
        self.hybrid_combo.currentTextChanged.connect(self.update_compatibility_message)
        self.security_combo.currentTextChanged.connect(self.update_compatibility_message)


        self.sign_button = QPushButton("✍️ Hybrid Sign", self)
        self.sign_button.setStyleSheet("background-color: #58D68D; color: white; padding: 5px;")
        self.sign_button.clicked.connect(self.sign_document)
        layout.addWidget(self.sign_button)

        self.signature_tab.setLayout(layout)

    # Vérification
    def setup_verification_tab(self):
        layout = QVBoxLayout()
        
        icon_label = QLabel(self)
        pixmap = QPixmap("icons/search.png")  
        icon_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio))
        layout.addWidget(icon_label, alignment=Qt.AlignCenter)

        layout.addWidget(QLabel("🧐 Verify your signature"))

        # 🔹 Button
        self.verify_button = QPushButton("🔍 Verify Signature", self)
        self.verify_button.setStyleSheet("background-color: #EC7063; color: white; padding: 5px;")
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.verify_button)

        self.verify_tab.setLayout(layout)

    #  Results
    def setup_results_tab(self):
        layout = QVBoxLayout()

        icon_label = QLabel(self)
        pixmap = QPixmap("icons/results.png")  
        icon_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio))
        layout.addWidget(icon_label, alignment=Qt.AlignCenter)
        
        # 🔹 Table of results
        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Algorithm", "Security Level", "Setup (ms)", "Sign (ms)", "Verify (ms)", "Total Time (ms)"])
        layout.addWidget(self.table)

        self.results_tab.setLayout(layout)


    def import_document(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import a Document", "", "All Files (*)", options=options)
        if file_name:
            self.file_path = file_name
            self.file_label.setText(f"Selected: {file_name}")


    def update_compatibility_message(self):
        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()
        level = self.security_combo.currentText()

        if self.is_valid_combination(traditional_algo, hybrid_algo, level):
            self.compatibility_msg.setText("✅ Compatible combination for selected level.")
            self.compatibility_msg.setStyleSheet("color: green;")
        else:
            compatible = self.find_compatible_level(traditional_algo, hybrid_algo)
            if compatible:
                self.compatibility_msg.setText(f"⚠️ Not compatible with level {level}. Try level: {compatible}.")
                self.compatibility_msg.setStyleSheet("color: orange;")
            else:
                self.compatibility_msg.setText("❌ No compatible security level for this combination.")
                self.compatibility_msg.setStyleSheet("color: red;")

    def is_valid_combination(self, traditional_algo, hybrid_algo, security_level):
        """ Vérifie si la combinaison est autorisée au niveau de sécurité sélectionné. """
        valid_combinations = {
            "2 (Standard)": [("DSA", "Dilithium"), ("RSA", "Falcon"),("RSA", "Dilithium"),("DSA", "Falcon")],
            "3 (High)": [("RSA", "Dilithium"),("ECDSA", "Dilithium")],
            "5 (Highest)": [ ("ECDSA", "Falcon")]
        }
        return (traditional_algo, hybrid_algo) in valid_combinations[security_level]
    
    valid_combinations = {
            "2 (Standard)": [("DSA", "Dilithium"), ("RSA", "Falcon"),("RSA", "Dilithium"),("DSA", "Falcon")],
            "3 (High)": [("RSA", "Dilithium"),("ECDSA", "Dilithium")],
            "5 (Highest)": [ ("ECDSA", "Falcon")]
        }
    
    def find_compatible_level(self, traditional_algo, hybrid_algo):
        for level, pairs in self.valid_combinations.items():
            if (traditional_algo, hybrid_algo) in pairs:
                return level
        return None

    def sign_document(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please import a file first!")
            return

        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()
        security_level = self.security_combo.currentText()

        output_file = self.file_path + ".signed"
        self.signed_file_path = output_file

        command = ["./hybrid_signature", self.file_path, traditional_algo, hybrid_algo, output_file]
        
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip().split("\n")
            print("Raw Output:", output)  
            # Parse timing results according to the format you're using
            traditional_data = {"setup": 0, "sign": 0, "verify": 0}
            hybrid_data = {"setup": 0, "sign": 0, "verify": 0}
            
            for line in output:
                print(f"Processing line: {line}") 
                # Parse lines like "Dilithium Setup: 0.123456" or "RSA Setup: 0.123456"
                for algo in [traditional_algo, hybrid_algo]:
                    for phase in ["Setup", "Sign", "Verify"]:
                        prefix = f"{algo} {phase}:"
                        if prefix in line:
                            try:
                                # Convert from seconds to milliseconds 
                                time_str = line.split(prefix)[1].strip().split()[0] 
                                time_value = float(time_str) * 1000
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
        if not hasattr(self, "signed_file_path") or not self.signed_file_path:
            QMessageBox.warning(self, "Error", "Please sign a file first!")
            return

        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()
        output_file = self.file_path + ".signed"

        if not traditional_algo or not hybrid_algo:
            QMessageBox.warning(self, "Error", "Please select both algorithms!")
            return

        if not os.path.exists(self.signed_file_path):
            QMessageBox.critical(self, "Error", "The signed file does not exist. Please check the signing process.")
            return

        try:
            verification_result = ["./hybrid_signature", self.file_path, traditional_algo, hybrid_algo, output_file]

            if verification_result:
                QMessageBox.information(self, "Verification Result", f"Verification Successful")
            else:
                QMessageBox.warning(self, "Verification Result", "Verification failed!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification process failed:\n{str(e)}")



if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())
