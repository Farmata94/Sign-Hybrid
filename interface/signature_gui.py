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

        self.signature_tab = QWidget()
        self.setup_signature_tab()
        self.tabs.addTab(self.signature_tab, "🔏 Signature")

        self.verify_tab = QWidget()
        self.setup_verification_tab()
        self.tabs.addTab(self.verify_tab, "✔️ Vérification")

        self.results_tab = QWidget()
        self.setup_results_tab()
        self.tabs.addTab(self.results_tab, "📊 Résultats")

        # 🔵 NOUVEL ONGLET : Combinaison
        self.combination_tab = QWidget()
        self.setup_combination_tab()
        self.tabs.addTab(self.combination_tab, "📘 Combinaison")

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

        self.security_label = QLabel("🔒 Security Level:")
        layout.addWidget(self.security_label)
        self.security_combo = QComboBox(self)
        self.security_combo.addItems(["2 (Standard)", "3 (High)", "5 (Highest)"])
        layout.addWidget(self.security_combo)

        self.traditional_combo = QComboBox(self)
        self.traditional_combo.addItems(["RSA", "DSA", "ECDSA"])
        layout.addWidget(QLabel("📝 Traditional Algorithm:"))
        layout.addWidget(self.traditional_combo)

        self.hybrid_combo = QComboBox(self)
        self.hybrid_combo.addItems(["Dilithium", "Falcon", "Phinics"])
        layout.addWidget(QLabel("🛡 Post-Quantum Algorithm:"))
        layout.addWidget(self.hybrid_combo)

        self.sign_button = QPushButton("✍️ Hybrid Sign", self)
        self.sign_button.setStyleSheet("background-color: #58D68D; color: white; padding: 5px;")
        self.sign_button.clicked.connect(self.sign_document)
        layout.addWidget(self.sign_button)

        self.signature_tab.setLayout(layout)

    def setup_verification_tab(self):
        layout = QVBoxLayout()
        
        icon_label = QLabel(self)
        pixmap = QPixmap("icons/search.png")  
        icon_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio))
        layout.addWidget(icon_label, alignment=Qt.AlignCenter)

        layout.addWidget(QLabel("🧐 Verify your signature"))

        self.verify_button = QPushButton("🔍 Verify Signature", self)
        self.verify_button.setStyleSheet("background-color: #EC7063; color: white; padding: 5px;")
        self.verify_button.clicked.connect(self.verify_signature)
        layout.addWidget(self.verify_button)

        self.verify_tab.setLayout(layout)

    def setup_results_tab(self):
        layout = QVBoxLayout()

        icon_label = QLabel(self)
        pixmap = QPixmap("icons/results.png")  
        icon_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio))
        layout.addWidget(icon_label, alignment=Qt.AlignCenter)
        
        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Algorithm", "Security Level", "Setup (ms)", "Sign (ms)", "Verify (ms)", "Total Time (ms)"])
        layout.addWidget(self.table)

        self.results_tab.setLayout(layout)

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

    def import_document(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import a Document", "", "All Files (*)", options=options)
        if file_name:
            self.file_path = file_name
            self.file_label.setText(f"Selected: {file_name}")

    def is_valid_combination(self, traditional_algo, hybrid_algo, security_level):
        valid_combinations = {
            "2 (Standard)": [("DSA", "Dilithium"), ("RSA", "Falcon"), ("RSA", "Dilithium")],
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

        command = ["./hybrid_signature", self.file_path, traditional_algo, hybrid_algo, output_file]
        
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip().split("\n")
            traditional_data = {"setup": 0, "sign": 0, "verify": 0}
            hybrid_data = {"setup": 0, "sign": 0, "verify": 0}
            
            for line in output:
                for algo in [traditional_algo, hybrid_algo]:
                    for phase in ["Setup", "Sign", "Verify"]:
                        prefix = f"{algo} {phase}:"
                        if prefix in line:
                            try:
                                time_value = float(line.split(prefix)[1].strip()) * 1000
                                if algo == traditional_algo:
                                    traditional_data[phase.lower()] = time_value
                                else:
                                    hybrid_data[phase.lower()] = time_value
                            except (ValueError, IndexError):
                                continue

            timing_data = [
                (traditional_algo, traditional_data, security_level),
                (hybrid_algo, hybrid_data, security_level)
            ]
            
            self.update_table(timing_data)
            QMessageBox.information(self, "Success", "File signed successfully!")
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"Signature process failed!\n{e.stderr}")

    def update_table(self, timing_data):
        self.table.setRowCount(len(timing_data))
        
        for row, (algo, times, security_level) in enumerate(timing_data):
            total_time = times.get('setup', 0) + times.get('sign', 0) + times.get('verify', 0)
            self.table.setItem(row, 0, QTableWidgetItem(algo))
            self.table.setItem(row, 1, QTableWidgetItem(security_level))
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
