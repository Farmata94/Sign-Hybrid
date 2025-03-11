import sys
import subprocess
import time  
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox, QFileDialog, QMessageBox,QTableWidget,QTableWidgetItem
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
        self.sign_button.clicked.connect(self.sign_document)  # Lancer la signature
        layout.addWidget(self.sign_button)

        # Button verify
        self.verify_button = QPushButton("Verify the signature", self)
        self.verify_button.clicked.connect(self.verify_document)  
        layout.addWidget(self.verify_button)

        self.table = QTableWidget(self)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Algorithm", "Time (s)"])
        layout.addWidget(self.table)


        self.setLayout(layout)
        self.setWindowTitle("Hybrid Signature")
        self.resize(400, 250)

        self.file_path = None  

    def import_document(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import a document", "", "All Files (*);;Text Files (*.txt)", options=options)
        if file_name:
            self.file_path = file_name
            self.file_label.setText(f"Selected: {file_name}")

    def sign_document(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please import a file first!")
            return

        traditional_algo = self.traditional_combo.currentText()
        hybrid_algo = self.hybrid_combo.currentText()

        # Mapping des noms pour l'exécutable C
        algo_mapping = {
            "RSA": "RSA",
            "DSA": "DSA",
            "ECDSA": "ECDSA",
            "Dilithium": "Dilithium",
            "Falcon": "Falcon",
            "Phinics":"Phinics"
        }

        trad_algo_c = algo_mapping[traditional_algo]
        hybrid_algo_c = algo_mapping[hybrid_algo]

        output_file = self.file_path + ".signed"
        self.signed_file_path = output_file

        command = ["./hybrid_signature", self.file_path, trad_algo_c, hybrid_algo_c, output_file]
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip().split("\n")

            times = {}
            for line in output:
                try:
                    algo, time_str = line.split(": ")
                    times[algo] = float(time_str)
                except ValueError:
                    continue  # Ignore lines that don't match the expected format

            self.update_table(times)

        except subprocess.CalledProcessError:
            QMessageBox.critical(self, "Error", "Signature process failed!")

    def verify_document(self):
        if not self.signed_file_path:
            QMessageBox.warning(self, "Error", "Please import a signed file first!")
            return

        # Exécuter le programme C pour vérifier la signature hybride
        command = ["./hybrid_verify", self.signed_file_path]
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            output = result.stdout.strip().split("\n")

            # Affichage des résultats dans l'interface
            for line in output:
                print(line)  # Optionnel, pour afficher les résultats dans la console

            # Afficher un message de succès ou d'erreur selon la sortie
            QMessageBox.information(self, "Verification Result", "\n".join(output))

        except subprocess.CalledProcessError:
            QMessageBox.critical(self, "Error", "Verification process failed!")

    def update_table(self, times):
        self.table.setRowCount(len(times))
        for i, (algo, time) in enumerate(times.items()):
            self.table.setItem(i, 0, QTableWidgetItem(algo))
            self.table.setItem(i, 1, QTableWidgetItem(f"{time:.6f}"))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())
