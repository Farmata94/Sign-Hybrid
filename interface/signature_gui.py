import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox, QFileDialog, QMessageBox

class SignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Bouton pour importer un document
        self.import_button = QPushButton("Import a file", self)
        self.import_button.clicked.connect(self.import_document)
        layout.addWidget(self.import_button)

        # Label pour afficher le fichier importé
        self.file_label = QLabel("No file selected", self)
        layout.addWidget(self.file_label)

        # Sélection de la signature traditionnelle
        self.traditional_label = QLabel("Select the traditional signature algorithm", self)
        layout.addWidget(self.traditional_label)

        self.traditional_combo = QComboBox(self)
        self.traditional_combo.addItems(["RSA", "DSA", "ECDSA"])
        layout.addWidget(self.traditional_combo)

        # Sélection de la signature hybride
        self.hybrid_label = QLabel("Select the hybrid signature algorithm:", self)
        layout.addWidget(self.hybrid_label)

        self.hybrid_combo = QComboBox(self)
        self.hybrid_combo.addItems(["Dilithium", "Falcon"])
        layout.addWidget(self.hybrid_combo)

        # Bouton pour signer
        self.sign_button = QPushButton("Sign a file", self)
        self.sign_button.clicked.connect(self.sign_document)  # Lancer la signature
        layout.addWidget(self.sign_button)

        # Label pour le statut
        self.status_label = QLabel("", self)
        layout.addWidget(self.status_label)

        self.setLayout(layout)
        self.setWindowTitle("Hybrid Signature")
        self.resize(400, 250)

        self.file_path = None  # Stocke le fichier importé

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
            "RSA": "rsa",
            "DSA": "dsa",
            "ECDSA": "ecdsa",
            "Dilithium": "dilithium",
            "Falcon": "falcon"
        }

        trad_algo_c = algo_mapping[traditional_algo]
        hybrid_algo_c = algo_mapping[hybrid_algo]

        output_file = self.file_path + ".signed"

        # Exécuter le programme C avec les arguments
        command = ["./hybrid_signature", self.file_path, trad_algo_c, hybrid_algo_c, output_file]
        try:
            subprocess.run(command, check=True)
            QMessageBox.information(self, "Success", f"File signed successfully!\nSaved as: {output_file}")
            self.status_label.setText(f"Signed file: {output_file}")
        except subprocess.CalledProcessError:
            QMessageBox.critical(self, "Error", "Signature process failed!")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())
