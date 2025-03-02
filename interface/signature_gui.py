import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox, QFileDialog

class SignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.file_path = ""  # Stocke le fichier sélectionné

    def initUI(self):
        layout = QVBoxLayout()

        # Bouton pour importer un document
        self.import_button = QPushButton("Import a file", self)
        self.import_button.clicked.connect(self.import_document)
        layout.addWidget(self.import_button)

        # Sélection de la signature traditionnelle
        self.traditional_label = QLabel("Select the traditional signature algorithm", self)
        layout.addWidget(self.traditional_label)

        self.traditional_combo = QComboBox(self)
        self.traditional_combo.addItems(["RSA", "DSA", "ECDSA"])
        layout.addWidget(self.traditional_combo)

        # Sélection de la signature hybride
        self.hybrid_label = QLabel("Select hybrid signature algorithm:", self)
        layout.addWidget(self.hybrid_label)

        self.hybrid_combo = QComboBox(self)
        self.hybrid_combo.addItems(["Dilithium", "Falcon"])
        layout.addWidget(self.hybrid_combo)

        # Bouton pour signer
        self.sign_button = QPushButton("Sign a file", self)
        self.sign_button.clicked.connect(self.sign_file)
        layout.addWidget(self.sign_button)

        # Label d'analyse des performances
        self.performance_label = QLabel("Performance analysis", self)
        layout.addWidget(self.performance_label)

        self.setLayout(layout)
        self.setWindowTitle("Hybrid Signature")
        self.resize(400, 200)

    def import_document(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import a document", "", "All Files (*);;Text Files (*.txt)", options=options)
        if file_name:
            self.file_path = file_name
            print(f"Document imported: {self.file_path}")

    def sign_file(self):
        if not self.file_path:
            print("No document selected.")
            return

        # Récupération des choix de signature
        traditional_sig = self.traditional_combo.currentText()
        hybrid_sig = self.hybrid_combo.currentText()

        # Appel du programme C en lui passant le fichier et les types de signatures
        result = subprocess.run(["./hybrid_signature", self.file_path, traditional_sig, hybrid_sig], capture_output=True, text=True)

        if result.returncode == 0:
            print("File signed successfully!")
            print("Signature details:", result.stdout)
        else:
            print("Error in signing:", result.stderr)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())
