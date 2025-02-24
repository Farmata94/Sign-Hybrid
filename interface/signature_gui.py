import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox, QFileDialog

class SignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Bouton pour importer un document
        self.import_button = QPushButton("Import a file ", self)
        self.import_button.clicked.connect(self.import_document)
        layout.addWidget(self.import_button)

        # Sélection de la signature traditionnelle
        self.traditional_label = QLabel("Select the traditional signature algorithm", self)
        layout.addWidget(self.traditional_label)

        self.traditional_combo = QComboBox(self)
        self.traditional_combo.addItems(["RSA", "DSA", "ECDSA"])
        layout.addWidget(self.traditional_combo)

        # Sélection de la signature hybride
        self.hybrid_label = QLabel("Select hybrid signature algorithm :", self)
        layout.addWidget(self.hybrid_label)

        self.hybrid_combo = QComboBox(self)
        self.hybrid_combo.addItems(["Dilithium", "Falcon"])
        layout.addWidget(self.hybrid_combo)

        # Bouton pour signer
        self.sign_button = QPushButton("Sign a file", self)
        layout.addWidget(self.sign_button)

        # Label d'analyse des performances
        self.performance_label = QLabel("Performance analysis", self)
        layout.addWidget(self.performance_label)

        self.setLayout(layout)
        self.setWindowTitle("Signature Hybride")
        self.resize(400, 200)

    def import_document(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Importer un document", "", "All Files (*);;Text Files (*.txt)", options=options)
        if file_name:
            print(f"Document importé : {file_name}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())
