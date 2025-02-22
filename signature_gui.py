import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox

class SignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.label = QLabel("Sélectionnez l'algorithme de signature :", self)
        layout.addWidget(self.label)

        self.combo = QComboBox(self)
        self.combo.addItems(["RSA", "DSA", "ECDSA", "Falcon", "Dilithium"])
        layout.addWidget(self.combo)

        self.sign_button = QPushButton("Signer un document", self)
        layout.addWidget(self.sign_button)

        self.performance_label = QLabel("Analyse des performances :", self)
        layout.addWidget(self.performance_label)

        self.setLayout(layout)
        self.setWindowTitle("Signature Hybride")
        self.resize(400, 200)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SignatureApp()
    ex.show()
    sys.exit(app.exec_())
