import sys

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox

from CSCipher import CSCipher
from UI.about_dialog import Ui_About
from UI.file_dialog import Ui_FileDialog
from UI.start_form import Ui_MainWindow


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        QtWidgets.QMainWindow.__init__(self, parent=parent)
        self.setupUi(self)
        self.fileButton.clicked.connect(self.on_click_file)
        self.infoButton.clicked.connect(self.on_click_info)

    def on_click_file(self):
        file = FileDialog()
        file.exec_()

    def on_click_info(self):
        about = AboutDialog()
        about.exec_()


class AboutDialog(QtWidgets.QDialog, Ui_About):
    __algoritm__ = '''
    Алгоритм CS-Cipher по принципу работы является 8 раундовой SP-сетью
    При шифровании данных используются побитовые операции, байтовые перестановки и табличные замены'''
    __about__ = '''
    Программная реализация алгоритма CS-Cipher. 
    Выполнил студент группы БИСТ-19-2
    Колесников Степан Андреевич
    ИТКН НИТУ <<МИСИС>>
    Москва, 2021'''

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent=parent)
        self.About = QtWidgets.QDialog()
        self.setupUi(self)
        self.aboutButton.clicked.connect(self.onAboutClicked)
        self.algoritmButton.clicked.connect(self.onAlgoritmClicked)

    def onAlgoritmClicked(self):
        QMessageBox.about(self.About, 'Алгоритм', self.__algoritm__)

    def onAboutClicked(self):
        QMessageBox.about(self.About, 'Инфо', self.__about__)


class FileDialog(QtWidgets.QDialog, Ui_FileDialog):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent=parent)
        self.FileDialog = QtWidgets.QDialog()
        self.setupUi(self)
        self.encryptBox.stateChanged.connect(self.onCheckedGenerate)
        self.inputFileButton.clicked.connect(self.onInputClick)
        self.keyFileButton.clicked.connect(self.onKeyClick)
        self.outputFileButton.clicked.connect(self.onOutputClick)
        self.startButton.clicked.connect(self.onStartClick)

    def onInputClick(self):
        self.inputFile = QtWidgets.QFileDialog.getOpenFileName()[0]

    def onKeyClick(self):
        self.keyFile = QtWidgets.QFileDialog.getOpenFileName(filter='*.txt')[0]

    def onOutputClick(self):
        self.outputFile = QtWidgets.QFileDialog.getOpenFileName()[0]

    def onStartClick(self):
        encrypt = self.encryptBox.isChecked()
        if self.inputFile is None or self.inputFile == '' or self.inputFile == ' ':
            QMessageBox.about(self.FileDialog, "", "Вы забыли выбрать входной файл")
        if self.outputFile is None or self.outputFile == '' or self.outputFile == ' ':
            self.outputFile = 'output'
        if self.generateBox.isChecked():
            self.keyFile = None
        cs = CSCipher(self.inputFile, self.keyFile, self.outputFile, not encrypt)
        cs.start()
        QMessageBox.about(self.FileDialog, "", "Готово")
        self.outputFile = None
        self.keyFile = None
        self.inputFile = None

    def onCheckedGenerate(self):
        if self.encryptBox.isChecked():
            self.generateBox.setEnabled(True)
        else:
            self.generateBox.setChecked(False)
            self.generateBox.setEnabled(False)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
