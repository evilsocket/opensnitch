
from PyQt5 import QtCore, QtWidgets

class Message():

    @staticmethod
    def ok(title, message, icon):
        msgBox = QtWidgets.QMessageBox()
        msgBox.setText("<b>{0}</b><br><br>{1}".format(title, message))
        msgBox.setIcon(icon)
        msgBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msgBox.exec_()

    @staticmethod
    def yes_no(title, message, icon):
        msgBox = QtWidgets.QMessageBox()
        msgBox.setText(title)
        msgBox.setIcon(icon)
        msgBox.setInformativeText(message)
        msgBox.setStandardButtons(QtWidgets.QMessageBox.Cancel | QtWidgets.QMessageBox.Yes)
        msgBox.setDefaultButton(QtWidgets.QMessageBox.Cancel)
        return msgBox.exec_()

class FileDialog():

    @staticmethod
    def save(parent):
        options = QtWidgets.QFileDialog.Options()
        fileName, _ = QtWidgets.QFileDialog.getSaveFileName(parent, "", "","All Files (*)", options=options)
        return fileName

    @staticmethod
    def select(parent):
        options = QtWidgets.QFileDialog.Options()
        fileName, _ = QtWidgets.QFileDialog.getOpenFileName(parent, "", "","All Files (*)", options=options)
        return fileName

    @staticmethod
    def select_dir(parent, current_dir):
        options = QtWidgets.QFileDialog.Options()
        fileName = QtWidgets.QFileDialog.getExistingDirectory(parent, "", current_dir, options)
        return fileName

