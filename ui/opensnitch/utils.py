
from PyQt5 import QtCore, QtWidgets

class Message():

    @staticmethod
    def ok(title, message, icon):
        msgBox = QtWidgets.QMessageBox()
        msgBox.setText(title)
        msgBox.setIcon(icon)
        msgBox.setInformativeText(message)
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
