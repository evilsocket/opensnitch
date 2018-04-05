from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5 import QtDBus
import threading
import logging
import queue
import sys
import os

DIALOG_UI_PATH = "%s/res/dialog.ui" % os.path.dirname(sys.modules[__name__].__file__)

class Dialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self.setupUi(self)

        self._done = threading.Event()
        self._allow_button = self.findChild(QtWidgets.QPushButton, "allowButton")
        self._allow_button.clicked.connect(self._on_allow_click)
        self._block_button = self.findChild(QtWidgets.QPushButton, "denyButton")
        self._block_button.clicked.connect(self._on_block_click)
        self._duration_combo = self.findChild(QtWidgets.QComboBox, "actionComboBox")
        self._duration_combo.currentIndexChanged[str].connect(self._on_duration_changed)

    def promptUser(self, req):
        self._done.clear()
        self.show()
        self._done.wait()

    def _on_duration_changed(self):
        s_option = self._duration_combo.currentText()

    def _on_allow_click(self):
        self.hide()
        self._done.set()

    def _on_block_click(self):
        self.hide()
        self._done.set()

