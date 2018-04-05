from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5 import QtDBus
import threading
import logging
import queue
import sys
import os

DIALOG_UI_PATH = "%s/res/dialog.ui" % os.path.dirname(sys.modules[__name__].__file__)

class Dialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self.setupUi(self)

        self._request = None
        self._trigger.connect(self.on_request)
        self._done = threading.Event()

        self._app_name_label = self.findChild(QtWidgets.QLabel, "appNameLabel")
        self._app_icon_label = self.findChild(QtWidgets.QLabel, "iconLabel")
        self._message_label = self.findChild(QtWidgets.QLabel, "messageLabel")

        self._allow_button = self.findChild(QtWidgets.QPushButton, "allowButton")
        self._allow_button.clicked.connect(self._on_allow_click)
        self._block_button = self.findChild(QtWidgets.QPushButton, "denyButton")
        self._block_button.clicked.connect(self._on_block_click)
        self._duration_combo = self.findChild(QtWidgets.QComboBox, "actionComboBox")
        self._duration_combo.currentIndexChanged[str].connect(self._on_duration_changed)

    def promptUser(self, request):
        self._request = request
        self._trigger.emit()
        self._done.wait()

    @QtCore.pyqtSlot()
    def on_request(self):
        self._done.clear()
        if self._request is not None:
            self._setup_request(self._request)
            self.show()

    def _setup_request(self, req):
        self._app_name_label.setText(req.process_path)
        self._message_label.setText("<b>%s</b> is connecting to %s on %s port %d" % ( \
            req.process_path,
            req.dst_host or req.dst_ip,
            req.protocol,
            req.dst_port
        ))

    def _on_duration_changed(self):
        s_option = self._duration_combo.currentText()

    def _on_allow_click(self):
        self.hide()
        self._done.set()

    def _on_block_click(self):
        self.hide()
        self._done.set()

