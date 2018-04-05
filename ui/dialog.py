from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5 import QtDBus
import threading
import logging
import queue
import sys
import os

from desktop_parser import LinuxDesktopParser

DIALOG_UI_PATH = "%s/res/dialog.ui" % os.path.dirname(sys.modules[__name__].__file__)

class Dialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self.setupUi(self)

        self._lock = threading.Lock()
        self._request = None
        self._trigger.connect(self.on_request)
        self._done = threading.Event()

        self._apps_parser = LinuxDesktopParser()

        self._app_name_label = self.findChild(QtWidgets.QLabel, "appNameLabel")
        self._app_icon_label = self.findChild(QtWidgets.QLabel, "iconLabel")
        self._message_label = self.findChild(QtWidgets.QLabel, "messageLabel")

        self._src_ip_label = self.findChild(QtWidgets.QLabel, "sourceIPLabel")
        self._dst_ip_label = self.findChild(QtWidgets.QLabel, "destIPLabel")
        self._dst_port_label = self.findChild(QtWidgets.QLabel, "destPortLabel")
        self._dst_host_label = self.findChild(QtWidgets.QLabel, "destHostLabel")
        self._uid_label = self.findChild(QtWidgets.QLabel, "uidLabel")
        self._pid_label = self.findChild(QtWidgets.QLabel, "pidLabel")
        self._args_label = self.findChild(QtWidgets.QLabel, "argsLabel")

        self._apply_button = self.findChild(QtWidgets.QPushButton, "applyButton")
        self._apply_button.clicked.connect(self._on_apply_clicked)

        self._action_combo = self.findChild(QtWidgets.QComboBox, "actionCombo")
        self._what_combo = self.findChild(QtWidgets.QComboBox, "whatCombo")
        self._duration_combo = self.findChild(QtWidgets.QComboBox, "durationCombo")

    def promptUser(self, request):
        with self._lock:
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
        app_name, app_icon, desk = self._apps_parser.get_info_by_path(req.process_path)
        print "path=%s -> name=%s icon=%s desk=%s" % (req.process_path, app_name, app_icon, desk)
                
        if app_name == "":
            self._app_name_label.setText(req.process_path)
        else:
            self._app_name_label.setText(app_name)
            
        if app_icon is not None:
            icon = QtGui.QIcon().fromTheme(app_icon)
            pixmap = icon.pixmap(icon.actualSize(QtCore.QSize(48, 48)))
            self._app_icon_label.setPixmap(pixmap)

        self._message_label.setText("<b>%s</b> is connecting to %s on %s port %d" % ( \
            app_name or req.process_path,
            req.dst_host or req.dst_ip,
            req.protocol,
            req.dst_port
        ))

        self._src_ip_label.setText(req.src_ip)
        self._dst_ip_label.setText(req.dst_ip)
        self._dst_port_label.setText("%s" % req.dst_port)
        self._dst_host_label.setText(req.dst_host)
        self._uid_label.setText("%s" % req.user_id)
        self._pid_label.setText("%s" % req.process_id)
        self._args_label.setText(' '.join(req.process_args))

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(Dialog, self).keyPressEvent(event)

    def closeEvent(self, e):
        self._on_apply_clicked()
        e.ignore()
        # super(Dialog, self).closeEvent(e)

    def _on_apply_clicked(self):
        self.hide()
        self._done.set()

