import threading
import logging
import queue
import sys
import os
import pwd

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5 import QtDBus

from slugify import slugify

from desktop_parser import LinuxDesktopParser

import ui_pb2

DIALOG_UI_PATH = "%s/res/dialog.ui" % os.path.dirname(sys.modules[__name__].__file__)

class Dialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self.setupUi(self)

        self._lock = threading.Lock()
        self._con = None
        self._rule = None
        self._trigger.connect(self.on_connection_triggered)
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

    def promptUser(self, connection):
        # one at a time
        with self._lock:
            # reset state
            self._rule = None
            self._con = connection
            self._done.clear()
            # trigger on_connection_triggered
            self._trigger.emit()
            # wait for user choice
            self._done.wait()
            
            return self._rule

    @QtCore.pyqtSlot()
    def on_connection_triggered(self):
        self._render_connection(self._con)
        self.show()

    def _render_connection(self, con):
        app_name, app_icon, desk = self._apps_parser.get_info_by_path(con.process_path, "dialog-question")
        if app_name == "":
            self._app_name_label.setText(con.process_path)
        else:
            self._app_name_label.setText(app_name)

        icon = QtGui.QIcon().fromTheme(app_icon)
        pixmap = icon.pixmap(icon.actualSize(QtCore.QSize(48, 48)))
        self._app_icon_label.setPixmap(pixmap)

        self._message_label.setText("<b>%s</b> is connecting to <b>%s</b> on %s port %d" % ( \
            con.process_path,
            con.dst_host or con.dst_ip,
            con.protocol,
            con.dst_port
        ))

        self._src_ip_label.setText(con.src_ip)
        self._dst_ip_label.setText(con.dst_ip)
        self._dst_port_label.setText("%s" % con.dst_port)
        self._dst_host_label.setText(con.dst_host)
        self._uid_label.setText("%d (%s)" % (con.user_id, pwd.getpwuid(con.user_id).pw_name))
        self._pid_label.setText("%s" % con.process_id)
        self._args_label.setText(' '.join(con.process_args))

        self._what_combo.clear()
        self._what_combo.addItem("from this process")
        self._what_combo.addItem("from user %d" % con.user_id)
        self._what_combo.addItem("to port %d" % con.dst_port)
        self._what_combo.addItem("to %s" % con.dst_ip)
        if con.dst_host != "":
            self._what_combo.addItem("to %s" % con.dst_host)

        self._what_combo.setCurrentIndex(0)
        self._action_combo.setCurrentIndex(0)
        self._duration_combo.setCurrentIndex(1)

        self.setFixedSize(self.size())

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(Dialog, self).keyPressEvent(event)

    # prevent a click on the window's x 
    # from quitting the whole application
    def closeEvent(self, e):
        self._on_apply_clicked()
        e.ignore()

    def _on_apply_clicked(self):
        self._rule = ui_pb2.RuleReply(name="user.choice")
    
        action_idx = self._action_combo.currentIndex()
        if action_idx == 0:
            self._rule.action = "allow"
        else:
            self._rule.action = "deny"

        duration_idx = self._duration_combo.currentIndex()
        if duration_idx == 0:
            self._rule.duration = "once"
        elif duration_idx == 1:
            self._rule.duration = "until restart"
        else:
            self._rule.duration = "always"
        
        what_idx = self._what_combo.currentIndex()
        if what_idx == 0:
            self._rule.what = "process.path"
            self._rule.value = self._con.process_path 

        elif what_idx == 1:
            self._rule.what = "user.id"
            self._rule.value = "%s" % self._con.user_id 
        
        elif what_idx == 2:
            self._rule.what = "dest.port"
            self._rule.value = "%s" % self._con.dst_port 

        elif what_idx == 3:
            self._rule.what = "dest.ip"
            self._rule.value = self._con.dst_ip 
        
        else:
            self._rule.what = "dest.host"
            self._rule.value = self._con.dst_host 

        self._rule.name = slugify("%s %s %s" % (self._rule.action, self._rule.what, self._rule.value))
        
        self.hide()
        # signal that the user took a decision and 
        # a new rule is available
        self._done.set()

