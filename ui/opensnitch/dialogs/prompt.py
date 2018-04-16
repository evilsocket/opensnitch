import threading
import logging
import sys
import time
import os
import pwd

from PyQt5 import QtCore, QtGui, uic, QtWidgets

from slugify import slugify

from desktop_parser import LinuxDesktopParser
from config import Config
from version import version

import ui_pb2

DIALOG_UI_PATH = "%s/../res/prompt.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PromptDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _prompt_trigger = QtCore.pyqtSignal()
    _tick_trigger = QtCore.pyqtSignal()
    _timeout_trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self.setupUi(self)

        self.setWindowTitle("OpenSnitch v%s" % version)

        self._cfg = Config.get()
        self._lock = threading.Lock()
        self._con = None
        self._rule = None
        self._local = True
        self._peer = None
        self._prompt_trigger.connect(self.on_connection_prompt_triggered)
        self._timeout_trigger.connect(self.on_timeout_triggered)
        self._tick_trigger.connect(self.on_tick_triggered)
        self._tick = self._cfg.default_timeout
        self._tick_thread = None
        self._done = threading.Event()

        self._apps_parser = LinuxDesktopParser()

        self._app_name_label = self.findChild(QtWidgets.QLabel, "appNameLabel")
        self._app_icon_label = self.findChild(QtWidgets.QLabel, "iconLabel")
        self._message_label = self.findChild(QtWidgets.QLabel, "messageLabel")

        self._src_ip_label = self.findChild(QtWidgets.QLabel, "sourceIPLabel")
        self._dst_ip_label = self.findChild(QtWidgets.QLabel, "destIPLabel")
        self._uid_label = self.findChild(QtWidgets.QLabel, "uidLabel")
        self._pid_label = self.findChild(QtWidgets.QLabel, "pidLabel")
        self._args_label = self.findChild(QtWidgets.QLabel, "argsLabel")

        self._apply_button = self.findChild(QtWidgets.QPushButton, "applyButton")
        self._apply_button.clicked.connect(self._on_apply_clicked)

        self._action_combo = self.findChild(QtWidgets.QComboBox, "actionCombo")
        self._what_combo = self.findChild(QtWidgets.QComboBox, "whatCombo")
        self._duration_combo = self.findChild(QtWidgets.QComboBox, "durationCombo")

    def promptUser(self, connection, is_local, peer):
        # one at a time
        with self._lock:
            # reset state
            self._tick = self._cfg.default_timeout
            self._tick_thread = threading.Thread(target=self._timeout_worker)
            self._rule = None
            self._local = is_local
            self._peer = peer
            self._con = connection
            self._done.clear()
            # trigger and show dialog
            self._prompt_trigger.emit()
            # start timeout thread
            self._tick_thread.start()
            # wait for user choice or timeout
            self._done.wait()
            
            return self._rule

    def _timeout_worker(self):
        while self._tick > 0 and self._done.is_set() is False:
            self._tick -= 1
            self._tick_trigger.emit()
            time.sleep(1)
        
        if not self._done.is_set():
            self._timeout_trigger.emit()

    @QtCore.pyqtSlot()
    def on_connection_prompt_triggered(self):
        self._render_connection(self._con)
        self.show()

    @QtCore.pyqtSlot()
    def on_tick_triggered(self):
        self._apply_button.setText("Apply (%d)" % self._tick)

    @QtCore.pyqtSlot()
    def on_timeout_triggered(self):
        self._on_apply_clicked()

    def _render_connection(self, con):
        if self._local:
            app_name, app_icon, _ = self._apps_parser.get_info_by_path(con.process_path, "terminal")
        else:
            app_name, app_icon = "", "terminal"

        if app_name == "":
            self._app_name_label.setText(con.process_path)
        else:
            self._app_name_label.setText(app_name)

        icon = QtGui.QIcon().fromTheme(app_icon)
        pixmap = icon.pixmap(icon.actualSize(QtCore.QSize(48, 48)))
        self._app_icon_label.setPixmap(pixmap)

        if self._local:
            message = "<b>%s</b> is connecting to <b>%s</b> on %s port %d" % ( \
                        app_name,
                        con.dst_host or con.dst_ip,
                        con.protocol,
                        con.dst_port )
        else:
            message = "The process <b>%s</b> running on the computer <b>%s</b> is connecting to <b>%s</b> on %s port %d" % ( \
                        app_name,
                        self._peer.split(':')[1],
                        con.dst_host or con.dst_ip,
                        con.protocol,
                        con.dst_port )

        self._message_label.setText(message)

        self._src_ip_label.setText(con.src_ip)
        self._dst_ip_label.setText(con.dst_ip)

        if self._local:
            uid = "%d (%s)" % (con.user_id, pwd.getpwuid(con.user_id).pw_name)
        else:
            uid = "%d" % con.user_id

        self._uid_label.setText(uid)
        self._pid_label.setText("%s" % con.process_id)
        self._args_label.setText(' '.join(con.process_args))

        self._what_combo.clear()
        self._what_combo.addItem("from this process")
        self._what_combo.addItem("from user %d" % con.user_id)
        self._what_combo.addItem("to port %d" % con.dst_port)
        self._what_combo.addItem("to %s" % con.dst_ip)
        if con.dst_host != "":
            self._what_combo.addItem("to %s" % con.dst_host)
            parts = con.dst_host.split('.')[1:]
            nparts = len(parts)
            for i in range(0, nparts - 1):
                self._what_combo.addItem("to *.%s" % '.'.join(parts[i:]))

        if self._cfg.default_action == "allow":
            self._action_combo.setCurrentIndex(0)
        else:
            self._action_combo.setCurrentIndex(1)

        if self._cfg.default_duration == "once":
            self._duration_combo.setCurrentIndex(0)
        elif self._cfg.default_duration == "until restart":
            self._duration_combo.setCurrentIndex(1)
        else:
            self._duration_combo.setCurrentIndex(2)

        self._what_combo.setCurrentIndex(0)

        self._apply_button.setText("Apply (%d)" % self._tick)

        self.setFixedSize(self.size())

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(PromptDialog, self).keyPressEvent(event)

    # prevent a click on the window's x 
    # from quitting the whole application
    def closeEvent(self, e):
        self._on_apply_clicked()
        e.ignore()

    def _on_apply_clicked(self):
        self._rule = ui_pb2.Rule(name="user.choice")

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
            self._rule.operator.type = "simple"
            self._rule.operator.operand = "process.path"
            self._rule.operator.data = self._con.process_path 

        elif what_idx == 1:
            self._rule.operator.type = "simple"
            self._rule.operator.operand = "user.id"
            self._rule.operator.data = "%s" % self._con.user_id 
        
        elif what_idx == 2:
            self._rule.operator.type = "simple"
            self._rule.operator.operand = "dest.port"
            self._rule.operator.data = "%s" % self._con.dst_port 

        elif what_idx == 3:
            self._rule.operator.type = "simple"
            self._rule.operator.operand = "dest.ip"
            self._rule.operator.data = self._con.dst_ip 
        
        elif what_idx == 4:
            self._rule.operator.type = "simple"
            self._rule.operator.operand = "dest.host"
            self._rule.operator.data = self._con.dst_host 

        else:
            self._rule.operator.type = "regexp"
            self._rule.operator.operand = "dest.host"
            self._rule.operator.data = ".*%s" % '\.'.join(self._con.dst_host.split('.')[what_idx - 4:])

        self._rule.name = slugify("%s %s %s" % (self._rule.action, self._rule.operator.type, self._rule.operator.data))
        
        self.hide()
        # signal that the user took a decision and 
        # a new rule is available
        self._done.set()

