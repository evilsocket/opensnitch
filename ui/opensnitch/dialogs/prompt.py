import threading
import logging
import sys
import time
import os
import pwd
import json
from datetime import datetime

from PyQt5 import QtCore, QtGui, uic, QtWidgets

from slugify import slugify

from desktop_parser import LinuxDesktopParser
from config import Config
from version import version
from database import Database

import ui_pb2

DIALOG_UI_PATH = "%s/../res/prompt.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PromptDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _prompt_trigger = QtCore.pyqtSignal()
    _tick_trigger = QtCore.pyqtSignal()
    _timeout_trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self._cfg = Config.get()
        self._db = Database.instance()

        dialog_geometry = self._cfg.getSettings("promptDialog/geometry")
        if dialog_geometry != None:
            self.restoreGeometry(dialog_geometry)

        self.setupUi(self)

        self.setWindowTitle("OpenSnitch v%s" % version)

        self._lock = threading.Lock()
        self._con = None
        self._rule = None
        self._local = True
        self._peer = None
        self._prompt_trigger.connect(self.on_connection_prompt_triggered)
        self._timeout_trigger.connect(self.on_timeout_triggered)
        self._tick_trigger.connect(self.on_tick_triggered)
        self._tick = int(self._cfg.getSettings("global/default_timeout"))
        self._tick_thread = None
        self._done = threading.Event()
        self._apply_text = "Apply"
        self._timeout_triggered = False

        self._apps_parser = LinuxDesktopParser()

        self._app_name_label = self.findChild(QtWidgets.QLabel, "appNameLabel")
        self._app_icon_label = self.findChild(QtWidgets.QLabel, "iconLabel")
        self._message_label = self.findChild(QtWidgets.QLabel, "messageLabel")

        self._src_ip_label = self.findChild(QtWidgets.QLabel, "sourceIPLabel")
        self._dst_ip_label = self.findChild(QtWidgets.QLabel, "destIPLabel")
        self._dst_port_label = self.findChild(QtWidgets.QLabel, "destPortLabel")
        self._uid_label = self.findChild(QtWidgets.QLabel, "uidLabel")
        self._pid_label = self.findChild(QtWidgets.QLabel, "pidLabel")
        self._args_label = self.findChild(QtWidgets.QLabel, "argsLabel")

        self._apply_button = self.findChild(QtWidgets.QPushButton, "applyButton")
        self._apply_button.clicked.connect(self._on_apply_clicked)

        self._action_combo = self.findChild(QtWidgets.QComboBox, "actionCombo")
        self._what_combo = self.findChild(QtWidgets.QComboBox, "whatCombo")
        self._what_dstip_combo = self.findChild(QtWidgets.QComboBox, "whatIPCombo")
        self._duration_combo = self.findChild(QtWidgets.QComboBox, "durationCombo")
        self._what_dstip_combo.setVisible(False)

        self._dst_ip_check = self.findChild(QtWidgets.QCheckBox, "checkDstIP")
        self._dst_port_check = self.findChild(QtWidgets.QCheckBox, "checkDstPort")
        self._uid_check = self.findChild(QtWidgets.QCheckBox, "checkUserID")
        self._advanced_check = self.findChild(QtWidgets.QPushButton, "checkAdvanced")
        self._dst_ip_check.setVisible(False)
        self._dst_port_check.setVisible(False)
        self._uid_check.setVisible(False)

        self._is_advanced_checked = False
        self._advanced_check.toggled.connect(self._checkbox_toggled)

    def _checkbox_toggled(self, state):
        self._apply_button.setText("%s" % self._apply_text)
        self._tick_thread.stop = state

        self._dst_ip_check.setVisible(state)
        self._what_dstip_combo.setVisible(state)
        self._dst_ip_label.setVisible(not state)
        self._dst_port_check.setVisible(state)
        self._uid_check.setVisible(state)
        self._is_advanced_checked = state

    def promptUser(self, connection, is_local, peer):
        # one at a time
        with self._lock:
            # reset state
            if self._tick_thread != None and self._tick_thread.is_alive():
                self._tick_thread.join()
            self._tick = int(self._cfg.getSettings("global/default_timeout"))
            self._tick_thread = threading.Thread(target=self._timeout_worker)
            self._tick_thread.stop = self._is_advanced_checked
            self._timeout_triggered = False
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
            
            return self._rule, self._timeout_triggered

    def _timeout_worker(self):
        while self._tick > 0 and self._done.is_set() is False:
            t = threading.currentThread()
            if getattr(t, "stop", True):
                self._tick = int(self._cfg.getSettings("global/default_timeout"))
                continue

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
        self._apply_button.setText("%s (%d)" % (self._apply_text, self._tick))

    @QtCore.pyqtSlot()
    def on_timeout_triggered(self):
        self._timeout_triggered = True
        self._on_apply_clicked()

    def _render_connection(self, con):
        if self._local:
            app_name, app_icon, _ = self._apps_parser.get_info_by_path(con.process_path, "terminal")
        else:
            app_name, app_icon = "", "terminal"

        if app_name == "":
            app_name = "Unknown process"
            self._app_name_label.setText("Outgoing connection")
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
        self._dst_port_label.setText(str(con.dst_port))

        if self._local:
            try:
                uid = "%d (%s)" % (con.user_id, pwd.getpwuid(con.user_id).pw_name)
            except:
                uid = ""
        else:
            uid = "%d" % con.user_id

        self._uid_label.setText(uid)
        self._pid_label.setText("%s" % con.process_id)
        self._args_label.setText(' '.join(con.process_args))

        self._what_combo.clear()
        self._what_dstip_combo.clear()
        if int(con.process_id) > 0:
            self._what_combo.addItem("from this process", "process_id")
        if int(con.user_id) >= 0:
            self._what_combo.addItem("from user %s" % uid, "user_id")
        self._what_combo.addItem("to port %d" % con.dst_port, "dst_port")
        self._what_combo.addItem("to %s" % con.dst_ip, "dst_ip")

        if con.dst_host != "" and con.dst_host != con.dst_ip:
            self._what_combo.addItem("to %s" % con.dst_host, "simple_host")
            self._what_dstip_combo.addItem("to %s" % con.dst_host, "simple_host")

            parts = con.dst_host.split('.')[1:]
            nparts = len(parts)
            for i in range(0, nparts - 1):
                self._what_combo.addItem("to *.%s" % '.'.join(parts[i:]), "regex_host")
                self._what_dstip_combo.addItem("to *.%s" % '.'.join(parts[i:]), "regex_host")

        self._what_dstip_combo.addItem("to %s" % con.dst_ip, "dst_ip")

        parts = con.dst_ip.split('.')
        nparts = len(parts)
        for i in range(1, nparts):
            self._what_combo.addItem("to %s.*" % '.'.join(parts[:i]), "regex_ip")
            self._what_dstip_combo.addItem("to %s.*" % '.'.join(parts[:i]), "regex_ip")

        if self._cfg.getSettings("global/default_action") == "allow":
            self._action_combo.setCurrentIndex(0)
        else:
            self._action_combo.setCurrentIndex(1)

        if self._cfg.getSettings("global/default_duration") == "once":
            self._duration_combo.setCurrentIndex(0)
        elif self._cfg.getSettings("global/default_duration") == "30s":
            self._duration_combo.setCurrentIndex(1)
        elif self._cfg.getSettings("global/default_duration") == "5m":
            self._duration_combo.setCurrentIndex(2)
        elif self._cfg.getSettings("global/default_duration") == "15m":
            self._duration_combo.setCurrentIndex(3)
        elif self._cfg.getSettings("global/default_duration") == "30m":
            self._duration_combo.setCurrentIndex(4)
        elif self._cfg.getSettings("global/default_duration") == "1h":
            self._duration_combo.setCurrentIndex(5)
        elif self._cfg.getSettings("global/default_duration") == "until restart":
            self._duration_combo.setCurrentIndex(6)
        else:
            self._duration_combo.setCurrentIndex(7)

        if int(con.process_id) > 0:
            self._what_combo.setCurrentIndex(0)
        else:
            self._what_combo.setCurrentIndex(1)

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

    def _get_duration(self, duration_idx):
        if duration_idx == 0:
            return "once"
        elif duration_idx == 1:
            return "30s"
        elif duration_idx == 2:
            return "5m"
        elif duration_idx == 3:
            return "15m"
        elif duration_idx == 4:
            return "30m"
        elif duration_idx == 5:
            return "1h"
        elif duration_idx == 6:
            return "until restart"
        else:
            return "always"

    def _get_combo_operator(self, combo, what_idx):
        if combo.itemData(what_idx) == "process_id":
            return "simple", "process.path", self._con.process_path

        elif combo.itemData(what_idx) == "user_id":
            return "simple", "user.id", "%s" % self._con.user_id
        
        elif combo.itemData(what_idx) == "dst_port":
            return "simple", "dest.port", "%s" % self._con.dst_port

        elif combo.itemData(what_idx) == "dst_ip":
            return "simple", "dest.ip", self._con.dst_ip
        
        elif combo.itemData(what_idx) == "simple_host":
            return "simple", "dest.host", self._con.dst_host

        elif combo.itemData(what_idx) == "regex_host":
            return "regexp", "dest.host", "%s" % '\.'.join(combo.currentText().split('.')).replace("*", ".*")[3:]

        elif combo.itemData(what_idx) == "regex_ip":
            return "regexp", "dest.ip", "%s" % '\.'.join(combo.currentText().split('.')).replace("*", ".*")[3:]

    def _on_apply_clicked(self):
        self._cfg.setSettings("promptDialog/geometry", self.saveGeometry())
        self._rule = ui_pb2.Rule(name="user.choice")

        action_idx = self._action_combo.currentIndex()
        if action_idx == 0:
            self._rule.action = "allow"
        else:
            self._rule.action = "deny"

        self._rule.duration = self._get_duration(self._duration_combo.currentIndex())

        what_idx = self._what_combo.currentIndex()
        self._rule.operator.type, self._rule.operator.operand, self._rule.operator.data = self._get_combo_operator(self._what_combo, what_idx)

        # TODO: move to a method
        is_advanced=False
        data=[]
        if self._dst_ip_check.isChecked() and (self._what_combo.itemData(what_idx) == "process_id" or
                self._what_combo.itemData(what_idx) == "user_id" or
                self._what_combo.itemData(what_idx) == "dst_port"):
            is_advanced=True
            _type, _operand, _data = self._get_combo_operator(self._what_dstip_combo, self._what_dstip_combo.currentIndex())
            data.append({"type": _type, "operand": _operand, "data": _data})

        if self._dst_port_check.isChecked() and self._what_combo.itemData(what_idx) != "dst_port":
            is_advanced=True
            data.append({"type": "simple", "operand": "dest.port", "data": str(self._con.dst_port)})

        if self._uid_check.isChecked() and self._what_combo.itemData(what_idx) != "user_id":
            is_advanced=True
            data.append({"type": "simple", "operand": "user.id", "data": str(self._con.user_id)})

        if is_advanced and self._advanced_check.isChecked():
            data.append({"type": self._rule.operator.type, "operand": self._rule.operator.operand, "data": self._rule.operator.data})
            self._rule.operator.data = json.dumps(data)
            self._rule.operator.type = "list"
            self._rule.operator.operand = ""

        self._rule.name = slugify("%s %s %s" % (self._rule.action, self._rule.operator.type, self._rule.operator.data))
        self.hide()
        if self._is_advanced_checked:
            self._advanced_check.toggle()
        self._id_advanced_checked = False

        # signal that the user took a decision and 
        # a new rule is available
        self._done.set()

