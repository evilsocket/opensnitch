import threading
import logging
import sys
import time
import os
import pwd
import json
import re
from datetime import datetime

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

    DEFAULT_TIMEOUT = 15

    ACTION_ALLOW = "allow"
    ACTION_DENY  = "deny"

    CFG_DEFAULT_TIMEOUT = "global/default_timeout"
    CFG_DEFAULT_ACTION = "global/default_action"

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)
        # Other interesting flags: QtCore.Qt.Tool | QtCore.Qt.BypassWindowManagerHint
        self._cfg = Config.get()
        self.setupUi(self)

        dialog_geometry = self._cfg.getSettings("promptDialog/geometry")
        if dialog_geometry == QtCore.QByteArray:
            self.restoreGeometry(dialog_geometry)

        self.setWindowTitle("OpenSnitch v%s" % version)

        self._lock = threading.Lock()
        self._con = None
        self._rule = None
        self._local = True
        self._peer = None
        self._prompt_trigger.connect(self.on_connection_prompt_triggered)
        self._timeout_trigger.connect(self.on_timeout_triggered)
        self._tick_trigger.connect(self.on_tick_triggered)
        self._tick = int(self._cfg.getSettings(self.CFG_DEFAULT_TIMEOUT)) if self._cfg.getSettings(self.CFG_DEFAULT_TIMEOUT) else self.DEFAULT_TIMEOUT
        self._tick_thread = None
        self._done = threading.Event()
        self._timeout_text = ""
        self._timeout_triggered = False

        self._apps_parser = LinuxDesktopParser()

        self.denyButton.clicked.connect(self._on_deny_clicked)
        # also accept button
        self.applyButton.clicked.connect(self._on_apply_clicked)
        self._apply_text = "Allow"
        self._deny_text = "Deny"
        self._default_action = self._cfg.getSettings(self.CFG_DEFAULT_ACTION)

        self.whatIPCombo.setVisible(False)
        self.checkDstIP.setVisible(False)
        self.checkDstPort.setVisible(False)
        self.checkUserID.setVisible(False)

        self._ischeckAdvanceded = False
        self.checkAdvanced.toggled.connect(self._checkbox_toggled)

    def showEvent(self, event):
        super(PromptDialog, self).showEvent(event)
        self.resize(540, 300)
        self.activateWindow()

    def _checkbox_toggled(self, state):
        self.applyButton.setText("%s" % self._apply_text)
        self.denyButton.setText("%s" % self._deny_text)
        self._tick_thread.stop = state

        self.checkDstIP.setVisible(state)
        self.whatIPCombo.setVisible(state)
        self.destIPLabel.setVisible(not state)
        self.checkDstPort.setVisible(state)
        self.checkUserID.setVisible(state)
        self._ischeckAdvanceded = state

    def promptUser(self, connection, is_local, peer):
        # one at a time
        with self._lock:
            # reset state
            if self._tick_thread != None and self._tick_thread.is_alive():
                self._tick_thread.join()
            self._cfg.reload()
            self._tick = int(self._cfg.getSettings(self.CFG_DEFAULT_TIMEOUT)) if self._cfg.getSettings(self.CFG_DEFAULT_TIMEOUT) else self.DEFAULT_TIMEOUT
            self._tick_thread = threading.Thread(target=self._timeout_worker)
            self._tick_thread.stop = self._ischeckAdvanceded
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
            # stop only stops the coundtdown, not the thread itself.
            if getattr(t, "stop", True):
                self._tick = int(self._cfg.getSettings(self.CFG_DEFAULT_TIMEOUT))
                time.sleep(1)
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
        if self._cfg.getSettings(self.CFG_DEFAULT_ACTION) == self.ACTION_ALLOW:
            self._timeout_text = "%s (%d)" % (self._apply_text, self._tick)
            self.applyButton.setText(self._timeout_text)
        else:
            self._timeout_text = "%s (%d)" % (self._deny_text, self._tick)
            self.denyButton.setText(self._timeout_text)

    @QtCore.pyqtSlot()
    def on_timeout_triggered(self):
        self._timeout_triggered = True
        self._send_rule()

    def _configure_default_duration(self):
        if self._cfg.getSettings("global/default_duration") == "once":
            self.durationCombo.setCurrentIndex(0)
        elif self._cfg.getSettings("global/default_duration") == "30s":
            self.durationCombo.setCurrentIndex(1)
        elif self._cfg.getSettings("global/default_duration") == "5m":
            self.durationCombo.setCurrentIndex(2)
        elif self._cfg.getSettings("global/default_duration") == "15m":
            self.durationCombo.setCurrentIndex(3)
        elif self._cfg.getSettings("global/default_duration") == "30m":
            self.durationCombo.setCurrentIndex(4)
        elif self._cfg.getSettings("global/default_duration") == "1h":
            self.durationCombo.setCurrentIndex(5)
        elif self._cfg.getSettings("global/default_duration") == "for this session":
            self.durationCombo.setCurrentIndex(6)
        elif self._cfg.getSettings("global/default_duration") == "forever":
            self.durationCombo.setCurrentIndex(7)
        else:
            # default to "for this session"
            self.durationCombo.setCurrentIndex(6)

    def _set_cmd_action_text(self):
        if self._cfg.getSettings(self.CFG_DEFAULT_ACTION) == self.ACTION_ALLOW:
            self.applyButton.setText("%s (%d)" % (self._apply_text, self._tick))
            self.denyButton.setText(self._deny_text)
            self.applyButton.setFocus()
        else:
            self.denyButton.setText("%s (%d)" % (self._deny_text, self._tick))
            self.applyButton.setText(self._apply_text)
            self.denyButton.setFocus()


    def _render_connection(self, con):
        app_name, app_icon, _ = self._apps_parser.get_info_by_path(con.process_path, "terminal")
        if app_name != con.process_path and con.process_path not in con.process_args:
            self.appPathLabel.setFixedHeight(20)
            self.appPathLabel.setText("(%s)" % con.process_path)
        else:
            self.appPathLabel.setFixedHeight(1)
            self.appPathLabel.setText("")

        if app_name == "":
            app_name = "Unknown process"
            self.appNameLabel.setText("Outgoing connection")
        else:
            self.appNameLabel.setText(app_name)

        self.cwdLabel.setText(con.process_cwd)
        self.cwdLabel.setToolTip(con.process_cwd)

        icon = QtGui.QIcon().fromTheme(app_icon)
        pixmap = icon.pixmap(icon.actualSize(QtCore.QSize(48, 48)))
        self.iconLabel.setPixmap(pixmap)

        if self._local:
            message = "<b>%s</b> is connecting to <b>%s</b> on %s port %d" % ( \
                        app_name,
                        con.dst_host or con.dst_ip,
                        con.protocol,
                        con.dst_port )
        else:
            message = "<b>Remote</b> process <b>%s</b> running on <b>%s</b> is connecting to <b>%s</b> on %s port %d" % ( \
                        app_name,
                        self._peer.split(':')[1],
                        con.dst_host or con.dst_ip,
                        con.protocol,
                        con.dst_port )

        self.messageLabel.setText(message)

        self.sourceIPLabel.setText(con.src_ip)
        self.destIPLabel.setText(con.dst_ip)
        self.destPortLabel.setText(str(con.dst_port))

        if self._local:
            try:
                uid = "%d (%s)" % (con.user_id, pwd.getpwuid(con.user_id).pw_name)
            except:
                uid = ""
        else:
            uid = "%d" % con.user_id

        self.uidLabel.setText(uid)
        self.pidLabel.setText("%s" % con.process_id)
        self.argsLabel.setText(' '.join(con.process_args))
        self.argsLabel.setToolTip(' '.join(con.process_args))

        self.whatCombo.clear()
        self.whatIPCombo.clear()
        if int(con.process_id) > 0:
            self.whatCombo.addItem("from this process", "process_path")

        self.whatCombo.addItem("from this command line", "process_args")
        if self.argsLabel.text() == "":
            self.argsLabel.setText(con.process_path)

        # the order of the entries must match those in the preferences dialog
        self.whatCombo.addItem("to port %d" % con.dst_port, "dst_port")
        self.whatCombo.addItem("to %s" % con.dst_ip, "dst_ip")
        if int(con.user_id) >= 0:
            self.whatCombo.addItem("from user %s" % uid, "user_id")

        if con.dst_host != "" and con.dst_host != con.dst_ip:
            try:
                # get the domain that a process is trying to resolve. format: 1.1.1.1 (host.example.com)
                dst_host_regexp = re.search("(.*)\s\((.*)\)", con.dst_host)
            except Exception:
                pass

            dst_host = con.dst_host
            if dst_host_regexp != None and len(dst_host_regexp.groups()) == 2:
                dst_host = dst_host_regexp.group(2)
                print("host regexp: " + dst_host)

            self._add_dsthost_to_combo(dst_host)

        self.whatIPCombo.addItem("to %s" % con.dst_ip, "dst_ip")

        parts = con.dst_ip.split('.')
        nparts = len(parts)
        for i in range(1, nparts):
            self.whatCombo.addItem("to %s.*" % '.'.join(parts[:i]), "regex_ip")
            self.whatIPCombo.addItem("to %s.*" % '.'.join(parts[:i]), "regex_ip")

        self._default_action = self._cfg.getSettings(self.CFG_DEFAULT_ACTION)

        self._configure_default_duration()

        if int(con.process_id) > 0:
            self.whatCombo.setCurrentIndex(int(self._cfg.getSettings("global/default_target")))
        else:
            self.whatCombo.setCurrentIndex(2)

        self._set_cmd_action_text()

        self.setFixedSize(self.size())

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(PromptDialog, self).keyPressEvent(event)

    # prevent a click on the window's x 
    # from quitting the whole application
    def closeEvent(self, e):
        self._send_rule()
        e.ignore()

    def _add_dsthost_to_combo(self, dst_host):
        self.whatCombo.addItem("%s" % dst_host, "simple_host")
        self.whatIPCombo.addItem("%s" % dst_host, "simple_host")

        parts = dst_host.split('.')[1:]
        nparts = len(parts)
        for i in range(0, nparts - 1):
            self.whatCombo.addItem("to *.%s" % '.'.join(parts[i:]), "regex_host")
            self.whatIPCombo.addItem("to *.%s" % '.'.join(parts[i:]), "regex_host")

        if nparts == 1:
            self.whatCombo.addItem("to *%s" % dst_host, "regex_host")
            self.whatIPCombo.addItem("to *%s" % dst_host, "regex_host")

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
        if combo.itemData(what_idx) == "process_path":
            return "simple", "process.path", self._con.process_path

        elif combo.itemData(what_idx) == "process_args":
            return "simple", "process.command", self.argsLabel.text()

        elif combo.itemData(what_idx) == "user_id":
            return "simple", "user.id", "%s" % self._con.user_id

        elif combo.itemData(what_idx) == "dst_port":
            return "simple", "dest.port", "%s" % self._con.dst_port

        elif combo.itemData(what_idx) == "dst_ip":
            return "simple", "dest.ip", self._con.dst_ip

        elif combo.itemData(what_idx) == "simple_host":
            return "simple", "dest.host", combo.currentText()

        elif combo.itemData(what_idx) == "regex_host":
            return "regexp", "dest.host", "%s" % '\.'.join(combo.currentText().split('.')).replace("*", ".*")[3:]

        elif combo.itemData(what_idx) == "regex_ip":
            return "regexp", "dest.ip", "%s" % '\.'.join(combo.currentText().split('.')).replace("*", ".*")[3:]

    def _on_deny_clicked(self):
        self._default_action = self.ACTION_DENY
        self._send_rule()

    def _on_apply_clicked(self):
        self._default_action = self.ACTION_ALLOW
        self._send_rule()

    def _get_rule_name(self):
        rule_temp_name = slugify("%s %s" % (self._rule.action, self._rule.duration))
        if self._ischeckAdvanceded:
            rule_temp_name = "%s-list" % rule_temp_name
        else:
            rule_temp_name = "%s-simple" % rule_temp_name
        rule_temp_name = slugify("%s %s" % (rule_temp_name, self._rule.operator.data))

        return rule_temp_name

    def _send_rule(self):
        self._cfg.setSettings("promptDialog/geometry", self.saveGeometry())
        self._rule = ui_pb2.Rule(name="user.choice")
        self._rule.enabled = True

        self._rule.action = self._default_action

        self._rule.duration = self._get_duration(self.durationCombo.currentIndex())

        what_idx = self.whatCombo.currentIndex()
        self._rule.operator.type, self._rule.operator.operand, self._rule.operator.data = self._get_combo_operator(self.whatCombo, what_idx)

        rule_temp_name = self._get_rule_name()

        # TODO: move to a method
        data=[]
        if self._ischeckAdvanceded and self.checkDstIP.isChecked() and self.whatCombo.itemData(what_idx) != "dst_ip":
            _type, _operand, _data = self._get_combo_operator(self.whatIPCombo, self.whatIPCombo.currentIndex())
            data.append({"type": _type, "operand": _operand, "data": _data})
            rule_temp_name = slugify("%s %s" % (rule_temp_name, _data))

        if self._ischeckAdvanceded and self.checkDstPort.isChecked() and self.whatCombo.itemData(what_idx) != "dst_port":
            data.append({"type": "simple", "operand": "dest.port", "data": str(self._con.dst_port)})
            rule_temp_name = slugify("%s %s" % (rule_temp_name, str(self._con.dst_port)))

        if self._ischeckAdvanceded and self.checkUserID.isChecked() and self.whatCombo.itemData(what_idx) != "user_id":
            data.append({"type": "simple", "operand": "user.id", "data": str(self._con.user_id)})
            rule_temp_name = slugify("%s %s" % (rule_temp_name, str(self._con.user_id)))

        if self._ischeckAdvanceded:
            data.append({"type": self._rule.operator.type, "operand": self._rule.operator.operand, "data": self._rule.operator.data})
            self._rule.operator.data = json.dumps(data)
            self._rule.operator.type = "list"
            self._rule.operator.operand = ""

        self._rule.name = rule_temp_name

        self.hide()
        if self._ischeckAdvanceded:
            self.checkAdvanced.toggle()
        self._idcheckAdvanceded = False

        # signal that the user took a decision and 
        # a new rule is available
        self._done.set()

