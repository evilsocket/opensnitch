import threading
import sys
import time
import os
import os.path
import pwd
import json
import ipaddress
from datetime import datetime

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC, QEvent

from slugify import slugify

from opensnitch.utils import Icons
from opensnitch.desktop_parser import LinuxDesktopParser
from opensnitch.config import Config
from opensnitch.version import version
from opensnitch.actions import Actions
from opensnitch.rules import Rules, Rule
from opensnitch.nodes import Nodes

from opensnitch import ui_pb2

DIALOG_UI_PATH = "%s/../res/prompt.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PromptDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _prompt_trigger = QtCore.pyqtSignal()
    _tick_trigger = QtCore.pyqtSignal()
    _timeout_trigger = QtCore.pyqtSignal()

    PAGE_MAIN = 2
    PAGE_DETAILS = 0
    PAGE_CHECKSUMS = 1

    DEFAULT_TIMEOUT = 15

    # don't translate
    FIELD_REGEX_HOST    = "regex_host"
    FIELD_REGEX_IP      = "regex_ip"
    FIELD_PROC_PATH     = "process_path"
    FIELD_PROC_ARGS     = "process_args"
    FIELD_PROC_ID       = "process_id"
    FIELD_USER_ID       = "user_id"
    FIELD_DST_IP        = "dst_ip"
    FIELD_DST_PORT      = "dst_port"
    FIELD_DST_NETWORK   = "dst_network"
    FIELD_DST_HOST      = "simple_host"
    FIELD_APPIMAGE      = "appimage_path"

    DURATION_30s    = "30s"
    DURATION_5m     = "5m"
    DURATION_15m    = "15m"
    DURATION_30m    = "30m"
    DURATION_1h     = "1h"
    # don't translate

    APPIMAGE_PREFIX = "/tmp/.mount_"

    # label displayed in the pop-up combo
    DURATION_session = QC.translate("popups", "until reboot")
    # label displayed in the pop-up combo
    DURATION_forever = QC.translate("popups", "forever")

    def __init__(self, parent=None, appicon=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)
        # Other interesting flags: QtCore.Qt.Tool | QtCore.Qt.BypassWindowManagerHint
        self._cfg = Config.get()
        self._rules = Rules.instance()
        self._nodes = Nodes.instance()

        self.setupUi(self)
        self.setWindowIcon(appicon)
        self.installEventFilter(self)

        self._width = None
        self._height = None

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
        self._tick = int(self._cfg.getSettings(self._cfg.DEFAULT_TIMEOUT_KEY)) if self._cfg.hasKey(self._cfg.DEFAULT_TIMEOUT_KEY) else self.DEFAULT_TIMEOUT
        self._tick_thread = None
        self._done = threading.Event()
        self._timeout_text = ""
        self._timeout_triggered = False

        self._apps_parser = LinuxDesktopParser()

        self.whatIPCombo.setVisible(False)
        self.checkDstIP.setVisible(False)
        self.checkDstPort.setVisible(False)
        self.checkUserID.setVisible(False)
        self.appDescriptionLabel.setVisible(False)

        self._ischeckAdvanceded = False
        self.checkAdvanced.toggled.connect(self._check_advanced_toggled)

        self.checkAdvanced.clicked.connect(self._button_clicked)
        self.durationCombo.activated.connect(self._button_clicked)
        self.whatCombo.activated.connect(self._button_clicked)
        self.whatIPCombo.activated.connect(self._button_clicked)
        self.checkDstIP.clicked.connect(self._button_clicked)
        self.checkDstPort.clicked.connect(self._button_clicked)
        self.checkUserID.clicked.connect(self._button_clicked)
        self.cmdInfo.clicked.connect(self._cb_cmdinfo_clicked)
        self.cmdBack.clicked.connect(self._cb_cmdback_clicked)

        self.cmdUpdateRule.clicked.connect(self._cb_update_rule_clicked)
        self.cmdBackChecksums.clicked.connect(self._cb_cmdback_clicked)
        self.messageLabel.linkActivated.connect(self._cb_warninglbl_clicked)

        self.allowIcon = Icons.new(self, "emblem-default")
        denyIcon = Icons.new(self, "emblem-important")
        rejectIcon = Icons.new(self, "window-close")
        backIcon = Icons.new(self, "go-previous")
        infoIcon = Icons.new(self, "dialog-information")

        self.cmdInfo.setIcon(infoIcon)
        self.cmdBack.setIcon(backIcon)
        self.cmdBackChecksums.setIcon(backIcon)

        self._default_action = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)

        self.allowButton.clicked.connect(lambda: self._on_action_clicked(Config.ACTION_ALLOW_IDX))
        self.allowButton.setIcon(self.allowIcon)
        self._allow_text = QC.translate("popups", "Allow")
        self._action_text = [
            QC.translate("popups", "Deny"),
            QC.translate("popups", "Allow"),
            QC.translate("popups", "Reject")
        ]
        self._action_icon = [denyIcon, self.allowIcon, rejectIcon]

        m = QtWidgets.QMenu()
        m.addAction(denyIcon, self._action_text[Config.ACTION_DENY_IDX]).triggered.connect(
            lambda: self._on_action_clicked(Config.ACTION_DENY_IDX)
        )
        m.addAction(self.allowIcon, self._action_text[Config.ACTION_ALLOW_IDX]).triggered.connect(
            lambda: self._on_action_clicked(Config.ACTION_ALLOW_IDX)
        )
        m.addAction(rejectIcon, self._action_text[Config.ACTION_REJECT_IDX]).triggered.connect(
            lambda: self._on_action_clicked(Config.ACTION_REJECT_IDX)
        )
        self.actionButton.setMenu(m)
        self.actionButton.setText(self._action_text[Config.ACTION_DENY_IDX])
        self.actionButton.setIcon(self._action_icon[Config.ACTION_DENY_IDX])
        if self._default_action != Config.ACTION_ALLOW_IDX:
            self.actionButton.setText(self._action_text[self._default_action])
            self.actionButton.setIcon(self._action_icon[self._default_action])
        self.actionButton.clicked.connect(self._on_deny_btn_clicked)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.MouseButtonPress:
            self._stop_countdown()
            return True
        return False

    def showEvent(self, event):
        super(PromptDialog, self).showEvent(event)
        self.activateWindow()
        self.adjust_size()
        self.move_popup()

    def adjust_size(self):
        if self._width is None or self._height is None:
            self._width = self.width()
            self._height = self.height()

        self.resize(QtCore.QSize(self._width, self._height))

    def move_popup(self):
        popup_pos = self._cfg.getInt(self._cfg.DEFAULT_POPUP_POSITION)
        point = QtWidgets.QDesktopWidget().availableGeometry()
        if popup_pos == self._cfg.POPUP_TOP_RIGHT:
            self.move(point.topRight())
        elif popup_pos == self._cfg.POPUP_TOP_LEFT:
            self.move(point.topLeft())
        elif popup_pos == self._cfg.POPUP_BOTTOM_RIGHT:
            self.move(point.bottomRight())
        elif popup_pos == self._cfg.POPUP_BOTTOM_LEFT:
            self.move(point.bottomLeft())

    def _stop_countdown(self):
        action_idx = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)
        if action_idx == Config.ACTION_ALLOW_IDX:
            self.allowButton.setText(self._allow_text)
            self.allowButton.setIcon(self.allowIcon)
        else:
            self.actionButton.setText(self._action_text[action_idx])
            self.actionButton.setIcon(self._action_icon[action_idx])
        self._tick_thread.stop = True

    def _check_advanced_toggled(self, state):
        self.checkDstIP.setVisible(state)
        self.whatIPCombo.setVisible(state)
        self.destIPLabel.setVisible(not state)
        self.checkDstPort.setVisible(state == True and (self._con != None and self._con.dst_port != 0))
        self.checkUserID.setVisible(state)
        self.checkSum.setVisible(self._con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] != "" and state)
        self.checksumLabel_2.setVisible(self._con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] != "" and state)
        self.checksumLabel.setVisible(self._con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] != "" and state)
        self.stackedWidget.setCurrentIndex(self.PAGE_MAIN)

        self._ischeckAdvanceded = state
        self.adjust_size()
        self.move_popup()

    def _button_clicked(self):
        self._stop_countdown()

    def _cb_warninglbl_clicked(self):
        self._stop_countdown()
        self.stackedWidget.setCurrentIndex(self.PAGE_CHECKSUMS)

    def _cb_cmdinfo_clicked(self):
        self.stackedWidget.setCurrentIndex(self.PAGE_DETAILS)
        self._stop_countdown()

    def _cb_update_rule_clicked(self):
        self.labelChecksumStatus.setStyleSheet('')
        curRule = self.comboChecksumRule.currentText()
        if curRule == "":
            return

        # get rule from the db
        records = self._rules.get_by_name(self._peer, curRule)
        if records == None or records.first() == False:
            self.labelChecksumStatus.setStyleSheet('color: red')
            self.labelChecksumStatus.setText("✘ " + QC.translate("popups", "Rule not updated, not found by name"))
            return
        # transform it to proto rule
        rule_obj = Rule.new_from_records(records)
        if rule_obj.operator.type != Config.RULE_TYPE_LIST:
            if rule_obj.operator.operand == Config.OPERAND_PROCESS_HASH_MD5:
                rule_obj.operator.data = self._con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]
        else:
            for op in rule_obj.operator.list:
                if op.operand == Config.OPERAND_PROCESS_HASH_MD5:
                    op.data = self._con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]
                    break
        # add it back again to the db
        added = self._rules.add_rules(self._peer, [rule_obj])
        if not added:
            self.labelChecksumStatus.setStyleSheet('color: red')
            self.labelChecksumStatus.setText("✘ " + QC.translate("popups", "Rule not updated."))
            return

        self._nodes.send_notification(
            self._peer,
            ui_pb2.Notification(
                id=int(str(time.time()).replace(".", "")),
                type=ui_pb2.CHANGE_RULE,
                data="",
                rules=[rule_obj]
            )
        )
        self.labelChecksumStatus.setStyleSheet('color: green')
        self.labelChecksumStatus.setText("✔" + QC.translate("popups", "Rule updated."))

    def _cb_cmdback_clicked(self):
        self.stackedWidget.setCurrentIndex(self.PAGE_MAIN)
        self._stop_countdown()

    def _set_elide_text(self, widget, text, max_size=132):
        if len(text) > max_size:
            text = text[:max_size] + "..."

        widget.setText(text)

    def promptUser(self, connection, is_local, peer):
        # one at a time
        with self._lock:
            # reset state
            if self._tick_thread != None and self._tick_thread.is_alive():
                self._tick_thread.join()
            self._cfg.reload()
            self._tick = int(self._cfg.getSettings(self._cfg.DEFAULT_TIMEOUT_KEY)) if self._cfg.hasKey(self._cfg.DEFAULT_TIMEOUT_KEY) else self.DEFAULT_TIMEOUT
            self._tick_thread = threading.Thread(target=self._timeout_worker)
            self._tick_thread.stop = self._ischeckAdvanceded
            self._timeout_triggered = False
            self._rule = None
            self._local = is_local
            self._con = connection

            # XXX: workaround for protobufs that don't report the address of
            # the node. In this case the addr is "unix:/local"
            proto, addr = self._nodes.get_addr(peer)
            self._peer = proto
            if addr != None:
                self._peer = proto+":"+addr

            self._done.clear()
            # trigger and show dialog
            self._prompt_trigger.emit()
            # start timeout thread
            self._tick_thread.start()
            # wait for user choice or timeout
            self._done.wait()

            return self._rule, self._timeout_triggered

    def _timeout_worker(self):
        if self._tick == 0:
            self._timeout_trigger.emit()
            return

        while self._tick > 0 and self._done.is_set() is False:
            t = threading.currentThread()
            # stop only stops the coundtdown, not the thread itself.
            if getattr(t, "stop", True):
                self._tick = int(self._cfg.getSettings(self._cfg.DEFAULT_TIMEOUT_KEY))
                time.sleep(1)
                continue

            self._tick -= 1
            self._tick_trigger.emit()
            time.sleep(1)

        if not self._done.is_set():
            self._timeout_trigger.emit()

    @QtCore.pyqtSlot()
    def on_connection_prompt_triggered(self):
        self.stackedWidget.setCurrentIndex(self.PAGE_MAIN)
        self._render_connection(self._con)
        if self._tick > 0:
            self.show()
        # render details after displaying the pop-up.
        self._render_details(self._peer, self.connDetails, self._con)

    @QtCore.pyqtSlot()
    def on_tick_triggered(self):
        self._set_cmd_action_text()

    @QtCore.pyqtSlot()
    def on_timeout_triggered(self):
        self._timeout_triggered = True
        self._send_rule()

    def _hide_widget(self, widget, hide):
        widget.setVisible(not hide)

    def _configure_default_duration(self):
        if self._cfg.hasKey(self._cfg.DEFAULT_DURATION_KEY):
            cur_idx = self._cfg.getInt(self._cfg.DEFAULT_DURATION_KEY)
            self.durationCombo.setCurrentIndex(cur_idx)
        else:
            self.durationCombo.setCurrentIndex(self._cfg.DEFAULT_DURATION_IDX)

    def _set_cmd_action_text(self):
        action_idx = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)
        if action_idx == Config.ACTION_ALLOW_IDX:
            self.allowButton.setText("{0} ({1})".format(self._allow_text, self._tick))
            self.allowButton.setIcon(self.allowIcon)
            self.actionButton.setText(self._action_text[Config.ACTION_DENY_IDX])
        else:
            self.allowButton.setText(self._allow_text)
            self.actionButton.setText("{0} ({1})".format(self._action_text[action_idx], self._tick))
            self.actionButton.setIcon(self._action_icon[action_idx])

    def _set_app_description(self, description):
        if description != None and description != "":
            self.appDescriptionLabel.setVisible(True)
            self.appDescriptionLabel.setFixedHeight(50)
            self.appDescriptionLabel.setToolTip(description)
            self._set_elide_text(self.appDescriptionLabel, "%s" % description)
        else:
            self.appDescriptionLabel.setVisible(False)
            self.appDescriptionLabel.setFixedHeight(0)
            self.appDescriptionLabel.setText("")

    def _set_app_path(self, app_name, app_args, con):
        # show the binary path if it's not part of the cmdline args:
        # cmdline: telnet 1.1.1.1 (path: /usr/bin/telnet.netkit)
        # cmdline: /usr/bin/telnet.netkit 1.1.1.1 (the binary path is part of the cmdline args, no need to display it)
        if con.process_path != "" and len(con.process_args) >= 1 and con.process_path not in con.process_args:
            self.appPathLabel.setToolTip("Process path: %s" % con.process_path)
            if app_name.lower() == app_args:
                self._set_elide_text(self.appPathLabel, "%s" % con.process_path)
            else:
                self._set_elide_text(self.appPathLabel, "(%s)" % con.process_path)
            self.appPathLabel.setVisible(True)
        elif con.process_path != "" and len(con.process_args) == 0:
            self._set_elide_text(self.appPathLabel, "%s" % con.process_path)
            self.appPathLabel.setVisible(True)
        else:
            self.appPathLabel.setVisible(False)
            self.appPathLabel.setText("")

    def _set_app_args(self, app_name, app_args):
        # if the app name and the args are the same, there's no need to display
        # the args label (amule for example)
        if app_name.lower() != app_args:
            self.argsLabel.setVisible(True)
            self._set_elide_text(self.argsLabel, app_args)
            self.argsLabel.setToolTip(app_args)
        else:
            self.argsLabel.setVisible(False)
            self.argsLabel.setText("")

    def _verify_checksums(self, con, rule):
        """return true if the checksum of a rule matches the one of the process
        opening a connection.
        """
        if rule.operator.type != Config.RULE_TYPE_LIST:
            return True, ""

        if con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] == "":
            return True, ""

        for ro in rule.operator.list:
            if ro.type == Config.RULE_TYPE_SIMPLE and ro.operand == Config.OPERAND_PROCESS_HASH_MD5:
                if ro.data != con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]:
                    return False, ro.data

        return True, ""

    def _display_checksums_warning(self, peer, con):
        self.messageLabel.setStyleSheet('')
        self.labelChecksumStatus.setText('')

        records = self._rules.get_by_field(peer, "operator_data", con.process_path)

        if records != None and records.first():
            rule = Rule.new_from_records(records)
            validates, expected = self._verify_checksums(con, rule)
            if not validates:
                self.messageLabel.setStyleSheet('color: red')
                self.messageLabel.setText(
                    QC.translate("popups", "WARNING, bad checksum (<a href='#'>More info</a>)"
                                 )
                )
                self.labelChecksumNote.setText(
                    QC.translate("popups", "<font color=\"red\">WARNING, checksums differ.</font><br><br>Current process ({0}):<br>{1}<br><br>Expected from the rule:<br>{2}"
                                 .format(
                                     con.process_id,
                                     con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5],
                                     expected
                )))

                self.comboChecksumRule.clear()
                self.comboChecksumRule.addItem(rule.name)
                while records.next():
                    rule = Rule.new_from_records(records)
                    self.comboChecksumRule.addItem(rule.name)

                return "<b>WARNING</b><br>bad md5<br>This process:{0}<br>Expected from rule: {1}<br><br>".format(
                    con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5],
                    expected
                )

        return ""

    def _render_details(self, peer, detailsWidget, con):
        tree = ""
        space = "&nbsp;"
        spaces = "&nbsp;"
        indicator = ""

        self._display_checksums_warning(peer, con)

        try:
            # reverse() doesn't exist on old protobuf libs.
            con.process_tree.reverse()
        except:
            pass
        for path in con.process_tree:
            tree = "{0}<p>│{1}\t{2}{3}{4}</p>".format(tree, path.value, spaces, indicator, path.key)
            spaces += "&nbsp;" * 4
            indicator = "\\_ "

        # XXX: table element doesn't work?
        details = """<b>{0}</b> {1}:{2} -> {3}:{4}
<br><br>
<b>Path:</b>{5}{6}<br>
<b>Cmdline:</b>&nbsp;{7}<br>
<b>CWD:</b>{8}{9}<br>
<b>MD5:</b>{10}{11}<br>
<b>UID:</b>{12}{13}<br>
<b>PID:</b>{14}{15}<br>
<br>
<b>Process tree:</b><br>
{16}
<br>
<p><b>Environment variables:<b></p>
{17}
""".format(
    con.protocol.upper(),
    con.src_port, con.src_ip, con.dst_ip, con.dst_port,
    space * 6, con.process_path,
    " ".join(con.process_args),
    space * 6, con.process_cwd,
    space * 7, con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5],
    space * 9, con.user_id,
    space * 9, con.process_id,
    tree,
    "".join('<p>{}={}</p>'.format(key, value) for key, value in con.process_env.items())
)

        detailsWidget.document().clear()
        detailsWidget.document().setHtml(details)
        detailsWidget.moveCursor(QtGui.QTextCursor.Start)

    def _render_connection(self, con):
        app_name, app_icon, description, _ = self._apps_parser.get_info_by_path(con.process_path, "terminal")
        app_args = " ".join(con.process_args)
        self._set_app_description(description)
        self._set_app_path(app_name, app_args, con)
        self._set_app_args(app_name, app_args)

        self.checksumLabel.setText(con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5])
        self.checkSum.setChecked(False)

        if app_name == "":
            self.appPathLabel.setVisible(False)
            self.argsLabel.setVisible(False)
            self.argsLabel.setText("")
            app_name = QC.translate("popups", "Unknown process %s" % con.process_path)
            self.appNameLabel.setText(QC.translate("popups", "Outgoing connection"))
        else:
            self._set_elide_text(self.appNameLabel, "%s" % app_name, max_size=42)
            self.appNameLabel.setToolTip(app_name)

        self.cwdLabel.setToolTip("%s %s" % (QC.translate("popups", "Process launched from:"), con.process_cwd))
        self._set_elide_text(self.cwdLabel, con.process_cwd, max_size=32)

        pixmap = Icons.get_by_appname(app_icon)
        self.iconLabel.setPixmap(pixmap)

        message = self._get_popup_message(app_name, con)

        self.messageLabel.setText(message)
        self.messageLabel.setToolTip(message)

        self.sourceIPLabel.setText(con.src_ip)
        self.destIPLabel.setText(con.dst_ip)
        if con.dst_port == 0:
            self.destPortLabel.setText("")
        else:
            self.destPortLabel.setText(str(con.dst_port))
        self._hide_widget(self.destPortLabel, con.dst_port == 0)
        self._hide_widget(self.checkSum, con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] == "" or not self._ischeckAdvanceded)
        self._hide_widget(self.checksumLabel, con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] == "" or not self._ischeckAdvanceded)
        self._hide_widget(self.checksumLabel_2, con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] == "" or not self._ischeckAdvanceded)
        self._hide_widget(self.destPortLabel_1, con.dst_port == 0)
        self._hide_widget(self.checkDstPort, con.dst_port == 0 or not self._ischeckAdvanceded)

        if self._local:
            try:
                uid = "%d (%s)" % (con.user_id, pwd.getpwuid(con.user_id).pw_name)
            except:
                uid = ""
        else:
            uid = "%d" % con.user_id

        self.uidLabel.setText(uid)

        self.whatCombo.clear()
        self.whatIPCombo.clear()

        # the order of these combobox entries must match those in the preferences dialog
        # prefs -> UI -> Default target
        self.whatCombo.addItem(QC.translate("popups", "from this executable"), self.FIELD_PROC_PATH)
        if int(con.process_id) < 0:
            self.whatCombo.model().item(0).setEnabled(False)

        self.whatCombo.addItem(QC.translate("popups", "from this command line"), self.FIELD_PROC_ARGS)

        self.whatCombo.addItem(QC.translate("popups", "to port {0}").format(con.dst_port), self.FIELD_DST_PORT)
        self.whatCombo.addItem(QC.translate("popups", "to {0}").format(con.dst_ip), self.FIELD_DST_IP)

        self.whatCombo.addItem(QC.translate("popups", "from user {0}").format(uid), self.FIELD_USER_ID)
        if int(con.user_id) < 0:
            self.whatCombo.model().item(4).setEnabled(False)

        self.whatCombo.addItem(QC.translate("popups", "from this PID"), self.FIELD_PROC_ID)
        #######################

        if con.process_path.startswith(self.APPIMAGE_PREFIX):
            self._add_appimage_pattern_to_combo(self.whatCombo, con)

        self._add_dst_networks_to_combo(self.whatCombo, con.dst_ip)

        if con.dst_host != "" and con.dst_host != con.dst_ip:
            self._add_dsthost_to_combo(con.dst_host)

        self.whatIPCombo.addItem(QC.translate("popups", "to {0}").format(con.dst_ip), self.FIELD_DST_IP)

        parts = con.dst_ip.split('.')
        nparts = len(parts)
        for i in range(1, nparts):
            self.whatCombo.addItem(QC.translate("popups", "to {0}.*").format('.'.join(parts[:i])), self.FIELD_REGEX_IP)
            self.whatIPCombo.addItem(QC.translate("popups", "to {0}.*").format( '.'.join(parts[:i])), self.FIELD_REGEX_IP)

        self._add_dst_networks_to_combo(self.whatIPCombo, con.dst_ip)

        self._default_action = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)

        self._configure_default_duration()

        if int(con.process_id) > 0:
            self.whatCombo.setCurrentIndex(int(self._cfg.getSettings(self._cfg.DEFAULT_TARGET_KEY)))
        else:
            self.whatCombo.setCurrentIndex(2)


        self.checkDstIP.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_DSTIP))
        self.checkDstPort.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_DSTPORT))
        self.checkUserID.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_UID))
        self.checkSum.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_CHECKSUM))
        if self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED):
            self.checkAdvanced.toggle()

        self._set_cmd_action_text()
        self.checkAdvanced.setFocus()

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

    def _add_appimage_pattern_to_combo(self, combo, con):
        """appimages' absolute path usually starts with /tmp/.mount_<
        """
        appimage_bin = os.path.basename(con.process_path)
        appimage_path = os.path.dirname(con.process_path)
        combo.addItem(
            QC.translate("popups", "from {0}*/{1}").format(appimage_path[:-6], appimage_bin),
            self.FIELD_APPIMAGE
        )

    def _add_dst_networks_to_combo(self, combo, dst_ip):
        if type(ipaddress.ip_address(dst_ip)) == ipaddress.IPv4Address:
            combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/24", strict=False)),  self.FIELD_DST_NETWORK)
            combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/16", strict=False)),  self.FIELD_DST_NETWORK)
            combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/8", strict=False)),   self.FIELD_DST_NETWORK)
        else:
            combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/64", strict=False)),  self.FIELD_DST_NETWORK)
            combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/128", strict=False)), self.FIELD_DST_NETWORK)

    def _add_dsthost_to_combo(self, dst_host):
        self.whatCombo.addItem("%s" % dst_host, self.FIELD_DST_HOST)
        self.whatIPCombo.addItem("%s" % dst_host, self.FIELD_DST_HOST)

        parts = dst_host.split('.')[1:]
        nparts = len(parts)
        for i in range(0, nparts - 1):
            self.whatCombo.addItem(QC.translate("popups", "to *.{0}").format('.'.join(parts[i:])), self.FIELD_REGEX_HOST)
            self.whatIPCombo.addItem(QC.translate("popups", "to *.{0}").format('.'.join(parts[i:])), self.FIELD_REGEX_HOST)

    def _get_popup_message(self, app_name, con):
        """
        _get_popup_message helps constructing the message that is displayed on
        the pop-up dialog. Example:
            curl is connecting to www.opensnitch.io on TCP port 443
        """
        message = "<b>%s</b>" % app_name
        if not self._local:
            message = QC.translate("popups", "<b>Remote</b> process %s running on <b>%s</b>") % ( \
                message,
                self._peer.split(':')[1])

        msg_action = QC.translate("popups", "is connecting to <b>%s</b> on %s port %d") % ( \
            con.dst_host or con.dst_ip,
            con.protocol.upper(),
            con.dst_port )

        # icmp port is 0 (i.e.: no port)
        if con.dst_port == 0:
            msg_action = QC.translate("popups", "is connecting to <b>%s</b>, %s") % ( \
                con.dst_host or con.dst_ip,
                con.protocol.upper() )

        if con.dst_port == 53 and con.dst_ip != con.dst_host and con.dst_host != "":
            msg_action = QC.translate("popups", "is attempting to resolve <b>%s</b> via %s, %s port %d") % ( \
                con.dst_host,
                con.dst_ip,
                con.protocol.upper(),
                con.dst_port)

        return "%s %s" % (message, msg_action)

    def _get_duration(self, duration_idx):
        if duration_idx == 0:
            return Config.DURATION_ONCE
        elif duration_idx == 1:
            return self.DURATION_30s
        elif duration_idx == 2:
            return self.DURATION_5m
        elif duration_idx == 3:
            return self.DURATION_15m
        elif duration_idx == 4:
            return self.DURATION_30m
        elif duration_idx == 5:
            return self.DURATION_1h
        elif duration_idx == 6:
            return Config.DURATION_UNTIL_RESTART
        else:
            return Config.DURATION_ALWAYS

    def _get_combo_operator(self, combo, what_idx, con):
        if combo.itemData(what_idx) == self.FIELD_PROC_PATH:
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_PATH, con.process_path

        elif combo.itemData(what_idx) == self.FIELD_PROC_ARGS:
            # this should not happen
            if len(con.process_args) == 0 or con.process_args[0] == "":
                return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_PATH, con.process_path
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_COMMAND, ' '.join(con.process_args)

        elif combo.itemData(what_idx) == self.FIELD_PROC_ID:
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_ID, "{0}".format(con.process_id)

        elif combo.itemData(what_idx) == self.FIELD_USER_ID:
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_USER_ID, "%s" % con.user_id

        elif combo.itemData(what_idx) == self.FIELD_DST_PORT:
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_DEST_PORT, "%s" % con.dst_port

        elif combo.itemData(what_idx) == self.FIELD_DST_IP:
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_DEST_IP, con.dst_ip

        elif combo.itemData(what_idx) == self.FIELD_DST_HOST:
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_DEST_HOST, combo.currentText()

        elif combo.itemData(what_idx) == self.FIELD_DST_NETWORK:
            # strip "to ": "to x.x.x/20" -> "x.x.x/20"
            # we assume that to is one word in all languages
            parts = combo.currentText().split(' ')
            text = parts[len(parts)-1]
            return Config.RULE_TYPE_NETWORK, Config.OPERAND_DEST_NETWORK, text

        elif combo.itemData(what_idx) == self.FIELD_REGEX_HOST:
            parts = combo.currentText().split(' ')
            text = parts[len(parts)-1]
            # ^(|.*\.)yahoo\.com
            dsthost = r'\.'.join(text.split('.')).replace("*", "")
            dsthost = r'^(|.*\.)%s' % dsthost[2:]
            return Config.RULE_TYPE_REGEXP, Config.OPERAND_DEST_HOST, dsthost

        elif combo.itemData(what_idx) == self.FIELD_REGEX_IP:
            parts = combo.currentText().split(' ')
            text = parts[len(parts)-1]
            return Config.RULE_TYPE_REGEXP, Config.OPERAND_DEST_IP, "%s" % r'\.'.join(text.split('.')).replace("*", ".*")

        elif combo.itemData(what_idx) == self.FIELD_APPIMAGE:
            appimage_bin = os.path.basename(con.process_path)
            appimage_path = os.path.dirname(con.process_path).replace(".", "\.")
            return Config.RULE_TYPE_REGEXP, Config.OPERAND_PROCESS_PATH, r'^{0}[0-9A-Za-z]{{6}}/{1}$'.format(appimage_path[:-6], appimage_bin)

    def _on_action_clicked(self, action):
        self._default_action = action
        self._send_rule()

    def _on_deny_btn_clicked(self, action):
        self._default_action = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)
        if self._default_action == Config.ACTION_ALLOW_IDX:
            self._default_action = Config.ACTION_DENY_IDX
        self._send_rule()

    def _is_list_rule(self):
        return self.checkUserID.isChecked() or \
            self.checkDstPort.isChecked() or \
            self.checkDstIP.isChecked() or \
            self.checkSum.isChecked()

    def _get_rule_name(self, rule):
        rule_temp_name = slugify("%s %s" % (rule.action, rule.duration))
        if self._is_list_rule():
            rule_temp_name = "%s-list" % rule_temp_name
        else:
            rule_temp_name = "%s-simple" % rule_temp_name
        rule_temp_name = slugify("%s %s" % (rule_temp_name, rule.operator.data))

        return rule_temp_name[:128]

    def _send_rule(self):
        try:
            self._cfg.setSettings("promptDialog/geometry", self.saveGeometry())
            self._rule = ui_pb2.Rule(name="user.choice")
            self._rule.created = int(datetime.now().timestamp())
            self._rule.enabled = True
            self._rule.duration = self._get_duration(self.durationCombo.currentIndex())

            self._rule.action = Config.ACTION_ALLOW
            if self._default_action == Config.ACTION_DENY_IDX:
                self._rule.action = Config.ACTION_DENY
            elif self._default_action == Config.ACTION_REJECT_IDX:
                self._rule.action = Config.ACTION_REJECT

            what_idx = self.whatCombo.currentIndex()
            self._rule.operator.type, self._rule.operator.operand, self._rule.operator.data = self._get_combo_operator(self.whatCombo, what_idx, self._con)
            if self._rule.operator.data == "":
                print("Invalid rule, discarding: ", self._rule)
                self._rule = None
                return

            rule_temp_name = self._get_rule_name(self._rule)
            self._rule.name = rule_temp_name

            # TODO: move to a method
            data=[]
            if self.checkDstIP.isChecked() and self.whatCombo.itemData(what_idx) != self.FIELD_DST_IP:
                _type, _operand, _data = self._get_combo_operator(self.whatIPCombo, self.whatIPCombo.currentIndex(), self._con)
                data.append({"type": _type, "operand": _operand, "data": _data})
                rule_temp_name = slugify("%s %s" % (rule_temp_name, _data))

            if self.checkDstPort.isChecked() and self.whatCombo.itemData(what_idx) != self.FIELD_DST_PORT:
                data.append({"type": Config.RULE_TYPE_SIMPLE, "operand": Config.OPERAND_DEST_PORT, "data": str(self._con.dst_port)})
                rule_temp_name = slugify("%s %s" % (rule_temp_name, str(self._con.dst_port)))

            if self.checkUserID.isChecked() and self.whatCombo.itemData(what_idx) != self.FIELD_USER_ID:
                data.append({"type": Config.RULE_TYPE_SIMPLE, "operand": Config.OPERAND_USER_ID, "data": str(self._con.user_id)})
                rule_temp_name = slugify("%s %s" % (rule_temp_name, str(self._con.user_id)))

            if self.checkSum.isChecked() and self.checksumLabel.text() != "":
                _type, _operand, _data = Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_HASH_MD5, self.checksumLabel.text()
                data.append({"type": _type, "operand": _operand, "data": _data})
                rule_temp_name = slugify("%s %s" % (rule_temp_name, _operand))

            is_list_rule = self._is_list_rule()

            # If the user has selected to filter by cmdline, but the launched
            # command path is not absolute, we can't trust it. In this case,
            # also filter by the absolute path to the binary.
            if self._rule.operator.operand == Config.OPERAND_PROCESS_COMMAND:
                proc_args = " ".join(self._con.process_args)
                proc_args = proc_args.split(" ")
                if os.path.isabs(proc_args[0]) == False:
                    is_list_rule = True
                    data.append({"type": Config.RULE_TYPE_SIMPLE, "operand": Config.OPERAND_PROCESS_PATH, "data": str(self._con.process_path)})

            if is_list_rule:
                data.append({
                    "type": self._rule.operator.type,
                    "operand": self._rule.operator.operand,
                    "data": self._rule.operator.data
                })
                # We need to send back the operator list to the AskRule() call
                # as json string, in order to add it to the DB.
                self._rule.operator.data = json.dumps(data)
                self._rule.operator.type = Config.RULE_TYPE_LIST
                self._rule.operator.operand = Config.RULE_TYPE_LIST
                for op in data:
                    self._rule.operator.list.extend([
                        ui_pb2.Operator(
                            type=op['type'],
                            operand=op['operand'],
                            sensitive=False if op.get('sensitive') == None else op['sensitive'],
                            data="" if op.get('data') == None else op['data']
                        )
                    ])

            exists = self._rules.exists(self._rule, self._peer)
            if not exists:
                self._rule.name = self._rules.new_unique_name(rule_temp_name, self._peer, "")

            self.hide()
            if self._ischeckAdvanceded:
                self.checkAdvanced.toggle()
            self._ischeckAdvanceded = False

        except Exception as e:
            print("[pop-up] exception creating a rule:", e)
        finally:
            # signal that the user took a decision and
            # a new rule is available
            self._done.set()
            self.hide()
