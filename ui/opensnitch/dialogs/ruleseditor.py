
from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC
from slugify import slugify
from datetime import datetime
import re
import sys
import os
import pwd
from opensnitch import ui_pb2
import time
import ipaddress

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.database import Database
from opensnitch.database.enums import RuleFields, ConnFields
from opensnitch.version import version
from opensnitch.utils import Message, FileDialog, Icons, NetworkInterfaces
from opensnitch.rules import Rule, Rules

DIALOG_UI_PATH = "%s/../res/ruleseditor.ui" % os.path.dirname(sys.modules[__name__].__file__)
class RulesEditorDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    LOG_TAG = "[rules editor]"
    classA_net = r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    classB_net = r'172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]+\.\d{1,3}\.\d{1,3}'
    classC_net = r'192\.168\.\d{1,3}\.\d{1,3}'
    others_net = r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}'
    multinets = r'2[32][23459]\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    MULTICAST_RANGE = "^(" + multinets + ")$"
    LAN_RANGES = "^(" + others_net + "|" + classC_net + "|" + classB_net + "|" + classA_net + "|::1|f[cde].*::.*)$"
    LAN_LABEL = "LAN"
    MULTICAST_LABEL = "MULTICAST"

    ADD_RULE = 0
    EDIT_RULE = 1
    WORK_MODE = ADD_RULE

    PW_USER = 0
    PW_UID = 2

    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    def __init__(self, parent=None, _rule=None, appicon=None):
        super(RulesEditorDialog, self).__init__(parent)

        self._notifications_sent = {}
        self._nodes = Nodes.instance()
        self._db = Database.instance()
        self._rules = Rules.instance()
        self._notification_callback.connect(self._cb_notification_callback)
        self._old_rule_name = None

        self.setupUi(self)
        self.setWindowIcon(appicon)

        self.buttonBox.setStandardButtons(
            QtWidgets.QDialogButtonBox.Help |
            QtWidgets.QDialogButtonBox.Reset |
            QtWidgets.QDialogButtonBox.Close |
            QtWidgets.QDialogButtonBox.Save
        )

        self.buttonBox.button(QtWidgets.QDialogButtonBox.Reset).clicked.connect(self._cb_reset_clicked)
        self.buttonBox.button(QtWidgets.QDialogButtonBox.Close).clicked.connect(self._cb_close_clicked)
        self.buttonBox.button(QtWidgets.QDialogButtonBox.Save).clicked.connect(self._cb_save_clicked)
        self.buttonBox.button(QtWidgets.QDialogButtonBox.Help).clicked.connect(self._cb_help_clicked)
        self.selectListButton.clicked.connect(self._cb_select_list_button_clicked)
        self.selectListRegexpButton.clicked.connect(self._cb_select_regexp_list_button_clicked)
        self.selectIPsListButton.clicked.connect(self._cb_select_ips_list_button_clicked)
        self.selectNetsListButton.clicked.connect(self._cb_select_nets_list_button_clicked)
        self.protoCheck.toggled.connect(self._cb_proto_check_toggled)
        self.procCheck.toggled.connect(self._cb_proc_check_toggled)
        self.cmdlineCheck.toggled.connect(self._cb_cmdline_check_toggled)
        self.ifaceCheck.toggled.connect(self._cb_iface_check_toggled)
        self.dstPortCheck.toggled.connect(self._cb_dstport_check_toggled)
        self.srcPortCheck.toggled.connect(self._cb_srcport_check_toggled)
        self.uidCheck.toggled.connect(self._cb_uid_check_toggled)
        self.pidCheck.toggled.connect(self._cb_pid_check_toggled)
        self.srcIPCheck.toggled.connect(self._cb_srcip_check_toggled)
        self.dstIPCheck.toggled.connect(self._cb_dstip_check_toggled)
        self.dstHostCheck.toggled.connect(self._cb_dsthost_check_toggled)
        self.dstListsCheck.toggled.connect(self._cb_dstlists_check_toggled)
        self.dstListRegexpCheck.toggled.connect(self._cb_dstregexplists_check_toggled)
        self.dstListIPsCheck.toggled.connect(self._cb_dstiplists_check_toggled)
        self.dstListNetsCheck.toggled.connect(self._cb_dstnetlists_check_toggled)
        self.uidCombo.currentIndexChanged.connect(self._cb_uid_combo_changed)
        self.md5Check.toggled.connect(self._cb_md5check_toggled)

        self._users_list = pwd.getpwall()

        if QtGui.QIcon.hasThemeIcon("emblem-default"):
            return

        applyIcon = Icons.new(self, "emblem-default")
        denyIcon = Icons.new(self, "emblem-important")
        rejectIcon = Icons.new(self, "window-close")
        openIcon = Icons.new(self, "document-open")
        self.actionAllowRadio.setIcon(applyIcon)
        self.actionDenyRadio.setIcon(denyIcon)
        self.actionRejectRadio.setIcon(rejectIcon)
        self.selectListButton.setIcon(openIcon)
        self.selectListRegexpButton.setIcon(openIcon)
        self.selectNetsListButton.setIcon(openIcon)
        self.selectIPsListButton.setIcon(openIcon)

        if _rule != None:
            self._load_rule(rule=_rule)

    def showEvent(self, event):
        super(RulesEditorDialog, self).showEvent(event)

        # save old combo values so we don't overwrite them here.
        oldIface = self.ifaceCombo.currentText()
        oldUid = self.uidCombo.currentText()
        self.ifaceCombo.clear()
        self.uidCombo.clear()
        if self._nodes.is_local(self.nodesCombo.currentText()):
            self.ifaceCombo.addItems(NetworkInterfaces.list().keys())
            try:
                for ip in NetworkInterfaces.list().values():
                    if self.srcIPCombo.findText(ip) == -1:
                        self.srcIPCombo.insertItem(0, ip)
                    if self.dstIPCombo.findText(ip) == -1:
                        self.dstIPCombo.insertItem(0, ip)

                self._users_list = pwd.getpwall()
                self.uidCombo.blockSignals(True);
                for user in self._users_list:
                    self.uidCombo.addItem("{0} ({1})".format(user[self.PW_USER], user[self.PW_UID]), user[self.PW_UID])
            except Exception as e:
                print("[ruleseditor] Error adding IPs:", e)
            finally:
                self.uidCombo.blockSignals(False);
        self.ifaceCombo.setCurrentText(oldIface)
        self.uidCombo.setCurrentText(oldUid)

    def _bool(self, s):
        return s == 'True'

    def _cb_accept_clicked(self):
        pass

    def _cb_close_clicked(self):
        self.hide()

    def _cb_reset_clicked(self):
        self._reset_state()

    def _cb_help_clicked(self):
        QtGui.QDesktopServices.openUrl(QtCore.QUrl(Config.HELP_URL))

    def _cb_select_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstListsLine.text())
        if dirName != None and dirName != "":
            self.dstListsLine.setText(dirName)

    def _cb_select_nets_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstListNetsLine.text())
        if dirName != None and dirName != "":
            self.dstListNetsLine.setText(dirName)

    def _cb_select_ips_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstListIPsLine.text())
        if dirName != None and dirName != "":
            self.dstListIPsLine.setText(dirName)

    def _cb_select_regexp_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstRegexpListsLine.text())
        if dirName != None and dirName != "":
            self.dstRegexpListsLine.setText(dirName)

    def _cb_proto_check_toggled(self, state):
        self.protoCombo.setEnabled(state)

    def _cb_proc_check_toggled(self, state):
        self.procLine.setEnabled(state)
        self.checkProcRegexp.setEnabled(state)

    def _cb_cmdline_check_toggled(self, state):
        self.cmdlineLine.setEnabled(state)
        self.checkCmdlineRegexp.setEnabled(state)

    def _cb_iface_check_toggled(self, state):
        self.ifaceCombo.setEnabled(state)

    def _cb_dstport_check_toggled(self, state):
        self.dstPortLine.setEnabled(state)

    def _cb_srcport_check_toggled(self, state):
        self.srcPortLine.setEnabled(state)

    def _cb_uid_check_toggled(self, state):
        self.uidCombo.setEnabled(state)

    def _cb_pid_check_toggled(self, state):
        self.pidLine.setEnabled(state)

    def _cb_srcip_check_toggled(self, state):
        self.srcIPCombo.setEnabled(state)

    def _cb_dstip_check_toggled(self, state):
        self.dstIPCombo.setEnabled(state)

    def _cb_dsthost_check_toggled(self, state):
        self.dstHostLine.setEnabled(state)

    def _cb_dstlists_check_toggled(self, state):
        self.dstListsLine.setEnabled(state)
        self.selectListButton.setEnabled(state)

    def _cb_dstregexplists_check_toggled(self, state):
        self.dstRegexpListsLine.setEnabled(state)
        self.selectListRegexpButton.setEnabled(state)

    def _cb_dstiplists_check_toggled(self, state):
        self.dstListIPsLine.setEnabled(state)
        self.selectIPsListButton.setEnabled(state)

    def _cb_dstnetlists_check_toggled(self, state):
        self.dstListNetsLine.setEnabled(state)
        self.selectNetsListButton.setEnabled(state)

    def _cb_uid_combo_changed(self, index):
        self.uidCombo.setCurrentText(str(self._users_list[index][self.PW_UID]))

    def _cb_md5check_toggled(self, state):
        self.md5Line.setEnabled(state)

    def _set_status_error(self, msg):
        self.statusLabel.setStyleSheet('color: red')
        self.statusLabel.setText(msg)

    def _set_status_message(self, msg):
        self.statusLabel.setStyleSheet('color: green')
        self.statusLabel.setText(msg)

    def _cb_save_clicked(self):
        if self.nodesCombo.count() == 0:
            self._set_status_error(QC.translate("rules", "There're no nodes connected."))
            return

        rule_name = self.ruleNameEdit.text()
        if rule_name == "":
            return

        node = self.nodesCombo.currentText()
        # avoid to overwrite rules when:
        # - adding a new rule.
        # - when a rule is renamed, i.e., the rule is edited or added and the
        #   user changes the name.
        if self.WORK_MODE == self.ADD_RULE and self._db.get_rule(rule_name, node).next() == True:
            self._set_status_error(QC.translate("rules", "There's already a rule with this name."))
            return
        elif self.WORK_MODE == self.EDIT_RULE and rule_name != self._old_rule_name and \
            self._db.get_rule(rule_name, node).next() == True:
            self._set_status_error(QC.translate("rules", "There's already a rule with this name."))
            return

        if self.md5Check.isChecked() and not self.procCheck.isChecked():
            self._set_status_error(QC.translate("rules", "Process path must be checked in order to verify checksums."))
            return

        result, error = self._save_rule()
        if result == False:
            self._set_status_error(error)
            return

        self._add_rule()
        if self._old_rule_name != None and self._old_rule_name != self.rule.name:
            self._delete_rule()

        self._old_rule_name = rule_name

        # after adding a new rule, we enter into EDIT mode, to allow further
        # changes without closing the dialog.
        if self.WORK_MODE == self.ADD_RULE:
            self.WORK_MODE = self.EDIT_RULE

        self._rules.updated.emit(0)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        #print(self.LOG_TAG, "Rule notification received: ", reply.id, reply.code)
        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.OK:
                self._set_status_message(QC.translate("rules", "Rule applied."))
            else:
                self._set_status_error(QC.translate("rules", "Error applying rule: {0}").format(reply.data))

            del self._notifications_sent[reply.id]

    def _get_duration(self, duration_idx):
        if duration_idx == 0:
            return Config.DURATION_ONCE
        elif duration_idx == 1:
            return Config.DURATION_30s
        elif duration_idx == 2:
            return Config.DURATION_5m
        elif duration_idx == 3:
            return Config.DURATION_15m
        elif duration_idx == 4:
            return Config.DURATION_30m
        elif duration_idx == 5:
            return Config.DURATION_1h
        elif duration_idx == 6:
            return Config.DURATION_UNTIL_RESTART
        else:
            return Config.DURATION_ALWAYS

    def _load_duration(self, duration):
        if duration == Config.DURATION_ONCE:
            return 0
        elif duration == Config.DURATION_30s:
            return 1
        elif duration == Config.DURATION_5m:
            return 2
        elif duration == Config.DURATION_15m:
            return 3
        elif duration == Config.DURATION_30m:
            return 4
        elif duration == Config.DURATION_1h:
            return 5
        elif duration == Config.DURATION_UNTIL_RESTART:
            return 6
        else:
            # always
            return 7

    def _is_regex(self, text):
        charset="\\*{[|^?$"
        for c in charset:
            if c in text:
                return True
        return False

    def _is_valid_regex(self, regex):
        try:
            re.compile(regex)
            return True
        except re.error as e:
            self.statusLabel.setText(str(e))
            return False

    def set_fields_from_connection(self, records):
        self.nodesCombo.setCurrentText(records.value(ConnFields.Node))
        self.protoCombo.setCurrentText(records.value(ConnFields.Protocol).upper())
        self.srcIPCombo.setCurrentText(records.value(ConnFields.SrcIP))
        self.dstIPCombo.setCurrentText(records.value(ConnFields.DstIP))
        self.dstHostLine.setText(records.value(ConnFields.DstHost))
        self.dstPortLine.setText(records.value(ConnFields.DstPort))
        self.srcPortLine.setText(records.value(ConnFields.SrcPort))
        self.uidCombo.setCurrentText(records.value(ConnFields.UID))
        self.pidLine.setText(records.value(ConnFields.PID))
        self.procLine.setText(records.value(ConnFields.Process))
        self.cmdlineLine.setText(records.value(ConnFields.Cmdline))

    def _reset_state(self):
        self._old_rule_name = None
        self.rule = None

        self.ruleNameEdit.setText("")
        self.ruleDescEdit.setPlainText("")
        self.statusLabel.setText("")

        self.actionDenyRadio.setChecked(True)
        self.durationCombo.setCurrentIndex(0)

        self.protoCheck.setChecked(False)
        self.protoCombo.setCurrentText("")

        self.procCheck.setChecked(False)
        self.checkProcRegexp.setEnabled(False)
        self.checkProcRegexp.setChecked(False)
        self.procLine.setText("")

        self.cmdlineCheck.setChecked(False)
        self.checkCmdlineRegexp.setEnabled(False)
        self.checkCmdlineRegexp.setChecked(False)
        self.cmdlineLine.setText("")

        self.uidCheck.setChecked(False)
        self.uidCombo.setCurrentText("")

        self.pidCheck.setChecked(False)
        self.pidLine.setText("")

        self.ifaceCheck.setChecked(False)
        self.ifaceCombo.setCurrentText("")

        self.dstPortCheck.setChecked(False)
        self.dstPortLine.setText("")

        self.srcPortCheck.setChecked(False)
        self.srcPortLine.setText("")

        self.srcIPCheck.setChecked(False)
        self.srcIPCombo.setCurrentText("")

        self.dstIPCheck.setChecked(False)
        self.dstIPCombo.setCurrentText("")

        self.dstHostCheck.setChecked(False)
        self.dstHostLine.setText("")

        self.selectListButton.setEnabled(False)
        self.dstListsCheck.setChecked(False)
        self.dstListsLine.setText("")

        self.selectListRegexpButton.setEnabled(False)
        self.dstListRegexpCheck.setChecked(False)
        self.dstRegexpListsLine.setText("")

        self.selectIPsListButton.setEnabled(False)
        self.dstListIPsCheck.setChecked(False)
        self.dstListIPsLine.setText("")

        self.selectNetsListButton.setEnabled(False)
        self.dstListNetsCheck.setChecked(False)
        self.dstListNetsLine.setText("")

        self.md5Check.setChecked(False)
        self.md5Line.setText("")
        self.md5Line.setEnabled(False)

    def _load_rule(self, addr=None, rule=None):
        if self._load_nodes(addr) == False:
            return False

        self.ruleNameEdit.setText(rule.name)
        self.ruleDescEdit.setPlainText(rule.description)
        self.enableCheck.setChecked(rule.enabled)
        self.precedenceCheck.setChecked(rule.precedence)
        self.nologCheck.setChecked(rule.nolog)
        if rule.action == Config.ACTION_DENY:
            self.actionDenyRadio.setChecked(True)
        elif rule.action == Config.ACTION_ALLOW:
            self.actionAllowRadio.setChecked(True)
        elif rule.action == Config.ACTION_REJECT:
            self.actionRejectRadio.setChecked(True)

        self.durationCombo.setCurrentIndex(self._load_duration(self.rule.duration))

        if self.rule.operator.type != Config.RULE_TYPE_LIST:
            self._load_rule_operator(self.rule.operator)
        else:
            for op in self.rule.operator.list:
                self._load_rule_operator(op)

        return True

    def _load_rule_operator(self, operator):
        self.sensitiveCheck.setChecked(operator.sensitive)
        if operator.operand == Config.OPERAND_PROTOCOL:
            self.protoCheck.setChecked(True)
            self.protoCombo.setEnabled(True)
            self.protoCombo.setCurrentText(operator.data.upper())

        if operator.operand == Config.OPERAND_PROCESS_PATH:
            self.procCheck.setChecked(True)
            self.procLine.setEnabled(True)
            self.procLine.setText(operator.data)
            self.checkProcRegexp.setEnabled(True)
            self.checkProcRegexp.setChecked(operator.type == Config.RULE_TYPE_REGEXP)

        if operator.operand == Config.OPERAND_PROCESS_COMMAND:
            self.cmdlineCheck.setChecked(True)
            self.cmdlineLine.setEnabled(True)
            self.cmdlineLine.setText(operator.data)
            self.checkCmdlineRegexp.setEnabled(True)
            self.checkCmdlineRegexp.setChecked(operator.type == Config.RULE_TYPE_REGEXP)

        if operator.operand == Config.OPERAND_USER_ID:
            self.uidCheck.setChecked(True)
            self.uidCombo.setEnabled(True)
            self.uidCombo.setCurrentText(operator.data)

        if operator.operand == Config.OPERAND_PROCESS_ID:
            self.pidCheck.setChecked(True)
            self.pidLine.setEnabled(True)
            self.pidLine.setText(operator.data)

        if operator.operand == Config.OPERAND_IFACE_OUT:
            self.ifaceCheck.setChecked(True)
            self.ifaceCombo.setEnabled(True)
            self.ifaceCombo.setCurrentText(operator.data)

        if operator.operand == Config.OPERAND_SOURCE_PORT:
            self.srcPortCheck.setChecked(True)
            self.srcPortLine.setEnabled(True)
            self.srcPortLine.setText(operator.data)

        if operator.operand == Config.OPERAND_DEST_PORT:
            self.dstPortCheck.setChecked(True)
            self.dstPortLine.setEnabled(True)
            self.dstPortLine.setText(operator.data)

        if operator.operand == Config.OPERAND_SOURCE_IP or operator.operand == Config.OPERAND_SOURCE_NETWORK:
            self.srcIPCheck.setChecked(True)
            self.srcIPCombo.setEnabled(True)
            if operator.data == self.LAN_RANGES:
                self.srcIPCombo.setCurrentText(self.LAN_LABEL)
            elif operator.data == self.MULTICAST_RANGE:
                self.srcIPCombo.setCurrentText(self.MULTICAST_LABEL)
            else:
                self.srcIPCombo.setCurrentText(operator.data)

        if operator.operand == Config.OPERAND_DEST_IP or operator.operand == Config.OPERAND_DEST_NETWORK:
            self.dstIPCheck.setChecked(True)
            self.dstIPCombo.setEnabled(True)
            if operator.data == self.LAN_RANGES:
                self.dstIPCombo.setCurrentText(self.LAN_LABEL)
            elif operator.data == self.MULTICAST_RANGE:
                self.dstIPCombo.setCurrentText(self.MULTICAST_LABEL)
            else:
                self.dstIPCombo.setCurrentText(operator.data)

        if operator.operand == Config.OPERAND_DEST_HOST:
            self.dstHostCheck.setChecked(True)
            self.dstHostLine.setEnabled(True)
            self.dstHostLine.setText(operator.data)

        if operator.operand == Config.OPERAND_LIST_DOMAINS:
            self.dstListsCheck.setChecked(True)
            self.dstListsCheck.setEnabled(True)
            self.dstListsLine.setText(operator.data)
            self.selectListButton.setEnabled(True)

        if operator.operand == Config.OPERAND_LIST_DOMAINS_REGEXP:
            self.dstListRegexpCheck.setChecked(True)
            self.dstListRegexpCheck.setEnabled(True)
            self.dstRegexpListsLine.setText(operator.data)
            self.selectListRegexpButton.setEnabled(True)

        if operator.operand == Config.OPERAND_LIST_IPS:
            self.dstListIPsCheck.setChecked(True)
            self.dstListIPsCheck.setEnabled(True)
            self.dstListIPsLine.setText(operator.data)
            self.selectIPsListButton.setEnabled(True)

        if operator.operand == Config.OPERAND_LIST_NETS:
            self.dstListNetsCheck.setChecked(True)
            self.dstListNetsCheck.setEnabled(True)
            self.dstListNetsLine.setText(operator.data)
            self.selectNetsListButton.setEnabled(True)

        if operator.operand == Config.OPERAND_PROCESS_HASH_MD5:
            self.md5Check.setChecked(True)
            self.md5Line.setEnabled(True)
            self.md5Line.setText(operator.data)



    def _load_nodes(self, addr=None):
        try:
            self.nodesCombo.clear()
            self._node_list = self._nodes.get()

            if addr != None and addr not in self._node_list:
                Message.ok(QC.translate("rules", "<b>Error loading rule</b>"),
                        QC.translate("rules", "node {0} not connected".format(addr)),
                        QtWidgets.QMessageBox.Warning)
                return False

            if len(self._node_list) < 2:
                self.nodeApplyAllCheck.setVisible(False)

            for node in self._node_list:
                self.nodesCombo.addItem(node)

            if addr != None:
                self.nodesCombo.setCurrentText(addr)

        except Exception as e:
            print(self.LOG_TAG, "exception loading nodes: ", e, addr)
            return False

        return True

    def _insert_rule_to_db(self, node_addr):
        # the order of the fields doesn't matter here, as long as we use the
        # name of the field.
        self._rules.add_rules(node_addr, [self.rule])

    def _add_rule(self):
        try:
            if self.nodeApplyAllCheck.isChecked():
                for pos in range(self.nodesCombo.count()):
                    self._insert_rule_to_db(self.nodesCombo.itemText(pos))
            else:
                self._insert_rule_to_db(self.nodesCombo.currentText())

            notif = ui_pb2.Notification(
                    id=int(str(time.time()).replace(".", "")),
                    type=ui_pb2.CHANGE_RULE,
                    data="",
                    rules=[self.rule])
            if self.nodeApplyAllCheck.isChecked():
                nid = self._nodes.send_notifications(notif, self._notification_callback)
            else:
                nid = self._nodes.send_notification(self.nodesCombo.currentText(), notif, self._notification_callback)

            self._notifications_sent[nid] = notif
        except Exception as e:
            print(self.LOG_TAG, "add_rule() exception: ", e)

    def _delete_rule(self):
        try:
            # if the rule name has changed, we need to remove the old one
            if self._old_rule_name != self.rule.name:
                node = self.nodesCombo.currentText()
                old_rule = self.rule
                old_rule.name = self._old_rule_name
                if self.nodeApplyAllCheck.isChecked():
                    nid, noti = self._nodes.delete_rule(rule_name=self._old_rule_name, addr=None, callback=self._notification_callback)
                    self._notifications_sent[nid] = noti
                else:
                    nid, noti = self._nodes.delete_rule(self._old_rule_name, node, self._notification_callback)
                    self._notifications_sent[nid] = noti

        except Exception as e:
            print(self.LOG_TAG, "delete_rule() exception: ", e)


    def _save_rule(self):
        """
        Create a new rule based on the fields selected.

        Ensure that some constraints are met:
        - Determine if a field can be a regexp.
        - Validate regexp.
        - Fields cannot be empty.
        - If the user has not provided a rule name, auto assign one.
        """
        self.rule = ui_pb2.Rule()
        self.rule.created = int(datetime.now().timestamp())
        self.rule.name = self.ruleNameEdit.text()
        self.rule.description = self.ruleDescEdit.toPlainText()
        self.rule.enabled = self.enableCheck.isChecked()
        self.rule.precedence = self.precedenceCheck.isChecked()
        self.rule.nolog = self.nologCheck.isChecked()
        self.rule.operator.type = Config.RULE_TYPE_SIMPLE
        self.rule.action = Config.ACTION_DENY
        if self.actionAllowRadio.isChecked():
            self.rule.action = Config.ACTION_ALLOW
        elif self.actionRejectRadio.isChecked():
            self.rule.action = Config.ACTION_REJECT

        self.rule.duration = self._get_duration(self.durationCombo.currentIndex())

        # FIXME: there should be a sensitive checkbox per operand
        self.rule.operator.sensitive = self.sensitiveCheck.isChecked()
        rule_data = []
        if self.protoCheck.isChecked():
            if self.protoCombo.currentText() == "":
                return False, QC.translate("rules", "protocol can not be empty, or uncheck it")

            self.rule.operator.operand = Config.OPERAND_PROTOCOL
            self.rule.operator.data = self.protoCombo.currentText()
            rule_data.append(
                    {
                        "type": Config.RULE_TYPE_SIMPLE,
                        "operand": Config.OPERAND_PROTOCOL,
                        "data": self.protoCombo.currentText().lower(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.protoCombo.currentText()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.protoCombo.currentText()) == False:
                    return False, QC.translate("rules", "Protocol regexp error")

        if self.procCheck.isChecked():
            if self.procLine.text() == "":
                return False, QC.translate("rules", "process path can not be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_PATH
            self.rule.operator.data = self.procLine.text()
            rule_data.append(
                    {
                        "type": Config.RULE_TYPE_SIMPLE,
                        "operand": Config.OPERAND_PROCESS_PATH,
                        "data": self.procLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self.checkProcRegexp.isChecked():
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.procLine.text()) == False:
                    return False, QC.translate("rules", "Process path regexp error")

        if self.cmdlineCheck.isChecked():
            if self.cmdlineLine.text() == "":
                return False, QC.translate("rules", "command line can not be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_COMMAND
            self.rule.operator.data = self.cmdlineLine.text()
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_SIMPLE,
                        'operand': Config.OPERAND_PROCESS_COMMAND,
                        'data': self.cmdlineLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self.checkCmdlineRegexp.isChecked():
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.cmdlineLine.text()) == False:
                    return False, QC.translate("rules", "Command line regexp error")

        if self.ifaceCheck.isChecked():
            if self.ifaceCombo.currentText() == "":
                return False, QC.translate("rules", "Network interface can not be empty")

            self.rule.operator.operand = Config.OPERAND_IFACE_OUT
            self.rule.operator.data = self.ifaceCombo.currentText()
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_SIMPLE,
                        'operand': Config.OPERAND_IFACE_OUT,
                        'data': self.ifaceCombo.currentText(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.ifaceCombo.currentText()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.ifaceCombo.currentText()) == False:
                    return False, QC.translate("rules", "Network interface regexp error")

        if self.srcPortCheck.isChecked():
            if self.srcPortLine.text() == "":
                return False, QC.translate("rules", "Source port can not be empty")

            self.rule.operator.operand = Config.OPERAND_SOURCE_PORT
            self.rule.operator.data = self.srcPortLine.text()
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_SIMPLE,
                        'operand': Config.OPERAND_SOURCE_PORT,
                        'data': self.srcPortLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.srcPortLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.srcPortLine.text()) == False:
                    return False, QC.translate("rules", "Source port regexp error")

        if self.dstPortCheck.isChecked():
            if self.dstPortLine.text() == "":
                return False, QC.translate("rules", "Dest port can not be empty")

            self.rule.operator.operand = Config.OPERAND_DEST_PORT
            self.rule.operator.data = self.dstPortLine.text()
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_SIMPLE,
                        'operand': Config.OPERAND_DEST_PORT,
                        'data': self.dstPortLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.dstPortLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.dstPortLine.text()) == False:
                    return False, QC.translate("rules", "Dst port regexp error")

        if self.dstHostCheck.isChecked():
            if self.dstHostLine.text() == "":
                return False, QC.translate("rules", "Dest host can not be empty")

            self.rule.operator.operand = Config.OPERAND_DEST_HOST
            self.rule.operator.data = self.dstHostLine.text()
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_SIMPLE,
                        'operand': Config.OPERAND_DEST_HOST,
                        'data': self.dstHostLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.dstHostLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.dstHostLine.text()) == False:
                    return False, QC.translate("rules", "Dst host regexp error")

        if self.srcIPCheck.isChecked():
            if self.srcIPCombo.currentText() == "":
                return False, QC.translate("rules", "Source IP/Network can not be empty")

            srcIPtext = self.srcIPCombo.currentText()

            if srcIPtext == self.LAN_LABEL:
                self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
                srcIPtext = self.LAN_RANGES
            elif srcIPtext == self.MULTICAST_LABEL:
                self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
                srcIPtext = self.MULTICAST_RANGE
            else:
                try:
                    if type(ipaddress.ip_address(self.srcIPCombo.currentText())) == ipaddress.IPv4Address \
                    or type(ipaddress.ip_address(self.srcIPCombo.currentText())) == ipaddress.IPv6Address:
                        self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                        self.rule.operator.type = Config.RULE_TYPE_SIMPLE
                except Exception:
                    self.rule.operator.operand = Config.OPERAND_SOURCE_NETWORK
                    self.rule.operator.type = Config.RULE_TYPE_NETWORK

                if self._is_regex(srcIPtext):
                    self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                    self.rule.operator.type = Config.RULE_TYPE_REGEXP
                    if self._is_valid_regex(self.srcIPCombo.currentText()) == False:
                        return False, QC.translate("rules", "Source IP regexp error")

            rule_data.append(
                    {
                        'type': self.rule.operator.type,
                        'operand': self.rule.operator.operand,
                        'data': srcIPtext,
                        "sensitive": self.sensitiveCheck.isChecked()
                        })

        if self.dstIPCheck.isChecked():
            if self.dstIPCombo.currentText() == "":
                return False, QC.translate("rules", "Dest IP/Network can not be empty")

            dstIPtext = self.dstIPCombo.currentText()

            if dstIPtext == self.LAN_LABEL:
                self.rule.operator.operand = Config.OPERAND_DEST_IP
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
                dstIPtext = self.LAN_RANGES
            elif dstIPtext == self.MULTICAST_LABEL:
                self.rule.operator.operand = Config.OPERAND_DEST_IP
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
                dstIPtext = self.MULTICAST_RANGE
            else:
                try:
                    if type(ipaddress.ip_address(self.dstIPCombo.currentText())) == ipaddress.IPv4Address \
                    or type(ipaddress.ip_address(self.dstIPCombo.currentText())) == ipaddress.IPv6Address:
                        self.rule.operator.operand = Config.OPERAND_DEST_IP
                        self.rule.operator.type = Config.RULE_TYPE_SIMPLE
                except Exception:
                    self.rule.operator.operand = Config.OPERAND_DEST_NETWORK
                    self.rule.operator.type = Config.RULE_TYPE_NETWORK

                if self._is_regex(dstIPtext):
                    self.rule.operator.operand = Config.OPERAND_DEST_IP
                    self.rule.operator.type = Config.RULE_TYPE_REGEXP
                    if self._is_valid_regex(self.dstIPCombo.currentText()) == False:
                        return False, QC.translate("rules", "Dst IP regexp error")

            rule_data.append(
                    {
                        'type': self.rule.operator.type,
                        'operand': self.rule.operator.operand,
                        'data': dstIPtext,
                        "sensitive": self.sensitiveCheck.isChecked()
                        })

        if self.uidCheck.isChecked():
            uidType = Config.RULE_TYPE_SIMPLE
            uid = self.uidCombo.currentText()

            if uid == "":
                return False, QC.translate("rules", "User ID can not be empty")

            try:
                # sometimes when loading a rule, instead of the UID, the format
                # "user (uid)" is set. So try to parse it, in order not to save
                # a wrong uid.
                uidtmp = uid.split(" ")
                if len(uidtmp) == 1:
                    int(uidtmp[0])
                else:
                    uid = str(pwd.getpwnam(uidtmp[0])[self.PW_UID])
            except:
                # if it's not a digit and nor a system user (user (id)), see if
                # it's a regexp.
                if self._is_regex(self.uidCombo.currentText()):
                    uidType = Config.RULE_TYPE_REGEXP
                    if self._is_valid_regex(self.uidCombo.currentText()) == False:
                        return False, QC.translate("rules", "User ID regexp error")

                else:
                    return False, QC.translate("rules", "Invalid UID, it must be a digit.")

            self.rule.operator.operand = Config.OPERAND_USER_ID
            self.rule.operator.data = self.uidCombo.currentText()
            rule_data.append(
                    {
                        'type': uidType,
                        'operand': Config.OPERAND_USER_ID,
                        'data': uid,
                        "sensitive": self.sensitiveCheck.isChecked()
                        })

        if self.pidCheck.isChecked():
            if self.pidLine.text() == "":
                return False, QC.translate("rules", "PID field can not be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_ID
            self.rule.operator.data = self.pidLine.text()
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_SIMPLE,
                        'operand': Config.OPERAND_PROCESS_ID,
                        'data': self.pidLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.pidLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.pidLine.text()) == False:
                    return False, QC.translate("rules", "PID field regexp error")

        if self.dstListsCheck.isChecked():
            if self.dstListsLine.text() == "":
                return False, QC.translate("rules", "Lists field cannot be empty")
            if os.path.isdir(self.dstListsLine.text()) == False:
                return False, QC.translate("rules", "Lists field must be a directory")

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_DOMAINS
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_LISTS,
                        'operand': Config.OPERAND_LIST_DOMAINS,
                        'data': self.dstListsLine.text(),
                        'sensitive': self.sensitiveCheck.isChecked()
                        })
            self.rule.operator.data = ""

        if self.dstListRegexpCheck.isChecked():
            if self.dstRegexpListsLine.text() == "":
                return False, QC.translate("rules", "Lists field cannot be empty")
            if os.path.isdir(self.dstRegexpListsLine.text()) == False:
                return False, QC.translate("rules", "Lists field must be a directory")

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_DOMAINS_REGEXP
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_LISTS,
                        'operand': Config.OPERAND_LIST_DOMAINS_REGEXP,
                        'data': self.dstRegexpListsLine.text(),
                        'sensitive': self.sensitiveCheck.isChecked()
                        })
            self.rule.operator.data = ""

        if self.dstListNetsCheck.isChecked():
            if self.dstListNetsLine.text() == "":
                return False, QC.translate("rules", "Lists field cannot be empty")
            if os.path.isdir(self.dstListNetsLine.text()) == False:
                return False, QC.translate("rules", "Lists field must be a directory")

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_NETS
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_LISTS,
                        'operand': Config.OPERAND_LIST_NETS,
                        'data': self.dstListNetsLine.text(),
                        'sensitive': self.sensitiveCheck.isChecked()
                        })
            self.rule.operator.data = ""


        if self.dstListIPsCheck.isChecked():
            if self.dstListIPsLine.text() == "":
                return False, QC.translate("rules", "Lists field cannot be empty")
            if os.path.isdir(self.dstListIPsLine.text()) == False:
                return False, QC.translate("rules", "Lists field must be a directory")

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_IPS
            rule_data.append(
                    {
                        'type': Config.RULE_TYPE_LISTS,
                        'operand': Config.OPERAND_LIST_IPS,
                        'data': self.dstListIPsLine.text(),
                        'sensitive': self.sensitiveCheck.isChecked()
                        })
            self.rule.operator.data = ""

        if self.md5Check.isChecked():
            if self.md5Line.text() == "":
                return False, QC.translate("rules", "md5 line cannot be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_HASH_MD5
            self.rule.operator.data = self.md5Line.text().lower()
            rule_data.append(
                {
                    'type': Config.RULE_TYPE_SIMPLE,
                    'operand': Config.OPERAND_PROCESS_HASH_MD5,
                    'data': self.md5Line.text().lower(),
                    "sensitive": False
                })
            if self._is_regex(self.md5Line.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if self._is_valid_regex(self.pidLine.text()) == False:
                    return False, QC.translate("rules", "md5 field regexp error")



        if len(rule_data) >= 2:
            self.rule.operator.type = Config.RULE_TYPE_LIST
            self.rule.operator.operand = Config.RULE_TYPE_LIST
            self.rule.operator.data = ""
            for rd in rule_data:
                self.rule.operator.list.extend([
                    ui_pb2.Operator(
                        type=rd['type'],
                        operand=rd['operand'],
                        data=rd['data'],
                        sensitive=rd['sensitive']
                    )
                ])
                print(self.rule.operator.list)

        elif len(rule_data) == 1:
            self.rule.operator.operand = rule_data[0]['operand']
            self.rule.operator.data = rule_data[0]['data']
            if self.checkProcRegexp.isChecked():
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
            elif self.checkCmdlineRegexp.isChecked():
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
            elif (self.procCheck.isChecked() == False and self.cmdlineCheck.isChecked() == False) \
                        and self._is_regex(self.rule.operator.data):
                    self.rule.operator.type = Config.RULE_TYPE_REGEXP

        else:
            return False, QC.translate("rules", "Select at least one field.")

        if self.ruleNameEdit.text() == "":
            self.rule.name = slugify("%s %s %s" % (self.rule.action, self.rule.operator.type, self.rule.operator.data))

        return True, ""

    def edit_rule(self, records, _addr=None):
        self.WORK_MODE = self.EDIT_RULE
        self._reset_state()

        self.rule = Rule.new_from_records(records)
        if self.rule.operator.type not in Config.RulesTypes:
            Message.ok(QC.translate("rules", "<b>Rule not supported</b>"),
                       QC.translate("rules", "This type of rule ({0}) is not supported by version {1}".format(self.rule.operator.type, version)),
                       QtWidgets.QMessageBox.Warning)
            self.hide()
            return

        self._old_rule_name = records.value(RuleFields.Name)

        if self._load_rule(addr=_addr, rule=self.rule):
            self.show()

    def new_rule(self):
        self.WORK_MODE = self.ADD_RULE
        self._reset_state()
        self._load_nodes()
        self.show()

    def new_rule_from_connection(self, coltime):
        self.WORK_MODE = self.ADD_RULE
        self._reset_state()
        self._load_nodes()

        try:
            records = self._db.get_connection_by_field("time", coltime)
            if records.next() == False:
                print(self.LOG_TAG, "error loading connection fields by time: {0}".format(coltime))
                return False

            self.set_fields_from_connection(records)
            self.show()
        except Exception as e:
            print(self.LOG_TAG, "exception creating new rule from connection:", e)
            return False

        return True
