
from PyQt5 import Qt, QtCore, QtGui, uic, QtWidgets
from slugify import slugify
from datetime import datetime
import re
import json
import sys
import os
import ui_pb2
import time

from config import Config
from nodes import Nodes
from database import Database

DIALOG_UI_PATH = "%s/../res/ruleseditor.ui" % os.path.dirname(sys.modules[__name__].__file__)
class RulesEditorDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    LOG_TAG = "[rules editor]"
    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    def __init__(self, parent=None, _rule=None):
        super(RulesEditorDialog, self).__init__(parent)
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self._notifications_sent = {}
        self._nodes = Nodes.instance()
        self._db = Database.instance()
        self._notification_callback.connect(self._cb_notification_callback)
        self._old_rule_name = None

        self.setupUi(self)

        self.buttonBox.button(QtWidgets.QDialogButtonBox.Reset).clicked.connect(self._cb_reset_clicked)
        self.buttonBox.button(QtWidgets.QDialogButtonBox.Close).clicked.connect(self._cb_close_clicked)
        self.buttonBox.button(QtWidgets.QDialogButtonBox.Apply).clicked.connect(self._cb_apply_clicked)
        self.buttonBox.button(QtWidgets.QDialogButtonBox.Help).clicked.connect(self._cb_help_clicked)
        self.protoCheck.toggled.connect(self._cb_proto_check_toggled)
        self.procCheck.toggled.connect(self._cb_proc_check_toggled)
        self.cmdlineCheck.toggled.connect(self._cb_cmdline_check_toggled)
        self.dstPortCheck.toggled.connect(self._cb_dstport_check_toggled)
        self.uidCheck.toggled.connect(self._cb_uid_check_toggled)
        self.dstIPCheck.toggled.connect(self._cb_dstip_check_toggled)
        self.dstHostCheck.toggled.connect(self._cb_dsthost_check_toggled)

        if _rule != None:
            self._load_rule(rule=_rule)

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

    def _cb_proto_check_toggled(self, state):
        self.protoCombo.setEnabled(state)

    def _cb_proc_check_toggled(self, state):
        self.procLine.setEnabled(state)

    def _cb_cmdline_check_toggled(self, state):
        self.cmdlineLine.setEnabled(state)

    def _cb_dstport_check_toggled(self, state):
        self.dstPortLine.setEnabled(state)

    def _cb_uid_check_toggled(self, state):
        self.uidLine.setEnabled(state)

    def _cb_dstip_check_toggled(self, state):
        self.dstIPLine.setEnabled(state)

    def _cb_dsthost_check_toggled(self, state):
        self.dstHostLine.setEnabled(state)

    def _set_status_error(self, msg):
        self.statusLabel.setStyleSheet('color: red')
        self.statusLabel.setText(msg)

    def _set_status_message(self, msg):
        self.statusLabel.setStyleSheet('color: green')
        self.statusLabel.setText(msg)

    def _cb_apply_clicked(self):
        result, error = self._save_rule()
        if result == False:
            self._set_status_error(error)
            return
        if self.nodesCombo.count() == 0:
            self._set_status_error("There're no nodes connected.")
            return

        self._add_rule()
        self._delete_rule()

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        #print(self.LOG_TAG, "Rule notification received: ", reply.id, reply.code)
        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.OK:
                self._set_status_message("Rule applied.")
            else:
                self._set_status_error("Error applying rule: %s" % reply.data)

            del self._notifications_sent[reply.id]

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

    def _reset_state(self):
        self.ruleNameEdit.setText("")
        self.statusLabel.setText("")

        self.actionDenyRadio.setChecked(True)
        self.durationCombo.setCurrentIndex(0)

        self.protoCheck.setChecked(False)
        self.protoCombo.setCurrentText("")

        self.procCheck.setChecked(False)
        self.procLine.setText("")
            
        self.cmdlineCheck.setChecked(False)
        self.cmdlineLine.setText("")
            
        self.uidCheck.setChecked(False)
        self.uidLine.setText("")
            
        self.dstPortCheck.setChecked(False)
        self.dstPortLine.setText("")
            
        self.dstIPCheck.setChecked(False)
        self.dstIPLine.setText("")
            
        self.dstHostCheck.setChecked(False)
        self.dstHostLine.setText("")

    def _load_rule(self, addr=None, rule=None):
        self._load_nodes(addr)

        self.ruleNameEdit.setText(rule.name)
        self.enableCheck.setChecked(rule.enabled)
        self.precedenceCheck.setChecked(rule.precedence)
        if rule.action == "deny":
            self.actionDenyRadio.setChecked(True)
        if rule.action == "allow":
            self.actionAllowRadio.setChecked(True)

        self.durationCombo.setCurrentText(self.rule.duration)
        
        if self.rule.operator.type != "list":
            self._load_rule_operator(self.rule.operator)
        else:
            rule_options = json.loads(self.rule.operator.data)
            for r in rule_options:
                _sensitive = False
                if 'sensitive' in r:
                    _sensitive = r['sensitive']

                op = ui_pb2.Operator(type=r['type'], operand=r['operand'], data=r['data'], sensitive=_sensitive)
                self._load_rule_operator(op)
    
    def _load_rule_operator(self, operator):
        self.sensitiveCheck.setChecked(operator.sensitive)
        if operator.operand == "protocol":
            self.protoCheck.setChecked(True)
            self.protoCombo.setEnabled(True)
            self.protoCombo.setCurrentText(operator.data.upper())

        if operator.operand == "process.path":
            self.procCheck.setChecked(True)
            self.procLine.setEnabled(True)
            self.procLine.setText(operator.data)

        if operator.operand == "process.command":
            self.cmdlineCheck.setChecked(True)
            self.cmdlineLine.setEnabled(True)
            self.cmdlineLine.setText(operator.data)

        if operator.operand == "user.id":
            self.uidCheck.setChecked(True)
            self.uidLine.setEnabled(True)
            self.uidLine.setText(operator.data)

        if operator.operand == "dest.port":
            self.dstPortCheck.setChecked(True)
            self.dstPortLine.setEnabled(True)
            self.dstPortLine.setText(operator.data)

        if operator.operand == "dest.ip":
            self.dstIPCheck.setChecked(True)
            self.dstIPLine.setEnabled(True)
            self.dstIPLine.setText(operator.data)

        if operator.operand == "dest.host":
            self.dstHostCheck.setChecked(True)
            self.dstHostLine.setEnabled(True)
            self.dstHostLine.setText(operator.data)

    def _load_nodes(self, addr=None):
        try:
            self.nodesCombo.clear()

            self._node_list = self._nodes.get()
            if len(self._node_list) <= 1:
                self.nodeApplyAllCheck.setVisible(False)

            for node in self._node_list:
                self.nodesCombo.addItem(node)

            if addr != None:
                self.nodesCombo.setCurrentText(addr)

        except Exception as e:
            print(self.LOG_TAG, "exception loading nodes: ", e, addr)

    def _insert_rule_to_db(self, node_addr):
        self._db.insert("rules",
            "(time, node, name, enabled, precedence, action, duration, operator_type, operator_sensitive, operator_operand, operator_data)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    node_addr, self.rule.name,
                    str(self.rule.enabled), str(self.rule.precedence),
                    self.rule.action, self.rule.duration, self.rule.operator.type,
                    str(self.rule.operator.sensitive), self.rule.operator.operand, self.rule.operator.data),
                action_on_conflict="REPLACE")

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
            if self._old_rule_name != None:

                # if the rule name has changed, we need to remove the old one
                if self._old_rule_name != self.rule.name:
                    self._db.remove("DELETE FROM rules WHERE name='%s'" % self._old_rule_name)

                    old_rule = self.rule
                    old_rule.name = self._old_rule_name
                    notif_delete = ui_pb2.Notification(type=ui_pb2.DELETE_RULE, rules=[old_rule])
                    if self.nodeApplyAllCheck.isChecked():
                        nid = self._nodes.send_notifications(notif_delete, self._notification_callback)
                    else:
                        nid = self._nodes.send_notification(self.nodesCombo.currentText(), notif_delete, self._notification_callback)

                self._old_rule_name = None
        except Exception as e:
            print(self.LOG_TAG, "delete_rule() exception: ", e)
    
    
    def _save_rule(self):
        """
        Create a new rule based on the fields selected.

        Ensure that some constraints are met:
        - Determine if a field can be a regexp.
        - Validate regexp.
        - Fields cam not be empty.
        - If the user has not provided a rule name, auto assign one.
        """
        self.rule = ui_pb2.Rule()
        self.rule.name = self.ruleNameEdit.text()
        self.rule.enabled = self.enableCheck.isChecked()
        self.rule.precedence = self.precedenceCheck.isChecked()
        self.rule.action = "deny" if self.actionDenyRadio.isChecked() else "allow"
        self.rule.duration = self.durationCombo.currentText()
        
        # FIXME: there should be a sensitive checkbox per operand
        self.rule.operator.sensitive = self.sensitiveCheck.isChecked()
        rule_data = []
        if self.protoCheck.isChecked():
            if self.protoCombo.currentText() == "":
                return False, "protocol can not be empty, or uncheck it"

            self.rule.operator.operand = "protocol"
            self.rule.operator.data = self.protoCombo.currentText()
            rule_data.append(
                    {
                        "type": "simple",
                        "operand": "protocol",
                        "data": self.protoCombo.currentText().lower(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.protoCombo.currentText()):
                rule_data[len(rule_data)-1]['type'] = "regexp"
                if self._is_valid_regex(self.protoCombo.currentText()) == False:
                    return False, "Protocol regexp error"

        if self.procCheck.isChecked():
            if self.procLine.text() == "":
                return False, "process path can not be empty"

            self.rule.operator.operand = "process.path"
            self.rule.operator.data = self.procLine.text()
            rule_data.append(
                    {
                        "type": "simple",
                        "operand": "process.path",
                        "data": self.procLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.procLine.text()):
                rule_data[len(rule_data)-1]['type'] = "regexp"
                if self._is_valid_regex(self.procLine.text()) == False:
                    return False, "Process path regexp error"

        if self.cmdlineCheck.isChecked():
            if self.cmdlineLine.text() == "":
                return False, "command line can not be empty"

            self.rule.operator.operand = "process.command"
            self.rule.operator.data = self.cmdlineLine.text()
            rule_data.append(
                    {
                        'type': 'simple',
                        'operand': 'process.command',
                        'data': self.cmdlineLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.cmdlineLine.text()):
                rule_data[len(rule_data)-1]['type'] = "regexp"
                if self._is_valid_regex(self.cmdlineLine.text()) == False:
                    return False, "Command line regexp error"
        
        if self.dstPortCheck.isChecked():
            if self.dstPortLine.text() == "":
                return False, "Dest port can not be empty"

            self.rule.operator.operand = "dest.port"
            self.rule.operator.data = self.dstPortLine.text()
            rule_data.append(
                    {
                        'type': 'simple',
                        'operand': 'dest.port',
                        'data': self.dstPortLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.dstPortLine.text()):
                rule_data[len(rule_data)-1]['type'] = "regexp"
                if self._is_valid_regex(self.dstPortLine.text()) == False:
                    return False, "Dst port regexp error"
        
        if self.dstHostCheck.isChecked():
            if self.dstHostLine.text() == "":
                return False, "Dest host can not be empty"

            self.rule.operator.operand = "dest.host"
            self.rule.operator.data = self.dstHostLine.text()
            rule_data.append(
                    {
                        'type': 'simple',
                        'operand': 'dest.host',
                        'data': self.dstHostLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.dstHostLine.text()):
                rule_data[len(rule_data)-1]['type'] = "regexp"
                if self._is_valid_regex(self.dstHostLine.text()) == False:
                    return False, "Dst host regexp error"
        
        if self.dstIPCheck.isChecked():
            if self.dstIPLine.text() == "":
                return False, "Dest IP can not be empty"

            self.rule.operator.operand = "dest.ip"
            self.rule.operator.data = self.dstIPLine.text()
            rule_data.append(
                    {
                        'type': 'simple',
                        'operand': 'dest.ip',
                        'data': self.dstIPLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.dstIPLine.text()):
                rule_data[len(rule_data)-1]['type'] = "regexp"
                if self._is_valid_regex(self.dstIPLine.text()) == False:
                    return False, "Dst IP regexp error"
        
        if self.uidCheck.isChecked():
            if self.uidLine.text() == "":
                return False, "User ID can not be empty"

            self.rule.operator.operand = "user.id"
            self.rule.operator.data = self.uidLine.text()
            rule_data.append(
                    {
                        'type': 'simple',
                        'operand': 'user.id',
                        'data': self.uidLine.text(),
                        "sensitive": self.sensitiveCheck.isChecked()
                        })
            if self._is_regex(self.uidLine.text()):
                rule_data[len(rule_data)-1]['type'] = "regexp"
                if self._is_valid_regex(self.uidLine.text()) == False:
                    return False, "User ID regexp error"

        if len(rule_data) > 1:
            self.rule.operator.type = "list"
            self.rule.operator.operand = ""
            self.rule.operator.data = json.dumps(rule_data)
        elif len(rule_data) == 1:
            self.rule.operator.type = "simple"
            self.rule.operator.operand = rule_data[0]['operand']
            self.rule.operator.data = rule_data[0]['data']
            if self._is_regex(self.rule.operator.data):
                self.rule.operator.type = "regexp"

        if self.ruleNameEdit.text() == "":
            self.rule.name = slugify("%s %s %s" % (self.rule.action, self.rule.operator.type, self.rule.operator.data))

        return True, ""

    def edit_rule(self, records, _addr=None):
        self._reset_state()

        self.rule = ui_pb2.Rule(name=records.value(2))
        self.rule.enabled = self._bool(records.value(3))
        self.rule.precedence = self._bool(records.value(4))
        self.rule.action = records.value(5)
        self.rule.duration = records.value(6)
        self.rule.operator.type = records.value(7)
        self.rule.operator.sensitive = self._bool(records.value(8))
        self.rule.operator.operand = records.value(9)
        self.rule.operator.data = "" if records.value(10) == None else str(records.value(10))

        self._old_rule_name = records.value(2)
        
        self._load_rule(addr=_addr, rule=self.rule)
        self.show()

    def new_rule(self):
        self._reset_state()
        self._load_nodes()
        self.show()
