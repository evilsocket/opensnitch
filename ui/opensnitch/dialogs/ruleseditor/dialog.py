from PyQt6 import QtCore, QtGui, uic, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC
from slugify import slugify
from datetime import datetime
import sys
import os
import pwd
import time
import ipaddress

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.database import Database
from opensnitch.database.enums import RuleFields, ConnFields
from opensnitch.version import version
from opensnitch.utils import (
    Message,
    FileDialog,
    Icons,
    NetworkInterfaces,
    qvalidator,
    logger
)
from opensnitch.utils.network_aliases import NetworkAliases
from opensnitch.rules import Rule, Rules
from . import (
    constants,
    nodes,
    rules,
    signals,
    utils
)

DIALOG_UI_PATH = "%s/../../res/ruleseditor.ui" % os.path.dirname(sys.modules[__name__].__file__)
class RulesEditorDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    _notification_callback = QtCore.pyqtSignal(str, ui_pb2.NotificationReply)

    def __init__(self, parent=None, modal=True, appicon=None):
        super(RulesEditorDialog, self).__init__(parent)

        self.logger = logger.get(__name__)
        self.notifications_sent = {}
        self._nodes = Nodes.instance()
        self._db = Database.instance()
        self._rules = Rules.instance()
        self._notification_callback.connect(self.cb_notification_callback)
        self._old_rule_name = None
        self._users_list = pwd.getpwall()

        self.setupUi(self)
        self.setModal(modal)
        if appicon is not None:
            self.setWindowIcon(appicon)

        utils.load_aliases_into_menu(self)
        utils.set_rulename_validator(self)
        self.buttonBox.setStandardButtons(
            QtWidgets.QDialogButtonBox.StandardButton.Help |
            QtWidgets.QDialogButtonBox.StandardButton.Reset |
            QtWidgets.QDialogButtonBox.StandardButton.Close |
            QtWidgets.QDialogButtonBox.StandardButton.Save
        )

        signals.connect_all(self)
        utils.configure_icons(self)

    def showEvent(self, event):
        super(RulesEditorDialog, self).showEvent(event)
        self.init()

    def init(self):
        # save old combo values so we don't overwrite them here.
        oldIface = self.ifaceCombo.currentText()
        oldUid = self.uidCombo.currentText()
        self.ifaceCombo.clear()
        self.uidCombo.clear()
        addr = nodes.get_node_addr(self)
        if addr is not None and self._nodes.is_local(addr):
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
                    self.uidCombo.addItem("{0} ({1})".format(user[constants.PW_USER], user[constants.PW_UID]), user[constants.PW_UID])
            except Exception as e:
                self.logger.warning("Error adding IPs: %s", repr(e))
            finally:
                self.uidCombo.blockSignals(False);

        nodes.load_rules(self, addr)
        self.ifaceCombo.setCurrentText(oldIface)
        self.uidCombo.setCurrentText(oldUid)

    def add_section(self, widget, icon, lbl):
        """adds a new tab to the Preferences, and returns the new index"""
        return self.tabWidget.addTab(widget, icon, lbl)

    def insert_section(self, idx, widget, lbl):
        """inserts a new tab at the given index"""
        return self.tabWidget.insertTab(idx, widget, lbl)

    def remove_section(self, idx):
        """removes a tab"""
        return self.tabWidget.removeTab(idx)

    def enable_section(self, idx, enable):
        """enables or disables a tab"""
        return self.tabWidget.setTabEnabled(idx, enable)

    def set_section_title(self, idx, text):
        """changes the title of a tab"""
        return self.tabWidget.setTabText(idx, text)

    def set_section_visible(self, idx, visible):
        """makes the tab visible or not"""
        return self.tabWidget.setTabVisible(idx, visible)

    def get_section(self, idx):
        """returns the widget of the given index"""
        return self.tabWidget.widget(idx)

    def cb_rule_name_validator_result(self, result):
        if result == QtGui.QValidator.State.Invalid:
            utils.set_status_error(
                self,
                QC.translate("rules",
                             "Invalid rule name (not allowed characters: '{0}' )".format(constants.INVALID_RULE_NAME_CHARS)
                             )
            )
        else:
            utils.set_status_message(self, "")

    def cb_accept_clicked(self):
        pass

    def cb_close_clicked(self):
        self.hide()

    def cb_reset_clicked(self):
        utils.reset_state(self)

    def cb_help_clicked(self):
        QtGui.QDesktopServices.openUrl(QtCore.QUrl(Config.HELP_URL))

    def cb_select_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstListsLine.text())
        if dirName is not None and dirName != "":
            self.dstListsLine.setText(dirName)

    def cb_select_nets_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstListNetsLine.text())
        if dirName is not None and dirName != "":
            self.dstListNetsLine.setText(dirName)

    def cb_select_ips_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstListIPsLine.text())
        if dirName is not None and dirName != "":
            self.dstListIPsLine.setText(dirName)

    def cb_select_regexp_list_button_clicked(self):
        dirName = FileDialog.select_dir(self, self.dstRegexpListsLine.text())
        if dirName is not None and dirName != "":
            self.dstRegexpListsLine.setText(dirName)

    def cb_proto_check_toggled(self, state):
        self.protoCombo.setEnabled(state)

    def cb_proc_check_toggled(self, state):
        self.procLine.setEnabled(state)
        self.checkProcRegexp.setEnabled(state)
        self.checkProcRegexp.setVisible(state)

    def cb_cmdline_check_toggled(self, state):
        self.cmdlineLine.setEnabled(state)
        self.checkCmdlineRegexp.setEnabled(state)
        self.checkCmdlineRegexp.setVisible(state)

    def cb_iface_check_toggled(self, state):
        self.ifaceCombo.setEnabled(state)

    def cb_dstport_check_toggled(self, state):
        self.dstPortLine.setEnabled(state)

    def cb_srcport_check_toggled(self, state):
        self.srcPortLine.setEnabled(state)

    def cb_uid_check_toggled(self, state):
        self.uidCombo.setEnabled(state)

    def cb_pid_check_toggled(self, state):
        self.pidLine.setEnabled(state)

    def cb_srcip_check_toggled(self, state):
        self.srcIPCombo.setEnabled(state)

    def cb_dstip_check_toggled(self, state):
        self.dstIPCombo.setEnabled(state)

    def cb_dsthost_check_toggled(self, state):
        self.dstHostLine.setEnabled(state)

    def cb_dstlists_check_toggled(self, state):
        self.dstListsLine.setEnabled(state)
        self.selectListButton.setEnabled(state)

    def cb_dstregexplists_check_toggled(self, state):
        self.dstRegexpListsLine.setEnabled(state)
        self.selectListRegexpButton.setEnabled(state)

    def cb_dstiplists_check_toggled(self, state):
        self.dstListIPsLine.setEnabled(state)
        self.selectIPsListButton.setEnabled(state)

    def cb_dstnetlists_check_toggled(self, state):
        self.dstListNetsLine.setEnabled(state)
        self.selectNetsListButton.setEnabled(state)

    def cb_uid_combo_changed(self, index):
        self.uidCombo.setCurrentText(str(self._users_list[index][constants.PW_UID]))

    def cb_nodes_combo_changed(self, index):
        addr = self.nodesCombo.itemData(index)
        nodes.load_rules(self, addr)

    def cb_md5check_toggled(self, state):
        self.md5Line.setEnabled(state)

    def cb_save_clicked(self):
        if self.nodesCombo.count() == 0:
            utils.set_status_error(self, QC.translate("rules", "There're no nodes connected."))
            return

        rule_name = self.ruleNameEdit.text()
        if rule_name == "":
            return

        #node = self.nodesCombo.currentText()
        node = nodes.get_node_addr(self)
        # avoid to overwrite rules when:
        # - adding a new rule.
        # - when a rule is renamed, i.e., the rule is edited or added and the
        #   user changes the name.
        if constants.WORK_MODE == constants.ADD_RULE and self._db.get_rule(rule_name, node).next() == True:
            utils.set_status_error(self, QC.translate("rules", "There's already a rule with this name."))
            return
        elif constants.WORK_MODE == constants.EDIT_RULE and rule_name != self._old_rule_name and \
            self._db.get_rule(rule_name, node).next() == True:
            utils.set_status_error(self, QC.translate("rules", "There's already a rule with this name."))
            return

        if self.md5Check.isChecked() and not self.procCheck.isChecked():
            utils.set_status_error(self, QC.translate("rules", "Process path must be checked in order to verify checksums."))
            return

        result, error = self.save_rule()
        if result is False:
            utils.set_status_error(self, error)
            return

        self.add_rule()
        if self._old_rule_name is not None and self._old_rule_name != self.rule.name:
            self.delete_rule()

        self._old_rule_name = rule_name

        # after adding a new rule, we enter into EDIT mode, to allow further
        # changes without closing the dialog.
        if constants.WORK_MODE == constants.ADD_RULE:
            constants.WORK_MODE = constants.EDIT_RULE

        self._rules.updated.emit(0)

    @QtCore.pyqtSlot(str, ui_pb2.NotificationReply)
    def cb_notification_callback(self, addr, reply):
        #print(self.LOG_TAG, "Rule notification received: ", reply.id, reply.code)
        if reply.id in self.notifications_sent:
            if reply.code == ui_pb2.OK:
                utils.set_status_message(self, QC.translate("rules", "Rule applied."))
            else:
                utils.set_status_error(self, QC.translate("rules", "Error applying rule: {0}").format(reply.data))

            del self.notifications_sent[reply.id]

    def new_rule(self):
        constants.WORK_MODE = constants.ADD_RULE
        utils.reset_state(self)
        nodes.load_all(self)
        self.show()

    def new_rule_from_connection(self, coltime):
        constants.WORK_MODE = constants.ADD_RULE
        utils.reset_state(self)
        nodes.load_all(self)

        try:
            records = self._db.get_connection_by_field("time", coltime)
            if records.next() is False:
                self.logger.error("error loading connection fields by time: %s", coltime)
                return False

            rules.set_fields_from_connection(self, records)
            self.show()
        except Exception as e:
            self.logger.warning("exception creating new rule from connection: %s", repr(e))
            return False

        return True

    def edit_rule(self, records, _addr=None):
        constants.WORK_MODE = constants.EDIT_RULE
        utils.reset_state(self)

        self.rule = Rule.new_from_records(records)
        if self.rule.operator.type not in Config.RulesTypes:
            Message.ok(QC.translate("rules", "<b>Rule not supported</b>"),
                       QC.translate("rules", "This type of rule ({0}) is not supported by version {1}".format(self.rule.operator.type, version)),
                       QtWidgets.QMessageBox.Icon.Warning)
            self.hide()
            return

        self._old_rule_name = records.value(RuleFields.Name)

        if self.load_rule(addr=_addr, rule=self.rule):
            # show() is needed to open the dialog
            self.show()
            self.exec()

    def load_rule(self, addr=None, rule=None):
        if nodes.load_all(self, addr) is False:
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

        self.durationCombo.setCurrentIndex(rules.load_duration(self, self.rule.duration))

        if self.rule.operator.type != Config.RULE_TYPE_LIST:
            rules.load_operator(self, self.rule.operator)
        else:
            for op in self.rule.operator.list:
                rules.load_operator(self, op)

        return True

    def add_rule(self):
        try:
            addr = nodes.get_node_addr(self)
            if self.nodeApplyAllCheck.isChecked():
                for idx in range(self.nodesCombo.count()):
                    rules.insert_rule_to_db(self, self.nodesCombo.itemData(idx), self.rule)
            else:
                rules.insert_rule_to_db(self, addr, self.rule)

            notif = ui_pb2.Notification(
                    id=int(str(time.time()).replace(".", "")),
                    type=ui_pb2.CHANGE_RULE,
                    data="",
                    rules=[self.rule])
            if self.nodeApplyAllCheck.isChecked():
                nid = self._nodes.send_notifications(notif, self._notification_callback)
            else:
                nid = self._nodes.send_notification(addr, notif, self._notification_callback)

            self.notifications_sent[nid] = notif
        except Exception as e:
            self.logger.warning("add_rule() exception: %s", repr(e))

    def delete_rule(self):
        try:
            # if the rule name has changed, we need to remove the old one
            if self._old_rule_name != self.rule.name:
                node = nodes.get_node_addr(self)
                old_rule = self.rule
                old_rule.name = self._old_rule_name
                if self.nodeApplyAllCheck.isChecked():
                    nid, noti = self._nodes.delete_rule(rule_name=self._old_rule_name, addr=None, callback=self._notification_callback)
                    self.notifications_sent[nid] = noti
                else:
                    nid, noti = self._nodes.delete_rule(self._old_rule_name, node, self._notification_callback)
                    self.notifications_sent[nid] = noti

        except Exception as e:
            self.logger.warning("delete_rule() exception: %s", repr(e))


    def save_rule(self):
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

        self.rule.duration = rules.get_duration(self, self.durationCombo.currentIndex())

        # FIXME: there should be a sensitive checkbox per operand
        self.rule.operator.sensitive = self.sensitiveCheck.isChecked()
        rule_data = []
        if self.protoCheck.isChecked():
            if self.protoCombo.currentText() == "":
                return False, QC.translate("rules", "protocol can not be empty, or uncheck it")

            self.rule.operator.operand = Config.OPERAND_PROTOCOL
            self.rule.operator.data = self.protoCombo.currentText()
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_SIMPLE,
                    Config.OPERAND_PROTOCOL,
                    self.protoCombo.currentText().lower(),
                    self.sensitiveCheck.isChecked()
                )
            )
            if utils.is_regex(self, self.protoCombo.currentText()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.protoCombo.currentText()) is False:
                    return False, QC.translate("rules", "Protocol regexp error")

            elif "," in self.protoCombo.currentText():
                ok, result = utils.comma_to_regexp(self, self.protoCombo.currentText().lower(), str)
                if ok:
                    rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                    rule_data[len(rule_data)-1]['data'] = result
                else:
                    return False, result

        if self.procCheck.isChecked():
            if self.procLine.text() == "":
                return False, QC.translate("rules", "process path can not be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_PATH
            self.rule.operator.data = self.procLine.text()
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_SIMPLE,
                    Config.OPERAND_PROCESS_PATH,
                    self.procLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            if self.checkProcRegexp.isChecked():
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.procLine.text()) is False:
                    return False, QC.translate("rules", "Process path regexp error")

        if self.cmdlineCheck.isChecked():
            if self.cmdlineLine.text() == "":
                return False, QC.translate("rules", "command line can not be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_COMMAND
            self.rule.operator.data = self.cmdlineLine.text()
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_SIMPLE,
                    Config.OPERAND_PROCESS_COMMAND,
                    self.cmdlineLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            if self.checkCmdlineRegexp.isChecked():
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.cmdlineLine.text()) is False:
                    return False, QC.translate("rules", "Command line regexp error")

        if self.ifaceCheck.isChecked():
            if self.ifaceCombo.currentText() == "":
                return False, QC.translate("rules", "Network interface can not be empty")

            self.rule.operator.operand = Config.OPERAND_IFACE_OUT
            self.rule.operator.data = self.ifaceCombo.currentText()
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_SIMPLE,
                    Config.OPERAND_IFACE_OUT,
                    self.ifaceCombo.currentText(),
                    self.sensitiveCheck.isChecked()
                )
            )
            if utils.is_regex(self, self.ifaceCombo.currentText()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.ifaceCombo.currentText()) is False:
                    return False, QC.translate("rules", "Network interface regexp error")

            elif "," in self.ifaceCombo.currentText():
                ok, result = utils.comma_to_regexp(self, self.ifaceCombo.currentText(), str)
                if ok:
                    rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                    rule_data[len(rule_data)-1]['data'] = result
                else:
                    return False, result

        if self.srcPortCheck.isChecked():
            if self.srcPortLine.text() == "":
                return False, QC.translate("rules", "Source port can not be empty")

            self.rule.operator.operand = Config.OPERAND_SOURCE_PORT
            src_port = self.srcPortLine.text()
            self.rule.operator.data = src_port
            op_type = Config.RULE_TYPE_SIMPLE
            if constants.RANGE_SEPARATOR in self.srcPortLine.text():
                src_port = src_port.replace(" ", "")
                op_type = Config.RULE_TYPE_RANGE
            rule_data.append(
                rules.new_operator(
                    op_type,
                    Config.OPERAND_SOURCE_PORT,
                    src_port,
                    self.sensitiveCheck.isChecked()
                )
            )
            if utils.is_regex(self, self.srcPortLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.srcPortLine.text()) is False:
                    return False, QC.translate("rules", "Source port regexp error")

            elif "," in self.srcPortLine.text():
                ok, result = utils.comma_to_regexp(self, self.srcPortLine.text(), int)
                if ok:
                    rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                    rule_data[len(rule_data)-1]['data'] = result
                else:
                    return False, result

        if self.dstPortCheck.isChecked():
            if self.dstPortLine.text() == "":
                return False, QC.translate("rules", "Dest port can not be empty")

            self.rule.operator.operand = Config.OPERAND_DEST_PORT
            dst_port = self.dstPortLine.text()
            op_type = Config.RULE_TYPE_SIMPLE
            if constants.RANGE_SEPARATOR in dst_port:
                dst_port = dst_port.replace(" ", "")
                op_type = Config.RULE_TYPE_RANGE
            rule_data.append(
                rules.new_operator(
                    op_type,
                    Config.OPERAND_DEST_PORT,
                    dst_port,
                    self.sensitiveCheck.isChecked()
                )
            )
            if utils.is_regex(self, self.dstPortLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.dstPortLine.text()) is False:
                    return False, QC.translate("rules", "Dst port regexp error")

            elif "," in self.dstPortLine.text():
                ok, result = utils.comma_to_regexp(self, self.dstPortLine.text(), int)
                if ok:
                    rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                    rule_data[len(rule_data)-1]['data'] = result
                else:
                    return False, result

        if self.dstHostCheck.isChecked():
            if self.dstHostLine.text() == "":
                return False, QC.translate("rules", "Dest host can not be empty")

            self.rule.operator.operand = Config.OPERAND_DEST_HOST
            self.rule.operator.data = self.dstHostLine.text()
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_SIMPLE,
                    Config.OPERAND_DEST_HOST,
                    self.dstHostLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            if utils.is_regex(self, self.dstHostLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.dstHostLine.text()) is False:
                    return False, QC.translate("rules", "Dst host regexp error")

            elif "," in self.dstHostLine.text():
                ok, result = utils.comma_to_regexp(self, self.dstHostLine.text(), str)
                if ok:
                    rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                    rule_data[len(rule_data)-1]['data'] = result
                else:
                    return False, result

        if self.srcIPCheck.isChecked():
            if self.srcIPCombo.currentText() == "":
                return False, QC.translate("rules", "Source IP/Network can not be empty")

            srcIPtext = self.srcIPCombo.currentText()

            if srcIPtext == constants.LAN_LABEL:
                self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
                srcIPtext = constants.LAN_RANGES
            elif srcIPtext == constants.MULTICAST_LABEL:
                self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
                srcIPtext = constants.MULTICAST_RANGE
            else:
                try:
                    if type(ipaddress.ip_address(self.srcIPCombo.currentText())) == ipaddress.IPv4Address \
                    or type(ipaddress.ip_address(self.srcIPCombo.currentText())) == ipaddress.IPv6Address:
                        self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                        self.rule.operator.type = Config.RULE_TYPE_SIMPLE
                except Exception:
                    self.rule.operator.operand = Config.OPERAND_SOURCE_NETWORK
                    self.rule.operator.type = Config.RULE_TYPE_NETWORK

                if utils.is_regex(self, srcIPtext):
                    self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                    self.rule.operator.type = Config.RULE_TYPE_REGEXP
                    if utils.is_valid_regex(self, self.srcIPCombo.currentText()) is False:
                        return False, QC.translate("rules", "Source IP regexp error")

                elif "," in srcIPtext:
                    ok, result = utils.comma_to_regexp(self, srcIPtext, str)
                    if ok:
                        self.rule.operator.operand = Config.OPERAND_SOURCE_IP
                        self.rule.operator.type = Config.RULE_TYPE_REGEXP
                        srcIPtext = result
                    else:
                        return False, result

            rule_data.append(
                rules.new_operator(
                    self.rule.operator.type,
                    self.rule.operator.operand,
                    srcIPtext,
                    self.sensitiveCheck.isChecked()
                )
            )

        if self.dstIPCheck.isChecked():
            if self.dstIPCombo.currentText() == "":
                return False, QC.translate("rules", "Dest IP/Network can not be empty")

            dstIPtext = self.dstIPCombo.currentText()

            if dstIPtext in NetworkAliases.get_alias_all():
                self.rule.operator.type = Config.RULE_TYPE_NETWORK
                self.rule.operator.operand = Config.OPERAND_DEST_NETWORK
                self.rule.operator.data = dstIPtext
            else:
                if dstIPtext == constants.LAN_LABEL:
                    self.rule.operator.operand = Config.OPERAND_DEST_IP
                    self.rule.operator.type = Config.RULE_TYPE_REGEXP
                    dstIPtext = constants.LAN_RANGES
                elif dstIPtext == constants.MULTICAST_LABEL:
                    self.rule.operator.operand = Config.OPERAND_DEST_IP
                    self.rule.operator.type = Config.RULE_TYPE_REGEXP
                    dstIPtext = constants.MULTICAST_RANGE
                else:
                    try:
                        if type(ipaddress.ip_address(self.dstIPCombo.currentText())) == ipaddress.IPv4Address \
                        or type(ipaddress.ip_address(self.dstIPCombo.currentText())) == ipaddress.IPv6Address:
                            self.rule.operator.operand = Config.OPERAND_DEST_IP
                            self.rule.operator.type = Config.RULE_TYPE_SIMPLE
                    except Exception:
                        self.rule.operator.operand = Config.OPERAND_DEST_NETWORK
                        self.rule.operator.type = Config.RULE_TYPE_NETWORK

                    if utils.is_regex(self, dstIPtext):
                        self.rule.operator.operand = Config.OPERAND_DEST_IP
                        self.rule.operator.type = Config.RULE_TYPE_REGEXP
                        if utils.is_valid_regex(self, self.dstIPCombo.currentText()) is False:
                            return False, QC.translate("rules", "Dst IP regexp error")
                    elif "," in dstIPtext:
                        ok, result = utils.comma_to_regexp(self, dstIPtext, str)
                        if ok:
                            self.rule.operator.operand = Config.OPERAND_DEST_IP
                            self.rule.operator.type = Config.RULE_TYPE_REGEXP
                            dstIPtext = result
                        else:
                            return False, result

            rule_data.append(
                rules.new_operator(
                    self.rule.operator.type,
                    self.rule.operator.operand,
                    dstIPtext,
                    self.sensitiveCheck.isChecked()
                )
            )

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
                    uid = str(pwd.getpwnam(uidtmp[0])[constants.PW_UID])
            except:
                # if it's not a digit and nor a system user (user (id)), see if
                # it's a regexp.
                if utils.is_regex(self, self.uidCombo.currentText()):
                    uidType = Config.RULE_TYPE_REGEXP
                    if utils.is_valid_regex(self, self.uidCombo.currentText()) is False:
                        return False, QC.translate("rules", "User ID regexp error")

                else:
                    return False, QC.translate("rules", "Invalid UID, it must be a digit.")

            self.rule.operator.operand = Config.OPERAND_USER_ID
            self.rule.operator.data = self.uidCombo.currentText()
            rule_data.append(
                rules.new_operator(
                    uidType,
                    Config.OPERAND_USER_ID,
                    uid,
                    self.sensitiveCheck.isChecked()
                )
            )

        if self.pidCheck.isChecked():
            if self.pidLine.text() == "":
                return False, QC.translate("rules", "PID field can not be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_ID
            self.rule.operator.data = self.pidLine.text()
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_SIMPLE,
                    Config.OPERAND_PROCESS_ID,
                    self.pidLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            if utils.is_regex(self, self.pidLine.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.pidLine.text()) is False:
                    return False, QC.translate("rules", "PID field regexp error")

        if self.dstListsCheck.isChecked():
            error = utils.is_valid_list_path(self, self.dstListsLine)
            if error:
                return False, error

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_DOMAINS
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_LISTS,
                    Config.OPERAND_LIST_DOMAINS,
                    self.dstListsLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            self.rule.operator.data = ""

        if self.dstListRegexpCheck.isChecked():
            error = utils.is_valid_list_path(self, self.dstRegexpListsLine)
            if error:
                return False, error

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_DOMAINS_REGEXP
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_LISTS,
                    Config.OPERAND_LIST_DOMAINS_REGEXP,
                    self.dstRegexpListsLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            self.rule.operator.data = ""

        if self.dstListNetsCheck.isChecked():
            error = utils.is_valid_list_path(self, self.dstListNetsLine)
            if error:
                return False, error

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_NETS
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_LISTS,
                    Config.OPERAND_LIST_NETS,
                    self.dstListNetsLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            self.rule.operator.data = ""


        if self.dstListIPsCheck.isChecked():
            error = utils.is_valid_list_path(self, self.dstListIPsLine)
            if error:
                return False, error

            self.rule.operator.type = Config.RULE_TYPE_LISTS
            self.rule.operator.operand = Config.OPERAND_LIST_IPS
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_LISTS,
                    Config.OPERAND_LIST_IPS,
                    self.dstListIPsLine.text(),
                    self.sensitiveCheck.isChecked()
                )
            )
            self.rule.operator.data = ""

        if self.md5Check.isChecked():
            if self.md5Line.text() == "":
                return False, QC.translate("rules", "md5 line cannot be empty")

            self.rule.operator.operand = Config.OPERAND_PROCESS_HASH_MD5
            self.rule.operator.data = self.md5Line.text().lower()
            rule_data.append(
                rules.new_operator(
                    Config.RULE_TYPE_SIMPLE,
                    Config.OPERAND_PROCESS_HASH_MD5,
                    self.md5Line.text().lower(),
                    False
                )
            )
            if utils.is_regex(self, self.md5Line.text()):
                rule_data[len(rule_data)-1]['type'] = Config.RULE_TYPE_REGEXP
                if utils.is_valid_regex(self, self.pidLine.text()) is False:
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

        elif len(rule_data) == 1:
            self.rule.operator.operand = rule_data[0]['operand']
            self.rule.operator.data = rule_data[0]['data']
            if self.checkProcRegexp.isChecked():
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
            elif self.checkCmdlineRegexp.isChecked():
                self.rule.operator.type = Config.RULE_TYPE_REGEXP
            elif (self.procCheck.isChecked() is False and self.cmdlineCheck.isChecked() is False) \
                        and utils.is_regex(self, self.rule.operator.data):
                    self.rule.operator.type = Config.RULE_TYPE_REGEXP

        else:
            return False, QC.translate("rules", "Select at least one field.")

        if self.ruleNameEdit.text() == "":
            self.rule.name = slugify("%s %s %s" % (self.rule.action, self.rule.operator.type, self.rule.operator.data))

        return True, ""
