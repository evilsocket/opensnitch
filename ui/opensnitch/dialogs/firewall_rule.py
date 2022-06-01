import sys
import os
import os.path

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.nodes import Nodes
from opensnitch.utils import NetworkServices, QuickHelp, Icons
from opensnitch import ui_pb2
import opensnitch.firewall as Fw
from opensnitch.firewall.utils import Utils as FwUtils


DIALOG_UI_PATH = "%s/../res/firewall_rule.ui" % os.path.dirname(sys.modules[__name__].__file__)
class FwRuleDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    LOG_TAG = "[fw rule dialog]"
    ACTION_IDX_DENY = 0
    ACTION_IDX_ALLOW = 1

    IN = 0
    OUT = 1

    OP_NEW = 0
    OP_SAVE = 1
    OP_DELETE = 2

    FORM_TYPE_SIMPLE = 0
    FORM_TYPE_EXCLUDE_SERVICE = 1
    FORM_TYPE = FORM_TYPE_SIMPLE

    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    def __init__(self, parent=None, appicon=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.setWindowIcon(appicon)
        # Other interesting flags: QtCore.Qt.Tool | QtCore.Qt.BypassWindowManagerHint
        self._fw = Fw.Firewall.instance()
        self._nodes = Nodes.instance()

        self._notification_callback.connect(self._cb_notification_callback)
        self._notifications_sent = {}

        self.uuid = ""
        self.simple_port_idx = None

        self._nodes.nodesUpdated.connect(self._cb_nodes_updated)
        self.cmdClose.clicked.connect(self._cb_close_clicked)
        self.cmdAdd.clicked.connect(self._cb_add_clicked)
        self.cmdSave.clicked.connect(self._cb_save_clicked)
        self.cmdDelete.clicked.connect(self._cb_delete_clicked)
        self.helpButton.clicked.connect(self._cb_help_button_clicked)

        self.net_srv = NetworkServices()
        self.comboPorts.addItems(self.net_srv.to_array())
        self.comboPorts.currentIndexChanged.connect(self._cb_combo_ports_index_changed)

        if QtGui.QIcon.hasThemeIcon("emblem-default"):
            return

        saveIcon = Icons.new("document-save")
        delIcon = Icons.new("edit-delete")
        closeIcon = Icons.new("window-close")
        addIcon = Icons.new("list-add")
        helpIcon = Icons.new("help-browser")
        self.cmdSave.setIcon(saveIcon)
        self.cmdDelete.setIcon(delIcon)
        self.cmdClose.setIcon(closeIcon)
        self.cmdAdd.setIcon(addIcon)
        self.helpButton.setIcon(helpIcon)

    def showEvent(self, event):
        super(FwRuleDialog, self).showEvent(event)
        self._reset_fields()
        self._load_nodes()

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        self._enable_buttons()

        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.OK:
                rep = self._notifications_sent[reply.id]
                if 'operation' in rep and rep['operation'] == self.OP_DELETE:
                    self.tabWidget.setDisabled(True)
                    self._set_status_successful(QC.translate("firewall", "Rule deleted"))
                    self._disable_controls()
                    return

                self._set_status_successful(QC.translate("firewall", "Rule added"))

            else:
                self._set_status_error(QC.translate("firewall", "Error: {0}").format(reply.data))

            del self._notifications_sent[reply.id]

    @QtCore.pyqtSlot(int)
    def _cb_nodes_updated(self, total):
        self.tabWidget.setDisabled(True if total == 0 else False)

    def closeEvent(self, e):
        self._close()

    def _cb_combo_ports_index_changed(self, idx):
        self.simple_port_idx = idx

    def _cb_help_button_clicked(self):
        QuickHelp.show(
            QC.translate("firewall",
                         "You can use ',' or '-' to specify multiple ports or a port range:<br>" \
                         "22 or 22,443 or 50000-60000"
                         )
        )


    def _cb_close_clicked(self):
        self._close()

    def _cb_delete_clicked(self):
        node_addr, node, chain = self.form_to_protobuf()
        if node_addr == None:
            self._set_status_error(QC.translate("firewall", "Invalid rule, review parameters"))
            return

        self._set_status_message(QC.translate("firewall", "Deleting rule, wait"))
        ok, fw_config = self._fw.delete_rule(node_addr, self.uuid)
        if not ok:
            self._set_status_error(QC.translate("firewall", "Error updating rule"))
            return

        self.send_notification(node_addr, node['firewall'], self.OP_DELETE)

    def _cb_save_clicked(self):
        node_addr, node, chain = self.form_to_protobuf()
        if node_addr == None:
            self._set_status_error(QC.translate("firewall", "Invalid rule, review parameters"))
            return

        self._set_status_message(QC.translate("firewall", "Adding rule, wait"))
        ok, err = self._fw.update_rule(node_addr, self.uuid, chain)
        if not ok:
            self._set_status_error(QC.translate("firewall", "Error updating rule: {0}".format(err)))
            return

        self._enable_buttons(False)
        self.send_notification(node_addr, node['firewall'], self.OP_SAVE)

    def _cb_add_clicked(self):
        node_addr, node, chain = self.form_to_protobuf()
        if node_addr == None:
            self._set_status_error(QC.translate("firewall", "Invalid rule, review parameters"))
            return
        ok, err = self._fw.insert_rule(node_addr, chain)
        if not ok:
            self._set_status_error(QC.translate("firewall", "Error adding rule: {0}".format(err)))
            return
        self._set_status_message(QC.translate("firewall", "Adding rule, wait"))
        self._enable_buttons(False)
        self.send_notification(node_addr, node['firewall'], self.OP_NEW)

    def _close(self):
        self.hide()

    def _load_nodes(self):
        self.comboNodes.clear()
        self._node_list = self._nodes.get()
        for addr in self._node_list:
            self.comboNodes.addItem(addr)

        if len(self._node_list) == 0:
            self.tabWidget.setDisabled(True)

    def load(self, addr, uuid):
        self.show()

        self.FORM_TYPE = self.FORM_TYPE_SIMPLE
        self.setWindowTitle(QC.translate("firewall", "Firewall rule"))
        self.cmdDelete.setVisible(True)
        self.cmdSave.setVisible(True)
        self.cmdAdd.setVisible(False)
        self.checkEnable.setVisible(True)
        self.checkEnable.setEnabled(True)
        self.checkEnable.setChecked(True)
        self.comboOperator.setVisible(True)
        self.comboOperator.setCurrentIndex(0)
        self.frameDirection.setVisible(True)
        self.frameAction.setVisible(True)

        self.cmdSave.setVisible(False)
        self.cmdDelete.setVisible(False)
        self.cmdAdd.setVisible(True)


        self.cmdSave.setVisible(True)
        self.cmdAdd.setVisible(False)
        self.cmdDelete.setVisible(True)
        self.show()

        self.uuid = uuid

        node, rule = self._fw.get_rule_by_uuid(uuid)
        # TODO: implement complex rules
        if rule == None or \
                (rule.Hook.lower() != Fw.Hooks.INPUT.value and rule.Hook.lower() != Fw.Hooks.OUTPUT.value):
            hook = "invalid" if rule == None else rule.Hook
            self._set_status_error(QC.translate("firewall", "Rule type ({0}) not supported yet".format(hook)))
            self._disable_controls()
            return
        if len(rule.Rules[0].Expressions) > 1:
            self._set_status_error(QC.translate("firewall", "Complex rules types not supported yet"))
            self._disable_controls()
            return

        self.checkEnable.setChecked(rule.Rules[0].Enabled)
        self.lineDescription.setText(rule.Rules[0].Description)

        # TODO: support complex expressions: tcp dport 22 ip daddr != 127.0.0.1
        isNotSupported = True
        for exp in rule.Rules[0].Expressions:
            if Fw.Utils.isExprPort(exp.Statement.Name):
                try:
                    self.comboPorts.setCurrentIndex(
                        self.net_srv.index_by_port(exp.Statement.Values[0].Value)
                    )
                except:
                    self.comboPorts.setCurrentText(exp.Statement.Values[0].Value)

                op = Fw.Operator.EQUAL.value if exp.Statement.Op == "" else exp.Statement.Op
                self.comboOperator.setCurrentIndex(
                    Fw.Operator.values().index(op)
                )
                isNotSupported = False
                break
        if isNotSupported:
            self._set_status_error(QC.translate("firewall", "Only port rules can be edited for now."))
            self._disable_controls()
            return

        if rule.Hook.lower() == Fw.Hooks.INPUT.value:
            self.comboDirection.setCurrentIndex(0)
        else:
            self.comboDirection.setCurrentIndex(1)
        # TODO: changing the direction of an existed rule needs work, it causes
        # some nasty effects. Disabled for now.
        self.comboDirection.setEnabled(False)

        self.comboVerdict.setCurrentIndex(
            Fw.Verdicts.values().index(
                rule.Rules[0].Target.lower()
            )-1
        )

    def new(self):
        self.show()

        self.FORM_TYPE = self.FORM_TYPE_SIMPLE
        self.setWindowTitle(QC.translate("firewall", "Firewall rule"))
        self.cmdDelete.setVisible(False)
        self.cmdSave.setVisible(False)
        self.cmdAdd.setVisible(True)
        self.checkEnable.setVisible(True)
        self.checkEnable.setEnabled(True)
        self.checkEnable.setChecked(True)
        self.comboOperator.setVisible(True)
        self.comboOperator.setCurrentIndex(0)
        self.frameDirection.setVisible(True)
        self.frameAction.setVisible(True)

        self.cmdSave.setVisible(False)
        self.cmdDelete.setVisible(False)
        self.cmdAdd.setVisible(True)

    def exclude_service(self):
        self.show()

        self.FORM_TYPE = self.FORM_TYPE_EXCLUDE_SERVICE
        self.setWindowTitle(QC.translate("firewall", "Exclude service"))
        self.cmdDelete.setVisible(False)
        self.cmdSave.setVisible(False)
        self.cmdAdd.setVisible(True)
        self.checkEnable.setVisible(False)
        self.checkEnable.setEnabled(True)
        self.comboOperator.setVisible(False)
        self.comboOperator.setCurrentIndex(0)
        self.frameDirection.setVisible(False)
        self.frameAction.setVisible(False)

        self.checkEnable.setChecked(True)

    def form_to_protobuf(self):
        """Transform form widgets to protouf struct
        """
        chain = Fw.ChainFilter.input()

        # output rules must be placed under mangle table and before
        # interception rules. Otherwise we'd intercept them.
        if self.comboDirection.currentIndex() == self.OUT or self.FORM_TYPE == self.FORM_TYPE_EXCLUDE_SERVICE:
            chain = Fw.ChainMangle.output()

        rule = Fw.Rules.new(
            enabled=self.checkEnable.isChecked(),
            _uuid=self.uuid,
            description=self.lineDescription.text(),
            target=Fw.Verdicts.values()[self.comboVerdict.currentIndex()+1] # index 0 is ""
        )

        if self.comboPorts.currentText() != "":
            portValue = "0"
            try:
                if "," in self.comboPorts.currentText() or "-" in self.comboPorts.currentText():
                    raise ValueError("port entered is multiport or a port range")
                if self.simple_port_idx == None:
                    raise ValueError("user didn't select a port from the list")

                portValue = self.net_srv.port_by_index(
                    self.comboPorts.currentIndex()
                )
            except:
                portValue = self.comboPorts.currentText()

            if portValue == "" or portValue == "0":
                return

            # TODO: should we add a TCP/UDP port?
            portValue = portValue.replace(" ", "")
            exprs = Fw.Expr.new(
                Fw.Operator.values()[self.comboOperator.currentIndex()],
                Fw.Statements.TCP.value,
                [(Fw.Statements.DPORT.value, portValue)]
            )
            rule.Expressions.extend([exprs])

        chain.Rules.extend([rule])

        node_addr = self.comboNodes.currentText()
        node = self._nodes.get_node(node_addr)
        return node_addr, node, chain

    def send_notification(self, node_addr, fw_config, op):
        nid, notif = self._nodes.reload_fw(node_addr, fw_config, self._notification_callback)
        self._notifications_sent[nid] = {'addr': node_addr, 'operation': op, 'notif': notif}

    def _set_status_error(self, msg):
        self.statusLabel.show()
        self.statusLabel.setStyleSheet('color: red')
        self.statusLabel.setText(msg)

    def _set_status_successful(self, msg):
        self.statusLabel.show()
        self.statusLabel.setStyleSheet('color: green')
        self.statusLabel.setText(msg)

    def _set_status_message(self, msg):
        self.statusLabel.show()
        self.statusLabel.setStyleSheet('color: darkorange')
        self.statusLabel.setText(msg)

    def _reset_status_message(self):
        self.statusLabel.setText("")
        self.statusLabel.hide()

    def _reset_fields(self):
        self.FORM_TYPE = self.FORM_TYPE_SIMPLE
        self.setWindowTitle(QC.translate("firewall", "Firewall rule"))

        self.cmdDelete.setVisible(False)
        self.cmdSave.setVisible(False)
        self.cmdAdd.setVisible(True)

        self.checkEnable.setVisible(True)
        self.checkEnable.setEnabled(True)
        self.checkEnable.setChecked(True)
        self.comboOperator.setVisible(True)
        self.comboOperator.setCurrentIndex(0)
        self.frameDirection.setVisible(True)
        self.frameAction.setVisible(True)

        self._reset_status_message()
        self._enable_buttons()
        self.tabWidget.setDisabled(False)
        self.lineDescription.setText("")
        self.comboPorts.setCurrentText("")
        self.comboDirection.setCurrentIndex(0)
        self.comboDirection.setEnabled(True)
        self.comboVerdict.setCurrentIndex(0)
        self.uuid = ""

    def _enable_buttons(self, enable=True):
        """Disable add/save buttons until a response is received from the daemon.
        """
        self.cmdSave.setEnabled(enable)
        self.cmdAdd.setEnabled(enable)
        self.cmdDelete.setEnabled(enable)

    def _disable_buttons(self, disabled=True):
        self.cmdSave.setDisabled(disabled)
        self.cmdAdd.setDisabled(disabled)
        self.cmdDelete.setDisabled(disabled)

    def _disable_controls(self):
        self._disable_buttons()
        self.tabWidget.setDisabled(True)
