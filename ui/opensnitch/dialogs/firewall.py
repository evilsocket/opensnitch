import sys
import time
import os
import os.path
import json

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.dialogs.firewall_rule import FwRuleDialog
from opensnitch import ui_pb2
import opensnitch.firewall as Fw


DIALOG_UI_PATH = "%s/../res/firewall.ui" % os.path.dirname(sys.modules[__name__].__file__)
class FirewallDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    LOG_TAG = "[fw dialog]"

    COMBO_IN = 0
    COMBO_OUT = 1

    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    def __init__(self, parent=None, appicon=None, node=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.setWindowIcon(appicon)
        self.appicon = appicon

        self.secHighIcon = QtGui.QIcon.fromTheme("security-high")
        self.secMediumIcon = QtGui.QIcon.fromTheme("security-medium")
        self.secLowIcon = QtGui.QIcon.fromTheme("security-low")
        self.lblStatusIcon.setPixmap( self.secHighIcon.pixmap(96,96) );

        self._fwrule_dialog = FwRuleDialog(appicon=self.appicon)
        self._cfg = Config.get()
        self._fw = Fw.Firewall.instance()
        self._nodes = Nodes.instance()

        self._notification_callback.connect(self._cb_notification_callback)
        self._notifications_sent = {}

        self._nodes.nodesUpdated.connect(self._cb_nodes_updated)
        self.cmdNewRule.clicked.connect(self._cb_new_rule_clicked)
        self.cmdExcludeService.clicked.connect(self._cb_exclude_service_clicked)
        self.comboInput.currentIndexChanged.connect(lambda: self._cb_combo_policy_changed(self.COMBO_IN))
        self.comboOutput.currentIndexChanged.connect(lambda: self._cb_combo_policy_changed(self.COMBO_OUT))
        self.sliderFwEnable.valueChanged.connect(self._cb_enable_fw_changed)
        self.cmdClose.clicked.connect(self._cb_close_clicked)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.OK:
                rep = self._notifications_sent[reply.id]
                self._set_status_successful(QC.translate("firewall", "Configuration applied."))

            else:
                self._set_status_error(QC.translate("firewall", "Error: {0}").format(reply.data))

            del self._notifications_sent[reply.id]
        else:
            print(self.LOG_TAG, "unknown notification:", reply)


    @QtCore.pyqtSlot(int)
    def _cb_nodes_updated(self, total):
        self._check_fw_status()

    # TODO: load json from a file (a set of rules for example) and deserialize
    # it to protobuf: Parse(json.dumps(jobject), FwRule()), requires protobuf
    # >= 3.15
    # we wouldn't need to parse it manually.
    def _cb_combo_policy_changed(self, combo):
        pol_idx = 0
        wantedHook = Fw.Hooks.INPUT.value
        if combo == self.COMBO_OUT:
            wantedHook = Fw.Hooks.OUTPUT.value
            pol_idx = self.comboOutput.currentIndex()
        else:
            pol_idx = self.comboInput.currentIndex()

        wantedPolicy = Fw.Policy.DROP.value
        if pol_idx == 0:
            wantedPolicy = Fw.Policy.ACCEPT.value

        for addr in self._nodes.get():
            pol_changed = False
            fwcfg = self._nodes.get_node(addr)['firewall']
            if self._fw.chains.set_policy(addr, hook=wantedHook, policy=wantedPolicy):
                self.send_notification(addr, fwcfg)
            else:
                print(self.LOG_TAG, "error applying policy:", combo, "index:", idx, "does the chain exist? table filter -> chain input filter")
                self._set_status_message(QC.translate("firewall", "Policy not applied, check the firewall rules."))

    def _cb_new_rule_clicked(self):
        self.new_rule()

    def _cb_exclude_service_clicked(self):
        self.exclude_service()

    def _cb_enable_fw_changed(self, enable):
        if enable:
            self._set_status_message(QC.translate("firewall", "Enabling firewall..."))
        else:
            self._set_status_message(QC.translate("firewall", "Disabling firewall..."))

        for addr in self._nodes.get():
            fwcfg = self._nodes.get_node(addr)['firewall']
            fwcfg.Enabled = True if enable else False
            self.send_notification(addr, fwcfg)

        self.lblStatusIcon.setEnabled(enable)
        self.policiesBox.setEnabled(enable)

        time.sleep(1)

    def _cb_close_clicked(self):
        self._close()

    def _load_nodes(self):
        self._nodes = self._nodes.get()

    def _close(self):
        self.hide()

    def showEvent(self, event):
        super(FirewallDialog, self).showEvent(event)
        self._reset_fields()
        self._check_fw_status()

    def send_notification(self, node_addr, fw_config):
        self._set_status_message(QC.translate("firewall", "Applying changes..."))
        nid, notif = self._nodes.reload_fw(node_addr, fw_config, self._notification_callback)
        self._notifications_sent[nid] = {'addr': node_addr, 'notif': notif}

    def _check_fw_status(self):
        self.lblFwStatus.setText("")
        self.sliderFwEnable.blockSignals(True)
        self.comboInput.blockSignals(True)
        self.comboOutput.blockSignals(True)

        if self._nodes.count() == 0:
            self._disable_widgets()
            return

        # TODO: handle nodes' firewall properly
        enableFw = False
        for addr in self._nodes.get():
            self._fwConfig = self._nodes.get_node(addr)['firewall']
            enableFw |= self._fwConfig.Enabled

            n = self._nodes.get_node(addr)
            j = json.loads(n['data'].config)

            if j['Firewall'] == "iptables":
                self._disable_widgets()
                self.lblFwStatus.setText(
                    QC.translate("firewall",
                                 "OpenSnitch is using 'iptables' as firewall, but it's not configurable from the GUI.\n"
                                "Set 'Firewall' option to 'nftables' in /etc/opensnitchd/default-config.json \n"
                                "if you want to configure firewall rules from the GUI."
                                 ))
                return
            if n['data'].systemFirewall.Version == 0:
                self._disable_widgets()
                self.lblFwStatus.setText(
                    QC.translate("firewall", "<html>The firewall configuration is outdated,\n"
                                 "you need to update it to the new format: <a href=\""+ Config.HELP_SYS_RULES_URL + "\">learn more</a>"
                                 "</html>"
                ))
                return

            # XXX: Here we loop twice over the chains. We could have 1 loop.
            pol_in = self._fw.chains.get_policy(addr, Fw.Hooks.INPUT.value)
            pol_out = self._fw.chains.get_policy(addr, Fw.Hooks.OUTPUT.value)

            if pol_in != None:
                self.comboInput.setCurrentIndex(
                    Fw.Policy.values().index(pol_in)
                )
            else:
                self._set_status_error(QC.translate("firewall", "Error getting INPUT chain policy"))
                self._disable_widgets()
            if pol_out != None:
                self.comboOutput.setCurrentIndex(
                    Fw.Policy.values().index(pol_out)
                )
            else:
                self._set_status_error(QC.translate("firewall", "Error getting OUTPUT chain policy"))
                self._disable_widgets()


        # some nodes may have the firewall disabled whilst other enabled
        #if not enableFw:
        #    self.lblFwStatus(QC.translate("firewall", "Some nodes have the firewall disabled"))

        self._disable_widgets(False)
        self.lblStatusIcon.setEnabled(enableFw)
        self.sliderFwEnable.setValue(enableFw)
        self.sliderFwEnable.blockSignals(False)
        self.comboInput.blockSignals(False)
        self.comboOutput.blockSignals(False)



    def load_rule(self, addr, uuid):
        self._fwrule_dialog.load(addr, uuid)

    def new_rule(self):
        self._fwrule_dialog.new()

    def exclude_service(self):
        self._fwrule_dialog.exclude_service()

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
        self._reset_status_message()

    def _disable_widgets(self, disable=True):
        self.sliderFwEnable.setEnabled(not disable)
        self.comboInput.setEnabled(not disable)
        self.comboOutput.setEnabled(not disable)
        self.cmdNewRule.setEnabled(not disable)
        self.cmdExcludeService.setEnabled(not disable)
