import sys
import time
import os
import os.path
import json

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.utils import Icons
from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.dialogs.firewall_rule import FwRuleDialog
from opensnitch import ui_pb2
import opensnitch.firewall as Fw
import opensnitch.firewall.profiles as FwProfiles


DIALOG_UI_PATH = "%s/../res/firewall.ui" % os.path.dirname(sys.modules[__name__].__file__)
class FirewallDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    LOG_TAG = "[fw dialog]"

    COMBO_IN = 0
    COMBO_OUT = 1

    POLICY_ACCEPT = 0
    POLICY_DROP = 1

    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    def __init__(self, parent=None, appicon=None, node=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.setWindowIcon(appicon)
        self.appicon = appicon

        # TODO: profiles are ready to be used. They need to be tested, and
        # create some default profiles (home, office, public, ...)
        self.comboProfile.setVisible(False)
        self.lblProfile.setVisible(False)

        self.secHighIcon = Icons.new("security-high")
        self.secMediumIcon = Icons.new("security-medium")
        self.secLowIcon = Icons.new("security-low")
        self.lblStatusIcon.setPixmap(self.secHighIcon.pixmap(96, 96))

        self._fwrule_dialog = FwRuleDialog(appicon=self.appicon)
        self._cfg = Config.get()
        self._fw = Fw.Firewall.instance()
        self._nodes = Nodes.instance()
        self._fw_profiles = {}

        self._notification_callback.connect(self._cb_notification_callback)
        self._notifications_sent = {}

        self._nodes.nodesUpdated.connect(self._cb_nodes_updated)
        self.cmdNewRule.clicked.connect(self._cb_new_rule_clicked)
        self.cmdAllowOUTService.clicked.connect(self._cb_allow_out_service_clicked)
        self.cmdAllowINService.clicked.connect(self._cb_allow_in_service_clicked)
        self.comboInput.currentIndexChanged.connect(lambda: self._cb_combo_policy_changed(self.COMBO_IN))
        self.comboProfile.currentIndexChanged.connect(self._cb_combo_profile_changed)
        self.sliderFwEnable.valueChanged.connect(self._cb_enable_fw_changed)
        self.cmdClose.clicked.connect(self._cb_close_clicked)

        # TODO: when output policy is set to Drop, all outbound traffic is
        # blocked.
        #self.comboOutput.currentIndexChanged.connect(lambda: self._cb_combo_policy_changed(self.COMBO_OUT))

        if QtGui.QIcon.hasThemeIcon("document-new"):
            return

        closeIcon = Icons.new("window-close")
        excludeIcon = Icons.new("go-up")
        allowInIcon = Icons.new("go-down")
        newIcon = Icons.new("document-new")
        self.cmdClose.setIcon(closeIcon)
        self.cmdAllowOUTService.setIcon(excludeIcon)
        self.cmdAllowINService.setIcon(allowInIcon)
        self.cmdNewRule.setIcon(newIcon)

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

    def _cb_combo_profile_changed(self, idx):
        combo_profile = self._fw_profiles[idx]
        json_profile = json.dumps(list(combo_profile.values())[0]['Profile'])

        for addr in self._nodes.get():
            fwcfg = self._nodes.get_node(addr)['firewall']
            ok, err = self._fw.apply_profile(addr, json_profile)
            if ok:
                self.send_notification(addr, fwcfg)
            else:
                self._set_status_error(QC.translate("firewall", "error adding profile extra rules:", err))

    def _cb_combo_policy_changed(self, combo):
        wantedProfile = FwProfiles.ProfileAcceptInput.value
        if combo == self.COMBO_OUT:
            wantedProfile = FwProfiles.ProfileAcceptOutput.value
            if self.comboOutput.currentIndex() == self.POLICY_DROP:
                wantedProfile = FwProfiles.ProfileDropOutput.value
        else:
            if self.comboInput.currentIndex() == self.POLICY_DROP:
                wantedProfile = FwProfiles.ProfileDropInput.value

        for addr in self._nodes.get():
            fwcfg = self._nodes.get_node(addr)['firewall']

            json_profile = json.dumps(wantedProfile)
            ok, err = self._fw.apply_profile(addr, json_profile)
            if ok:
                self.send_notification(addr, fwcfg)
            else:
                self._set_status_error(QC.translate("firewall", "Policy not applied: {0}".format(err)))

    def _cb_new_rule_clicked(self):
        self.new_rule()

    def _cb_allow_out_service_clicked(self):
        self.allow_out_service()

    def _cb_allow_in_service_clicked(self):
        self.allow_in_service()

    def _cb_enable_fw_changed(self, enable):
        self._disable_widgets(not enable)
        if enable:
            self._set_status_message(QC.translate("firewall", "Enabling firewall..."))
        else:
            self._set_status_message(QC.translate("firewall", "Disabling firewall..."))

        # if previous input policy was DROP, when disabling the firewall it
        # must be ACCEPT to allow output traffic.
        if not enable and self.comboInput.currentIndex() == self.POLICY_DROP:
            self.comboInput.setCurrentIndex(self.POLICY_ACCEPT)

        for addr in self._nodes.get():
            fwcfg = self._nodes.get_node(addr)['firewall']
            fwcfg.Enabled = True if enable else False
            self.send_notification(addr, fwcfg)

        self.lblStatusIcon.setEnabled(enable)
        self.policiesBox.setEnabled(enable)

        time.sleep(0.5)

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
        self._fw_profiles = FwProfiles.Profiles.load_predefined_profiles()
        self.comboProfile.blockSignals(True)
        for pr in self._fw_profiles:
            self.comboProfile.addItem([pr[k] for k in pr][0]['Name'])
        self.comboProfile.blockSignals(False)

    def send_notification(self, node_addr, fw_config):
        self._set_status_message(QC.translate("firewall", "Applying changes..."))
        nid, notif = self._nodes.reload_fw(node_addr, fw_config, self._notification_callback)
        self._notifications_sent[nid] = {'addr': node_addr, 'notif': notif}

    def _check_fw_status(self):
        self.lblFwStatus.setText("")
        self.sliderFwEnable.blockSignals(True)
        self.comboInput.blockSignals(True)
        self.comboOutput.blockSignals(True)
        self.comboProfile.blockSignals(True)

        self._disable_widgets()
        if self._nodes.count() == 0:
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
                self.sliderFwEnable.setEnabled(False)
                self.lblFwStatus.setText(
                    QC.translate("firewall",
                                 "OpenSnitch is using 'iptables' as firewall, but it's not configurable from the GUI.\n"
                                "Set 'Firewall' option to 'nftables' in /etc/opensnitchd/default-config.json \n"
                                "if you want to configure firewall rules from the GUI."
                                 ))
                return
            if n['data'].systemFirewall.Version == 0:
                self._disable_widgets()
                self.sliderFwEnable.setEnabled(False)
                self.lblFwStatus.setText(
                    QC.translate("firewall", "<html>The firewall configuration is outdated,\n"
                                 "you need to update it to the new format: <a href=\"{0}\">learn more</a>"
                                 "</html>".format(Config.HELP_SYS_RULES_URL)
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

        self._disable_widgets(not enableFw)
        self.lblStatusIcon.setEnabled(enableFw)
        self.sliderFwEnable.setValue(enableFw)
        self.sliderFwEnable.blockSignals(False)
        self.comboInput.blockSignals(False)
        self.comboOutput.blockSignals(False)
        self.comboProfile.blockSignals(False)

    def load_rule(self, addr, uuid):
        self._fwrule_dialog.load(addr, uuid)

    def new_rule(self):
        self._fwrule_dialog.new()

    def allow_out_service(self):
        self._fwrule_dialog.exclude_service(self.COMBO_OUT)

    def allow_in_service(self):
        self._fwrule_dialog.exclude_service(self.COMBO_IN)

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
        self.comboInput.setEnabled(not disable)
        #self.comboOutput.setEnabled(not disable)
        self.cmdNewRule.setEnabled(not disable)
        self.cmdAllowOUTService.setEnabled(not disable)
        self.cmdAllowINService.setEnabled(not disable)
