import sys
import time
import os
import os.path
import json

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.utils import Icons, Message
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

        self.secHighIcon = Icons.new(self, "security-high")
        self.secMediumIcon = Icons.new(self, "security-medium")
        self.secLowIcon = Icons.new(self, "security-low")
        self.lblStatusIcon.setPixmap(self.secHighIcon.pixmap(96, 96))

        self._fwrule_dialog = FwRuleDialog(appicon=self.appicon)
        self._cfg = Config.get()
        self._fw = Fw.Firewall.instance()
        self._nodes = Nodes.instance()
        self._fw_profiles = {}
        self._last_profile = {
            self.COMBO_IN: FwProfiles.ProfileAcceptInput.value,
            self.COMBO_OUT: FwProfiles.ProfileAcceptInput.value
        }

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
        self.cmdHelp.clicked.connect(
            lambda: QtGui.QDesktopServices.openUrl(QtCore.QUrl(Config.HELP_SYSFW_URL))
        )

        # TODO: when output policy is set to Drop, all outbound traffic is
        # blocked.
        #self.comboOutput.currentIndexChanged.connect(lambda: self._cb_combo_policy_changed(self.COMBO_OUT))

        if QtGui.QIcon.hasThemeIcon("document-new"):
            return

        closeIcon = Icons.new(self, "window-close")
        excludeIcon = Icons.new(self, "go-up")
        allowInIcon = Icons.new(self, "go-down")
        newIcon = Icons.new(self, "document-new")
        helpIcon = Icons.new(self, "help-browser")
        self.cmdClose.setIcon(closeIcon)
        self.cmdAllowOUTService.setIcon(excludeIcon)
        self.cmdAllowINService.setIcon(allowInIcon)
        self.cmdNewRule.setIcon(newIcon)
        self.cmdHelp.setIcon(helpIcon)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        self.comboInput.setEnabled(True)
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
        self._reset_status_message()
        self.comboInput.setEnabled(False)

        wantedProfile = FwProfiles.ProfileAcceptInput.value
        if combo == self.COMBO_OUT:
            wantedProfile = FwProfiles.ProfileAcceptOutput.value
            if self.comboOutput.currentIndex() == self.POLICY_DROP:
                wantedProfile = FwProfiles.ProfileDropOutput.value
        else:
            if self.comboInput.currentIndex() == self.POLICY_DROP:
                wantedProfile = FwProfiles.ProfileDropInput.value


        if combo == self.COMBO_IN and \
                self.comboInput.currentIndex() == self.POLICY_ACCEPT:
            json_profile = json.dumps(FwProfiles.ProfileDropInput.value)
            for addr in self._nodes.get():
                fwcfg = self._nodes.get_node(addr)['firewall']
                ok, err = self._fw.delete_profile(addr, json_profile)
                if not ok:
                    print(err)


        json_profile = json.dumps(wantedProfile)
        for addr in self._nodes.get():
            fwcfg = self._nodes.get_node(addr)['firewall']
            ok, err = self._fw.apply_profile(addr, json_profile)
            if ok:
                self.send_notification(addr, fwcfg)
            else:
                self._set_status_error(QC.translate("firewall", "Policy not applied: {0}".format(err)))

        self._last_profile[combo] = wantedProfile

    def _cb_new_rule_clicked(self):
        self.new_rule()

    def _cb_allow_out_service_clicked(self):
        self.allow_out_service()

    def _cb_allow_in_service_clicked(self):
        self.allow_in_service()

    def _cb_enable_fw_changed(self, enable):
        if self._nodes.count() == 0:
            self.sliderFwEnable.blockSignals(True)
            self.sliderFwEnable.setValue(False)
            self.sliderFwEnable.blockSignals(False)
            return
        self.enable_fw(enable)

    def _cb_close_clicked(self):
        self._close()

    def _load_nodes(self):
        self._nodes = self._nodes.get()

    def _close(self):
        self.hide()

    def _change_fw_backend(self, addr, node_cfg):
        nid, notif = self._nodes.change_node_config(addr, node_cfg, self._notification_callback)
        self._notifications_sent[nid] = notif

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

        try:
            enableFw = False
            if self._nodes.count() == 0:
                return

            # TODO: handle nodes' firewall properly
            for addr in self._nodes.get():
                node = self._nodes.get_node(addr)
                self._fwConfig = node['firewall']
                enableFw |= self._fwConfig.Enabled

                if self.fw_is_incompatible(addr, node):
                    enableFw = False
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

        except Exception as e:
            self._set_status_error("Firewall status error (report on github please): {0}".format(e))

        finally:
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

    def fw_is_incompatible(self, addr, node):
        """Check if the fw is compatible with this GUI.
        If it's incompatible, disable the option to enable it.
        """
        incompatible = False
        # firewall iptables is not supported from the GUI.
        # display a warning
        node_cfg = json.loads(node['data'].config)
        if node_cfg['Firewall'] == "iptables":
            self._disable_widgets()
            self.sliderFwEnable.setEnabled(False)
            if self.isHidden() == False and self.change_fw(addr, node_cfg):
                    node_cfg['Firewall'] = "nftables"
                    self.sliderFwEnable.setEnabled(True)
                    self.enable_fw(True)
                    self._change_fw_backend(addr, node_cfg)
                    return False
            incompatible = True

        if node['data'].systemFirewall.Version == 0:
            self._disable_widgets()
            self.sliderFwEnable.setEnabled(False)
            self.lblFwStatus.setText(
                QC.translate("firewall", "<html>The firewall configuration is outdated,\n"
                            "you need to update it to the new format: <a href=\"{0}\">learn more</a>"
                            "</html>".format(Config.HELP_SYS_RULES_URL)
            ))
            incompatible = True

        return incompatible

    def change_fw(self, addr, node_cfg):
        """Ask the user to change fw iptables to nftables
        """
        ret = Message.yes_no(
            QC.translate("firewall",
                        "In order to configure firewall rules from the GUI, we need to use 'nftables' instead of 'iptables'"
                        ),
            QC.translate("firewall", "Change default firewall to 'nftables' on node {0}?".format(addr)),
            QtWidgets.QMessageBox.Warning)
        if ret != QtWidgets.QMessageBox.Cancel:
            return True

        return False

    def enable_fw(self, enable):
        self._disable_widgets(not enable)
        if enable:
            self._set_status_message(QC.translate("firewall", "Enabling firewall..."))
        else:
            self._set_status_message(QC.translate("firewall", "Disabling firewall..."))

        # if previous input policy was DROP, when disabling the firewall it
        # must be ACCEPT to allow output traffic.
        if not enable and self.comboInput.currentIndex() == self.POLICY_DROP:
            self.comboInput.blockSignals(True)
            self.comboInput.setCurrentIndex(self.POLICY_ACCEPT)
            self.comboInput.blockSignals(False)
            for addr in self._nodes.get():
                json_profile = json.dumps(FwProfiles.ProfileAcceptInput.value)
                ok, err = self._fw.apply_profile(addr, json_profile)
                if not ok:
                    print("[firewall] Error applying INPUT ACCEPT profile: {0}".format(err))

        for addr in self._nodes.get():
            fwcfg = self._nodes.get_node(addr)['firewall']
            fwcfg.Enabled = True if enable else False
            self.send_notification(addr, fwcfg)

        self.lblStatusIcon.setEnabled(enable)
        self.policiesBox.setEnabled(enable)

        time.sleep(0.5)

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
