import sys
import time
import os
import json

from PyQt5 import QtCore, QtGui, uic, QtWidgets

from config import Config
from nodes import Nodes

import ui_pb2

DIALOG_UI_PATH = "%s/../res/preferences.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PreferencesDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    CFG_DISABLE_POPUPS   = "global/disable_popups"

    LOG_TAG = "[Preferences] "
    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self._cfg = Config.get()
        self._nodes = Nodes.instance()

        self._notification_callback.connect(self._cb_notification_callback)
        self._notifications_sent = {}

        self.setupUi(self)

        self.acceptButton.clicked.connect(self._cb_accept_button_clicked)
        self.applyButton.clicked.connect(self._cb_apply_button_clicked)
        self.cancelButton.clicked.connect(self._cb_cancel_button_clicked)
        self.popupsCheck.clicked.connect(self._cb_popups_check_toggled)

        if QtGui.QIcon.hasThemeIcon("emblem-default") == False:
            self.applyButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogApplyButton")))
            self.cancelButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogCloseButton")))
            self.acceptButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogSaveButton")))

    def showEvent(self, event):
        super(PreferencesDialog, self).showEvent(event)

        try:
            self._reset_status_message()
            self._hide_status_label()
            self.comboNodes.clear()

            self._node_list = self._nodes.get()
            for addr in self._node_list:
                self.comboNodes.addItem(addr)

            if len(self._node_list) == 0:
                self._reset_node_settings()
        except Exception as e:
            print(self.LOG_TAG + "exception loading nodes", e)

        self._load_settings()

        # connect the signals after loading settings, to avoid firing
        # the signals
        self.comboNodes.currentIndexChanged.connect(self._cb_node_combo_changed)
        self.comboNodeAction.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeDuration.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeMonitorMethod.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeLogLevel.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeLogFile.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeAddress.currentIndexChanged.connect(self._cb_node_needs_update)
        self.checkInterceptUnknown.clicked.connect(self._cb_node_needs_update)
        self.checkApplyToNodes.clicked.connect(self._cb_node_needs_update)

        # True when any node option changes
        self._node_needs_update = False

    def _load_settings(self):
        self._default_action = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)
        self._default_target = self._cfg.getSettings(self._cfg.DEFAULT_TARGET_KEY)
        self._default_timeout = self._cfg.getSettings(self._cfg.DEFAULT_TIMEOUT_KEY)
        self._disable_popups = self._cfg.getBool(self.CFG_DISABLE_POPUPS)

        if self._cfg.hasKey(self._cfg.DEFAULT_DURATION_KEY):
            self._default_duration = self._cfg.getInt(self._cfg.DEFAULT_DURATION_KEY)
        else:
            self._default_duration = self._cfg.DEFAULT_DURATION_IDX

        self.comboUIDuration.setCurrentIndex(self._default_duration)

        self.comboUIAction.setCurrentIndex(self._default_action)
        self.comboUITarget.setCurrentIndex(int(self._default_target))
        self.spinUITimeout.setValue(int(self._default_timeout))
        self.spinUITimeout.setEnabled(not self._disable_popups)
        self.popupsCheck.setChecked(self._disable_popups)

        self._load_node_settings()

    def _load_node_settings(self):
        addr = self.comboNodes.currentText()
        if addr != "":
            try:
                node_data = self._node_list[addr]['data']
                self.labelNodeVersion.setText(node_data.version)
                self.labelNodeName.setText(node_data.name)
                self.comboNodeLogLevel.setCurrentIndex(node_data.logLevel)

                node_config = json.loads(node_data.config)
                self.comboNodeAction.setCurrentText(node_config['DefaultAction'])
                self.comboNodeDuration.setCurrentText(node_config['DefaultDuration'])
                self.comboNodeMonitorMethod.setCurrentText(node_config['ProcMonitorMethod'])
                self.checkInterceptUnknown.setChecked(node_config['InterceptUnknown'])
                self.comboNodeLogLevel.setCurrentIndex(int(node_config['LogLevel']))

                if node_config.get('Server') != None:
                    self.comboNodeAddress.setEnabled(True)
                    self.comboNodeLogFile.setEnabled(True)

                    self.comboNodeAddress.setCurrentText(node_config['Server']['Address'])
                    self.comboNodeLogFile.setCurrentText(node_config['Server']['LogFile'])
                else:
                    self.comboNodeAddress.setEnabled(False)
                    self.comboNodeLogFile.setEnabled(False)
            except Exception as e:
                print(self.LOG_TAG + "exception loading config: ", e)

    def _reset_node_settings(self):
        self.comboNodeAction.setCurrentIndex(0)
        self.comboNodeDuration.setCurrentIndex(0)
        self.comboNodeMonitorMethod.setCurrentIndex(0)
        self.checkInterceptUnknown.setChecked(False)
        self.comboNodeLogLevel.setCurrentIndex(0)
        self.labelNodeName.setText("")
        self.labelNodeVersion.setText("")

    def _save_settings(self):
        if self.tabWidget.currentIndex() == 0:
            self._cfg.setSettings(self._cfg.DEFAULT_ACTION_KEY, self.comboUIAction.currentIndex())
            self._cfg.setSettings(self._cfg.DEFAULT_DURATION_KEY, int(self.comboUIDuration.currentIndex()))
            self._cfg.setSettings(self._cfg.DEFAULT_TARGET_KEY, self.comboUITarget.currentIndex())
            self._cfg.setSettings(self._cfg.DEFAULT_TIMEOUT_KEY, self.spinUITimeout.value())
            self._cfg.setSettings(self.CFG_DISABLE_POPUPS, bool(self.popupsCheck.isChecked()))
            # this is a workaround for not display pop-ups.
            # see #79 for more information.
            if self.popupsCheck.isChecked():
                self._cfg.setSettings(self._cfg.DEFAULT_TIMEOUT_KEY, 0)

        elif self.tabWidget.currentIndex() == 1:
            self._show_status_label()

            addr = self.comboNodes.currentText()
            if (self._node_needs_update or self.checkApplyToNodes.isChecked()) and addr != "":
                try:
                    notif = ui_pb2.Notification(
                            id=int(str(time.time()).replace(".", "")),
                            type=ui_pb2.CHANGE_CONFIG,
                            data="",
                            rules=[])
                    if self.checkApplyToNodes.isChecked():
                        for addr in self._nodes.get_nodes():
                            error = self._save_node_config(notif, addr)
                            if error != None:
                                self._set_status_error(error)
                                return
                    else:
                        error = self._save_node_config(notif, addr)
                        if error != None:
                            self._set_status_error(error)
                            return
                except Exception as e:
                    print(self.LOG_TAG + "exception saving config: ", e)
                    self._set_status_error(QtCore.QCoreApplication.translate("preferences", "Exception saving config: {0}").format(str(e)))

            self._node_needs_update = False

    def _save_node_config(self, notifObject, addr):
        try:
            self._set_status_message(QtCore.QCoreApplication.translate("preferences", "Applying configuration on {0} ...").format(addr))
            notifObject.data, error = self._load_node_config(addr)
            if error != None:
                return error

            self._nodes.save_node_config(addr, notifObject.data)
            nid = self._nodes.send_notification(addr, notifObject, self._notification_callback)

            self._notifications_sent[nid] = notifObject
        except Exception as e:
            print(self.LOG_TAG + "exception saving node config on %s: " % addr, e)
            self._set_status_error(QtCore.QCoreApplication.translate("Exception saving node config {0}: {1}").format((addr, str(e))))
            return addr + ": " + str(e)

        return None

    def _load_node_config(self, addr):
        try:
            if self.comboNodeAddress.currentText() == "":
                return None, QtCore.QCoreApplication.translate("preferences", "Server address can not be empty")

            node_action = Config.ACTION_DENY
            if self.comboNodeAction.currentIndex() == 1:
                node_action = Config.ACTION_ALLOW

            node_duration = Config.DURATION_ONCE
            if self.comboNodeDuration.currentIndex() == 1:
                node_duration = Config.DURATION_UNTIL_RESTART
            elif self.comboNodeDuration.currentIndex() == 2:
                node_duration = Config.DURATION_ALWAYS

            node_config = json.loads(self._nodes.get_node_config(addr))
            node_config['DefaultAction'] = node_action
            node_config['DefaultDuration'] = node_duration
            node_config['ProcMonitorMethod'] = self.comboNodeMonitorMethod.currentText()
            node_config['LogLevel'] = self.comboNodeLogLevel.currentIndex()
            node_config['InterceptUnknown'] = self.checkInterceptUnknown.isChecked()

            if node_config.get('Server') != None:
                # skip setting Server Address if we're applying the config to all nodes
                if self.checkApplyToNodes.isChecked():
                    print("skipping server address")
                    node_config['Server']['Address'] = self.comboNodeAddress.currentText()
                node_config['Server']['LogFile'] = self.comboNodeLogFile.currentText()
            #else:
            #    print(addr, " doesn't have Server item")
            return json.dumps(node_config), None
        except Exception as e:
            print(self.LOG_TAG + "exception loading node config on %s: " % addr, e)

        return None, QtCore.QCoreApplication.translate("preferences", "Error loading {0} configuration").format(addr)

    def _hide_status_label(self):
        self.statusLabel.hide()

    def _show_status_label(self):
        self.statusLabel.show()

    def _set_status_error(self, msg):
        self.statusLabel.setStyleSheet('color: red')
        self.statusLabel.setText(msg)

    def _set_status_successful(self, msg):
        self.statusLabel.setStyleSheet('color: green')
        self.statusLabel.setText(msg)

    def _set_status_message(self, msg):
        self.statusLabel.setStyleSheet('color: darkorange')
        self.statusLabel.setText(msg)

    def _reset_status_message(self):
        self.statusLabel.setText("")

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        #print(self.LOG_TAG, "Config notification received: ", reply.id, reply.code)
        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.OK:
                self._set_status_successful(QtCore.QCoreApplication.translate("preferences", "Configuration applied."))
            else:
                self._set_status_error(QtCore.QCoreApplication.translate("preferences", "Error applying configuration: {0}").format(reply.data))

            del self._notifications_sent[reply.id]

    def _cb_accept_button_clicked(self):
        self._save_settings()
        self.accept()

    def _cb_apply_button_clicked(self):
        self._save_settings()

    def _cb_cancel_button_clicked(self):
        self.reject()

    def _cb_popups_check_toggled(self, checked):
        self.spinUITimeout.setEnabled(not checked)
        if not checked:
            self.spinUITimeout.setValue(15)

    def _cb_node_combo_changed(self, index):
        self._load_node_settings()

    def _cb_node_needs_update(self):
        self._node_needs_update = True
