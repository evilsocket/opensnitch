import sys
import time
import os
import json

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.database import Database
from opensnitch.utils import Message

from opensnitch import ui_pb2

DIALOG_UI_PATH = "%s/../res/preferences.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PreferencesDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    LOG_TAG = "[Preferences] "
    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    TAB_POPUPS = 0
    TAB_UI = 1
    TAB_NODES = 2
    TAB_DB = 3

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self._cfg = Config.get()
        self._nodes = Nodes.instance()
        self._db = Database.instance()

        self._notification_callback.connect(self._cb_notification_callback)
        self._notifications_sent = {}

        self.setupUi(self)

        self.dbFileButton.setVisible(False)
        self.dbLabel.setVisible(False)
        self.dbType = None

        self.acceptButton.clicked.connect(self._cb_accept_button_clicked)
        self.applyButton.clicked.connect(self._cb_apply_button_clicked)
        self.cancelButton.clicked.connect(self._cb_cancel_button_clicked)
        self.helpButton.clicked.connect(self._cb_help_button_clicked)
        self.popupsCheck.clicked.connect(self._cb_popups_check_toggled)
        self.dbFileButton.clicked.connect(self._cb_file_db_clicked)
        self.checkUIRules.toggled.connect(self._cb_check_ui_rules_toggled)
        self.helpButton.setToolTipDuration(10 * 1000)

        if QtGui.QIcon.hasThemeIcon("emblem-default") == False:
            self.applyButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogApplyButton")))
            self.cancelButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogCloseButton")))
            self.acceptButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogSaveButton")))
            self.dbFileButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DirOpenIcon")))

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
        self.comboNodeAddress.currentTextChanged.connect(self._cb_node_needs_update)
        self.checkInterceptUnknown.clicked.connect(self._cb_node_needs_update)
        self.checkApplyToNodes.clicked.connect(self._cb_node_needs_update)
        self.comboDBType.currentIndexChanged.connect(self._cb_db_type_changed)

        # True when any node option changes
        self._node_needs_update = False

    def _load_settings(self):
        self._default_action = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)
        self._default_target = self._cfg.getSettings(self._cfg.DEFAULT_TARGET_KEY)
        self._default_timeout = self._cfg.getSettings(self._cfg.DEFAULT_TIMEOUT_KEY)
        self._disable_popups = self._cfg.getBool(self._cfg.DEFAULT_DISABLE_POPUPS)

        if self._cfg.hasKey(self._cfg.DEFAULT_DURATION_KEY):
            self._default_duration = self._cfg.getInt(self._cfg.DEFAULT_DURATION_KEY)
        else:
            self._default_duration = self._cfg.DEFAULT_DURATION_IDX

        self.comboUIDuration.setCurrentIndex(self._default_duration)
        self.comboUIDialogPos.setCurrentIndex(self._cfg.getInt(self._cfg.DEFAULT_POPUP_POSITION))

        self.comboUIRules.setCurrentIndex(self._cfg.getInt(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES))
        self.checkUIRules.setChecked(self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES))
        self.comboUIRules.setEnabled(self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES))
        #self._set_rules_duration_filter()

        self._cfg.setRulesDurationFilter(
            self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES),
            self._cfg.getInt(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES)
        )

        self.comboUIAction.setCurrentIndex(self._default_action)
        self.comboUITarget.setCurrentIndex(int(self._default_target))
        self.spinUITimeout.setValue(int(self._default_timeout))
        self.spinUITimeout.setEnabled(not self._disable_popups)
        self.popupsCheck.setChecked(self._disable_popups)

        self.showAdvancedCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED))
        self.dstIPCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_DSTIP))
        self.dstPortCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_DSTPORT))
        self.uidCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_UID))

        self.dbType = self._cfg.getInt(self._cfg.DEFAULT_DB_TYPE_KEY)
        self.comboDBType.setCurrentIndex(self.dbType)
        if self.comboDBType.currentIndex() != Database.DB_TYPE_MEMORY:
            self.dbFileButton.setVisible(True)
            self.dbLabel.setVisible(True)
            self.dbLabel.setText(self._cfg.getSettings(self._cfg.DEFAULT_DB_FILE_KEY))

        self._load_node_settings()
        self._load_ui_columns_config()

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

    def _load_node_config(self, addr):
        try:
            if self.comboNodeAddress.currentText() == "":
                return None, QC.translate("preferences", "Server address can not be empty")

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
                    node_config['Server']['Address'] = self.comboNodeAddress.currentText()
                node_config['Server']['LogFile'] = self.comboNodeLogFile.currentText()
            else:
                print(addr, " doesn't have Server item")
            return json.dumps(node_config, indent="    "), None
        except Exception as e:
            print(self.LOG_TAG + "exception loading node config on %s: " % addr, e)

        return None, QC.translate("preferences", "Error loading {0} configuration").format(addr)

    def _load_ui_columns_config(self):
        cols = self._cfg.getSettings(Config.STATS_SHOW_COLUMNS)
        if cols == None:
            return

        for c in range(7):
            checked = str(c) in cols
            if c == 0:
                self.checkHideTime.setChecked(checked)
            elif c == 1:
                self.checkHideNode.setChecked(checked)
            elif c == 2:
                self.checkHideAction.setChecked(checked)
            elif c == 3:
                self.checkHideDst.setChecked(checked)
            elif c == 4:
                self.checkHideProto.setChecked(checked)
            elif c == 5:
                self.checkHideProc.setChecked(checked)
            elif c == 6:
                self.checkHideRule.setChecked(checked)

    def _reset_node_settings(self):
        self.comboNodeAction.setCurrentIndex(0)
        self.comboNodeDuration.setCurrentIndex(0)
        self.comboNodeMonitorMethod.setCurrentIndex(0)
        self.checkInterceptUnknown.setChecked(False)
        self.comboNodeLogLevel.setCurrentIndex(0)
        self.labelNodeName.setText("")
        self.labelNodeVersion.setText("")

    def _save_settings(self):
        self._save_ui_config()
        self._save_db_config()

        if self.tabWidget.currentIndex() == self.TAB_NODES:
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
                    self._set_status_error(QC.translate("preferences", "Exception saving config: {0}").format(str(e)))

            self._node_needs_update = False


    def _save_db_config(self):
        dbtype = self.comboDBType.currentIndex()
        self._cfg.setSettings(Config.DEFAULT_DB_TYPE_KEY, dbtype)

        if self.comboDBType.currentIndex() == self.dbType:
            return

        if dbtype == self._db.get_db_file():
            return

        if self.comboDBType.currentIndex() != Database.DB_TYPE_MEMORY:
            if self.dbLabel.text() != "":
                self._cfg.setSettings(Config.DEFAULT_DB_FILE_KEY, self.dbLabel.text())
            else:
                Message.ok(
                    QC.translate("preferences", "Warning"),
                    QC.translate("preferences", "You must select a file for the database<br>or choose \"In memory\" type."),
                    QtWidgets.QMessageBox.Warning)
                return

        Message.ok(
            QC.translate("preferences", "DB type changed"),
            QC.translate("preferences", "Restart the GUI in order effects to take effect"),
            QtWidgets.QMessageBox.Warning)

        self.dbType = self.comboDBType.currentIndex()

    def _save_ui_config(self):
        self._save_ui_columns_config()

        self._cfg.setSettings(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES, int(self.comboUIRules.currentIndex()))
        self._cfg.setSettings(self._cfg.DEFAULT_IGNORE_RULES, bool(self.checkUIRules.isChecked()))
        #self._set_rules_duration_filter()
        self._cfg.setRulesDurationFilter(
            bool(self.checkUIRules.isChecked()),
            int(self.comboUIRules.currentIndex())
        )

        self._cfg.setSettings(self._cfg.DEFAULT_ACTION_KEY, self.comboUIAction.currentIndex())
        self._cfg.setSettings(self._cfg.DEFAULT_DURATION_KEY, int(self.comboUIDuration.currentIndex()))
        self._cfg.setSettings(self._cfg.DEFAULT_TARGET_KEY, self.comboUITarget.currentIndex())
        self._cfg.setSettings(self._cfg.DEFAULT_TIMEOUT_KEY, self.spinUITimeout.value())
        self._cfg.setSettings(self._cfg.DEFAULT_DISABLE_POPUPS, bool(self.popupsCheck.isChecked()))
        self._cfg.setSettings(self._cfg.DEFAULT_POPUP_POSITION, int(self.comboUIDialogPos.currentIndex()))

        self._cfg.setSettings(self._cfg.DEFAULT_POPUP_ADVANCED, bool(self.showAdvancedCheck.isChecked()))
        self._cfg.setSettings(self._cfg.DEFAULT_POPUP_ADVANCED_DSTIP, bool(self.dstIPCheck.isChecked()))
        self._cfg.setSettings(self._cfg.DEFAULT_POPUP_ADVANCED_DSTPORT, bool(self.dstPortCheck.isChecked()))
        self._cfg.setSettings(self._cfg.DEFAULT_POPUP_ADVANCED_UID, bool(self.uidCheck.isChecked()))
        # this is a workaround for not display pop-ups.
        # see #79 for more information.
        if self.popupsCheck.isChecked():
            self._cfg.setSettings(self._cfg.DEFAULT_TIMEOUT_KEY, 0)

    def _save_ui_columns_config(self):
        cols=list()
        if self.checkHideTime.isChecked():
            cols.append("0")
        if self.checkHideNode.isChecked():
            cols.append("1")
        if self.checkHideAction.isChecked():
            cols.append("2")
        if self.checkHideDst.isChecked():
            cols.append("3")
        if self.checkHideProto.isChecked():
            cols.append("4")
        if self.checkHideProc.isChecked():
            cols.append("5")
        if self.checkHideRule.isChecked():
            cols.append("6")

        self._cfg.setSettings(Config.STATS_SHOW_COLUMNS, cols)

    def _save_node_config(self, notifObject, addr):
        try:
            self._set_status_message(QC.translate("preferences", "Applying configuration on {0} ...").format(addr))
            notifObject.data, error = self._load_node_config(addr)
            if error != None:
                return error

            if addr.startswith("unix://"):
                self._cfg.setSettings(self._cfg.DEFAULT_DEFAULT_SERVER_ADDR, self.comboNodeAddress.currentText())
            else:
                self._nodes.save_node_config(addr, notifObject.data)
                nid = self._nodes.send_notification(addr, notifObject, self._notification_callback)

                self._notifications_sent[nid] = notifObject
        except Exception as e:
            print(self.LOG_TAG + "exception saving node config on %s: " % addr, e)
            self._set_status_error(QC.translate("Exception saving node config {0}: {1}").format((addr, str(e))))
            return addr + ": " + str(e)

        return None

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
                self._set_status_successful(QC.translate("preferences", "Configuration applied."))
            else:
                self._set_status_error(QC.translate("preferences", "Error applying configuration: {0}").format(reply.data))

            del self._notifications_sent[reply.id]

    def _cb_file_db_clicked(self):
        options = QtWidgets.QFileDialog.Options()
        fileName, _ = QtWidgets.QFileDialog.getSaveFileName(self, "", "","All Files (*)", options=options)
        if fileName:
            self.dbLabel.setText(fileName)

    def _cb_db_type_changed(self):
        if self.comboDBType.currentIndex() == Database.DB_TYPE_MEMORY:
            self.dbFileButton.setVisible(False)
            self.dbLabel.setVisible(False)
        else:
            self.dbFileButton.setVisible(True)
            self.dbLabel.setVisible(True)

    def _cb_accept_button_clicked(self):
        self._save_settings()
        self.accept()

    def _cb_apply_button_clicked(self):
        self._save_settings()

    def _cb_cancel_button_clicked(self):
        self.reject()

    def _cb_help_button_clicked(self):
        QtWidgets.QToolTip.showText(QtGui.QCursor.pos(),
                                    QC.translate("preferences",
                                                 "Hover the mouse over the texts to display the help<br><br>Don't forget to visit the wiki: <a href=\"{0}\">{0}</a>").format(Config.HELP_URL))

    def _cb_popups_check_toggled(self, checked):
        self.spinUITimeout.setEnabled(not checked)
        if not checked:
            self.spinUITimeout.setValue(15)

    def _cb_node_combo_changed(self, index):
        self._load_node_settings()

    def _cb_node_needs_update(self):
        self._node_needs_update = True

    def _cb_check_ui_rules_toggled(self, state):
        self.comboUIRules.setEnabled(state)
