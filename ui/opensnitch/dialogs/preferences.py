import sys
import time
import os
import json
import stat

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.database import Database
from opensnitch.utils import Message, QuickHelp, Themes, Icons, languages
from opensnitch.utils.xdg import Autostart
from opensnitch.notifications import DesktopNotifications

from opensnitch import ui_pb2, auth

DIALOG_UI_PATH = "%s/../res/preferences.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PreferencesDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    LOG_TAG = "[Preferences] "
    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)
    saved = QtCore.pyqtSignal()

    TAB_POPUPS = 0
    TAB_UI = 1
    TAB_RULES = 2
    TAB_NODES = 3
    TAB_DB = 4

    NODE_PAGE_GENERAL = 0
    NODE_PAGE_LOGGING = 1
    NODE_PAGE_AUTH = 2

    SUM = 1
    REST = 0

    AUTH_SIMPLE = 0
    AUTH_TLS_SIMPLE = 1
    AUTH_TLS_MUTUAL = 2

    NODE_AUTH = {
        AUTH_SIMPLE: auth.Simple,
        AUTH_TLS_SIMPLE: auth.TLSSimple,
        AUTH_TLS_MUTUAL: auth.TLSMutual
    }
    NODE_AUTH_VERIFY = {
        0: auth.NO_CLIENT_CERT,
        1: auth.REQ_CERT,
        2: auth.REQ_ANY_CERT,
        3: auth.VERIFY_CERT,
        4: auth.REQ_AND_VERIFY_CERT
    }

    def __init__(self, parent=None, appicon=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self._themes = Themes.instance()
        self._saved_theme = ""
        self._restart_msg = QC.translate("preferences", "Restart the GUI in order changes to take effect")
        self._changes_needs_restart = None

        self._cfg = Config.get()
        self._nodes = Nodes.instance()
        self._db = Database.instance()
        self._autostart = Autostart()

        self._notification_callback.connect(self._cb_notification_callback)
        self._notifications_sent = {}
        self._desktop_notifications = DesktopNotifications()

        self.setupUi(self)
        self.setWindowIcon(appicon)

        self.checkDBMaxDays.setEnabled(True)
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
        self.comboUITheme.currentIndexChanged.connect(self._cb_combo_themes_changed)
        self.cmdTimeoutUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUITimeout, self.SUM))
        self.cmdTimeoutDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUITimeout, self.REST))
        self.cmdRefreshUIUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUIRefresh, self.SUM))
        self.cmdRefreshUIDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUIRefresh, self.REST))
        self.cmdDBMaxDaysUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinDBMaxDays, self.SUM))
        self.cmdDBMaxDaysDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinDBMaxDays, self.REST))
        self.cmdDBPurgesUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinDBPurgeInterval, self.SUM))
        self.cmdDBPurgesDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinDBPurgeInterval, self.REST))
        self.cmdTestNotifs.clicked.connect(self._cb_test_notifs_clicked)
        self.radioSysNotifs.clicked.connect(self._cb_radio_system_notifications)
        self.helpButton.setToolTipDuration(30 * 1000)

        self.comboAuthType.currentIndexChanged.connect(self._cb_combo_auth_type_changed)
        self.comboAuthType.setItemData(PreferencesDialog.AUTH_SIMPLE, auth.Simple)
        self.comboAuthType.setItemData(PreferencesDialog.AUTH_TLS_SIMPLE, auth.TLSSimple)
        self.comboAuthType.setItemData(PreferencesDialog.AUTH_TLS_MUTUAL, auth.TLSMutual)
        self.comboNodeAuthType.setItemData(PreferencesDialog.AUTH_SIMPLE, auth.Simple)
        self.comboNodeAuthType.setItemData(PreferencesDialog.AUTH_TLS_SIMPLE, auth.TLSSimple)
        self.comboNodeAuthType.setItemData(PreferencesDialog.AUTH_TLS_MUTUAL, auth.TLSMutual)
        self.comboNodeAuthVerifyType.setItemData(0, auth.NO_CLIENT_CERT)
        self.comboNodeAuthVerifyType.setItemData(1, auth.REQ_CERT)
        self.comboNodeAuthVerifyType.setItemData(2, auth.REQ_ANY_CERT)
        self.comboNodeAuthVerifyType.setItemData(3, auth.VERIFY_CERT)
        self.comboNodeAuthVerifyType.setItemData(4, auth.REQ_AND_VERIFY_CERT)

        self.comboUIRules.currentIndexChanged.connect(self._cb_combo_uirules_changed)

        if QtGui.QIcon.hasThemeIcon("emblem-default"):
            return

        saveIcon = Icons.new(self, "document-save")
        applyIcon = Icons.new(self, "emblem-default")
        delIcon = Icons.new(self, "edit-delete")
        closeIcon = Icons.new(self, "window-close")
        openIcon = Icons.new(self, "document-open")
        helpIcon = Icons.new(self, "help-browser")
        addIcon = Icons.new(self, "list-add")
        delIcon = Icons.new(self, "list-remove")
        allowIcon = Icons.new(self, "emblem-default")
        denyIcon = Icons.new(self, "emblem-important")
        rejectIcon = Icons.new(self, "window-close")
        self.applyButton.setIcon(applyIcon)
        self.cancelButton.setIcon(closeIcon)
        self.acceptButton.setIcon(saveIcon)
        self.helpButton.setIcon(helpIcon)
        self.dbFileButton.setIcon(openIcon)

        self.cmdTimeoutUp.setIcon(addIcon)
        self.cmdTimeoutDown.setIcon(delIcon)
        self.cmdRefreshUIUp.setIcon(addIcon)
        self.cmdRefreshUIDown.setIcon(delIcon)
        self.cmdDBMaxDaysUp.setIcon(addIcon)
        self.cmdDBMaxDaysDown.setIcon(delIcon)
        self.cmdDBPurgesUp.setIcon(addIcon)
        self.cmdDBPurgesDown.setIcon(delIcon)

        self.comboUIAction.setItemIcon(Config.ACTION_DENY_IDX, denyIcon)
        self.comboUIAction.setItemIcon(Config.ACTION_ALLOW_IDX, allowIcon)
        self.comboUIAction.setItemIcon(Config.ACTION_REJECT_IDX, rejectIcon)

    def showEvent(self, event):
        super(PreferencesDialog, self).showEvent(event)

        try:
            self._changes_needs_restart = None
            self._settingsSaved = False
            self._reset_status_message()
            self._hide_status_label()
            self.comboNodes.clear()

            self._load_langs()

            self.comboNodeAddress.clear()
            run_path = "/run/user/{0}/opensnitch/".format(os.getuid())
            var_run_path = "/var{0}".format(run_path)
            self.comboNodeAddress.addItem("unix:///tmp/osui.sock")
            if os.path.exists(run_path):
                self.comboNodeAddress.addItem("unix://%s/osui.sock" % run_path)
            if os.path.exists(var_run_path):
                self.comboNodeAddress.addItem("unix://%s/osui.sock" % var_run_path)

            self._node_list = self._nodes.get()
            for addr in self._node_list:
                self.comboNodes.addItem(addr)

            if len(self._node_list) == 0:
                self._reset_node_settings()
                self._set_status_message(QC.translate("preferences", "There're no nodes connected"))
        except Exception as e:
            print(self.LOG_TAG + "exception loading nodes:", e)

        self._load_settings()

        # connect the signals after loading settings, to avoid firing
        # the signals
        self.comboNodes.currentIndexChanged.connect(self._cb_node_combo_changed)
        self.comboNodeAction.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeDuration.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeMonitorMethod.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeLogLevel.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeLogFile.currentIndexChanged.connect(self._cb_node_needs_update)
        self.checkNodeLogUTC.clicked.connect(self._cb_node_needs_update)
        self.checkNodeLogMicro.clicked.connect(self._cb_node_needs_update)
        self.comboNodeAddress.currentTextChanged.connect(self._cb_node_needs_update)
        self.checkInterceptUnknown.clicked.connect(self._cb_node_needs_update)
        self.checkApplyToNodes.clicked.connect(self._cb_node_needs_update)
        self.comboNodeAction.currentIndexChanged.connect(self._cb_node_needs_update)
        self.checkNodeAuthSkipVerify.clicked.connect(self._cb_node_needs_update)
        self.comboNodeAuthVerifyType.currentIndexChanged.connect(self._cb_node_needs_update)
        self.enableChecksums.clicked.connect(self._cb_node_needs_update)

        self.comboAuthType.currentIndexChanged.connect(self._cb_combo_auth_type_changed)
        self.comboNodeAuthType.currentIndexChanged.connect(self._cb_combo_node_auth_type_changed)

        self.lineCACertFile.textChanged.connect(self._cb_line_certs_changed)
        self.lineCertFile.textChanged.connect(self._cb_line_certs_changed)
        self.lineCertKeyFile.textChanged.connect(self._cb_line_certs_changed)
        self.lineNodeCACertFile.textChanged.connect(self._cb_node_line_certs_changed)
        self.lineNodeCertFile.textChanged.connect(self._cb_node_line_certs_changed)
        self.lineNodeCertKeyFile.textChanged.connect(self._cb_node_line_certs_changed)

        self.comboDBType.currentIndexChanged.connect(self._cb_db_type_changed)
        self.checkDBMaxDays.toggled.connect(self._cb_db_max_days_toggled)
        self.checkDBJrnlWal.toggled.connect(self._cb_db_jrnl_wal_toggled)

        # True when any node option changes
        self._node_needs_update = False

    def show_node_prefs(self, addr):
        self.show()
        self.comboNodes.setCurrentText(addr)
        self.tabWidget.setCurrentIndex(self.TAB_NODES)

    def _load_langs(self):
        try:
            self.comboUILang.clear()
            self.comboUILang.blockSignals(True)
            self.comboUILang.addItem(QC.translate("preferences", "System default"), "")
            langs, langNames = languages.get_all()
            for idx, lang in enumerate(langs):
                self.comboUILang.addItem(langNames[idx].capitalize(), langs[idx])
            self.comboUILang.blockSignals(False)
        except Exception as e:
            print(self.LOG_TAG + "exception loading languages:", e)

    def _load_themes(self):
        self.comboUITheme.blockSignals(True)
        theme_idx, self._saved_theme = self._themes.get_saved_theme()

        self.labelThemeError.setVisible(False)
        self.labelThemeError.setText("")
        self.comboUITheme.clear()
        self.comboUITheme.addItem(QC.translate("preferences", "System"))
        if self._themes.available():
            themes = self._themes.list_themes()
            self.comboUITheme.addItems(themes)
        else:
            self._saved_theme = ""
            self.labelThemeError.setStyleSheet('color: red')
            self.labelThemeError.setVisible(True)
            self.labelThemeError.setText(QC.translate("preferences", "Themes not available. Install qt-material: pip3 install qt-material"))

        self.comboUITheme.setCurrentIndex(theme_idx)
        self.comboUITheme.blockSignals(False)

    def _load_settings(self):
        self._default_action = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)
        self._default_target = self._cfg.getInt(self._cfg.DEFAULT_TARGET_KEY, 0)
        self._default_timeout = self._cfg.getInt(self._cfg.DEFAULT_TIMEOUT_KEY, Config.DEFAULT_TIMEOUT)
        self._disable_popups = self._cfg.getBool(self._cfg.DEFAULT_DISABLE_POPUPS)

        if self._cfg.hasKey(self._cfg.DEFAULT_DURATION_KEY):
            self._default_duration = self._cfg.getInt(self._cfg.DEFAULT_DURATION_KEY)
        else:
            self._default_duration = self._cfg.DEFAULT_DURATION_IDX

        self.comboUIDuration.setCurrentIndex(self._default_duration)
        self.comboUIDialogPos.setCurrentIndex(self._cfg.getInt(self._cfg.DEFAULT_POPUP_POSITION))

        self._ui_refresh_interval = self._cfg.getInt(self._cfg.STATS_REFRESH_INTERVAL, 0)
        self.spinUIRefresh.setValue(self._ui_refresh_interval)

        self.checkAutostart.setChecked(self._autostart.isEnabled())

        maxmsgsize = self._cfg.getSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH)
        if maxmsgsize:
            self.comboGrpcMsgSize.setCurrentText(maxmsgsize)
        else:
            self.comboGrpcMsgSize.setCurrentIndex(0)

        self.lineCACertFile.setText(self._cfg.getSettings(Config.AUTH_CA_CERT))
        self.lineCertFile.setText(self._cfg.getSettings(Config.AUTH_CERT))
        self.lineCertKeyFile.setText(self._cfg.getSettings(Config.AUTH_CERTKEY))
        authtype_idx = self.comboAuthType.findData(self._cfg.getSettings(Config.AUTH_TYPE))
        if authtype_idx <= 0:
            authtype_idx = 0
            self.lineCACertFile.setEnabled(False)
            self.lineCertFile.setEnabled(False)
            self.lineCertKeyFile.setEnabled(False)
        self.comboAuthType.setCurrentIndex(authtype_idx)

        saved_lang = self._cfg.getSettings(Config.DEFAULT_LANGUAGE)
        if saved_lang:
            saved_langname = self._cfg.getSettings(Config.DEFAULT_LANGNAME)
            self.comboUILang.blockSignals(True)
            self.comboUILang.setCurrentText(saved_langname)
            self.comboUILang.blockSignals(False)

        self.comboUIRules.blockSignals(True)
        self.comboUIRules.setCurrentIndex(self._cfg.getInt(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES))
        self.checkUIRules.setChecked(self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES))
        self.comboUIRules.setEnabled(self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES))
        #self._set_rules_duration_filter()

        self._cfg.setRulesDurationFilter(
            self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES),
            self._cfg.getInt(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES)
        )
        self.comboUIRules.blockSignals(False)

        self.comboUIAction.setCurrentIndex(self._default_action)
        self.comboUITarget.setCurrentIndex(self._default_target)
        self.spinUITimeout.setValue(self._default_timeout)
        self.spinUITimeout.setEnabled(not self._disable_popups)
        self.popupsCheck.setChecked(self._disable_popups)

        self.showAdvancedCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED))
        self.dstIPCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_DSTIP))
        self.dstPortCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_DSTPORT))
        self.uidCheck.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_UID))
        self.checkSum.setChecked(self._cfg.getBool(self._cfg.DEFAULT_POPUP_ADVANCED_CHECKSUM))

        # by default, if no configuration exists, enable notifications.
        self.groupNotifs.setChecked(self._cfg.getBool(Config.NOTIFICATIONS_ENABLED, True))
        self.radioSysNotifs.setChecked(
            True if self._cfg.getInt(Config.NOTIFICATIONS_TYPE) == Config.NOTIFICATION_TYPE_SYSTEM and self._desktop_notifications.is_available() == True else False
        )
        self.radioQtNotifs.setChecked(
            True if self._cfg.getInt(Config.NOTIFICATIONS_TYPE) == Config.NOTIFICATION_TYPE_QT or self._desktop_notifications.is_available() == False else False
        )

        self.dbType = self._cfg.getInt(self._cfg.DEFAULT_DB_TYPE_KEY)
        self.comboDBType.setCurrentIndex(self.dbType)
        if self.comboDBType.currentIndex() != Database.DB_TYPE_MEMORY:
            self.dbFileButton.setVisible(True)
            self.dbLabel.setVisible(True)
            self.dbLabel.setText(self._cfg.getSettings(self._cfg.DEFAULT_DB_FILE_KEY))
        dbMaxDays = self._cfg.getInt(self._cfg.DEFAULT_DB_MAX_DAYS, 1)
        dbJrnlWal = self._cfg.getBool(self._cfg.DEFAULT_DB_JRNL_WAL)
        dbPurgeInterval = self._cfg.getInt(self._cfg.DEFAULT_DB_PURGE_INTERVAL, 5)
        self._enable_db_cleaner_options(self._cfg.getBool(Config.DEFAULT_DB_PURGE_OLDEST), dbMaxDays)
        self._enable_db_jrnl_wal(self._cfg.getBool(Config.DEFAULT_DB_PURGE_OLDEST), dbJrnlWal)
        self.spinDBMaxDays.setValue(dbMaxDays)
        self.spinDBPurgeInterval.setValue(dbPurgeInterval)

        self._load_themes()
        self._load_node_settings()
        self._load_ui_columns_config()

    def _load_node_settings(self):
        addr = self.comboNodes.currentText()
        if addr == "":
            return

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

            if node_config.get('LogUTC') == None:
                node_config['LogUTC'] = False
            self.checkNodeLogUTC.setChecked(node_config['LogUTC'])
            if node_config.get('LogMicro') == None:
                node_config['LogMicro'] = False
            self.checkNodeLogMicro.setChecked(node_config['LogMicro'])

            if node_config.get('Server') != None:
                self.comboNodeAddress.setEnabled(True)
                self.comboNodeLogFile.setEnabled(True)

                self.comboNodeAddress.setCurrentText(node_config['Server']['Address'])
                self.comboNodeLogFile.setCurrentText(node_config['Server']['LogFile'])

                self._load_node_auth_settings(node_config['Server'])
            else:
                self.comboNodeAddress.setEnabled(False)
                self.comboNodeLogFile.setEnabled(False)


            if node_config.get('Rules') != None:
                self.enableChecksums.setChecked(node_config['Rules']['EnableChecksums'])
            else:
                node_config.update({"Rules":{"EnableChecksums":False}})
                self.enableChecksums.setChecked(False)


            self._node_list[addr]['data'].config = json.dumps(node_config, indent="    ")

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
            node_config['LogUTC'] = self.checkNodeLogUTC.isChecked()
            node_config['LogMicro'] = self.checkNodeLogMicro.isChecked()
            node_config['InterceptUnknown'] = self.checkInterceptUnknown.isChecked()

            if node_config.get('Server') != None:
                # skip setting Server Address if we're applying the config to all nodes
                node_config['Server']['Address'] = self.comboNodeAddress.currentText()
                node_config['Server']['LogFile'] = self.comboNodeLogFile.currentText()

                cfg = self._load_node_auth_config(node_config['Server'])
                if cfg != None:
                    node_config['Server'] = cfg
            else:
                print(addr, " doesn't have Server item")

            if node_config.get('Rules') != None:
                node_config['Rules']['EnableChecksums'] = self.enableChecksums.isChecked()
            else:
                print(addr, "Doesn't have Rules config option")
                node_config.update({"Rules":{"EnableChecksums":False}})

            return json.dumps(node_config, indent="    "), None
        except Exception as e:
            print(self.LOG_TAG + "exception loading node config on %s: " % addr, e)

        return None, QC.translate("preferences", "Error loading {0} configuration").format(addr)

    def _load_node_auth_settings(self, config):
        try:
            if config.get('Authentication') == None:
                self.toolBox.setItemEnabled(self.NODE_PAGE_AUTH, False)
                return
            authtype_idx = self.comboNodeAuthType.findData(config['Authentication']['Type'])
            self.lineNodeCACertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeServerCertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeCertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeCertKeyFile.setEnabled(authtype_idx >= 0)
            if authtype_idx >= 0:
                self.lineNodeCACertFile.setText(config['Authentication']['TLSOptions']['CACert'])
                self.lineNodeServerCertFile.setText(config['Authentication']['TLSOptions']['ServerCert'])
                self.lineNodeCertFile.setText(config['Authentication']['TLSOptions']['ClientCert'])
                self.lineNodeCertKeyFile.setText(config['Authentication']['TLSOptions']['ClientKey'])
                self.checkNodeAuthSkipVerify.setChecked(config['Authentication']['TLSOptions']['SkipVerify'])

                clienttype_idx = self.comboNodeAuthVerifyType.findData(config['Authentication']['TLSOptions']['ClientAuthType'])
                if clienttype_idx >= 0:
                    self.comboNodeAuthVerifyType.setCurrentIndex(clienttype_idx)
            else:
                authtype_idx = 0
            self.comboNodeAuthType.setCurrentIndex(authtype_idx)
        except Exception as e:
            print("[prefs] node auth options exception:", e)
            self._set_status_error(str(e))

    def _load_node_auth_config(self, config):
        try:
            if config.get('Authentication') == None:
                self.toolBox.setItemEnabled(self.NODE_PAGE_AUTH, False)
                return
            config['Authentication']['Type'] = self.NODE_AUTH[self.comboNodeAuthType.currentIndex()]
            config['Authentication']['TLSOptions']['CACert']= self.lineNodeCACertFile.text()
            config['Authentication']['TLSOptions']['ServerCert'] = self.lineNodeServerCertFile.text()
            config['Authentication']['TLSOptions']['ClientCert'] = self.lineNodeCertFile.text()
            config['Authentication']['TLSOptions']['ClientKey'] = self.lineNodeCertKeyFile.text()
            config['Authentication']['TLSOptions']['SkipVerify'] = self.checkNodeAuthSkipVerify.isChecked()
            config['Authentication']['TLSOptions']['ClientAuthType'] = self.NODE_AUTH_VERIFY[self.comboNodeAuthVerifyType.currentIndex()]

            return config
        except Exception as e:
            print("[prefs] node auth options exception:", e)
            self._set_status_error(str(e))
            return None

    def _load_ui_columns_config(self):
        cols = self._cfg.getSettings(Config.STATS_SHOW_COLUMNS)
        if cols == None:
            return

        for c in range(8):
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
                self.checkHideCmdline.setChecked(checked)
            elif c == 7:
                self.checkHideRule.setChecked(checked)

    def _reset_node_settings(self):
        self.comboNodeAction.setCurrentIndex(0)
        self.comboNodeDuration.setCurrentIndex(0)
        self.comboNodeMonitorMethod.setCurrentIndex(0)
        self.checkInterceptUnknown.setChecked(False)
        self.comboNodeLogLevel.setCurrentIndex(0)
        self.checkNodeLogUTC.setChecked(True)
        self.checkNodeLogMicro.setChecked(False)
        self.labelNodeName.setText("")
        self.labelNodeVersion.setText("")

    def _save_settings(self):
        self._reset_status_message()
        self._show_status_label()
        self._save_ui_config()
        if not self._save_db_config():
            return
        self._save_nodes_config()

        self.saved.emit()
        self._settingsSaved = True
        self._needs_restart()

    def _save_db_config(self):
        dbtype = self.comboDBType.currentIndex()
        db_name = self._cfg.getSettings(self._cfg.DEFAULT_DB_FILE_KEY)

        if self.dbLabel.text() != "" and \
                (self.comboDBType.currentIndex() != self.dbType or db_name != self.dbLabel.text()):
            self._changes_needs_restart = QC.translate("preferences", "DB type changed")

        if self.comboDBType.currentIndex() != Database.DB_TYPE_MEMORY:
            if self.dbLabel.text() != "":
                db_name = self.dbLabel.text()
            else:
                Message.ok(
                    QC.translate("preferences", "Warning"),
                    QC.translate("preferences", "You must select a file for the database<br>or choose \"In memory\" type."),
                    QtWidgets.QMessageBox.Warning)
                self.dbLabel.setText("")
                return False
        else:
            db_name = Database.DB_IN_MEMORY

        self._cfg.setSettings(Config.DEFAULT_DB_FILE_KEY, db_name)
        self._cfg.setSettings(Config.DEFAULT_DB_TYPE_KEY, dbtype)
        self._cfg.setSettings(Config.DEFAULT_DB_PURGE_OLDEST, bool(self.checkDBMaxDays.isChecked()))
        self._cfg.setSettings(Config.DEFAULT_DB_MAX_DAYS, int(self.spinDBMaxDays.value()))
        self._cfg.setSettings(Config.DEFAULT_DB_PURGE_INTERVAL, int(self.spinDBPurgeInterval.value()))
        self._cfg.setSettings(Config.DEFAULT_DB_JRNL_WAL, bool(self.checkDBJrnlWal.isChecked()))
        self.dbType = self.comboDBType.currentIndex()

        return True

    def _save_ui_config(self):
        try:
            self._save_ui_columns_config()

            maxmsgsize = self.comboGrpcMsgSize.currentText()
            if maxmsgsize != "":
                self._cfg.setSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH, maxmsgsize.replace(" ", ""))

            savedauthtype = self._cfg.getSettings(Config.AUTH_TYPE)
            authtype = self.comboAuthType.itemData(self.comboAuthType.currentIndex())
            cacert = self._cfg.getSettings(Config.AUTH_CA_CERT)
            cert = self._cfg.getSettings(Config.AUTH_CERT)
            certkey = self._cfg.getSettings(Config.AUTH_CERTKEY)
            if not self._validate_certs():
                return

            if savedauthtype != authtype or self.lineCertFile.text() != cert or \
                    self.lineCertKeyFile.text() != certkey or self.lineCACertFile.text() != cacert:
                self._changes_needs_restart = QC.translate("preferences", "Certificates changed")
            self._cfg.setSettings(Config.AUTH_TYPE, authtype)
            self._cfg.setSettings(Config.AUTH_CA_CERT, self.lineCACertFile.text())
            self._cfg.setSettings(Config.AUTH_CERT, self.lineCertFile.text())
            self._cfg.setSettings(Config.AUTH_CERTKEY, self.lineCertKeyFile.text())

            selected_lang = self.comboUILang.itemData(self.comboUILang.currentIndex())
            saved_lang = self._cfg.getSettings(Config.DEFAULT_LANGUAGE)
            saved_lang = "" if saved_lang is None else saved_lang
            if saved_lang != selected_lang:
                languages.save(self._cfg, selected_lang)
                self._changes_needs_restart = QC.translate("preferences", "Language changed")

            self._cfg.setSettings(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES, int(self.comboUIRules.currentIndex()))
            self._cfg.setSettings(self._cfg.DEFAULT_IGNORE_RULES, bool(self.checkUIRules.isChecked()))
            #self._set_rules_duration_filter()
            self._cfg.setRulesDurationFilter(
                bool(self.checkUIRules.isChecked()),
                int(self.comboUIRules.currentIndex())
            )
            if self.checkUIRules.isChecked():
                self._nodes.delete_rule_by_field(Config.DURATION_FIELD, Config.RULES_DURATION_FILTER)

            self._cfg.setSettings(self._cfg.STATS_REFRESH_INTERVAL, int(self.spinUIRefresh.value()))
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
            self._cfg.setSettings(self._cfg.DEFAULT_POPUP_ADVANCED_CHECKSUM, bool(self.checkSum.isChecked()))

            self._cfg.setSettings(self._cfg.NOTIFICATIONS_ENABLED, bool(self.groupNotifs.isChecked()))
            self._cfg.setSettings(self._cfg.NOTIFICATIONS_TYPE,
                                int(Config.NOTIFICATION_TYPE_SYSTEM if self.radioSysNotifs.isChecked() else Config.NOTIFICATION_TYPE_QT))

            self._themes.save_theme(self.comboUITheme.currentIndex(), self.comboUITheme.currentText())

            if self._themes.available() and self._saved_theme != "" and self.comboUITheme.currentText() == QC.translate("preferences", "System"):
                self._changes_needs_restart = QC.translate("preferences", "UI theme changed")

            # this is a workaround for not display pop-ups.
            # see #79 for more information.
            if self.popupsCheck.isChecked():
                self._cfg.setSettings(self._cfg.DEFAULT_TIMEOUT_KEY, 0)


            self._autostart.enable(self.checkAutostart.isChecked())

        except Exception as e:
            self._set_status_error(str(e))

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
        if self.checkHideCmdline.isChecked():
            cols.append("6")
        if self.checkHideRule.isChecked():
            cols.append("7")

        self._cfg.setSettings(Config.STATS_SHOW_COLUMNS, cols)

    def _save_nodes_config(self):
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
        elif addr == "":
            self._set_status_message(QC.translate("preferences", "There're no nodes connected"))

        self._node_needs_update = False

    def _save_node_config(self, notifObject, addr):
        try:
            self._set_status_message(QC.translate("preferences", "Applying configuration on {0} ...").format(addr))
            notifObject.data, error = self._load_node_config(addr)
            if error != None:
                return error

            savedAddr = self._cfg.getSettings(Config.DEFAULT_SERVER_ADDR)
            # exclude this message if there're more than one node connected
            if self.comboNodes.count() == 1 and savedAddr != None and savedAddr != self.comboNodeAddress.currentText():
                self._changes_needs_restart = QC.translate("preferences", "Ok")

            self._cfg.setSettings(Config.DEFAULT_SERVER_ADDR, self.comboNodeAddress.currentText())

            self._nodes.save_node_config(addr, notifObject.data)
            nid = self._nodes.send_notification(addr, notifObject, self._notification_callback)
            self._notifications_sent[nid] = notifObject

        except Exception as e:
            print(self.LOG_TAG + "exception saving node config on %s: " % addr, e)
            self._set_status_error(QC.translate("preferences", "Exception saving node config {0}: {1}").format((addr, str(e))))
            return addr + ": " + str(e)

        return None

    def _save_node_auth_config(self, config):
        try:
            if config.get('Authentication') == None:
                self.toolBox.setItemEnabled(self.NODE_PAGE_AUTH, False)
                return
            authtype_idx = self.comboNodeAuthType.findData(config['Authentication']['Type'])
            self.lineNodeCACertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeServerCertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeCertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeCertKeyFile.setEnabled(authtype_idx >= 0)
            if authtype_idx >= 0:
                self.lineNodeCACertFile.setText(config['Authentication']['TLSOptions']['CACert'])
                self.lineNodeServerCertFile.setText(config['Authentication']['TLSOptions']['ServerCert'])
                self.lineNodeCertFile.setText(config['Authentication']['TLSOptions']['ClientCert'])
                self.lineNodeCertKeyFile.setText(config['Authentication']['TLSOptions']['ClientKey'])
                self.checkNodeAuthSkipVerify.setChecked(config['Authentication']['TLSOptions']['SkipVerify'])

                clienttype_idx = self.comboNodeAuthVerifyType.findData(config['Authentication']['TLSOptions']['ClientAuthType'])
                if clienttype_idx >= 0:
                    self.comboNodeAuthVerifyType.setCurrentIndex(clienttype_idx)
            else:
                authtype_idx = 0
            self.comboNodeAuthType.setCurrentIndex(authtype_idx)
        except Exception as e:
            print("[prefs] node auth options exception:", e)
            self._set_status_error(str(e))


    def _validate_certs(self):
        try:
            if self.comboAuthType.currentIndex() == PreferencesDialog.AUTH_SIMPLE:
                return True

            if self.comboAuthType.currentIndex() > 0 and (self.lineCertFile.text() == "" or self.lineCertKeyFile.text() == ""):
                raise ValueError(QC.translate("preferences", "Certs fields cannot be empty."))

            if oct(stat.S_IMODE(os.lstat(self.lineCertFile.text()).st_mode)) != "0o600":
                self._set_status_message(
                    QC.translate("preferences", "cert file has excessive permissions, it should have 0600")
                )
            if oct(stat.S_IMODE(os.lstat(self.lineCertFile.text()).st_mode)) != "0o600":
                self._set_status_message(
                    QC.translate("preferences", "cert key file has excessive permissions, it should have 0600")
                )

            if self.comboAuthType.currentIndex() == PreferencesDialog.AUTH_TLS_MUTUAL:
                if oct(stat.S_IMODE(os.lstat(self.lineCACertFile.text()).st_mode)) != "0o600":
                    self._set_status_message(
                        QC.translate("preferences", "CA cert file has excessive permissions, it should have 0600")
                    )

            return True
        except Exception as e:
            self._changes_needs_restart = None
            self._set_status_error("certs error: {0}".format(e))
            return False

    def _needs_restart(self):
        if self._changes_needs_restart:
            Message.ok(self._changes_needs_restart,
                self._restart_msg,
                QtWidgets.QMessageBox.Warning)
            self._changes_needs_restart = None

    def _hide_status_label(self):
        self.statusLabel.hide()

    def _show_status_label(self):
        self.statusLabel.show()

    def _set_status_error(self, msg):
        self._show_status_label()
        self.statusLabel.setStyleSheet('color: red')
        self.statusLabel.setText(msg)

    def _set_status_successful(self, msg):
        self._show_status_label()
        self.statusLabel.setStyleSheet('color: green')
        self.statusLabel.setText(msg)

    def _set_status_message(self, msg):
        self._show_status_label()
        self.statusLabel.setStyleSheet('color: darkorange')
        self.statusLabel.setText(msg)

    def _reset_status_message(self):
        self.statusLabel.setText("")
        self._hide_status_label()

    def _enable_db_cleaner_options(self, enable, db_max_days):
        self.checkDBMaxDays.setChecked(enable)
        self.spinDBMaxDays.setEnabled(enable)
        self.spinDBPurgeInterval.setEnabled(enable)
        self.labelDBPurgeInterval.setEnabled(enable)
        self.labelDBPurgeDays.setEnabled(enable)
        self.labelDBPurgeMinutes.setEnabled(enable)
        self.cmdDBMaxDaysUp.setEnabled(enable)
        self.cmdDBMaxDaysDown.setEnabled(enable)
        self.cmdDBPurgesUp.setEnabled(enable)
        self.cmdDBPurgesDown.setEnabled(enable)

    def _enable_db_jrnl_wal(self, enable, db_jrnl_wal):
        self.checkDBJrnlWal.setChecked(db_jrnl_wal)
        self.checkDBJrnlWal.setEnabled(enable)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        #print(self.LOG_TAG, "Config notification received: ", reply.id, reply.code)
        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.OK:
                self._set_status_successful(QC.translate("preferences", "Configuration applied."))
            else:
                self._set_status_error(QC.translate("preferences", "Error applying configuration: {0}").format(reply.data))

            del self._notifications_sent[reply.id]

    def _cb_line_certs_changed(self, text):
        self._changes_needs_restart = QC.translate("preferences", "Certs changed")

    def _cb_node_line_certs_changed(self, text):
        self._changes_needs_restart = QC.translate("preferences", "Node certs changed")
        self._node_needs_update = True

    def _cb_file_db_clicked(self):
        options = QtWidgets.QFileDialog.Options()
        fileName, _ = QtWidgets.QFileDialog.getSaveFileName(self, "", "","All Files (*)", options=options)
        if fileName:
            self.dbLabel.setText(fileName)

    def _cb_combo_uirules_changed(self, idx):
        self._cfg.setRulesDurationFilter(
            self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES),
            idx
            #self._cfg.getInt(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES)
        )


    def _cb_db_type_changed(self):
        isDBMem = self.comboDBType.currentIndex() == Database.DB_TYPE_MEMORY
        self.dbFileButton.setVisible(not isDBMem)
        self.dbLabel.setVisible(not isDBMem)
        self.checkDBMaxDays.setChecked(self._cfg.getBool(Config.DEFAULT_DB_PURGE_OLDEST))
        self.checkDBJrnlWal.setEnabled(not isDBMem)
        self.checkDBJrnlWal.setChecked(False)

    def _cb_accept_button_clicked(self):
        self.accept()
        if not self._settingsSaved:
            self._save_settings()

    def _cb_apply_button_clicked(self):
        self._reset_status_message()
        self._save_settings()

    def _cb_cancel_button_clicked(self):
        self.reject()

    def _cb_help_button_clicked(self):
        QuickHelp.show(
            QC.translate("preferences",
                         "Hover the mouse over the texts to display the help<br><br>Don't forget to visit the wiki: <a href=\"{0}\">{0}</a>"
                         ).format(Config.HELP_URL)
        )

    def _cb_popups_check_toggled(self, checked):
        self.spinUITimeout.setEnabled(not checked)
        if not checked:
            self.spinUITimeout.setValue(20)

    def _cb_node_combo_changed(self, index):
        self._load_node_settings()

    def _cb_node_needs_update(self):
        self._node_needs_update = True

    def _cb_check_ui_rules_toggled(self, state):
        self.comboUIRules.setEnabled(state)

    def _cb_combo_themes_changed(self, index):
        self._themes.change_theme(self, self.comboUITheme.currentText())

    def _cb_combo_auth_type_changed(self, index):
        curtype = self.comboAuthType.itemData(self.comboAuthType.currentIndex())
        savedtype = self._cfg.getSettings(Config.AUTH_TYPE)
        if curtype != savedtype:
            self._changes_needs_restart = QC.translate("preferences", "Auth type changed")

        self.lineCACertFile.setEnabled(index == PreferencesDialog.AUTH_TLS_MUTUAL)
        self.lineCertFile.setEnabled(index >= PreferencesDialog.AUTH_TLS_SIMPLE)
        self.lineCertKeyFile.setEnabled(index >= PreferencesDialog.AUTH_TLS_SIMPLE)

    def _cb_combo_node_auth_type_changed(self, index):
        curtype = self.comboNodeAuthType.itemData(self.comboNodeAuthType.currentIndex())
        #savedtype = self._cfg.getSettings(Config.AUTH_TYPE)
        #if curtype != savedtype:
        #    self._changes_needs_restart = QC.translate("preferences", "Auth type changed")

        self.lineNodeCACertFile.setEnabled(index == PreferencesDialog.AUTH_TLS_MUTUAL)
        self.lineNodeServerCertFile.setEnabled(index >= PreferencesDialog.AUTH_TLS_SIMPLE)
        self.lineNodeCertFile.setEnabled(index >= PreferencesDialog.AUTH_TLS_SIMPLE)
        self.lineNodeCertKeyFile.setEnabled(index >= PreferencesDialog.AUTH_TLS_SIMPLE)
        self.checkNodeAuthSkipVerify.setEnabled(index >= PreferencesDialog.AUTH_TLS_SIMPLE)
        self.comboNodeAuthVerifyType.setEnabled(index >= PreferencesDialog.AUTH_TLS_SIMPLE)

        self._node_needs_update = True

    def _cb_db_max_days_toggled(self, state):
        self._enable_db_cleaner_options(state, 1)

    def _cb_db_jrnl_wal_toggled(self, state):
        self._changes_needs_restart = QC.translate("preferences", "DB journal_mode changed")

    def _cb_cmd_spin_clicked(self, spinWidget, operation):
        if operation == self.SUM:
            spinWidget.setValue(spinWidget.value() + 1)
        else:
            spinWidget.setValue(spinWidget.value() - 1)

        enablePopups = spinWidget.value() > 0
        self.popupsCheck.setChecked(not enablePopups)
        self.spinUITimeout.setEnabled(enablePopups)

    def _cb_radio_system_notifications(self):
        if self._desktop_notifications.is_available() == False:
            self.radioSysNotifs.setChecked(False)
            self.radioQtNotifs.setChecked(True)
            self._set_status_error(QC.translate("notifications", "System notifications are not available, you need to install python3-notify2."))
            return

    def _cb_test_notifs_clicked(self):
        try:
            self.cmdTestNotifs.setEnabled(False)
            if self._desktop_notifications.is_available() == False:
                self._set_status_error(QC.translate("notifications", "System notifications are not available, you need to install python3-notify2."))
                return

            if self.radioSysNotifs.isChecked():
                self._desktop_notifications.show("title", "body")
            else:
                pass
        except Exception as e:
            print(self.LOG_TAG + "exception testing notifications:", e)
        finally:
            self.cmdTestNotifs.setEnabled(True)
