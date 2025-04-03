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
from opensnitch.rules import DefaultRulesPath

from opensnitch import auth
import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

DIALOG_UI_PATH = "%s/../res/preferences.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PreferencesDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    LOG_TAG = "[Preferences] "
    _notification_callback = QtCore.pyqtSignal(str, ui_pb2.NotificationReply)
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

        doubleValidator = QtGui.QDoubleValidator(0, 20, 2, self)
        intValidator = QtGui.QIntValidator(0, 999999, self)
        self.lineUIScreenFactor.setValidator(doubleValidator)
        self.lineNodeMaxEvents.setValidator(intValidator)
        self.lineNodeMaxStats.setValidator(intValidator)
        self.lineNodeFwMonInterval.setValidator(intValidator)

        self.acceptButton.clicked.connect(self._cb_accept_button_clicked)
        self.applyButton.clicked.connect(self._cb_apply_button_clicked)
        self.cancelButton.clicked.connect(self._cb_cancel_button_clicked)
        self.helpButton.clicked.connect(self._cb_help_button_clicked)
        self.popupsCheck.clicked.connect(self._cb_popups_check_toggled)
        self.dbFileButton.clicked.connect(self._cb_file_db_clicked)
        self.cmdTimeoutUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUITimeout, self.SUM))
        self.cmdTimeoutDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUITimeout, self.REST))
        self.cmdRefreshUIUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUIRefresh, self.SUM))
        self.cmdRefreshUIDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUIRefresh, self.REST))
        self.cmdUIDensityUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUIDensity, self.SUM))
        self.cmdUIDensityDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinUIDensity, self.REST))
        self.cmdNodeGcUp.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinNodeGC, self.SUM))
        self.cmdNodeGcDown.clicked.connect(lambda: self._cb_cmd_spin_clicked(self.spinNodeGC, self.REST))
        self.cmdNodeRulesPath.clicked.connect(self._cb_cmd_node_rulespath_clicked)
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

        # XXX: disable Node duration. It will be removed in the future
        self.comboNodeDuration.setVisible(False)
        self.labelNodeDuration.setVisible(False)

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
        self.cmdUIDensityUp.setIcon(addIcon)
        self.cmdUIDensityDown.setIcon(delIcon)
        self.cmdDBMaxDaysUp.setIcon(addIcon)
        self.cmdDBMaxDaysDown.setIcon(delIcon)
        self.cmdDBPurgesUp.setIcon(addIcon)
        self.cmdDBPurgesDown.setIcon(delIcon)
        self.cmdNodeGcUp.setIcon(addIcon)
        self.cmdNodeGcDown.setIcon(delIcon)

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
            self.comboServerAddr.clear()
            run_path = "/run/user/{0}/opensnitch/".format(os.getuid())
            var_run_path = "/var{0}".format(run_path)
            self.comboNodeAddress.addItem("unix:///tmp/osui.sock")
            self.comboServerAddr.addItem("unix:///tmp/osui.sock")
            if os.path.exists(run_path):
                self.comboNodeAddress.addItem("unix://%s/osui.sock" % run_path)
                self.comboServerAddr.addItem("unix://%s/osui.sock" % run_path)
            if os.path.exists(var_run_path):
                self.comboNodeAddress.addItem("unix://%s/osui.sock" % var_run_path)
                self.comboServerAddr.addItem("unix://%s/osui.sock" % var_run_path)

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
        #self.comboNodeDuration.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeMonitorMethod.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeLogLevel.currentIndexChanged.connect(self._cb_node_needs_update)
        self.comboNodeLogFile.currentIndexChanged.connect(self._cb_node_needs_update)
        self.checkNodeLogUTC.clicked.connect(self._cb_node_needs_update)
        self.checkNodeLogMicro.clicked.connect(self._cb_node_needs_update)
        self.comboNodeAddress.currentTextChanged.connect(self._cb_node_needs_update)
        self.comboServerAddr.currentTextChanged.connect(self._cb_node_needs_update)
        self.checkInterceptUnknown.clicked.connect(self._cb_node_needs_update)
        self.checkInterceptLoopback.clicked.connect(self._cb_node_needs_update)
        self.checkApplyToNodes.clicked.connect(self._cb_node_needs_update)
        self.comboNodeAction.currentIndexChanged.connect(self._cb_node_needs_update)
        self.checkNodeAuthSkipVerify.clicked.connect(self._cb_node_needs_update)
        self.comboNodeAuthVerifyType.currentIndexChanged.connect(self._cb_node_needs_update)
        self.enableChecksums.clicked.connect(self._cb_node_needs_update)
        self.checkNodeFlushConns.clicked.connect(self._cb_node_needs_update)
        self.checkNodeBypassQueue.clicked.connect(self._cb_node_needs_update)
        self.spinNodeGC.valueChanged.connect(self._cb_node_needs_update)
        self.lineNodeMaxEvents.textChanged.connect(self._cb_node_needs_update)
        self.lineNodeMaxStats.textChanged.connect(self._cb_node_needs_update)
        self.lineNodeFwMonInterval.textChanged.connect(self._cb_node_needs_update)
        self.lineNodeRulesPath.textChanged.connect(self._cb_node_needs_update)

        self.comboAuthType.currentIndexChanged.connect(self._cb_combo_auth_type_changed)
        self.comboNodeAuthType.currentIndexChanged.connect(self._cb_combo_node_auth_type_changed)

        self.lineCACertFile.textChanged.connect(self._cb_line_certs_changed)
        self.lineCertFile.textChanged.connect(self._cb_line_certs_changed)
        self.lineCertKeyFile.textChanged.connect(self._cb_line_certs_changed)
        self.lineNodeCACertFile.textChanged.connect(self._cb_node_line_certs_changed)
        self.lineNodeCertFile.textChanged.connect(self._cb_node_line_certs_changed)
        self.lineNodeCertKeyFile.textChanged.connect(self._cb_node_line_certs_changed)

        self.lineUIScreenFactor.textChanged.connect(self._cb_ui_screen_factor_changed)
        self.checkUIRules.toggled.connect(self._cb_ui_check_rules_toggled)
        self.checkUIAutoScreen.toggled.connect(self._cb_ui_check_auto_scale_toggled)
        self.comboUITheme.currentIndexChanged.connect(self._cb_combo_themes_changed)
        self.spinUIDensity.valueChanged.connect(self._cb_spin_uidensity_changed)

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
        theme_idx, self._saved_theme, theme_density = self._themes.get_saved_theme()

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
        self._show_ui_density_widgets(theme_idx)
        try:
            self.spinUIDensity.setValue(int(theme_density))
        except Exception as e:
            print("load_theme() invalid theme density scale:", theme_density, ":", e)

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

         # by default, if no configuration exists, enable notifications.
        self.groupNotifs.setChecked(self._cfg.getBool(Config.NOTIFICATIONS_ENABLED, True))
        self.radioSysNotifs.setChecked(
            True if self._cfg.getInt(Config.NOTIFICATIONS_TYPE) == Config.NOTIFICATION_TYPE_SYSTEM and self._desktop_notifications.is_available() == True else False
        )
        self.radioQtNotifs.setChecked(
            True if self._cfg.getInt(Config.NOTIFICATIONS_TYPE) == Config.NOTIFICATION_TYPE_QT or self._desktop_notifications.is_available() == False else False
        )

        ## db
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
        self._load_ui_settings()

    def _load_ui_settings(self):
        self._ui_refresh_interval = self._cfg.getInt(self._cfg.STATS_REFRESH_INTERVAL, 0)
        self.spinUIRefresh.setValue(self._ui_refresh_interval)

        saved_lang = self._cfg.getSettings(Config.DEFAULT_LANGUAGE)
        if saved_lang:
            saved_langname = self._cfg.getSettings(Config.DEFAULT_LANGNAME)
            self.comboUILang.blockSignals(True)
            self.comboUILang.setCurrentText(saved_langname)
            self.comboUILang.blockSignals(False)

        auto_scale = self._cfg.getBool(Config.QT_AUTO_SCREEN_SCALE_FACTOR, default_value=True)
        screen_factor = self._cfg.getSettings(Config.QT_SCREEN_SCALE_FACTOR)
        if screen_factor is None or screen_factor == "":
            screen_factor = "1"
        self.lineUIScreenFactor.setText(screen_factor)
        self.checkUIAutoScreen.blockSignals(True)
        self.checkUIAutoScreen.setChecked(auto_scale)
        self.checkUIAutoScreen.blockSignals(False)
        self._show_ui_scalefactor_widgets(auto_scale)

        qt_platform = self._cfg.getSettings(Config.QT_PLATFORM_PLUGIN)
        if qt_platform is not None and qt_platform != "":
            self.comboUIQtPlatform.setCurrentText(qt_platform)

        self.checkAutostart.setChecked(self._autostart.isEnabled())

        maxmsgsize = self._cfg.getSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH)
        if maxmsgsize:
            self.comboGrpcMsgSize.setCurrentText(maxmsgsize)
        else:
            self.comboGrpcMsgSize.setCurrentIndex(0)

        server_addr = self._cfg.getSettings(Config.DEFAULT_SERVER_ADDR)
        if server_addr == "" or server_addr == None:
            server_addr = self.comboServerAddr.itemText(0)
        self.comboServerAddr.setCurrentText(server_addr)

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
            #self.comboNodeDuration.setCurrentText(node_config['DefaultDuration'])
            self.comboNodeMonitorMethod.setCurrentText(node_config['ProcMonitorMethod'])
            self.checkInterceptUnknown.setChecked(node_config['InterceptUnknown'])
            self.checkInterceptLoopback.setChecked(node_config['InterceptLoopback'])
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

            rules = node_config.get('Rules')
            if rules == None:
                rules = {}
            if rules.get('EnableChecksums') == None:
                rules['EnableChecksums'] = False
            if rules.get('Path') == None or rules.get('Path') == "":
                rules['Path'] = DefaultRulesPath
            node_config['Rules'] = rules

            self.enableChecksums.setChecked(rules.get('EnableChecksums'))
            self.lineNodeRulesPath.setText(rules.get('Path'))

            internal = node_config.get('Internal')
            if internal == None:
                internal = {}
            if internal.get('FlushConnsOnStart') == None:
                internal['FlushConnsOnStart'] = False
            if internal.get('GCPercent') == None:
                internal['GCPercent'] = 100
            node_config['Internal'] = internal

            self.checkNodeFlushConns.setChecked(internal.get('FlushConnsOnStart'))
            self.spinNodeGC.setValue(internal.get('GCPercent'))

            fwOptions = node_config.get('FwOptions')
            if fwOptions == None:
                fwOptions = {}
            if fwOptions.get('MonitorInterval') == None or fwOptions.get('MonitorInterval') == "":
                fwOptions['MonitorInterval'] = "15s"
            if fwOptions.get('QueueBypass') == None:
                fwOptions['QueueBypass'] = True
            node_config['FwOptions'] = fwOptions

            monInterval = fwOptions['MonitorInterval'][:-1]
            self.lineNodeFwMonInterval.setText(monInterval)
            self.checkNodeBypassQueue.setChecked(not fwOptions.get('QueueBypass'))

            stats = node_config.get('Stats')
            if stats == None:
                stats = {}
            if stats.get('MaxEvents') == None:
                stats['MaxEvents'] = 250
            if stats.get('MaxStats') == None:
                stats['MaxStats'] = 50
            node_config['Stats'] = stats

            self.lineNodeMaxEvents.setText(str(node_config['Stats']['MaxEvents']))
            self.lineNodeMaxStats.setText(str(node_config['Stats']['MaxStats']))

            self._node_list[addr]['data'].config = json.dumps(node_config, indent="    ")

        except Exception as e:
            print(self.LOG_TAG + "exception loading config: ", e)
            self._set_status_error(QC.translate("preferences", "Error loading config: {0}".format(e)))

    def _load_node_config(self, addr):
        """load the config of a node before sending it back to the node"""
        try:
            if self.comboNodeAddress.currentText() == "":
                return None, QC.translate("preferences", "Server address can not be empty")

            node_action = Config.ACTION_DENY
            if self.comboNodeAction.currentIndex() == Config.ACTION_ALLOW_IDX:
                node_action = Config.ACTION_ALLOW
            elif self.comboNodeAction.currentIndex() == Config.ACTION_REJECT_IDX:
                node_action = Config.ACTION_REJECT

            node_duration = Config.DURATION_ONCE

            node_conf = self._nodes.get_node_config(addr)
            if node_conf == None:
                return None, " "
            node_config = json.loads(node_conf)
            node_config['DefaultAction'] = node_action
            node_config['DefaultDuration'] = node_duration
            node_config['ProcMonitorMethod'] = self.comboNodeMonitorMethod.currentText()
            node_config['LogLevel'] = self.comboNodeLogLevel.currentIndex()
            node_config['LogUTC'] = self.checkNodeLogUTC.isChecked()
            node_config['LogMicro'] = self.checkNodeLogMicro.isChecked()
            node_config['InterceptUnknown'] = self.checkInterceptUnknown.isChecked()
            node_config['InterceptLoopback'] = self.checkInterceptLoopback.isChecked()

            if node_config.get('Server') != None:
                # skip setting Server Address if we're applying the config to all nodes
                node_config['Server']['Address'] = self.comboNodeAddress.currentText()
                node_config['Server']['LogFile'] = self.comboNodeLogFile.currentText()

                cfg = self._save_node_auth_config(node_config['Server'])
                if cfg != None:
                    node_config['Server'] = cfg
            else:
                print(addr, " doesn't have Server item")

            rules = node_config.get('Rules')
            if rules == None:
                rules = {}
            if rules.get('EnableChecksums') == None:
                rules['EnableChecksums'] = False
                self.enableChecksums.setChecked(False)
            if rules.get('Path') == None or rules.get('Path') == "":
                rules['Path'] = DefaultRulesPath
                self.lineNodeRulesPath.setText(DefaultRulesPath)

            rules['EnableChecksums'] = self.enableChecksums.isChecked()
            rules['Path'] = self.lineNodeRulesPath.text()
            node_config['Rules'] = rules

            internal = node_config.get('Internal')
            if internal == None:
                internal = {}
            if internal.get('FlushConnsOnStart') == None:
                internal['FlushConnsOnStart'] = False
                self.checkNodeFlushConns.setChecked(False)
            if internal.get('GCPercent') == None:
                internal['GCPercent'] = 100
                self.spinNodeGC.setValue(100)

            internal['FlushConnsOnStart'] = self.checkNodeFlushConns.isChecked()
            internal['GCPercent'] = self.spinNodeGC.value()
            node_config['Internal'] = internal

            fwOptions = node_config.get('FwOptions')
            if fwOptions == None:
                fwOptions = {}
            if fwOptions.get('MonitorInterval') == None:
                fwOptions['MonitorInterval'] = "15s"
            if fwOptions.get('QueueBypass') == None:
                fwOptions['QueueBypass'] = True
            node_config['FwOptions'] = fwOptions

            fwOptions['QueueBypass'] = not self.checkNodeBypassQueue.isChecked()
            fwOptions['MonitorInterval'] = self.lineNodeFwMonInterval.text() + "s"

            stats = node_config.get('Stats')
            if stats == None:
                stats = {}
            if stats.get('MaxEvents') == None:
                stats['MaxEvents'] = 250
                self.lineNodeMaxEvents.setText("250")
            if stats.get('MaxStats') == None:
                stats['MaxStats'] = 50
                self.lineNodeMaxStats.setText("50")

            stats['MaxEvents'] = int(self.lineNodeMaxEvents.text())
            stats['MaxStats'] = int(self.lineNodeMaxStats.text())
            node_config['Stats'] = stats

            return json.dumps(node_config, indent="    "), None
        except Exception as e:
            print(self.LOG_TAG + "exception loading node config on %s: " % addr, e)
            self._set_status_error(QC.translate("preferences", "Error loading node config: {0}".format(e)))

        return None, QC.translate("preferences", "Error loading {0} configuration").format(addr)

    def _load_node_auth_settings(self, config):
        try:
            if config == None:
                return

            auth = config.get('Authentication')
            authtype_idx = 0
            if auth != None:
                if auth.get('Type') != None:
                    authtype_idx = self.comboNodeAuthType.findData(auth['Type'])
            else:
                config['Authentication'] = {}
                auth = config.get('Authentication')

            self.lineNodeCACertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeServerCertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeCertFile.setEnabled(authtype_idx >= 0)
            self.lineNodeCertKeyFile.setEnabled(authtype_idx >= 0)

            tls = auth.get('TLSOptions')
            if tls != None and authtype_idx >= 0:
                if tls.get('CACert') != None:
                    self.lineNodeCACertFile.setText(tls['CACert'])
                if tls.get('ServerCert') != None:
                    self.lineNodeServerCertFile.setText(tls['ServerCert'])
                if tls.get('ClientCert') != None:
                    self.lineNodeCertFile.setText(tls['ClientCert'])
                if tls.get('ClientKey') != None:
                    self.lineNodeCertKeyFile.setText(tls['ClientKey'])
                if tls.get('SkipVerify') != None:
                    self.checkNodeAuthSkipVerify.setChecked(tls['SkipVerify'])

                if tls.get('ClientAuthType') != None:
                    clienttype_idx = self.comboNodeAuthVerifyType.findData(tls['ClientAuthType'])
                    if clienttype_idx >= 0:
                        self.comboNodeAuthVerifyType.setCurrentIndex(clienttype_idx)

            self.comboNodeAuthType.setCurrentIndex(authtype_idx)
            # signals are connected after this method is called
            self._cb_combo_node_auth_type_changed(authtype_idx)
        except Exception as e:
            print("[prefs] load node auth options exception:", e)
            self._set_status_error(QC.translate("preferences", "Error loading node auth config: {0}".format(e)))

    def _save_node_auth_config(self, config):
        try:
            auth = config.get('Authentication')
            if auth == None:
                auth = {}

            auth['Type'] = self.NODE_AUTH[self.comboNodeAuthType.currentIndex()]
            tls = auth.get('TLSOptions')
            if tls == None:
                tls = {}

            tls['CACert'] = self.lineNodeCACertFile.text()
            tls['ServerCert'] = self.lineNodeServerCertFile.text()
            tls['ClientCert'] = self.lineNodeCertFile.text()
            tls['ClientKey'] = self.lineNodeCertKeyFile.text()
            tls['SkipVerify'] = self.checkNodeAuthSkipVerify.isChecked()
            tls['ClientAuthType'] = self.NODE_AUTH_VERIFY[self.comboNodeAuthVerifyType.currentIndex()]
            auth['TLSOptions'] = tls
            config['Authentication'] = auth

            return config
        except Exception as e:
            print("[prefs] node auth options exception:", e)
            self._set_status_error(str(e))
            return None

    def _load_ui_columns_config(self):
        cols = self._cfg.getSettings(Config.STATS_SHOW_COLUMNS)
        if cols == None:
            return

        for c in range(13):
            checked = str(c) in cols

            if c == 0:
                self.checkHideTime.setChecked(checked)
            elif c == 1:
                self.checkHideNode.setChecked(checked)
            elif c == 2:
                self.checkHideAction.setChecked(checked)
            elif c == 3:
                self.checkHideSrcPort.setChecked(checked)
            elif c == 4:
                self.checkHideSrcIP.setChecked(checked)
            elif c == 5:
                self.checkHideDstIP.setChecked(checked)
            elif c == 6:
                self.checkHideDstHost.setChecked(checked)
            elif c == 7:
                self.checkHideDstPort.setChecked(checked)
            elif c == 8:
                self.checkHideProto.setChecked(checked)
            elif c == 9:
                self.checkHideUID.setChecked(checked)
            elif c == 10:
                self.checkHidePID.setChecked(checked)
            elif c == 11:
                self.checkHideProc.setChecked(checked)
            elif c == 12:
                self.checkHideCmdline.setChecked(checked)
            elif c == 13:
                self.checkHideRule.setChecked(checked)

    def _reset_node_settings(self):
        self.comboNodeAction.setCurrentIndex(0)
        #self.comboNodeDuration.setCurrentIndex(0)
        self.comboNodeMonitorMethod.setCurrentIndex(0)
        self.checkInterceptUnknown.setChecked(False)
        self.checkInterceptLoopback.setChecked(False)
        self.comboNodeLogLevel.setCurrentIndex(0)
        self.checkNodeLogUTC.setChecked(True)
        self.checkNodeLogMicro.setChecked(False)
        self.labelNodeName.setText("")
        self.labelNodeVersion.setText("")
        self.comboNodeAuthType.setCurrentIndex(self.AUTH_SIMPLE)
        self.lineNodeCACertFile.setText("")
        self.lineNodeServerCertFile.setText("")
        self.lineNodeCertFile.setText("")
        self.lineNodeCertKeyFile.setText("")
        self.checkNodeAuthSkipVerify.setChecked(False)
        self.comboNodeAuthVerifyType.setCurrentIndex(0)
        self._cb_combo_node_auth_type_changed(0)

    def _save_settings(self):
        self._reset_status_message()
        self._save_ui_config()
        if not self._save_db_config():
            return
        self._save_nodes_config()

        self._set_status_successful(QC.translate("preferences", "Configuration applied."))
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
            mmsize_saved = self._cfg.getSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH)
            if maxmsgsize != "" and mmsize_saved != maxmsgsize:
                self._cfg.setSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH, maxmsgsize.replace(" ", ""))
                self._changes_needs_restart = QC.translate("preferences", "Server options changed")

            savedauthtype = self._cfg.getSettings(Config.AUTH_TYPE)
            authtype = self.comboAuthType.itemData(self.comboAuthType.currentIndex())
            cacert = self._cfg.getSettings(Config.AUTH_CA_CERT)
            cert = self._cfg.getSettings(Config.AUTH_CERT)
            certkey = self._cfg.getSettings(Config.AUTH_CERTKEY)
            if not self._validate_certs():
                return

            server_addr = self._cfg.getSettings(Config.DEFAULT_SERVER_ADDR)
            if self.comboServerAddr.currentText() != server_addr:
                self._cfg.setSettings(Config.DEFAULT_SERVER_ADDR, self.comboServerAddr.currentText())
                self._changes_needs_restart = QC.translate("preferences", "Server address changed")

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

            self._themes.save_theme(self.comboUITheme.currentIndex(), self.comboUITheme.currentText(), str(self.spinUIDensity.value()))

            qt_platform = self._cfg.getSettings(Config.QT_PLATFORM_PLUGIN)
            if qt_platform != self.comboUIQtPlatform.currentText():
                self._changes_needs_restart = QC.translate("preferences", "Qt platform plugin changed")
            self._cfg.setSettings(Config.QT_PLATFORM_PLUGIN, self.comboUIQtPlatform.currentText())
            self._cfg.setSettings(Config.QT_AUTO_SCREEN_SCALE_FACTOR, bool(self.checkUIAutoScreen.isChecked()))
            self._cfg.setSettings(Config.QT_SCREEN_SCALE_FACTOR, self.lineUIScreenFactor.text())

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
        if self.checkHideSrcPort.isChecked():
            cols.append("3")
        if self.checkHideSrcIP.isChecked():
            cols.append("4")
        if self.checkHideDstIP.isChecked():
            cols.append("5")
        if self.checkHideDstHost.isChecked():
            cols.append("6")
        if self.checkHideDstPort.isChecked():
            cols.append("7")
        if self.checkHideProto.isChecked():
            cols.append("8")
        if self.checkHideUID.isChecked():
            cols.append("9")
        if self.checkHidePID.isChecked():
            cols.append("10")
        if self.checkHideProc.isChecked():
            cols.append("11")
        if self.checkHideCmdline.isChecked():
            cols.append("12")
        if self.checkHideRule.isChecked():
            cols.append("13")

        self._cfg.setSettings(Config.STATS_SHOW_COLUMNS, cols)

    def _save_nodes_config(self):
        addr = self.comboNodes.currentText()
        if (self._node_needs_update or self.checkApplyToNodes.isChecked()) and addr != "":
            self._set_status_message(QC.translate("preferences", "Saving configuration..."))
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
            if self._nodes.count() == 0:
                return
            self._set_status_message(QC.translate("preferences", "Applying configuration on {0} ...").format(addr))
            notifObject.data, error = self._load_node_config(addr)
            if error != None:
                return error

            # exclude this message if there're more than one node connected
            # XXX: unix:/local is a special name for the node, when the gRPC
            # does not return the correct address of the node.
            if (self.comboNodes.currentText() != "unix:/local" and self.comboNodes.currentText() != self.comboNodeAddress.currentText()) or \
                    self.comboServerAddr.currentText() != self.comboNodeAddress.currentText():
                self._changes_needs_restart = QC.translate("preferences", "Node address changed (update GUI address if needed)")

            self._nodes.save_node_config(addr, notifObject.data)
            nid = self._nodes.send_notification(addr, notifObject, self._notification_callback)
            self._notifications_sent[nid] = notifObject

        except Exception as e:
            print(self.LOG_TAG + "exception saving node config on %s: " % addr, e)
            self._set_status_error(QC.translate("preferences", "Exception saving node config {0}: {1}").format((addr, str(e))))
            return addr + ": " + str(e)

        return None

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


    def _show_ui_density_widgets(self, idx):
        """show ui density widget only for qt-material themes:
            https://github.com/UN-GCPDS/qt-material?tab=readme-ov-file#density-scale
        """
        hidden = idx == 0
        self.labelUIDensity.setHidden(hidden)
        self.spinUIDensity.setHidden(hidden)
        self.cmdUIDensityUp.setHidden(hidden)
        self.cmdUIDensityDown.setHidden(hidden)

    def _show_ui_scalefactor_widgets(self, show=False):
        self.labelUIScreenFactor.setHidden(show)
        self.lineUIScreenFactor.setHidden(show)

    def _hide_status_label(self):
        self.statusLabel.hide()

    def _show_status_label(self):
        self.statusLabel.show()

    def _set_status_error(self, msg):
        self._show_status_label()
        self.statusLabel.setStyleSheet('color: red')
        self.statusLabel.setText(msg)
        QtWidgets.QApplication.processEvents()

    def _set_status_successful(self, msg):
        self._show_status_label()
        self.statusLabel.setStyleSheet('color: green')
        self.statusLabel.setText(msg)
        QtWidgets.QApplication.processEvents()

    def _set_status_message(self, msg):
        self._show_status_label()
        self.statusLabel.setStyleSheet('color: darkorange')
        self.statusLabel.setText(msg)
        QtWidgets.QApplication.processEvents()

    def _reset_status_message(self):
        self.statusLabel.setText("")
        self._hide_status_label()
        # force widgets repainting
        QtWidgets.QApplication.processEvents()

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

    def _change_theme(self):
        extra_opts = {
            'density_scale': str(self.spinUIDensity.value())
        }
        self._themes.change_theme(self, self.comboUITheme.currentText(), extra_opts)

    @QtCore.pyqtSlot(str, ui_pb2.NotificationReply)
    def _cb_notification_callback(self, addr, reply):
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

    def _cb_cmd_node_rulespath_clicked(self):
        rulesdir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            os.path.expanduser("~"),
            QC.translate("preferences", 'Select a directory containing rules'),
            QtWidgets.QFileDialog.ShowDirsOnly | QtWidgets.QFileDialog.DontResolveSymlinks
        )
        if rulesdir == "":
            return

        self._node_needs_update = True
        self.lineNodeRulesPath.setText(rulesdir)

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

    def _cb_ui_check_rules_toggled(self, state):
        self.comboUIRules.setEnabled(state)

    def _cb_combo_themes_changed(self, index):
        self._change_theme()
        self._show_ui_density_widgets(index)

    def _cb_spin_uidensity_changed(self, value):
        self._change_theme()

    def _cb_ui_check_auto_scale_toggled(self, checked):
        self._changes_needs_restart = QC.translate("preferences", "Auto scale option changed")
        self._show_ui_scalefactor_widgets(checked)

    def _cb_ui_screen_factor_changed(self, text):
        self._changes_needs_restart = QC.translate("preferences", "Screen factor option changed")

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

        if spinWidget == self.popupsCheck:
            enablePopups = spinWidget.value() > 0
            self.popupsCheck.setChecked(not enablePopups)
            self.spinUITimeout.setEnabled(enablePopups)
            self._node_needs_update = True

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
