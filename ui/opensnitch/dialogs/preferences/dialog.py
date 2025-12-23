import sys
import os

from PyQt6 import QtCore, QtGui, uic, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.database import Database
from opensnitch.customwidgets.itemwidgetcentered import IconTextItem
from opensnitch.utils import (
    Icons,
    logger
)
from opensnitch.utils.xdg import Autostart
from opensnitch.utils.themes import Themes
from opensnitch.notifications import DesktopNotifications

from opensnitch import auth
import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from . import (
    signals,
    utils,
    settings,
)
from .sections import (
    ui as section_ui,
    db as section_db,
    nodes as section_nodes
)

DIALOG_UI_PATH = "%s/../../res/preferences.ui" % os.path.dirname(sys.modules[__name__].__file__)
class PreferencesDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    _notification_callback = QtCore.pyqtSignal(str, ui_pb2.NotificationReply)
    saved = QtCore.pyqtSignal()

    TAB_POPUPS = 0
    TAB_UI = 1
    TAB_SERVER = 2
    TAB_RULES = 3
    TAB_NODES = 4
    TAB_DB = 5

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
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowType.WindowStaysOnTopHint)

        self.themes = Themes.instance()
        self.saved_theme = ""
        # fixed message. Do not change it dynamically.
        self.restart_msg = QC.translate("preferences", "Restart the GUI in order changes to take effect")
        self.changes_needs_restart = None
        self.settingsSaved = False
        # True when any node option changes
        self.node_needs_update = False
        self.settings_changed = False
        self.loading_settings = False


        self.logger = logger.get(__name__)
        self.cfgMgr = Config.get()
        self.nodes = Nodes.instance()
        self.db = Database.instance()
        self._autostart = Autostart()

        self._notification_callback.connect(self.cb_notification_callback)
        self._notifications_sent = {}
        self.desktop_notifications = DesktopNotifications()

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

        signals.connect_all(self)
        self.helpButton.setToolTipDuration(30 * 1000)

        self.comboAuthType.currentIndexChanged.connect(self.cb_combo_auth_type_changed)
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

        self.comboUIRules.currentIndexChanged.connect(self.cb_combo_uirules_changed)

        # XXX: disable Node duration. It will be removed in the future
        self.comboNodeDuration.setVisible(False)
        self.labelNodeDuration.setVisible(False)

        saveIcon = Icons.new(self, "document-save")
        applyIcon = Icons.new(self, "emblem-default")
        delIcon = Icons.new(self, "edit-delete")
        closeIcon = Icons.new(self, "window-close")
        openIcon = Icons.new(self, "document-open")
        helpIcon = Icons.new(self, "help-browser")
        allowIcon = Icons.new(self, "emblem-default")
        denyIcon = Icons.new(self, "emblem-important")
        rejectIcon = Icons.new(self, "window-close")
        self.applyButton.setIcon(applyIcon)
        self.cancelButton.setIcon(closeIcon)
        self.acceptButton.setIcon(saveIcon)
        self.helpButton.setIcon(helpIcon)
        self.dbFileButton.setIcon(openIcon)

        self.comboUIAction.setItemIcon(Config.ACTION_DENY_IDX, denyIcon)
        self.comboUIAction.setItemIcon(Config.ACTION_ALLOW_IDX, allowIcon)
        self.comboUIAction.setItemIcon(Config.ACTION_REJECT_IDX, rejectIcon)

        leftOpts = [
            {
                'icon': Icons.new(self, 'pop-ups'),
                'text': QC.translate('preferences', 'Pop-ups')
            },
            {
                'icon': Icons.new(self, 'window-new'),
                'text': QC.translate('preferences', 'UI')
            },
            {
                'icon': Icons.new(self, 'network-server'),
                'text': QC.translate('preferences', 'Server')
            },
            {
                'icon': Icons.new(self, 'format-justify-fill'),
                'text': QC.translate('preferences', 'Rules')
            },
            {
                'icon': Icons.new(self, 'computer'),
                'text': QC.translate('preferences', 'Nodes')
            },
            {
                'icon': Icons.new(self, 'drive-harddisk'),
                'text': QC.translate('preferences', 'Database')
            }
        ]
        self.listWidget.setIconSize(QtCore.QSize(64, 64))
        for opt in leftOpts:
            item = QtWidgets.QListWidgetItem(self.listWidget)
            widget = IconTextItem(opt['icon'], opt['text'], size=24)
            item.setSizeHint(QtCore.QSize(64, 64))
            widget.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Maximum,
                QtWidgets.QSizePolicy.Policy.Expanding
            )
            self.listWidget.addItem(item)
            self.listWidget.setItemWidget(item, widget)

        self.listWidget.itemClicked.connect(self.cb_list_item_activated)
        cmdNodeCorner = QtWidgets.QPushButton("", objectName="cmdNodeCorner")
        cmdNodeCorner.setFlat(True)
        cmdNodeCorner.setIcon(Icons.new(parent, "document-save"))
        cmdNodeCorner.setToolTip(QC.translate("preferences", "Save these settings"))
        cmdNodeCorner.setVisible(False)
        self.tabNodeWidget.setCornerWidget(cmdNodeCorner)
        w = self.splitter.width()
        self.splitter.setSizes([int(w/3), w])

    def showEvent(self, event):
        super(PreferencesDialog, self).showEvent(event)
        self.init()

    def add_section(self, widget, icon, lbl):
        """adds a new tab to the Preferences, and returns the new index"""
        return self.stackedWidget.addTab(widget, icon, lbl)

    def insert_section(self, idx, widget, lbl):
        """inserts a new tab at the given index"""
        return self.stackedWidget.insertTab(idx, widget, lbl)

    def remove_section(self, idx):
        """removes a tab"""
        return self.stackedWidget.removeTab(idx)

    def enable_section(self, idx, enable):
        """enables or disables a tab"""
        return self.stackedWidget.setTabEnabled(idx, enable)

    def set_section_title(self, idx, text):
        """changes the title of a tab"""
        return self.stackedWidget.setTabText(idx, text)

    def set_section_visible(self, idx, visible):
        """makes the tab visible or not"""
        return self.stackedWidget.setTabVisible(idx, visible)

    def get_section(self, idx):
        """returns the widget of the given index"""
        return self.stackedWidget.widget(idx)

    def show_node_prefs(self, addr):
        """opens the dialog going directly to the Nodes tab"""
        self.show()
        nIdx = self.comboNodes.findData(addr)
        if nIdx != -1:
            self.comboNodes.setCurrentIndex(nIdx)
            self.stackedWidget.setCurrentIndex(self.TAB_NODES)

    def init(self):
        self.loading_settings = True
        try:
            self.changes_needs_restart = None
            self.node_needs_update = False
            self.settingsSaved = False
            self.settings_changed = False
            utils.reset_status_message(self)
            utils.hide_status_label(self)
            self.comboNodes.clear()

            section_ui.load_langs(self)

            self.comboNodeAddress.clear()
            self.comboServerAddr.clear()
            run_path = "/run/user/{0}/opensnitch/".format(os.getuid())
            var_run_path = f"/var{run_path}"
            self.comboNodeAddress.addItem("unix:///tmp/osui.sock")
            self.comboServerAddr.addItem("unix:///tmp/osui.sock")
            if os.path.exists(run_path):
                self.comboNodeAddress.addItem(f"unix://{run_path}/osui.sock")
                self.comboServerAddr.addItem(f"unix://{run_path}/osui.sock")
            if os.path.exists(var_run_path):
                self.comboNodeAddress.addItem(f"unix://{var_run_path}/osui.sock")
                self.comboServerAddr.addItem(f"unix://{var_run_path}/osui.sock")

            section_nodes.load(self)
            settings.load(self)
        except Exception as e:
            self.logger.warning("exception loading nodes: %s", repr(e))

        self.loading_settings = False

    @QtCore.pyqtSlot(str, ui_pb2.NotificationReply)
    def cb_notification_callback(self, addr, reply):
        self.logger.debug("new ntf reply: %s, %s", addr, reply)
        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.OK:
                utils.set_status_successful(self, QC.translate("preferences", "Configuration applied."))
            else:
                utils.set_status_error(self, QC.translate("preferences", "Error applying configuration: {0}").format(reply.data))

            del self._notifications_sent[reply.id]
        else:
            self.logger.debug("ntf reply not in the list: %s, %s", addr, reply)

    def cb_list_item_activated(self, item):
        idx = self.listWidget.currentRow()
        self.stackedWidget.setCurrentIndex(idx)

    def cb_line_certs_changed(self, text):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "Certs changed")

    def cb_node_line_certs_changed(self, text):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "Node certs changed")
        self.node_needs_update = True

    def cb_cmd_node_rulespath_clicked(self):
        rulesdir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            os.path.expanduser("~"),
            QC.translate("preferences", 'Select a directory containing rules'),
            QtWidgets.QFileDialog.Option.ShowDirsOnly | QtWidgets.QFileDialog.Option.DontResolveSymlinks
        )
        if rulesdir == "":
            return

        self.node_needs_update = True
        self.lineNodeRulesPath.setText(rulesdir)

    def cb_file_db_clicked(self):
        fileName, _ = QtWidgets.QFileDialog.getSaveFileName(self, "", "","All Files (*)")
        if fileName:
            self.dbLabel.setText(fileName)
        self.changes_needs_restart = QC.translate("preferences", "DB file changed")

    def cb_combo_uirules_changed(self, idx):
        if self.loading_settings:
            return
        self.cfgMgr.setRulesDurationFilter(
            self.cfgMgr.getBool(self.cfgMgr.DEFAULT_IGNORE_RULES),
            idx
            #self.cfgMgr.getInt(self.cfgMgr.DEFAULT_IGNORE_TEMPORARY_RULES)
        )

    def cb_db_type_changed(self):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "DB type changed")
        section_db.type_changed(self)

    def cb_accept_button_clicked(self):
        self.accept()
        if not self.settingsSaved:
            settings.save(self)

    def cb_apply_button_clicked(self):
        settings.save(self)

    def cb_cancel_button_clicked(self):
        self.reject()

    def cb_help_button_clicked(self):
        utils.show_help()

    def cb_popups_check_toggled(self, checked):
        if self.loading_settings:
            return
        self.settings_changed = True
        self.spinUITimeout.setEnabled(not checked)
        if not checked:
            self.spinUITimeout.setValue(20)

    def cb_node_combo_changed(self, index):
        if self.loading_settings:
            return
        section_nodes.load_node_settings(self)

    def cb_node_needs_update(self):
        if self.loading_settings:
            return
        self.node_needs_update = True

    def cb_server_settings_changed(self):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "Server settings changed")

    def cb_ui_check_rules_toggled(self, state):
        if self.loading_settings:
            return
        self.comboUIRules.setEnabled(state)

    def cb_combo_themes_changed(self, index):
        if self.loading_settings:
            return
        section_ui.change_theme(self)
        section_ui.show_ui_density_widgets(self, index)

    def cb_spin_uidensity_changed(self, value):
        if self.loading_settings:
            return
        section_ui.change_theme(self)

    def cb_ui_check_auto_scale_toggled(self, checked):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "Auto scale option changed")
        section_ui.show_ui_scalefactor_widgets(self, checked)

    def cb_ui_screen_factor_changed(self, text):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "Screen factor option changed")

    def cb_combo_auth_type_changed(self, index):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "Server auth type changed")
        utils.config_server_auth_type(self, index)

    def cb_combo_node_auth_type_changed(self, index):
        if self.loading_settings:
            return
        section_nodes.config_auth_type(self, index)

    def cb_db_max_days_toggled(self, state):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "DB max days changed")
        section_db.enable_db_cleaner_options(self, state, 1)

    def cb_db_jrnl_wal_toggled(self, state):
        if self.loading_settings:
            return
        self.changes_needs_restart = QC.translate("preferences", "DB journal_mode changed")

    def cb_cmd_spin_clicked(self, spinWidget, operation):
        utils.cmd_spin_clicked(self, spinWidget, operation)

    def cb_radio_system_notifications(self):
        utils.configure_notifications(self)

    def cb_test_notifs_clicked(self):
        utils.test_notifications(self)
