import datetime
import os
import json

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.version import version
from opensnitch.nodes import Nodes
from opensnitch.firewall import Firewall
from opensnitch.database.enums import AlertFields
from opensnitch.dialogs.firewall import FirewallDialog
from opensnitch.dialogs.preferences import PreferencesDialog
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
from opensnitch.dialogs.processdetails import ProcessDetailsDialog
from opensnitch.customwidgets.firewalltableview import FirewallTableModel
from opensnitch.customwidgets.generictableview import GenericTableModel
from opensnitch.customwidgets.addresstablemodel import AddressTableModel
from opensnitch.customwidgets.netstattablemodel import NetstatTableModel
from opensnitch.utils import Message, QuickHelp, AsnDB, Icons
from opensnitch.utils.infowindow import InfoWindow
from opensnitch.utils.xdg import xdg_current_desktop
from opensnitch.actions import Actions
from opensnitch.plugins import PluginBase
from opensnitch.rules import Rule, Rules

from . import (
    constants,
    menus,
    menu_actions,
    queries,
    views
)

from .tasks import (
    netstat,
    nodemon
)

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

class StatsDialog(menus.MenusManager, menu_actions.MenuActions, views.ViewsManager):

    settings_saved = QtCore.pyqtSignal()
    close_trigger = QtCore.pyqtSignal()
    _trigger = QtCore.pyqtSignal(bool, bool)
    _status_changed_trigger = QtCore.pyqtSignal(bool)
    _shown_trigger = QtCore.pyqtSignal()
    _notification_trigger = QtCore.pyqtSignal(ui_pb2.Notification)
    _notification_callback = QtCore.pyqtSignal(str, ui_pb2.NotificationReply)

    # FIXME: don't translate, used only for default argument on _update_status_label
    FIREWALL_DISABLED = "Disabled"

    def __init__(self, parent=None, address=None, db=None, dbname="db", appicon=None):
        super(StatsDialog, self).__init__(parent)
        self.setWindowFlags(QtCore.Qt.WindowType.Window)

        self.setWindowIcon(appicon)
        self.appicon = appicon

        self._db = db
        self._db_sqlite = self._db.get_db()
        self._db_name = dbname

        self.asndb = AsnDB.instance()

        self._nodes = Nodes.instance()
        self._fw = Firewall().instance()
        self._rules = Rules.instance()
        self._fw.rules.rulesUpdated.connect(self._cb_fw_rules_updated)
        self._nodes.nodesUpdated.connect(self._cb_nodes_updated)
        self._rules.updated.connect(self._cb_app_rules_updated)
        self._actions = Actions().instance()
        self._action_list = self._actions.getByType(PluginBase.TYPE_MAIN_DIALOG)

        self.netstat = netstat.Netstat(self, self.cfg, self._db)

        # TODO: allow to display multiples dialogs
        self._proc_details_dialog = ProcessDetailsDialog(appicon=appicon)
        # TODO: allow to navigate records by offsets
        self.prevButton.setVisible(False)
        self.nextButton.setVisible(False)


        self.fwTable.setVisible(False)
        self.alertsTable.setVisible(False)
        self.rulesTable.setVisible(True)

        self.daemon_connected = False

        self._address = address
        self._stats = None

        self._fw_dialog = None
        self._prefs_dialog = None
        #self._prefs_dialog = PreferencesDialog(appicon=appicon)
        #self._prefs_dialog.saved.connect(self._on_settings_saved)
        self._rules_dialog = RulesEditorDialog(appicon=appicon)
        self._trigger.connect(self._on_update_triggered)
        self._notification_callback.connect(self._cb_notification_callback)

        self.nodeLabel.setText("")
        self.nodeLabel.setStyleSheet('color: green;font-size:12pt; font-weight:600;')
        self.rulesSplitter.setStretchFactor(0,0)
        self.rulesSplitter.setStretchFactor(1,4)
        self.nodesSplitter.setStretchFactor(0,0)
        self.nodesSplitter.setStretchFactor(0,3)
        self.rulesTreePanel.resizeColumnToContents(1)
        self.rulesTreePanel.itemExpanded.connect(self._cb_rules_tree_item_expanded)

        self.startButton.clicked.connect(self._cb_start_clicked)
        self.nodeStartButton.clicked.connect(self._cb_node_start_clicked)
        self.nodeStartButton.setVisible(False)
        self.nodePrefsButton.setVisible(False)
        self.nodeActionsButton.setVisible(False)
        self.nodeDeleteButton.setVisible(False)
        self.nodeDeleteButton.clicked.connect(self._cb_node_delete_clicked)
        self.prefsButton.clicked.connect(self._cb_prefs_clicked)
        self.nodePrefsButton.clicked.connect(self._cb_node_prefs_clicked)
        self.fwButton.clicked.connect(lambda: self.open_firewall())
        self.comboAction.currentIndexChanged.connect(self._cb_combo_action_changed)
        self.limitCombo.currentIndexChanged.connect(self._cb_limit_combo_changed)
        self.tabWidget.currentChanged.connect(self._cb_tab_changed)
        self.delRuleButton.clicked.connect(self._cb_del_rule_clicked)
        self.rulesSplitter.splitterMoved.connect(lambda pos, index: self._cb_splitter_moved( constants.TAB_RULES, pos, index))
        self.nodesSplitter.splitterMoved.connect(lambda pos, index: self._cb_splitter_moved( constants.TAB_NODES, pos, index))
        self.rulesTreePanel.itemClicked.connect(self._cb_rules_tree_item_clicked)
        self.rulesTreePanel.itemDoubleClicked.connect(self._cb_rules_tree_item_double_clicked)
        self.enableRuleCheck.clicked.connect(self._cb_enable_rule_toggled)
        self.editRuleButton.clicked.connect(self._cb_edit_rule_clicked)
        self.newRuleButton.clicked.connect(self._cb_new_rule_clicked)
        self.cmdProcDetails.clicked.connect(self._cb_proc_details_clicked)
        self.comboRulesFilter.currentIndexChanged.connect(self._cb_rules_filter_combo_changed)
        self.helpButton.clicked.connect(self._cb_help_button_clicked)
        self.nextButton.clicked.connect(self._cb_next_button_clicked)
        self.prevButton.clicked.connect(self._cb_prev_button_clicked)

        self.enableRuleCheck.setVisible(False)
        self.delRuleButton.setVisible(False)
        self.editRuleButton.setVisible(False)
        self.nodeRuleLabel.setVisible(False)
        self.comboRulesFilter.setVisible(False)

        self.configure_main_btn_menu()

        self.TABLES[constants.TAB_MAIN]['view'] = self.view_setup(
            self.eventsTable,
            self.TABLES[constants.TAB_MAIN]['name'],
            self.TABLES[constants.TAB_MAIN]['display_fields'],
            order_by=self.TABLES[constants.TAB_MAIN]['last_order_by'],
            group_by=self.TABLES[constants.TAB_MAIN]['group_by'],
            delegate=self.TABLES[constants.TAB_MAIN]['delegate'],
            resize_cols=(),
            model=GenericTableModel(
                self.TABLES[constants.TAB_MAIN]['name'],
                self.TABLES[constants.TAB_MAIN]['header_labels']
            ),
            verticalScrollBar=self.connectionsTableScrollBar,
            limit=self.get_view_limit()
            )
        self.TABLES[constants.TAB_NODES]['view'] = self.view_setup(
            self.nodesTable,
            self.TABLES[constants.TAB_NODES]['name'],
            fields=self.TABLES[constants.TAB_NODES]['display_fields'],
            order_by=self.TABLES[constants.TAB_NODES]['last_order_by'],
            resize_cols=(constants.COL_NODE,),
            model=GenericTableModel(
                self.TABLES[constants.TAB_NODES]['name'],
                self.TABLES[constants.TAB_NODES]['header_labels']
            ),
            verticalScrollBar=self.verticalScrollBar,
            sort_direction= constants.SORT_ORDER[1],
            delegate=self.TABLES[constants.TAB_NODES]['delegate'],
            tracking_column=self.TABLES[constants.TAB_NODES]['tracking_column'])
        self.TABLES[constants.TAB_RULES]['view'] = self.view_setup(
            self.rulesTable,
            self.TABLES[constants.TAB_RULES]['name'],
            fields=self.TABLES[constants.TAB_RULES]['display_fields'],
            model=GenericTableModel(
                self.TABLES[constants.TAB_RULES]['name'],
                self.TABLES[constants.TAB_RULES]['header_labels']
            ),
            verticalScrollBar=self.rulesScrollBar,
            delegate=self.TABLES[constants.TAB_RULES]['delegate'],
            order_by=self.TABLES[constants.TAB_RULES]['last_order_by'],
            sort_direction= constants.SORT_ORDER[0],
            tracking_column=self.TABLES[constants.TAB_RULES]['tracking_column'])
        self.TABLES[constants.TAB_FIREWALL]['view'] = self.view_setup(
            self.fwTable,
            self.TABLES[constants.TAB_FIREWALL]['name'],
            model=FirewallTableModel("firewall"),
            verticalScrollBar=None,
            delegate=self.TABLES[constants.TAB_FIREWALL]['delegate'],
            order_by=self.TABLES[constants.TAB_FIREWALL]['last_order_by'],
            sort_direction= constants.SORT_ORDER[0])
        self.TABLES[constants.TAB_ALERTS]['view'] = self.view_setup(
            self.alertsTable,
            self.TABLES[constants.TAB_ALERTS]['name'],
            fields=self.TABLES[constants.TAB_ALERTS]['display_fields'],
            model=GenericTableModel(
                self.TABLES[constants.TAB_ALERTS]['name'],
                self.TABLES[constants.TAB_ALERTS]['header_labels']
            ),
            verticalScrollBar=self.alertsScrollBar,
            delegate=self.TABLES[constants.TAB_ALERTS]['delegate'],
            order_by=self.TABLES[constants.TAB_ALERTS]['last_order_by'],
            sort_direction= constants.SORT_ORDER[0])
        self.TABLES[constants.TAB_HOSTS]['view'] = self.view_setup(
            self.hostsTable,
            self.TABLES[constants.TAB_HOSTS]['name'],
            model=GenericTableModel(
                self.TABLES[constants.TAB_HOSTS]['name'],
                self.TABLES[constants.TAB_HOSTS]['header_labels']
            ),
            verticalScrollBar=self.hostsScrollBar,
            resize_cols=(constants.COL_WHAT,),
            delegate=self.TABLES[constants.TAB_HOSTS]['delegate'],
            order_by=self.TABLES[constants.TAB_HOSTS]['last_order_by'],
            limit=self.get_view_limit()
            )
        self.TABLES[constants.TAB_PROCS]['view'] = self.view_setup(
            self.procsTable,
            self.TABLES[constants.TAB_PROCS]['name'],
            model=GenericTableModel(
                self.TABLES[constants.TAB_PROCS]['name'],
                self.TABLES[constants.TAB_PROCS]['header_labels']
            ),
            verticalScrollBar=self.procsScrollBar,
            resize_cols=(constants.COL_WHAT,),
            delegate=self.TABLES[constants.TAB_PROCS]['delegate'],
            order_by=self.TABLES[constants.TAB_PROCS]['last_order_by'],
            limit=self.get_view_limit()
            )
        self.TABLES[constants.TAB_ADDRS]['view'] = self.view_setup(
            self.addrTable,
            self.TABLES[constants.TAB_ADDRS]['name'],
            model=AddressTableModel(
                self.TABLES[constants.TAB_ADDRS]['name'],
                self.TABLES[constants.TAB_ADDRS]['header_labels']
            ),
            verticalScrollBar=self.addrsScrollBar,
            resize_cols=(constants.COL_WHAT,),
            delegate=self.TABLES[constants.TAB_ADDRS]['delegate'],
            order_by=self.TABLES[constants.TAB_ADDRS]['last_order_by'],
            limit=self.get_view_limit()
            )
        self.TABLES[constants.TAB_PORTS]['view'] = self.view_setup(
            self.portsTable,
            self.TABLES[constants.TAB_PORTS]['name'],
            model=GenericTableModel(
                self.TABLES[constants.TAB_PORTS]['name'],
                self.TABLES[constants.TAB_PORTS]['header_labels']
            ),
            verticalScrollBar=self.portsScrollBar,
            resize_cols=(constants.COL_WHAT,),
            delegate=self.TABLES[constants.TAB_PORTS]['delegate'],
            order_by=self.TABLES[constants.TAB_PORTS]['last_order_by'],
            limit=self.get_view_limit()
            )
        self.TABLES[constants.TAB_USERS]['view'] = self.view_setup(
            self.usersTable,
            self.TABLES[constants.TAB_USERS]['name'],
            model=GenericTableModel(
                self.TABLES[constants.TAB_USERS]['name'],
                self.TABLES[constants.TAB_USERS]['header_labels']
            ),
            verticalScrollBar=self.usersScrollBar,
            resize_cols=(constants.COL_WHAT,),
            delegate=self.TABLES[constants.TAB_USERS]['delegate'],
            order_by=self.TABLES[constants.TAB_USERS]['last_order_by'],
            limit=self.get_view_limit()
            )
        self.TABLES[constants.TAB_NETSTAT]['view'] = self.view_setup(
            self.netstatTable,
            self.TABLES[constants.TAB_NETSTAT]['name'],
            self.TABLES[constants.TAB_NETSTAT]['display_fields'],
            model=NetstatTableModel(
                self.TABLES[constants.TAB_NETSTAT]['name'],
                self.TABLES[constants.TAB_NETSTAT]['header_labels']
            ),
            verticalScrollBar=self.netstatScrollBar,
            #resize_cols=(),
            delegate=self.TABLES[constants.TAB_NETSTAT]['delegate'],
            order_by=self.TABLES[constants.TAB_NETSTAT]['last_order_by'],
            limit=self.get_view_limit(),
            tracking_column=self.TABLES[constants.TAB_NETSTAT]['tracking_column']
            )

        self.TABLES[constants.TAB_NODES]['label'] = self.nodesLabel
        self.TABLES[constants.TAB_RULES]['label'] = self.ruleLabel
        self.TABLES[constants.TAB_HOSTS]['label'] = self.hostsLabel
        self.TABLES[constants.TAB_PROCS]['label'] = self.procsLabel
        self.TABLES[constants.TAB_ADDRS]['label'] = self.addrsLabel
        self.TABLES[constants.TAB_PORTS]['label'] = self.portsLabel
        self.TABLES[constants.TAB_USERS]['label'] = self.usersLabel
        self.TABLES[constants.TAB_NETSTAT]['label'] = self.netstatLabel

        self.TABLES[constants.TAB_NODES]['cmd'] = self.cmdNodesBack
        self.TABLES[constants.TAB_RULES]['cmd'] = self.cmdRulesBack
        self.TABLES[constants.TAB_HOSTS]['cmd'] = self.cmdHostsBack
        self.TABLES[constants.TAB_PROCS]['cmd'] = self.cmdProcsBack
        self.TABLES[constants.TAB_ADDRS]['cmd'] = self.cmdAddrsBack
        self.TABLES[constants.TAB_PORTS]['cmd'] = self.cmdPortsBack
        self.TABLES[constants.TAB_USERS]['cmd'] = self.cmdUsersBack
        self.TABLES[constants.TAB_NETSTAT]['cmd'] = self.cmdNetstatBack

        self.TABLES[constants.TAB_MAIN]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_NODES]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_RULES]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_HOSTS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_PROCS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_ADDRS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_PORTS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_USERS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[constants.TAB_NETSTAT]['cmdCleanStats'] = self.cmdCleanSql
        # the rules clean button is only for a particular rule, not all.
        self.TABLES[constants.TAB_MAIN]['cmdCleanStats'].clicked.connect(lambda: self._cb_clean_sql_clicked(constants.TAB_MAIN))

        self.TABLES[constants.TAB_MAIN]['filterLine'] = self.filterLine
        self.TABLES[constants.TAB_MAIN]['view'].doubleClicked.connect(self._cb_main_table_double_clicked)
        self.TABLES[constants.TAB_MAIN]['view'].installEventFilter(self)
        self.TABLES[constants.TAB_MAIN]['filterLine'].textChanged.connect(self._cb_events_filter_line_changed)

        self.TABLES[constants.TAB_MAIN]['view'].setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.TABLES[constants.TAB_MAIN]['view'].customContextMenuRequested.connect(self._cb_table_context_menu)

        self.get_search_widget().setCompleter(self.queries.get_completer(constants.TAB_MAIN))

        for idx in range(1, constants.TAB_TOTAL):
            if self.TABLES[idx]['cmd'] is not None:
                self.TABLES[idx]['cmd'].hide()
                self.TABLES[idx]['cmd'].setVisible(False)
                self.TABLES[idx]['cmd'].clicked.connect(lambda: self._cb_cmd_back_clicked(idx))
            if self.TABLES[idx]['cmdCleanStats'] is not None:
                self.TABLES[idx]['cmdCleanStats'].clicked.connect(lambda: self._cb_clean_sql_clicked(idx))
            if self.TABLES[idx]['label'] is not None:
                self.TABLES[idx]['label'].setStyleSheet('font-weight:600;')
                self.TABLES[idx]['label'].setVisible(False)
            self.TABLES[idx]['view'].doubleClicked.connect(self._cb_table_double_clicked)
            self.TABLES[idx]['view'].clicked.connect(self._cb_table_clicked)
            self.TABLES[idx]['view'].installEventFilter(self)
            self.TABLES[idx]['view'].setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
            self.TABLES[idx]['view'].customContextMenuRequested.connect(self._cb_table_context_menu)

        self.TABLES[constants.TAB_FIREWALL]['view'].rowsReordered.connect(self._cb_fw_table_rows_reordered)

        self._load_settings()

        self.iconStart = Icons.new(self, "media-playback-start")
        self.iconPause = Icons.new(self, "media-playback-pause")

        self.fwTreeEdit = QtWidgets.QPushButton()
        self.fwTreeEdit.setIcon(QtGui.QIcon().fromTheme("preferences-desktop"))
        self.fwTreeEdit.autoFillBackground = True
        self.fwTreeEdit.setFlat(True)
        self.fwTreeEdit.setSizePolicy(
            QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
        )
        self.fwTreeEdit.clicked.connect(self._cb_tree_edit_firewall_clicked)
        self._configure_buttons_icons()
        self._configure_plugins()

    #Sometimes a maximized window which had been minimized earlier won't unminimize
    #To workaround, we explicitely maximize such windows when unminimizing happens
    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.Type.WindowStateChange:
            if event.oldState() & QtCore.Qt.WindowState.WindowMinimized and event.oldState() & QtCore.Qt.WindowState.WindowMaximized:
                #a previously minimized maximized window ...
                if self.windowState() ^ QtCore.Qt.WindowState.WindowMinimized and xdg_current_desktop == "KDE":
                    # is not minimized anymore, i.e. it was unminimized
                    # docs: https://doc.qt.io/qt-5/qwidget.html#setWindowState
                    self.setWindowState(self.windowState() & ~QtCore.Qt.WindowState.WindowMinimized | QtCore.Qt.WindowState.WindowActive)

    def show(self):
        super(StatsDialog, self).show()
        self._fw_dialog = None
        self._prefs_dialog = None

        self._shown_trigger.emit()
        window_title = QC.translate("stats", "OpenSnitch Network Statistics {0}").format(version)
        if self._address is not None:
            window_title = QC.translate("stats", "OpenSnitch Network Statistics for {0}").format(self._address)
            self.nodeLabel.setText(self._address)
        self._load_settings()
        self._add_rulesTree_nodes()
        self._add_rulesTree_fw_chains()
        self.setWindowTitle(window_title)
        self.refresh_active_table()
        self.show_columns()

    def eventFilter(self, source, event):
        if event.type() == QtCore.QEvent.Type.KeyPress:
            if event.matches(QtGui.QKeySequence.StandardKey.Copy):
                self.copy_selected_rows()
                return True
            elif event.key() == QtCore.Qt.Key.Key_Delete:
                table = self.get_active_table()
                selection = table.selectedRows()
                if selection:
                    model = table.model()
                    self.table_menu_delete(self.get_current_view_idx(), model, selection)
                    # we need to manually refresh the model
                    table.selectionModel().clear()
                    self.refresh_active_table()
                return True
        return super(StatsDialog, self).eventFilter(source, event)

    def _configure_plugins(self):
        for conf in self._action_list:
            action = self._action_list[conf]
            for name in action['actions']:
                try:
                    action['actions'][name].configure(self)
                except Exception as e:
                    print("stats._configure_plugins() exception:", name, "-", e)

    def _configure_buttons_icons(self):

        newRuleIcon = Icons.new(self, "document-new")
        delRuleIcon = Icons.new(self, "edit-delete")
        editRuleIcon = Icons.new(self, "accessories-text-editor")
        prefsIcon = Icons.new(self, "preferences-system")
        searchIcon = Icons.new(self, "system-search")
        clearIcon = Icons.new(self, "edit-clear-all")
        leftArrowIcon = Icons.new(self, "go-previous")
        fwIcon = Icons.new(self, "security-high")
        optsIcon = Icons.new(self, "format-justify-fill")
        helpIcon = Icons.new(self, "help-browser")
        eventsIcon = Icons.new(self, "view-sort-ascending")
        rulesIcon = Icons.new(self, "address-book-new")
        procsIcon = Icons.new(self, "system-run")

        if QtGui.QIcon().hasThemeIcon("preferences-desktop") is False:
            self.fwTreeEdit.setText("+")

        self.tabWidget.setTabIcon( constants.TAB_MAIN, eventsIcon)
        self.tabWidget.setTabIcon( constants.TAB_RULES, rulesIcon)
        self.tabWidget.setTabIcon( constants.TAB_PROCS, procsIcon)
        self.newRuleButton.setIcon(newRuleIcon)
        self.delRuleButton.setIcon(delRuleIcon)
        self.editRuleButton.setIcon(editRuleIcon)
        self.prefsButton.setIcon(prefsIcon)
        self.helpButton.setIcon(helpIcon)
        self.startButton.setIcon(self.iconStart)
        self.fwButton.setIcon(fwIcon)
        self.cmdProcDetails.setIcon(searchIcon)
        self.nodeStartButton.setIcon(self.iconStart)
        self.nodePrefsButton.setIcon(prefsIcon)
        self.nodeDeleteButton.setIcon(clearIcon)
        self.nodeActionsButton.setIcon(optsIcon)
        self.actionsButton.setIcon(optsIcon)
        self.TABLES[constants.TAB_MAIN]['cmdCleanStats'].setIcon(clearIcon)
        for idx in range(1,8):
            self.TABLES[idx]['cmd'].setIcon(leftArrowIcon)
            if self.TABLES[idx]['cmdCleanStats'] is not None:
                self.TABLES[idx]['cmdCleanStats'].setIcon(clearIcon)

    def _load_settings(self):
        self._ui_refresh_interval = self.cfg.getInt(Config.STATS_REFRESH_INTERVAL, 0)
        dialog_geometry = self.cfg.getSettings(Config.STATS_GEOMETRY)
        dialog_maximized = self.cfg.getBool(Config.STATS_MAXIMIZED)
        dialog_last_tab = self.cfg.getSettings(Config.STATS_LAST_TAB)
        dialog_general_filter_text = self.cfg.getSettings(Config.STATS_FILTER_TEXT)
        dialog_general_filter_action = self.cfg.getSettings(Config.STATS_FILTER_ACTION)
        dialog_general_limit_results = self.cfg.getSettings(Config.STATS_LIMIT_RESULTS)
        if dialog_geometry is not None:
            self.restoreGeometry(dialog_geometry)
        if dialog_maximized and self.isVisible():
            self.showMaximized()
        if dialog_last_tab is not None:
            self.set_current_tab(int(dialog_last_tab))
        if dialog_general_filter_action is not None:
            self.comboAction.setCurrentIndex(int(dialog_general_filter_action))
        if dialog_general_limit_results is not None:
            # XXX: a little hack, because if the saved index is 0, the signal is not fired.
            # XXX: this causes to fire the event twice
            self.limitCombo.blockSignals(True)
            self.limitCombo.setCurrentIndex(4)
            self.limitCombo.setCurrentIndex(int(dialog_general_limit_results))
            self.limitCombo.blockSignals(False)

        rules_splitter_pos = self.cfg.getSettings(Config.STATS_RULES_SPLITTER_POS)
        if type(rules_splitter_pos) == QtCore.QByteArray:
            self.rulesSplitter.restoreState(rules_splitter_pos)
            rulesSizes = self.rulesSplitter.sizes()
            if self.in_detail_view(constants.TAB_RULES):
                self.comboRulesFilter.setVisible(False)
            elif len(rulesSizes) > 0:
                self.comboRulesFilter.setVisible(rulesSizes[0] == 0)
        else:
            # default position when the user hasn't moved it yet.

            # FIXME: The first time show() event is fired, this widget has no
            # real width yet. The second time is fired the width of the widget
            # is correct.
            w = self.rulesSplitter.width()
            self.rulesSplitter.setSizes([int(w/4), int(w/1)])

        nodes_splitter_pos = self.cfg.getSettings(Config.STATS_NODES_SPLITTER_POS)
        if type(nodes_splitter_pos) == QtCore.QByteArray:
            self.nodesSplitter.restoreState(nodes_splitter_pos)
        else:
            w = self.nodesSplitter.width()
            self.nodesSplitter.setSizes([w, 0])

        self.netstat.configure_combos()

        self.restore_details_view_columns(self.eventsTable.horizontalHeader(), Config.STATS_GENERAL_COL_STATE)
        self.restore_details_view_columns(self.nodesTable.horizontalHeader(), Config.STATS_NODES_COL_STATE)
        self.restore_details_view_columns(self.rulesTable.horizontalHeader(), Config.STATS_RULES_COL_STATE)
        self.restore_details_view_columns(self.fwTable.horizontalHeader(), Config.STATS_FW_COL_STATE)
        self.restore_details_view_columns(self.alertsTable.horizontalHeader(), Config.STATS_ALERTS_COL_STATE)
        self.restore_details_view_columns(self.netstatTable.horizontalHeader(), Config.STATS_NETSTAT_COL_STATE)

        rulesTreeNodes_expanded = self.cfg.getBool(Config.STATS_RULES_TREE_EXPANDED_1)
        if rulesTreeNodes_expanded is not None:
            rules_tree_nodes = self.get_tree_item(constants.RULES_TREE_NODES)
            if rules_tree_nodes is not None:
                rules_tree_nodes.setExpanded(rulesTreeNodes_expanded)
        rulesTreeApps_expanded = self.cfg.getBool(Config.STATS_RULES_TREE_EXPANDED_0)
        if rulesTreeApps_expanded is not None:
            rules_tree_apps = self.get_tree_item(constants.RULES_TREE_APPS)
            if rules_tree_apps is not None:
                rules_tree_apps.setExpanded(rulesTreeApps_expanded)

        if dialog_general_filter_text is not None:
            self.set_search_text(dialog_general_filter_text)

    def _save_settings(self):
        self.cfg.setSettings(Config.STATS_MAXIMIZED, self.isMaximized())
        self.cfg.setSettings(Config.STATS_GEOMETRY, self.saveGeometry())
        self.cfg.setSettings(Config.STATS_LAST_TAB, self.get_current_view_idx())
        self.cfg.setSettings(Config.STATS_LIMIT_RESULTS, self.limitCombo.currentIndex())
        self.cfg.setSettings(Config.STATS_FILTER_TEXT, self.get_search_text())

        header = self.eventsTable.horizontalHeader()
        self.cfg.setSettings(Config.STATS_GENERAL_COL_STATE, header.saveState())
        nodesHeader = self.nodesTable.horizontalHeader()
        self.cfg.setSettings(Config.STATS_NODES_COL_STATE, nodesHeader.saveState())
        rulesHeader = self.rulesTable.horizontalHeader()
        self.cfg.setSettings(Config.STATS_RULES_COL_STATE, rulesHeader.saveState())
        fwHeader = self.fwTable.horizontalHeader()
        self.cfg.setSettings(Config.STATS_FW_COL_STATE, fwHeader.saveState())
        alertsHeader = self.alertsTable.horizontalHeader()
        self.cfg.setSettings(Config.STATS_ALERTS_COL_STATE, alertsHeader.saveState())
        netstatHeader = self.netstatTable.horizontalHeader()
        self.cfg.setSettings(Config.STATS_NETSTAT_COL_STATE, netstatHeader.saveState())

        rules_tree_apps = self.get_tree_item(constants.RULES_TREE_APPS)
        if rules_tree_apps is not None:
            self.cfg.setSettings(Config.STATS_RULES_TREE_EXPANDED_0, rules_tree_apps.isExpanded())
        rules_tree_nodes = self.get_tree_item(constants.RULES_TREE_NODES)
        if rules_tree_nodes is not None:
            self.cfg.setSettings(Config.STATS_RULES_TREE_EXPANDED_1, rules_tree_nodes.isExpanded())

    def _cb_fw_rules_updated(self):
        self._add_rulesTree_fw_chains()

    def _cb_app_rules_updated(self, what):
        self.refresh_active_table()

    def _cb_nodes_updated(self, count):
        node_list = self.node_list()
        self.netstat.update_node_list(count, node_list)

    @QtCore.pyqtSlot(str)
    def _cb_fw_table_rows_reordered(self, node_addr):
        node = self.node_get(node_addr)
        nid, notif = self.node_reload_fw(node_addr, node['firewall'], self._notification_callback)
        self.save_ntf(nid, {'addr': node_addr, 'notif': notif})

    def _cb_tree_edit_firewall_clicked(self):
        self.open_firewall()

    def _cb_proc_details_clicked(self):
        table = self.get_view(self.get_current_view_idx())
        nrows = table.model().rowCount()
        pids = {}
        for row in range(0, nrows):
            pid = table.model().index(row, constants.COL_PROC_PID).data()
            node = table.model().index(row, constants.COL_NODE).data()
            if pid not in pids:
                pids[pid] = node

        self._proc_details_dialog.monitor(pids)

    @QtCore.pyqtSlot(str, ui_pb2.NotificationReply)
    def _cb_notification_callback(self, node_addr, reply):
        if self.ntf_reply_exists(reply.id):
            noti = self.get_notification(reply.id)

            # convert dictionary sent from _cb_fw_table_rows_reordered()
            if isinstance(noti, dict) and isinstance(noti["notif"].type, int):
                noti = noti["notif"]

            if noti.type == ui_pb2.TASK_START and reply.code != ui_pb2.ERROR:
                noti_data = json.loads(noti.data)
                if noti_data['name'] == nodemon.TASK_NAME:
                    self.node_mon.update_node_info(reply.data)
                elif noti_data['name'] == netstat.TASK_NAME:
                    self.netstat.update_node(node_addr, reply.data)
                else:
                    print("_cb_notification_callback, unknown task reply?", noti_data)
                return
            elif noti.type == ui_pb2.TASK_START and reply.code == ui_pb2.ERROR:
                self.netstatLabel.setText("error starting netstat table: {0}".format(reply.data))
            elif reply.code == ui_pb2.ERROR:
                Message.ok(
                    QC.translate("stats", "Error:"),
                    "{0}".format(reply.data),
                    QtWidgets.QMessageBox.Icon.Warning)
            else:
                print("_cb_notification_callback, unknown reply:", reply)

            self.del_notification(reply.id)

        else:
            #print("_cb_notification_callback, reply not in the list:", reply)
            Message.ok(
                QC.translate("stats", "Warning:"),
                "{0}".format(reply.data),
                QtWidgets.QMessageBox.Icon.Warning)

    def _cb_tab_changed(self, index):
        self.comboAction.setVisible(index == constants.TAB_MAIN)
        self.get_search_widget().setCompleter(self.queries.get_completer(index))

        if index != constants.TAB_NETSTAT and self.LAST_TAB == constants.TAB_NETSTAT:
            self.netstat.unmonitor_node(self.LAST_NETSTAT_NODE)

        if self.LAST_TAB == constants.TAB_NODES and self.LAST_SELECTED_ITEM != "":
            self.node_mon.unmonitor_deselected_node(self.LAST_SELECTED_ITEM)

        self.TABLES[index]['cmdCleanStats'].setVisible(True)
        if index ==  constants.TAB_MAIN:
            self.queries.set_events_query()
        elif index ==  constants.TAB_NETSTAT:
            self.netstat.monitor_node()
        else:
            if index == constants.TAB_RULES:
                # display the clean buton only if not in detail view
                self.TABLES[index]['cmdCleanStats'].setVisible( self.in_detail_view(index) )
                self._add_rulesTree_nodes()

            elif index == constants.TAB_PROCS:
                # make the button visible depending if we're in the detail view
                nrows = self.get_active_table().model().rowCount()
                self.cmdProcDetails.setVisible(self.in_detail_view(index) and nrows > 0)

            elif index == constants.TAB_NODES:
                self.TABLES[index]['cmdCleanStats'].setVisible( self.in_detail_view(index) )

        self.LAST_TAB = index
        self.refresh_active_table()

    def _cb_table_context_menu(self, pos):
        cur_idx = self.get_current_view_idx()
        if cur_idx != constants.TAB_RULES and cur_idx != constants.TAB_MAIN:
            # the only tables with context menu for now are events and rules table
            return
        if self.in_detail_view(constants.TAB_RULES):
            return

        refresh_table = False
        self.set_context_menu_active(True)
        if cur_idx == constants.TAB_MAIN:
            refresh_table = self.configure_events_contextual_menu(pos)
        elif cur_idx == constants.TAB_RULES:
            print("context rules:", self.alertsTable.isVisible())
            if self.fwTable.isVisible():
                refresh_table = self.configure_fwrules_contextual_menu(pos)
            elif self.alertsTable.isVisible():
                refresh_table = self.configure_alerts_contextual_menu(pos)
            else:
                refresh_table = self.configure_rules_contextual_menu(pos)

        self.set_context_menu_active(False)
        if refresh_table:
            self.refresh_active_table()

    def _cb_table_header_clicked(self, pos, sortIdx):
        # sortIdx is a SortOrder enum
        self.on_table_header_clicked(pos, sortIdx)

    def _cb_events_filter_line_changed(self, text):
        self.on_filter_line_changed(text)

    def _cb_limit_combo_changed(self, idx):
        if self.get_current_view_idx() ==  constants.TAB_MAIN:
            self.queries.set_events_query()
            return

        model = self.get_active_table().model()
        qstr = model.query().lastQuery()
        if "LIMIT" in qstr:
            qs = qstr.split(" LIMIT ")
            q = qs[0]
            #l = qs[1]
            qstr = q + self.get_view_limit()
        else:
            qstr = qstr + self.get_view_limit()

        self.queries.setQuery(model, qstr, limit=self.get_query_limit())

    def _cb_combo_action_changed(self, idx):
        if self.get_current_view_idx() != constants.TAB_MAIN:
            return

        self.cfg.setSettings(Config.STATS_GENERAL_FILTER_ACTION, idx)
        self.queries.set_events_query()

    def _cb_clean_sql_clicked(self, idx):
        cur_idx = self.get_current_view_idx()
        if cur_idx == constants.TAB_RULES:
            self._db.empty_rule(self.TABLES[cur_idx]['label'].text())
        elif self.in_detail_view(cur_idx):
            self.del_by_field(cur_idx, self.TABLES[cur_idx]['name'], self.TABLES[cur_idx]['label'].text())
        else:
            self._db.clean(self.TABLES[cur_idx]['name'])
        self.refresh_active_table()

    def _cb_cmd_back_clicked(self, idx):
        self.on_cmd_back_clicked(idx)

    def _cb_main_table_double_clicked(self, row):
        prev_idx = self.get_current_view_idx()
        data = row.data()
        idx = row.column()
        cur_idx = 1

        try:
            self.get_search_widget().setCompleter(self.queries.get_completer(cur_idx))
            if idx == constants.COL_NODE:
                cur_idx = constants.TAB_NODES
                self.set_in_detail_view(cur_idx, True)
                self.set_last_selected_item(row.model().index(row.row(), constants.COL_NODE).data())
                self.set_current_tab(cur_idx)
                self.set_active_widgets(prev_idx, True, str(data))
                self.queries.set_nodes_query(data)

            elif idx == constants.COL_RULES:
                cur_idx = constants.TAB_RULES
                r_name, node = self.set_rules_tab_active(row, cur_idx, constants.COL_RULES, constants.COL_NODE)
                self.set_in_detail_view(cur_idx, True)
                self.set_last_selected_item(r_name)
                self.set_active_widgets(prev_idx, True, str(data))
                self.queries.set_rules_query(r_name, node)

            elif idx == constants.COL_DSTIP:
                cur_idx = constants.TAB_ADDRS
                self.set_in_detail_view(cur_idx, True)
                ip = row.model().index(row.row(), constants.COL_DSTIP).data()
                self.set_last_selected_item(ip)
                self.set_current_tab(cur_idx)
                self.set_active_widgets(prev_idx, True, ip)
                self.queries.set_addrs_query(ip)

            elif idx == constants.COL_DSTHOST:
                cur_idx = constants.TAB_HOSTS
                self.set_in_detail_view(cur_idx, True)
                host = row.model().index(row.row(), constants.COL_DSTHOST).data()
                if host == "":
                    return
                self.set_last_selected_item(host)
                self.set_current_tab(cur_idx)
                self.set_active_widgets(prev_idx, True, host)
                self.queries.set_hosts_query(host)

            elif idx == constants.COL_DSTPORT:
                cur_idx = constants.TAB_PORTS
                self.set_in_detail_view(cur_idx, True)
                port = row.model().index(row.row(), constants.COL_DSTPORT).data()
                self.set_last_selected_item(port)
                self.set_current_tab(cur_idx)
                self.set_active_widgets(prev_idx, True, port)
                self.queries.set_ports_query(port)

            elif idx == constants.COL_UID:
                cur_idx = constants.TAB_USERS
                self.set_in_detail_view(cur_idx, True)
                uid = row.model().index(row.row(), constants.COL_UID).data()
                self.set_last_selected_item(uid)
                self.set_current_tab(cur_idx)
                self.set_active_widgets(prev_idx, True, uid)
                self.queries.set_users_query(uid)

            elif idx == constants.COL_PID:
                node = row.model().index(row.row(), constants.COL_NODE).data()
                pid = row.model().index(row.row(), constants.COL_PID).data()
                self.set_last_selected_item(pid)
                self._proc_details_dialog.monitor(
                    {pid: node}
                )
                return
            else:
                cur_idx = constants.TAB_PROCS
                self.set_in_detail_view(cur_idx, True)
                self.set_last_selected_item(row.model().index(row.row(), constants.COL_PROCS).data())
                self.set_current_tab(cur_idx)
                self.set_active_widgets(prev_idx, True, self.LAST_SELECTED_ITEM)
                nrows = self.queries.set_process_query(self.LAST_SELECTED_ITEM)
                self.cmdProcDetails.setVisible(nrows != 0)

        finally:
            self.restore_details_view_columns(
                self.TABLES[cur_idx]['view'].horizontalHeader(),
                "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
            )

    def _cb_table_clicked(self, idx):
        self.on_table_clicked(idx)

    def _cb_table_double_clicked(self, row):
        cur_idx = self.get_current_view_idx()
        if self.in_detail_view(cur_idx):
            return

        try:
            if cur_idx == constants.TAB_RULES and self.fwTable.isVisible():
                uuid = row.model().index(row.row(), 1).data(QtCore.Qt.ItemDataRole.UserRole.value+1)
                addr = row.model().index(row.row(), 2).data(QtCore.Qt.ItemDataRole.UserRole.value+1)
                self.load_fw_rule(addr, uuid)
                return

            elif cur_idx == constants.TAB_RULES and self.alertsTable.isVisible():
                atime = row.model().index(row.row(), constants.COL_TIME).data()
                anode = row.model().index(row.row(), constants.COL_NODE).data()
                self.display_alert_info(atime, anode)
                return

            self.set_in_detail_view(cur_idx, True)
            self.set_last_selected_item(row.model().index(row.row(), constants.COL_TIME).data())
            self.LAST_SCROLL_VALUE = self.TABLES[cur_idx]['view'].vScrollBar.value()
            self.get_search_widget().setCompleter(self.queries.get_completer(cur_idx))

            data = row.data()

            if cur_idx == constants.TAB_RULES:
                if self.alertsTable.isVisible():
                    return

                r_name, node = self.set_rules_tab_active(row, cur_idx, constants.COL_R_NAME, constants.COL_R_NODE)
                self.set_active_widgets(cur_idx, True, r_name)
                self.set_last_selected_item(r_name)
                self.queries.set_rules_query(r_name, node)
                return
            if cur_idx == constants.TAB_NODES:
                data = row.model().index(row.row(), constants.COL_NODE).data()
                self.set_last_selected_item(data)
            if cur_idx > constants.TAB_RULES:
                data = row.model().index(row.row(), constants.COL_WHAT).data()
                self.set_last_selected_item(data)
            if cur_idx == constants.TAB_NETSTAT:
                self.set_in_detail_view(cur_idx, False)

                if row.column() == constants.COL_NET_DST_IP:
                    cur_idx = constants.TAB_ADDRS
                    data = row.model().index(row.row(), constants.COL_NET_DST_IP).data()
                elif row.column() == constants.COL_NET_DST_PORT:
                    cur_idx = constants.TAB_PORTS
                    data = row.model().index(row.row(), constants.COL_NET_DST_PORT).data()
                elif row.column() == constants.COL_NET_UID:
                    cur_idx = constants.TAB_USERS
                    data = row.model().index(row.row(), constants.COL_NET_UID).data()
                elif row.column() == constants.COL_NET_PID:
                    if self.LAST_NETSTAT_NODE is None:
                        return
                    pid = row.model().index(row.row(), constants.COL_NET_PID).data()
                    pids = {}
                    pids[pid] = self.LAST_NETSTAT_NODE
                    self._proc_details_dialog.monitor(pids)
                    return
                else:
                    cur_idx = constants.TAB_PROCS
                    data = row.model().index(row.row(), constants.COL_NET_PROC).data()
                    if data == "":
                        return
                self.netstat.unmonitor_node(self.LAST_NETSTAT_NODE)
                self.set_current_tab(cur_idx)

            self.set_active_widgets(cur_idx, True, str(data))

            if cur_idx == constants.TAB_NODES:
                self.queries.set_nodes_query(data)
            elif cur_idx == constants.TAB_HOSTS:
                self.queries.set_hosts_query(data)
            elif cur_idx == constants.TAB_PROCS:
                nrows = self.queries.set_process_query(data)
                self.cmdProcDetails.setVisible(nrows != 0)
            elif cur_idx == constants.TAB_ADDRS:
                lbl_text = self.TABLES[cur_idx]['label'].text()
                if lbl_text != "":
                    asn = self.asndb.get_asn(lbl_text)
                    if asn != "":
                        lbl_text += " (" + asn + ")"
                self.TABLES[cur_idx]['label'].setText(lbl_text)
                self.queries.set_addrs_query(data)
            elif cur_idx == constants.TAB_PORTS:
                self.queries.set_ports_query(data)
            elif cur_idx == constants.TAB_USERS:
                self.queries.set_users_query(data)

        finally:
            self.restore_details_view_columns(
                self.TABLES[cur_idx]['view'].horizontalHeader(),
                "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
            )

    def _cb_prefs_clicked(self):
        self.open_settings()

    def _cb_rules_filter_combo_changed(self, idx):
        if idx == constants.RULES_TREE_APPS:
            self.queries.set_rules_filter()
        elif idx == constants.RULES_COMBO_PERMANENT:
            self.queries.set_rules_filter(constants.RULES_TREE_APPS, constants.RULES_TREE_PERMANENT)
        elif idx == constants.RULES_COMBO_TEMPORARY:
            self.queries.set_rules_filter(constants.RULES_TREE_APPS, constants.RULES_TREE_TEMPORARY)
        elif idx == constants.RULES_TREE_ALERTS:
            self.queries.set_rules_filter(-1, constants.RULES_TREE_ALERTS)
        elif idx == constants.RULES_COMBO_FW:
            self.queries.set_rules_filter(-1, constants.RULES_TREE_FIREWALL)

    def _cb_rules_tree_item_expanded(self, item):
        self.rulesTreePanel.resizeColumnToContents(0)
        self.rulesTreePanel.resizeColumnToContents(1)

    def _cb_rules_tree_item_double_clicked(self, item, col):
        # TODO: open fw chain editor
        pass

    def _cb_rules_tree_item_clicked(self, item, col):
        """Event fired when the user clicks on the left panel of the rules tab
        """
        item_model = self.rulesTreePanel.indexFromItem(item, col)
        item_row = item_model.row()
        parent = item.parent()
        parent_row = -1
        node_addr = ""
        fw_table = ""
        item_text = item.text(0)

        rulesHeader = self.rulesTable.horizontalHeader()
        self.cfg.setSettings(Config.STATS_RULES_COL_STATE, rulesHeader.saveState())

        self.clear_rows_selection()

        # FIXME: find a clever way of handling these options

        # top level items
        if parent is not None:
            parent_model = self.rulesTreePanel.indexFromItem(parent, 0)
            parent_row = parent_model.row()
            node_addr = parent_model.data()

            # 1st level items: nodes, rules types
            if parent.parent() is not None:
                parent = parent.parent()
                parent_model = self.rulesTreePanel.indexFromItem(parent, 0)
                item_row =  constants.FILTER_TREE_FW_TABLE
                parent_row = constants.RULES_TREE_FIREWALL
                fw_table = parent_model.data()

                # 2nd level items: chains
                if parent.parent() is not None:
                    parent = parent.parent()
                    parent_model = self.rulesTreePanel.indexFromItem(parent.parent(), 0)
                    parent_row = constants.RULES_TREE_FIREWALL
                    item_row =  constants.FILTER_TREE_FW_CHAIN
                    item_text = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
            # node
            else:
                if parent_row == constants.RULES_TREE_FIREWALL:
                    item_row =  constants.FILTER_TREE_FW_NODE
                node_addr = item_text

        if node_addr is None:
            return

        showFwTable = (parent_row == constants.RULES_TREE_FIREWALL or (parent_row == -1 and item_row == constants.RULES_TREE_FIREWALL))
        showAlertsTable = (parent_row == -1 and item_row == constants.RULES_TREE_ALERTS)
        self.fwTable.setVisible(showFwTable)
        self.alertsTable.setVisible(showAlertsTable)
        self.alertsScrollBar.setVisible(showAlertsTable)
        self.rulesTable.setVisible(not showFwTable and not showAlertsTable)
        self.rulesScrollBar.setVisible(not showFwTable and not showAlertsTable)

        self.queries.set_rules_filter(parent_row, item_row, item_text, node_addr, fw_table)

    def _cb_splitter_moved(self, tab, pos, index):
        self.on_splitter_moved(tab, pos, index)

    def _cb_start_clicked(self):
        if self.daemon_connected is False:
            self.startButton.setChecked(False)
            self.startButton.setIcon(self.iconStart)
            return

        self.update_interception_status(self.startButton.isChecked())
        self._status_changed_trigger.emit(self.startButton.isChecked())

        if self.startButton.isChecked():
            nid, noti = self.node_start_interception(callback=self._notification_callback)
        else:
            nid, noti = self.node_stop_interception(callback=self._notification_callback)

        self.save_ntf(nid, noti)

    def _cb_node_start_clicked(self):
        addr = self.TABLES[constants.TAB_NODES]['label'].text()
        if addr == "":
            return
        if self.nodeStartButton.isChecked():
            self.update_nodes_interception_status()
            nid, noti = self.node_start_interception(addr, self._notification_callback)
        else:
            self.update_nodes_interception_status(disable=True)
            nid, noti = self.node_stop_interception(addr, self._notification_callback)

        self.save_ntf(nid, noti)

    def _cb_node_prefs_clicked(self):
        addr = self.TABLES[constants.TAB_NODES]['label'].text()
        if addr == "":
            return
        self.open_settings(addr=addr)

    def _cb_node_delete_clicked(self):
        self.view_delete_node()

    def _cb_new_rule_clicked(self):
        self._rules_dialog.new_rule()

    def _cb_edit_rule_clicked(self):
        cur_idx = self.get_current_view_idx()
        records = self.get_rule(self.TABLES[cur_idx]['label'].text(), self.nodeRuleLabel.text())
        if records is None:
            return

        self._rules_dialog.edit_rule(records, self.nodeRuleLabel.text())

    def _cb_del_rule_clicked(self):
        ret = Message.yes_no(
            QC.translate("stats", "    You are about to delete this rule.    "),
            QC.translate("stats", "    Are you sure?"),
            QtWidgets.QMessageBox.Icon.Warning)
        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
            return

        self.del_rule(self.TABLES[self.get_current_view_idx()]['label'].text(), self.nodeRuleLabel.text())
        self.TABLES[constants.TAB_RULES]['cmd'].click()
        self.nodeRuleLabel.setText("")
        self.refresh_active_table()

    def _cb_enable_rule_toggled(self, state):
        self.enable_rule(state)

    def _cb_prev_button_clicked(self):
        model = self.get_active_table().model()
        model.fetchMore()

    def _cb_next_button_clicked(self):
        model = self.get_active_table().model()
        model.fetchMore()

    def _cb_help_button_clicked(self):
        QuickHelp.show(
            QC.translate(
                "stats",
                "<p><b>Quick help</b></p>" \
                "<p>- Use CTRL+c to copy selected rows.</p>" \
                "<p>- Use Home,End,PgUp,PgDown,PgUp,Up or Down keys to navigate rows.</p>" \
                "<p>- Use right click on a row to stop refreshing the view.</p>" \
                "<p>- Selecting more than one row also stops refreshing the view.</p>"
                "<p>- On the Events view, clicking on columns Node, Process or Rule<br>" \
                "jumps to the view of the selected item.</p>" \
                "<p>- On the rest of the views, double click on a row to get detailed<br>" \
                " information.</p><br>" \
                "<p>For more information visit the <a href=\"{0}\">wiki</a></p>" \
                "<br>".format(Config.HELP_URL)
            )
        )

    def open_firewall(self):
        if self._fw_dialog is None:
            self._fw_dialog = FirewallDialog(appicon=self.appicon)
        self._fw_dialog.show()


    def new_fw_rule(self):
        if self._fw_dialog is None:
            self._fw_dialog = FirewallDialog(appicon=self.appicon)
        self._fw_dialog.new_rule()

    def load_fw_rule(self, node, uuid):
        if self._fw_dialog is None:
            self._fw_dialog = FirewallDialog(appicon=self.appicon)
        self._fw_dialog.load_rule(node, uuid)

    def open_settings(self, addr=None):
        if self._prefs_dialog is None:
            self._prefs_dialog = PreferencesDialog(appicon=self.appicon)
            self._prefs_dialog.saved.connect(self._on_settings_saved)

        if addr is None:
            self._prefs_dialog.show()
        else:
            self._prefs_dialog.show_node_prefs(addr)

    def enable_rule(self, state):
        rule = ui_pb2.Rule(name=self.TABLES[self.get_current_view_idx()]['label'].text())
        rule.enabled = False
        rule.action = ""
        rule.duration = ""
        rule.operator.type = ""
        rule.operator.operand = ""
        rule.operator.data = ""

        notType = ui_pb2.DISABLE_RULE
        if state == True:
            notType = ui_pb2.ENABLE_RULE
        rule.enabled = state
        noti = ui_pb2.Notification(type=notType, rules=[rule])
        self._notification_trigger.emit(noti)

    def del_by_field(self, cur_idx, table, value):
        model = self.get_active_table().model()
        # get left side of the query: * GROUP BY ...
        qstr = model.query().lastQuery().split("GROUP BY")[0]
        # get right side of the query: ... WHERE *
        q = qstr.split("WHERE")

        field = "dst_host"
        if cur_idx ==  constants.TAB_NODES:
            field = "node"
        elif cur_idx ==  constants.TAB_PROCS:
            field = "process"
        elif cur_idx ==  constants.TAB_ADDRS:
            field = "dst_ip"
        elif cur_idx ==  constants.TAB_PORTS:
            field = "dst_port"
        elif cur_idx ==  constants.TAB_USERS:
            field = "uid"

        ret1 = self._db.remove("DELETE FROM {0} WHERE what = ?".format(table), [value])
        ret2 = self._db.remove("DELETE FROM connections WHERE {0} = ?".format(field), [value])

        return ret1 and ret2

    def del_rule(self, rule_name, node_addr):
        if rule_name is None or node_addr is None:
            print("_del_rule() invalid parameters")
            return
        nid, noti = self.node_del_rule(node_addr, rule_name, self._notification_callback)
        if nid is None:
            return
        self.save_ntf(nid, noti)

    def display_alert_info(self, time, node):
        text = ""
        records = self._db.get_alert(time, node)
        if records is not None and records.next() is False:
            return

        inf = InfoWindow(self)
        text += text + """
                    <b>{0}</b><br>
                    <b>Node:</b> {1}<br>
                    <b>Type:</b> {2} &ndash; <b>Severity:</b> {3}<br><br>
                    <b>{4}</b><br><br>
                    {5}

                    ---
""".format(
    records.value(AlertFields.Time),
    records.value(AlertFields.Node),
    records.value(AlertFields.Type),
    records.value(AlertFields.Priority),
    records.value(AlertFields.What),
    records.value(AlertFields.Body)
)

        inf.showHtml(text)

    def _update_status_label(self, running=False, text=FIREWALL_DISABLED):
        self.statusLabel.setText("%12s" % text)
        if running:
            self.statusLabel.setStyleSheet('color: green; margin: 5px')
            self.startButton.setIcon(self.iconPause)
        else:
            self.statusLabel.setStyleSheet('color: rgb(206, 92, 0); margin: 5px')
            self.startButton.setIcon(self.iconStart)

        self._add_rulesTree_nodes()
        self._add_rulesTree_fw_chains()

    def _add_rulesTree_nodes(self):
        if self.nodes_count() == 0:
            return

        nodes = self.node_list()
        labels=()
        for n in nodes:
            hostname = self.node_hostname(n)
            labels+=((n, hostname),)
        self.add_tree_items(constants.RULES_TREE_NODES, labels)

    def _add_rulesTree_fw_chains(self):
        expanded = list()
        selected = None
        scrollValue = self.rulesTreePanel.verticalScrollBar().value()
        fwItem = self.rulesTreePanel.topLevelItem(constants.RULES_TREE_FIREWALL)
        selected, expanded = self.get_tree_selected_items(constants.RULES_TREE_FIREWALL)

        self.rulesTreePanel.setAnimated(False)
        fwItem.takeChildren()
        self.rulesTreePanel.setItemWidget(fwItem, 1, self.fwTreeEdit)
        # XXX
        chains = self._fw.get_chains()
        for addr in chains:
            # add nodes
            hostname = self.node_hostname(addr)
            nodeRoot = QtWidgets.QTreeWidgetItem([addr, hostname])
            nodeRoot.setData(0, QtCore.Qt.ItemDataRole.UserRole, addr)
            fwItem.addChild(nodeRoot)
            for nodeChains in chains[addr]:
                # exclude legacy system rules
                if len(nodeChains) == 0:
                    continue
                for cc in nodeChains:
                    # add tables
                    tableName = f"{cc.Table}-{cc.Family}"
                    nodeTable = QtWidgets.QTreeWidgetItem([tableName])
                    nodeTable.setData(0, QtCore.Qt.ItemDataRole.UserRole, f"{addr}-{tableName}")

                    chainName = f"{cc.Name}-{cc.Hook}"
                    nodeChain = QtWidgets.QTreeWidgetItem([chainName, cc.Policy])
                    nodeChain.setData(0, QtCore.Qt.ItemDataRole.UserRole, f"{addr}-{chainName}")
                    nodeChain.setData(
                        0,
                        QtCore.Qt.ItemDataRole.UserRole,
                        # key to identify this chain
                        f"{addr}#{cc.Hook}#{cc.Name}"
                    )

                    #items = self._find_tree_fw_items("{0}-{1}".format(addr, tableName))
                    items = self.find_tree_items(
                        constants.RULES_TREE_FIREWALL,
                        f"{addr}-{tableName}"
                    )
                    if len(items) == 0:
                        # add table
                        nodeTable.addChild(nodeChain)
                        nodeRoot.addChild(nodeTable)
                    else:
                        # add chains
                        node = items[0]
                        node.addChild(nodeChain)

        # restore previous selected rows
        self.set_tree_selected_items(selected, expanded)

        self.rulesTreePanel.verticalScrollBar().setValue(scrollValue)
        self.rulesTreePanel.setAnimated(True)
        self.rulesTreePanel.resizeColumnToContents(0)
        self.rulesTreePanel.resizeColumnToContents(1)
        expanded = None

    def get_rule(self, rule_name, node_name):
        """
        get rule records, given the name of the rule and the node
        """
        cur_idx = self.get_current_view_idx()
        records = self._db.get_rule(rule_name, node_name)
        if records.next() is False:
            print("[stats dialog] edit rule, no records: ", rule_name, node_name)
            if self.TABLES[cur_idx]['cmd'] is not None:
                self.TABLES[cur_idx]['cmd'].click()
            return None

        return records

    @QtCore.pyqtSlot()
    def _on_settings_saved(self):
        self._ui_refresh_interval = self.cfg.getInt(Config.STATS_REFRESH_INTERVAL, 0)
        self.show_columns()
        self.settings_saved.emit()

    def _on_menu_exit_clicked(self, triggered):
        self.close_trigger.emit()

    # launched from a thread
    def update(self, is_local=True, stats=None, need_query_update=True):
        # lock mandatory when there're multiple clients
        with self._lock:
            if stats is not None:
                self._stats = stats
            # do not update any tab if the window is not visible
            if self.isVisible() and self.isMinimized() is False and self.needs_refresh():
                self._trigger.emit(is_local, need_query_update)

    @QtCore.pyqtSlot(bool, bool)
    def _on_update_triggered(self, is_local, need_query_update=False):
        if self._stats is None:
            self.reset_statusbar()
            return

        nodes = self.nodes_count()
        self.daemonVerLabel.setText(self._stats.daemon_version)
        if nodes <= 1:
            self.uptimeLabel.setText(str(datetime.timedelta(seconds=self._stats.uptime)))
            self.rulesLabel.setText("%s" % self._stats.rules)
            self.consLabel.setText("%s" % self._stats.connections)
            self.droppedLabel.setText("%s" % self._stats.dropped)
        else:
            self.uptimeLabel.setText("")
            self.rulesLabel.setText("")
            self.consLabel.setText("")
            self.droppedLabel.setText("")

        if need_query_update and not self.are_rows_selected():
            self.refresh_active_table()
            self._last_update = datetime.datetime.now()

    # prevent a click on the window's x
    # from quitting the whole application
    def closeEvent(self, e):
        if self._prefs_dialog is not None:
            self._prefs_dialog.saved.disconnect(self._on_settings_saved)
            self._prefs_dialog.deleteLater()
            self._prefs_dialog = None
            del self._prefs_dialog
        if self._fw_dialog is not None:
            self._fw_dialog.deleteLater()
            self._fw_dialog = None
            del self._fw_dialog

        self._save_settings()
        e.accept()
        self.hide()

    def hideEvent(self, e):
        self._save_settings()

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if event.matches(QtGui.QKeySequence.StandardKey.Find) or event.key() == QtCore.Qt.Key.Key_Slash:
            self.get_search_widget().setFocus()
        if not event.key() == QtCore.Qt.Key.Key_Escape:
            super(StatsDialog, self).keyPressEvent(event)
