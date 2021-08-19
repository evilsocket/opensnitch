import threading
import datetime
import sys
import os
import csv

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch import ui_pb2
from opensnitch.config import Config
from opensnitch.version import version
from opensnitch.nodes import Nodes
from opensnitch.dialogs.preferences import PreferencesDialog
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
from opensnitch.dialogs.processdetails import ProcessDetailsDialog
from opensnitch.customwidgets import ColorizedDelegate, ConnectionsTableModel
from opensnitch.utils import Message

DIALOG_UI_PATH = "%s/../res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)
class StatsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    RED = QtGui.QColor(0xff, 0x63, 0x47)
    GREEN = QtGui.QColor(0x2e, 0x90, 0x59)

    _trigger = QtCore.pyqtSignal(bool, bool)
    _status_changed_trigger = QtCore.pyqtSignal(bool)
    _shown_trigger = QtCore.pyqtSignal()
    _notification_trigger = QtCore.pyqtSignal(ui_pb2.Notification)
    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    SORT_ORDER = ["ASC", "DESC"]
    LIMITS = ["LIMIT 50", "LIMIT 100", "LIMIT 200", "LIMIT 300", ""]
    LAST_GROUP_BY = ""

    # general
    COL_TIME   = 0
    COL_NODE   = 1
    COL_ACTION = 2
    COL_DSTIP  = 3
    COL_PROTO  = 4
    COL_PROCS  = 5
    COL_RULES  = 6
    GENERAL_COL_NUM = 7

    # stats
    COL_WHAT   = 0

    # rules
    COL_R_NODE = 1
    COL_R_NAME = 2
    COL_R_ENABLED = 3
    COL_R_ACTION = 4
    COL_R_DURATION = 5
    COL_R_OP_TYPE = 6
    COL_R_OP_OPERAND = 7

    # procs
    COL_PID = 6

    TAB_MAIN  = 0
    TAB_NODES = 1
    TAB_RULES = 2
    TAB_HOSTS = 3
    TAB_PROCS = 4
    TAB_ADDRS = 5
    TAB_PORTS = 6
    TAB_USERS = 7

    # row of entries
    RULES_TREE_APPS  = 0
    RULES_TREE_NODES = 1
    RULES_TREE_PERMANENT = 0
    RULES_TREE_TEMPORARY = 1

    RULES_COMBO_PERMANENT = 1
    RULES_COMBO_TEMPORARY = 2

    RULES_TYPE_PERMANENT = 0
    RULES_TYPE_TEMPORARY = 1

    FILTER_TREE_APPS = 0
    FILTER_TREE_NODES = 3

    # FIXME: don't translate, used only for default argument on _update_status_label
    FIREWALL_DISABLED = "Disabled"

    # if the user clicks on an item of a table, it'll enter into the detail
    # view. From there, deny further clicks on the items.
    IN_DETAIL_VIEW = {
        0: False,
        1: False,
        2: False,
        3: False,
        4: False,
        5: False,
        6: False,
        7: False
    }

    commonDelegateConf = {
            'deny':      RED,
            'allow':     GREEN,
            'alignment': QtCore.Qt.AlignCenter | QtCore.Qt.AlignHCenter
            }

    commonTableConf = {
            "name": "",
            "label": None,
            "tipLabel": None,
            "cmd": None,
            "view": None,
            "model": None,
            "delegate": commonDelegateConf,
            "display_fields": "*"
            }

    TABLES = {
            TAB_MAIN: {
                "name": "connections",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": commonDelegateConf,
                "display_fields": "time as Time, " \
                        "node as Node, " \
                        "action as Action, " \
                        "CASE dst_host WHEN ''" \
                        "   THEN dst_ip || '  ->  ' || dst_port " \
                        "   ELSE dst_host || '  ->  ' || dst_port " \
                        "END Destination, " \
                        "protocol as Protocol, " \
                        "process as Process, " \
                        "rule as Rule",
                "group_by": LAST_GROUP_BY,
                "last_order_by": "1",
                "last_order_to": 1
                },
            TAB_NODES: {
                "name": "nodes",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": {
                    Nodes.OFFLINE: RED,
                    Nodes.ONLINE:  GREEN,
                    'alignment': QtCore.Qt.AlignCenter | QtCore.Qt.AlignHCenter
                    },
                "display_fields": "last_connection as LastConnection, "\
                        "addr as Addr, " \
                        "status as Status, " \
                        "hostname as Hostname, " \
                        "daemon_version as Version, " \
                        "daemon_uptime as Uptime, " \
                        "daemon_rules as Rules," \
                        "cons as Connections," \
                        "cons_dropped as Dropped," \
                        "version as Version",
                "last_order_by": "2",
                "last_order_to": 1
                },
            TAB_RULES: {
                "name": "rules",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": commonDelegateConf,
                "display_fields": "*",
                "last_order_by": "2",
                "last_order_to": 0
                },
            TAB_HOSTS: {
                "name": "hosts",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": commonDelegateConf,
                "display_fields": "*",
                "last_order_by": "2",
                "last_order_to": 1
                },
            TAB_PROCS: {
                "name": "procs",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": commonDelegateConf,
                "display_fields": "*",
                "last_order_by": "2",
                "last_order_to": 1
                },
            TAB_ADDRS: {
                "name": "addrs",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": commonDelegateConf,
                "display_fields": "*",
                "last_order_by": "2",
                "last_order_to": 1
                },
            TAB_PORTS: {
                "name": "ports",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": commonDelegateConf,
                "display_fields": "*",
                "last_order_by": "2",
                "last_order_to": 1
                },
            TAB_USERS: {
                "name": "users",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": commonDelegateConf,
                "display_fields": "*",
                "last_order_by": "2",
                "last_order_to": 1
                }
            }

    def __init__(self, parent=None, address=None, db=None, dbname="db"):
        super(StatsDialog, self).__init__(parent)
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self._current_desktop = os.environ['XDG_CURRENT_DESKTOP'] if os.environ.get("XDG_CURRENT_DESKTOP") != None else None

        self.setWindowFlags(QtCore.Qt.Window)
        self.setupUi(self)
        # columns names. Must be added here in order to names be translated.
        self.COL_STR_NAME = QC.translate("stats", "Name", "This is a word, without spaces and symbols.")
        self.COL_STR_ADDR = QC.translate("stats", "Address", "This is a word, without spaces and symbols.")
        self.COL_STR_STATUS = QC.translate("stats", "Status", "This is a word, without spaces and symbols.")
        self.COL_STR_HOSTNAME = QC.translate("stats", "Hostname", "This is a word, without spaces and symbols.")
        self.COL_STR_VERSION = QC.translate("stats", "Version", "This is a word, without spaces and symbols.")
        self.COL_STR_RULES_NUM = QC.translate("stats", "Rules", "This is a word, without spaces and symbols.")
        self.COL_STR_TIME = QC.translate("stats", "Time", "This is a word, without spaces and symbols.")
        self.COL_STR_ACTION = QC.translate("stats", "Action", "This is a word, without spaces and symbols.")
        self.COL_STR_DURATION = QC.translate("stats", "Duration", "This is a word, without spaces and symbols.")
        self.COL_STR_NODE = QC.translate("stats", "Node", "This is a word, without spaces and symbols.")
        self.COL_STR_ENABLED = QC.translate("stats", "Enabled", "This is a word, without spaces and symbols.")
        self.COL_STR_HITS = QC.translate("stats", "Hits", "This is a word, without spaces and symbols.")
        self.COL_STR_PROTOCOL = QC.translate("stats", "Protocol", "This is a word, without spaces and symbols.")
        self.COL_STR_PROCESS = QC.translate("stats", "Process", "This is a word, without spaces and symbols.")
        self.COL_STR_PROC_ARGS = QC.translate("stats", "Args", "This is a word, without spaces and symbols.")
        self.COL_STR_DESTINATION = QC.translate("stats", "Destination", "This is a word, without spaces and symbols.")
        self.COL_STR_DST_IP = QC.translate("stats", "DstIP", "This is a word, without spaces and symbols.")
        self.COL_STR_DST_HOST = QC.translate("stats", "DstHost", "This is a word, without spaces and symbols.")
        self.COL_STR_DST_PORT = QC.translate("stats", "DstPort", "This is a word, without spaces and symbols.")
        self.COL_STR_RULE = QC.translate("stats", "Rule", "This is a word, without spaces and symbols.")
        self.COL_STR_UID = QC.translate("stats", "UserID", "This is a word, without spaces and symbols.")
        self.COL_STR_LAST_CONNECTION = QC.translate("stats", "LastConnection", "This is a word, without spaces and symbols.")

        self.FIREWALL_STOPPED  = QC.translate("stats", "Not running")
        self.FIREWALL_DISABLED = QC.translate("stats", "Disabled")
        self.FIREWALL_RUNNING  = QC.translate("stats", "Running")

        self._db = db
        self._db_sqlite = self._db.get_db()
        self._db_name = dbname

        self._cfg = Config.get()
        self._nodes = Nodes.instance()

        # TODO: allow to display multiples dialogs
        self._proc_details_dialog = ProcessDetailsDialog()

        self.daemon_connected = False
        # skip table updates if a context menu is active
        self._context_menu_active = False

        self._lock = threading.RLock()
        self._address = address
        self._stats = None
        self._notifications_sent = {}

        self._prefs_dialog = PreferencesDialog()
        self._rules_dialog = RulesEditorDialog()
        self._trigger.connect(self._on_update_triggered)
        self._notification_callback.connect(self._cb_notification_callback)

        self.nodeLabel.setText("")
        self.nodeLabel.setStyleSheet('color: green;font-size:12pt; font-weight:600;')
        self.rulesSplitter.setStretchFactor(0,0)
        self.rulesSplitter.setStretchFactor(1,2)

        self.startButton.clicked.connect(self._cb_start_clicked)
        self.prefsButton.clicked.connect(self._cb_prefs_clicked)
        self.saveButton.clicked.connect(self._on_save_clicked)
        self.comboAction.currentIndexChanged.connect(self._cb_combo_action_changed)
        self.limitCombo.currentIndexChanged.connect(self._cb_limit_combo_changed)
        self.tabWidget.currentChanged.connect(self._cb_tab_changed)
        self.delRuleButton.clicked.connect(self._cb_del_rule_clicked)
        self.rulesSplitter.splitterMoved.connect(self._cb_rules_splitter_moved)
        self.rulesTreePanel.itemClicked.connect(self._cb_rules_tree_item_clicked)
        self.enableRuleCheck.clicked.connect(self._cb_enable_rule_toggled)
        self.editRuleButton.clicked.connect(self._cb_edit_rule_clicked)
        self.newRuleButton.clicked.connect(self._cb_new_rule_clicked)
        self.cmdProcDetails.clicked.connect(self._cb_proc_details_clicked)
        self.comboRulesFilter.currentIndexChanged.connect(self._cb_rules_filter_combo_changed)

        self.enableRuleCheck.setVisible(False)
        self.delRuleButton.setVisible(False)
        self.editRuleButton.setVisible(False)
        self.nodeRuleLabel.setVisible(False)
        self.comboRulesFilter.setVisible(False)

        self.TABLES[self.TAB_MAIN]['view'] = self._setup_table(QtWidgets.QTableView, self.eventsTable, "connections",
                self.TABLES[self.TAB_MAIN]['display_fields'],
                order_by="1",
                group_by=self.TABLES[self.TAB_MAIN]['group_by'],
                delegate=self.TABLES[self.TAB_MAIN]['delegate'],
                resize_cols=(),
                model=ConnectionsTableModel(),
                verticalScrollBar=self.connectionsTableScrollBar,
                limit=self._get_limit()
                )
        self.TABLES[self.TAB_NODES]['view'] = self._setup_table(QtWidgets.QTableView, self.nodesTable, "nodes",
                self.TABLES[self.TAB_NODES]['display_fields'],
                order_by="3,2,1",
                resize_cols=(self.COL_NODE,),
                delegate=self.TABLES[self.TAB_NODES]['delegate'])
        self.TABLES[self.TAB_RULES]['view'] = self._setup_table(QtWidgets.QTableView,
                self.rulesTable, "rules",
                delegate=self.TABLES[self.TAB_RULES]['delegate'],
                order_by="2",
                sort_direction=self.SORT_ORDER[0])
        self.TABLES[self.TAB_HOSTS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.hostsTable, "hosts",
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_HOSTS]['delegate'],
                order_by="2")
        self.TABLES[self.TAB_PROCS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.procsTable, "procs",
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_PROCS]['delegate'],
                order_by="2")
        self.TABLES[self.TAB_ADDRS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.addrTable, "addrs",
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_ADDRS]['delegate'],
                order_by="2")
        self.TABLES[self.TAB_PORTS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.portsTable, "ports",
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_PORTS]['delegate'],
                order_by="2")
        self.TABLES[self.TAB_USERS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.usersTable, "users",
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_USERS]['delegate'],
                order_by="2")

        self.TABLES[self.TAB_NODES]['label']    = self.nodesLabel
        self.TABLES[self.TAB_NODES]['tipLabel'] = self.tipNodesLabel
        self.TABLES[self.TAB_RULES]['label']    = self.ruleLabel
        self.TABLES[self.TAB_RULES]['tipLabel'] = self.tipRulesLabel
        self.TABLES[self.TAB_HOSTS]['label']    = self.hostsLabel
        self.TABLES[self.TAB_HOSTS]['tipLabel'] = self.tipHostsLabel
        self.TABLES[self.TAB_PROCS]['label']    = self.procsLabel
        self.TABLES[self.TAB_PROCS]['tipLabel'] = self.tipProcsLabel
        self.TABLES[self.TAB_ADDRS]['label']    = self.addrsLabel
        self.TABLES[self.TAB_ADDRS]['tipLabel'] = self.tipAddrsLabel
        self.TABLES[self.TAB_PORTS]['label']    = self.portsLabel
        self.TABLES[self.TAB_PORTS]['tipLabel'] = self.tipPortsLabel
        self.TABLES[self.TAB_USERS]['label']    = self.usersLabel
        self.TABLES[self.TAB_USERS]['tipLabel'] = self.tipUsersLabel

        self.TABLES[self.TAB_NODES]['cmd'] = self.cmdNodesBack
        self.TABLES[self.TAB_RULES]['cmd'] = self.cmdRulesBack
        self.TABLES[self.TAB_HOSTS]['cmd'] = self.cmdHostsBack
        self.TABLES[self.TAB_PROCS]['cmd'] = self.cmdProcsBack
        self.TABLES[self.TAB_ADDRS]['cmd'] = self.cmdAddrsBack
        self.TABLES[self.TAB_PORTS]['cmd'] = self.cmdPortsBack
        self.TABLES[self.TAB_USERS]['cmd'] = self.cmdUsersBack

        self.TABLES[self.TAB_MAIN]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_HOSTS]['cmdCleanStats'] = self.cmdCleanHosts
        self.TABLES[self.TAB_RULES]['cmdCleanStats'] = self.cmdCleanRules
        # the rules clean button is only for a particular rule, not all.
        self.TABLES[self.TAB_RULES]['cmdCleanStats'].setVisible(False)
        self.TABLES[self.TAB_PROCS]['cmdCleanStats'] = self.cmdCleanProcs
        self.TABLES[self.TAB_ADDRS]['cmdCleanStats'] = self.cmdCleanAddrs
        self.TABLES[self.TAB_PORTS]['cmdCleanStats'] = self.cmdCleanPorts
        self.TABLES[self.TAB_USERS]['cmdCleanStats'] = self.cmdCleanUsers
        self.TABLES[self.TAB_MAIN]['cmdCleanStats'].clicked.connect(lambda: self._cb_clean_sql_clicked(self.TAB_MAIN))

        self.TABLES[self.TAB_MAIN]['filterLine'] = self.filterLine
        self.TABLES[self.TAB_RULES]['filterLine'] = self.rulesFilterLine
        self.TABLES[self.TAB_HOSTS]['filterLine'] = self.hostsFilterLine
        self.TABLES[self.TAB_PROCS]['filterLine'] = self.procsFilterLine
        self.TABLES[self.TAB_ADDRS]['filterLine'] = self.addrsFilterLine
        self.TABLES[self.TAB_PORTS]['filterLine'] = self.portsFilterLine

        self.TABLES[self.TAB_MAIN]['view'].doubleClicked.connect(self._cb_main_table_double_clicked)
        self.TABLES[self.TAB_MAIN]['filterLine'].textChanged.connect(self._cb_events_filter_line_changed)

        self.TABLES[self.TAB_RULES]['view'].setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.TABLES[self.TAB_RULES]['view'].customContextMenuRequested.connect(self._cb_table_context_menu)
        for idx in range(1,8):
            self.TABLES[idx]['cmd'].hide()
            self.TABLES[idx]['cmd'].setVisible(False)
            self.TABLES[idx]['cmd'].clicked.connect(lambda: self._cb_cmd_back_clicked(idx))
            if self.TABLES[idx]['cmdCleanStats'] != None:
                self.TABLES[idx]['cmdCleanStats'].clicked.connect(lambda: self._cb_clean_sql_clicked(idx))
            self.TABLES[idx]['view'].doubleClicked.connect(self._cb_table_double_clicked)
            self.TABLES[idx]['label'].setStyleSheet('color: blue; font-size:9pt; font-weight:600;')
            self.TABLES[idx]['label'].setVisible(False)

            if self.TABLES[idx]['filterLine'] != None:
                self.TABLES[idx]['filterLine'].textChanged.connect(self._cb_events_filter_line_changed)

        self._load_settings()

        self._tables = ( \
            self.TABLES[self.TAB_MAIN]['view'],
            self.TABLES[self.TAB_NODES]['view'],
            self.TABLES[self.TAB_RULES]['view'],
            self.TABLES[self.TAB_HOSTS]['view'],
            self.TABLES[self.TAB_PROCS]['view'],
            self.TABLES[self.TAB_ADDRS]['view'],
            self.TABLES[self.TAB_PORTS]['view'],
            self.TABLES[self.TAB_USERS]['view']
        )
        self._file_names = ( \
            'events.csv',
            'nodes.csv',
            'rules.csv',
            'hosts.csv',
            'procs.csv',
            'addrs.csv',
            'ports.csv',
            'users.csv'
        )

        self.iconStart = QtGui.QIcon().fromTheme("media-playback-start")
        self.iconPause = QtGui.QIcon().fromTheme("media-playback-pause")

        if QtGui.QIcon.hasThemeIcon("document-new") == False:
            self._configure_buttons_icons()

    #Sometimes a maximized window which had been minimized earlier won't unminimize
    #To workaround, we explicitely maximize such windows when unminimizing happens
    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            if event.oldState() & QtCore.Qt.WindowMinimized and event.oldState() & QtCore.Qt.WindowMaximized:
                #a previously minimized maximized window ...
                if self.windowState() ^ QtCore.Qt.WindowMinimized and self._current_desktop == "KDE":
                    # is not minimized anymore, i.e. it was unminimized
                    # docs: https://doc.qt.io/qt-5/qwidget.html#setWindowState
                    self.setWindowState(self.windowState() & ~QtCore.Qt.WindowMinimized | QtCore.Qt.WindowActive)

    def showEvent(self, event):
        super(StatsDialog, self).showEvent(event)
        self._shown_trigger.emit()
        window_title = QC.translate("stats", "OpenSnitch Network Statistics {0}").format(version)
        if self._address is not None:
            window_title = QC.translate("stats", "OpenSnitch Network Statistics for {0}").format(self._address)
            self.nodeLabel.setText(self._address)
        self._load_settings()
        self._add_rulesTree_nodes()
        self.setWindowTitle(window_title)
        self._refresh_active_table()

    def _configure_buttons_icons(self):
        self.iconStart = self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_MediaPlay"))
        self.iconPause = self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_MediaPause"))

        self.newRuleButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_FileIcon")))
        self.delRuleButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_TrashIcon")))
        self.editRuleButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_FileDialogDetailedView")))
        self.saveButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogSaveButton")))
        self.prefsButton.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_FileDialogDetailedView")))
        self.startButton.setIcon(self.iconStart)
        self.cmdProcDetails.setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_FileDialogContentsView")))
        self.TABLES[self.TAB_MAIN]['cmdCleanStats'].setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogResetButton")))
        for idx in range(1,8):
            self.TABLES[idx]['cmd'].setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_ArrowLeft")))
            if self.TABLES[idx]['cmdCleanStats'] != None:
                self.TABLES[idx]['cmdCleanStats'].setIcon(self.style().standardIcon(getattr(QtWidgets.QStyle, "SP_DialogResetButton")))

    def _load_settings(self):
        dialog_geometry = self._cfg.getSettings(Config.STATS_GEOMETRY)
        dialog_last_tab = self._cfg.getSettings(Config.STATS_LAST_TAB)
        dialog_general_filter_text = self._cfg.getSettings(Config.STATS_FILTER_TEXT)
        dialog_general_filter_action = self._cfg.getSettings(Config.STATS_FILTER_ACTION)
        dialog_general_limit_results = self._cfg.getSettings(Config.STATS_LIMIT_RESULTS)
        if dialog_geometry != None:
            self.restoreGeometry(dialog_geometry)
        if dialog_last_tab != None:
            self.tabWidget.setCurrentIndex(int(dialog_last_tab))
        if dialog_general_filter_text != None:
            # prevent from firing textChanged signal
            self.filterLine.blockSignals(True);
            self.filterLine.setText(dialog_general_filter_text)
            self.filterLine.blockSignals(False);
        if dialog_general_filter_action != None:
            self.comboAction.setCurrentIndex(int(dialog_general_filter_action))
        if dialog_general_limit_results != None:
            # XXX: a little hack, because if the saved index is 0, the signal is not fired.
            # XXX: this causes to fire the event twice
            self.limitCombo.setCurrentIndex(4)
            self.limitCombo.setCurrentIndex(int(dialog_general_limit_results))

        rules_splitter_pos = self._cfg.getSettings(Config.STATS_RULES_SPLITTER_POS)
        if type(rules_splitter_pos) == QtCore.QByteArray:
            self.rulesSplitter.restoreState(rules_splitter_pos)
            rulesSizes = self.rulesSplitter.sizes()
            if self.IN_DETAIL_VIEW[self.TAB_RULES] == True:
                self.comboRulesFilter.setVisible(False)
            elif len(rulesSizes) > 0:
                self.comboRulesFilter.setVisible(rulesSizes[0] == 0)
        else:
            w = self.rulesSplitter.width()
            self.rulesSplitter.setSizes([w/4, w/2])

        self._restore_details_view_columns(self.eventsTable.horizontalHeader(), Config.STATS_GENERAL_COL_STATE)
        self._restore_details_view_columns(self.nodesTable.horizontalHeader(), Config.STATS_NODES_COL_STATE)
        self._restore_details_view_columns(self.rulesTable.horizontalHeader(), Config.STATS_RULES_COL_STATE)

        rulesTreeNodes_expanded = self._cfg.getBool(Config.STATS_RULES_TREE_EXPANDED_1)
        if rulesTreeNodes_expanded != None:
            rules_tree_nodes = self._get_rulesTree_item(self.RULES_TREE_NODES)
            if rules_tree_nodes != None:
                rules_tree_nodes.setExpanded(rulesTreeNodes_expanded)
        rulesTreeApps_expanded = self._cfg.getBool(Config.STATS_RULES_TREE_EXPANDED_0)
        if rulesTreeApps_expanded != None:
            rules_tree_apps = self._get_rulesTree_item(self.RULES_TREE_APPS)
            if rules_tree_apps != None:
                rules_tree_apps.setExpanded(rulesTreeApps_expanded)


    def _save_settings(self):
        self._cfg.setSettings(Config.STATS_GEOMETRY, self.saveGeometry())
        self._cfg.setSettings(Config.STATS_LAST_TAB, self.tabWidget.currentIndex())
        self._cfg.setSettings(Config.STATS_LIMIT_RESULTS, self.limitCombo.currentIndex())
        self._cfg.setSettings(Config.STATS_FILTER_TEXT, self.filterLine.text())

        header = self.eventsTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_GENERAL_COL_STATE, header.saveState())
        nodesHeader = self.nodesTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_NODES_COL_STATE, nodesHeader.saveState())
        rulesHeader = self.rulesTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_RULES_COL_STATE, rulesHeader.saveState())

        rules_tree_apps = self._get_rulesTree_item(self.RULES_TREE_APPS)
        if rules_tree_apps != None:
            self._cfg.setSettings(Config.STATS_RULES_TREE_EXPANDED_0, rules_tree_apps.isExpanded())
        rules_tree_nodes = self._get_rulesTree_item(self.RULES_TREE_NODES)
        if rules_tree_nodes != None:
            self._cfg.setSettings(Config.STATS_RULES_TREE_EXPANDED_1, rules_tree_nodes.isExpanded())


    def _del_rule(self, rule_name, node_addr):
        nid, noti = self._nodes.delete_rule(rule_name, node_addr, self._notification_callback)
        self._notifications_sent[nid] = noti

    def _cb_proc_details_clicked(self):
        table = self._tables[self.tabWidget.currentIndex()]
        nrows = table.model().rowCount()
        pids = {}
        for row in range(0, nrows):
            pid = table.model().index(row, self.COL_PID).data()
            node = table.model().index(row, self.COL_NODE).data()
            if pid not in pids:
                pids[pid] = node

        self._proc_details_dialog.monitor(pids)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        if reply.id in self._notifications_sent:
            if reply.code == ui_pb2.ERROR:
                Message.ok(
                    QC.translate("stats",
                                 "<b>Error:</b><br><br>",
                                 "{0}").format(reply.data),
                    QtWidgets.QMessageBox.Warning)

        else:
            Message.ok(
                QC.translate("stats", "Warning:"),
                "{0}".format(reply.data),
                QtWidgets.QMessageBox.Warning)

    def _cb_tab_changed(self, index):
        if index == self.TAB_MAIN:
            self._set_events_query()
        else:
            if index == self.TAB_RULES:
                self._add_rulesTree_nodes()

            if index == self.TAB_PROCS:
                # make the button visible depending if we're in the detail view
                nrows = self._get_active_table().model().rowCount()
                self.cmdProcDetails.setVisible(self.IN_DETAIL_VIEW[index] and nrows > 0)

            self._refresh_active_table()

    def _cb_table_context_menu(self, pos):
        cur_idx = self.tabWidget.currentIndex()
        if cur_idx != self.TAB_RULES:
            # the only table with context menu for now is the rules table
            return

        self._context_menu_active = True
        refresh_table = self._configure_rules_contextual_menu(pos)
        self._context_menu_active = False
        if refresh_table:
            self._refresh_active_table()

    def _configure_rules_contextual_menu(self, pos):
        cur_idx = self.tabWidget.currentIndex()
        table = self._get_active_table()
        model = table.model()

        selection = table.selectionModel().selectedRows()
        if selection:
            menu = QtWidgets.QMenu()
            durMenu = QtWidgets.QMenu(self.COL_STR_DURATION)
            actionMenu = QtWidgets.QMenu(self.COL_STR_ACTION)

            _actAllow = actionMenu.addAction(QC.translate("stats", "Allow"))
            _actDeny = actionMenu.addAction(QC.translate("stats", "Deny"))
            menu.addMenu(actionMenu)

            _durAlways = durMenu.addAction(QC.translate("stats", "Always"))
            _durUntilReboot = durMenu.addAction(QC.translate("stats", "Until reboot"))
            _dur1h = durMenu.addAction(Config.DURATION_1h)
            _dur30m = durMenu.addAction(Config.DURATION_30m)
            _dur15m = durMenu.addAction(Config.DURATION_15m)
            _dur5m = durMenu.addAction(Config.DURATION_5m)
            menu.addMenu(durMenu)

            is_rule_enabled = model.index(selection[0].row(), self.COL_R_ENABLED).data()
            menu_label_enable = QC.translate("stats", "Disable")
            if is_rule_enabled == "False":
                menu_label_enable = QC.translate("stats", "Enable")

            _menu_enable = menu.addAction(QC.translate("stats", menu_label_enable))
            _menu_duplicate = menu.addAction(QC.translate("stats", "Duplicate"))
            _menu_edit = menu.addAction(QC.translate("stats", "Edit"))
            _menu_delete = menu.addAction(QC.translate("stats", "Delete"))

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec_(table.mapToGlobal(point))

            model = table.model()
            if action == _menu_delete:
                ret = Message.yes_no(
                    QC.translate("stats", "    Your are about to delete this rule.    "),
                    QC.translate("stats", "    Are you sure?"),
                    QtWidgets.QMessageBox.Warning)
                if ret == QtWidgets.QMessageBox.Cancel:
                    return False
                self._table_menu_delete(cur_idx, model, selection)
            elif action == _menu_edit:
                self._table_menu_edit(cur_idx, model, selection)
            elif action == _menu_enable:
                self._table_menu_enable(cur_idx, model, selection, is_rule_enabled)
            elif action == _menu_duplicate:
                self._table_menu_duplicate(cur_idx, model, selection)
            elif action == _durAlways:
                self._table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_ALWAYS)
            elif action == _dur1h:
                self._table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_1h)
            elif action == _dur30m:
                self._table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_30m)
            elif action == _dur15m:
                self._table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_15m)
            elif action == _dur5m:
                self._table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_5m)
            elif action == _durUntilReboot:
                self._table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_UNTIL_RESTART)
            elif action == _actAllow:
                self._table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_ALLOW)
            elif action == _actDeny:
                self._table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_DENY)

        return True

    def _table_menu_duplicate(self, cur_idx, model, selection):

        for idx in selection:
            rule_name = model.index(idx.row(), self.COL_R_NAME).data()
            node_addr = model.index(idx.row(), self.COL_R_NODE).data()

            records = None
            for idx in range(0,100):
                records = self._get_rule(rule_name, node_addr)
                if records == None or records.size() == -1:
                    rule = self._rules_dialog.get_rule_from_records(records)
                    rule.name = "cloned-{0}-{1}".format(idx, rule.name)
                    self._db.insert("rules",
                        "(time, node, name, enabled, precedence, action, duration, operator_type, operator_sensitive, operator_operand, operator_data)",
                            (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                node_addr, rule.name,
                                str(rule.enabled), str(rule.precedence),
                                rule.action, rule.duration, rule.operator.type,
                                str(rule.operator.sensitive), rule.operator.operand, rule.operator.data),
                            action_on_conflict="IGNORE")
                    break

            if records != None and records.size() == -1:
                noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
                nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
                if nid != None:
                    self._notifications_sent[nid] = noti

    def _table_menu_change_rule_field(self, cur_idx, model, selection, field, value):
        for idx in selection:
            rule_name = model.index(idx.row(), self.COL_R_NAME).data()
            node_addr = model.index(idx.row(), self.COL_R_NODE).data()

            records = self._get_rule(rule_name, node_addr)
            rule = self._rules_dialog.get_rule_from_records(records)

            self._db.update(table="rules", fields="{0}=?".format(field),
                            values=[value], condition="name='{0}' AND node='{1}'".format(rule_name, node_addr),
                            action_on_conflict="")

            if field == "action":
                rule.action = value
            elif field == "duration":
                rule.duration = value
            elif field == "precedence":
                rule.precedence = value

            noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
            nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
            if nid != None:
                self._notifications_sent[nid] = noti

    def _table_menu_enable(self, cur_idx, model, selection, is_rule_enabled):
        rule_status = "False" if is_rule_enabled == "True" else "True"

        for idx in selection:
            rule_name = model.index(idx.row(), self.COL_R_NAME).data()
            node_addr = model.index(idx.row(), self.COL_R_NODE).data()

            records = self._get_rule(rule_name, node_addr)
            rule = self._rules_dialog.get_rule_from_records(records)
            rule_type = ui_pb2.DISABLE_RULE if is_rule_enabled == "True" else ui_pb2.ENABLE_RULE

            self._db.update(table="rules", fields="enabled=?",
                            values=[rule_status], condition="name='{0}' AND node='{1}'".format(rule_name, node_addr),
                            action_on_conflict="")

            noti = ui_pb2.Notification(type=rule_type, rules=[rule])
            nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
            if nid != None:
                self._notifications_sent[nid] = noti

    def _table_menu_delete(self, cur_idx, model, selection):

        for idx in selection:
            name = model.index(idx.row(), self.COL_R_NAME).data()
            node = model.index(idx.row(), self.COL_R_NODE).data()
            self._del_rule(name, node)

    def _table_menu_edit(self, cur_idx, model, selection):

        for idx in selection:
            name = model.index(idx.row(), self.COL_R_NAME).data()
            node = model.index(idx.row(), self.COL_R_NODE).data()
            records = self._get_rule(name, node)
            if records == None or records == -1:
                Message.ok("Rule error",
                           QC.translate("stats", "Rule not found by that name and node"),
                           QtWidgets.QMessageBox.Warning)
                return
            self._rules_dialog.edit_rule(records, node)
            break

    def _cb_table_header_clicked(self, pos, sortIdx):
        cur_idx = self.tabWidget.currentIndex()
        model = self._get_active_table().model()
        qstr = model.query().lastQuery().split("ORDER BY")[0]

        q = qstr.strip(" ") + " ORDER BY %d %s" % (pos+1, self.SORT_ORDER[sortIdx])
        if cur_idx > 0 and self.TABLES[cur_idx]['cmd'].isVisible() == False:
            self.TABLES[cur_idx]['last_order_by'] = pos+1
            self.TABLES[cur_idx]['last_order_to'] = sortIdx

            q = qstr.strip(" ") + self._get_order()

        if cur_idx == self.TAB_MAIN:
            q += self._get_limit()

        self.setQuery(model, q)

    def _cb_events_filter_line_changed(self, text):
        cur_idx = self.tabWidget.currentIndex()

        model = self.TABLES[cur_idx]['view'].model()
        qstr = None
        if cur_idx == StatsDialog.TAB_MAIN:
            self._cfg.setSettings(Config.STATS_FILTER_TEXT, text)
            self._set_events_query()
            return

        where_clause = self._get_filter_line_clause(cur_idx, text)
        qstr = self._db.get_query( self.TABLES[cur_idx]['name'], self.TABLES[cur_idx]['display_fields'] ) + \
            where_clause + self._get_order()

        if qstr != None:
            self.setQuery(model, qstr)

    def _cb_limit_combo_changed(self, idx):
        self._set_events_query()

    def _cb_combo_action_changed(self, idx):
        if self.tabWidget.currentIndex() != self.TAB_MAIN:
            return

        self._cfg.setSettings(Config.STATS_GENERAL_FILTER_ACTION, idx)
        self._set_events_query()

    def _cb_clean_sql_clicked(self, idx):
        if self.tabWidget.currentIndex() == StatsDialog.TAB_RULES:
            self._db.empty_rule(self.TABLES[self.tabWidget.currentIndex()]['label'].text())
        else:
            self._db.clean(self.TABLES[self.tabWidget.currentIndex()]['name'])
        self._refresh_active_table()

    def _cb_cmd_back_clicked(self, idx):
        cur_idx = self.tabWidget.currentIndex()
        self.IN_DETAIL_VIEW[cur_idx] = False

        self._set_active_widgets(False)
        if cur_idx == StatsDialog.TAB_RULES:
            self._restore_rules_tab_widgets(True)
            self._restore_details_view_columns(
                self.TABLES[cur_idx]['view'].horizontalHeader(),
                "{0}{1}".format(Config.STATS_VIEW_COL_STATE, cur_idx)
            )
            # return here and now, the query is set via set_rules_filter()
            return
        elif cur_idx == StatsDialog.TAB_PROCS:
            self.cmdProcDetails.setVisible(False)

        model = self._get_active_table().model()
        where_clause = ""
        if self.TABLES[cur_idx]['filterLine'] != None:
            filter_text = self.TABLES[cur_idx]['filterLine'].text()
            where_clause = self._get_filter_line_clause(cur_idx, filter_text)

        self.setQuery(model, self._db.get_query(self.TABLES[cur_idx]['name'], self.TABLES[cur_idx]['display_fields']) + where_clause + " " + self._get_order())
        self._restore_details_view_columns(
            self.TABLES[cur_idx]['view'].horizontalHeader(),
            "{0}{1}".format(Config.STATS_VIEW_COL_STATE, cur_idx)
        )

    def _cb_main_table_double_clicked(self, row):
        data = row.data()
        idx = row.column()
        cur_idx = 1

        if idx == StatsDialog.COL_NODE:
            cur_idx = self.TAB_NODES
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(True, str(data))
            p, addr = self._nodes.get_addr(data)
            self._set_nodes_query(addr)

        elif idx == StatsDialog.COL_PROCS:
            cur_idx = self.TAB_PROCS
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(True, str(data))
            self._set_process_query(data)

        elif idx == StatsDialog.COL_RULES:
            cur_idx = self.TAB_RULES
            self.IN_DETAIL_VIEW[cur_idx] = True
            self._set_rules_tab_active(row, cur_idx, self.COL_RULES, self.COL_NODE)
            self._set_active_widgets(True, str(data))

        else:
            return

        self._restore_details_view_columns(
            self.TABLES[cur_idx]['view'].horizontalHeader(),
            "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
        )

    def _cb_table_double_clicked(self, row):
        cur_idx = self.tabWidget.currentIndex()
        if self.IN_DETAIL_VIEW[cur_idx]:
            return
        self.IN_DETAIL_VIEW[cur_idx] = True

        data = row.data()

        if cur_idx == self.TAB_RULES:
            rule_name = row.model().index(row.row(), self.COL_R_NAME).data()
            self._set_active_widgets(True, rule_name)
            self._set_rules_tab_active(row, cur_idx, self.COL_R_NAME, self.COL_R_NODE)
            self._restore_details_view_columns(
                self.TABLES[cur_idx]['view'].horizontalHeader(),
                "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
            )
            return
        if cur_idx == self.TAB_NODES:
            data = row.model().index(row.row(), self.COL_NODE).data()
        if cur_idx > self.TAB_RULES:
            data = row.model().index(row.row(), self.COL_WHAT).data()


        self._set_active_widgets(True, str(data))

        if cur_idx == StatsDialog.TAB_NODES:
            self._set_nodes_query(data)
        elif cur_idx == StatsDialog.TAB_HOSTS:
            self._set_hosts_query(data)
        elif cur_idx == StatsDialog.TAB_PROCS:
            self._set_process_query(data)
        elif cur_idx == StatsDialog.TAB_ADDRS:
            self._set_addrs_query(data)
        elif cur_idx == StatsDialog.TAB_PORTS:
            self._set_ports_query(data)
        elif cur_idx == StatsDialog.TAB_USERS:
            self._set_users_query(data)

        self._restore_details_view_columns(
            self.TABLES[cur_idx]['view'].horizontalHeader(),
            "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
        )

    def _cb_prefs_clicked(self):
        self._prefs_dialog.show()

    def _cb_rules_filter_combo_changed(self, idx):
        if idx == self.RULES_TREE_APPS:
            self._set_rules_filter()
        elif idx == self.RULES_COMBO_PERMANENT:
            self._set_rules_filter(self.RULES_TREE_APPS, self.RULES_TREE_PERMANENT)
        elif idx == self.RULES_COMBO_TEMPORARY:
            self._set_rules_filter(self.RULES_TREE_APPS, self.RULES_TREE_TEMPORARY)

    def _cb_rules_tree_item_clicked(self, item, col):
        """
        Event fired when the user clicks on the left panel of the rules tab
        """
        item_model = self.rulesTreePanel.indexFromItem(item, col)
        parent = item.parent()
        parent_row = -1
        if parent != None:
            parent_model = self.rulesTreePanel.indexFromItem(parent, col)
            parent_row = parent_model.row()

        self._set_rules_filter(parent_row, item_model.row(), item.text(0))

    def _cb_rules_splitter_moved(self, pos, index):
        self.comboRulesFilter.setVisible(pos == 0)
        self._cfg.setSettings(Config.STATS_RULES_SPLITTER_POS, self.rulesSplitter.saveState())

    def _cb_start_clicked(self):
        if self.daemon_connected == False:
            self.startButton.setChecked(False)
            self.startButton.setIcon(self.iconStart)
            return

        self.update_interception_status(self.startButton.isChecked())
        self._status_changed_trigger.emit(self.startButton.isChecked())

        if self.startButton.isChecked():
            nid, noti = self._nodes.start_interception(_callback=self._notification_callback)
        else:
            nid, noti = self._nodes.stop_interception(_callback=self._notification_callback)

        self._notifications_sent[nid] = noti

    def _cb_new_rule_clicked(self):
        self._rules_dialog.new_rule()

    def _cb_edit_rule_clicked(self):
        cur_idx = self.tabWidget.currentIndex()
        records = self._get_rule(self.TABLES[cur_idx]['label'].text(), self.nodeRuleLabel.text())
        if records == None:
            return

        self._rules_dialog.edit_rule(records, self.nodeRuleLabel.text())

    def _cb_del_rule_clicked(self):
        ret = Message.yes_no(
            QC.translate("stats", "    You are about to delete this rule.    "),
            QC.translate("stats", "    Are you sure?"),
            QtWidgets.QMessageBox.Warning)
        if ret == QtWidgets.QMessageBox.Cancel:
            return

        self._del_rule(self.TABLES[self.tabWidget.currentIndex()]['label'].text(), self.nodeRuleLabel.text())
        self.TABLES[self.TAB_RULES]['cmd'].click()
        self.nodeRuleLabel.setText("")
        self._refresh_active_table()

    def _cb_enable_rule_toggled(self, state):
        rule = ui_pb2.Rule(name=self.TABLES[self.tabWidget.currentIndex()]['label'].text())
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

    # must be called after setModel() or setQuery()
    def _show_columns(self):
        cols = self._cfg.getSettings(Config.STATS_SHOW_COLUMNS)
        if cols == None:
            return

        for c in range(StatsDialog.GENERAL_COL_NUM):
            self.eventsTable.setColumnHidden(c, str(c) not in cols)

    def _update_status_label(self, running=False, text=FIREWALL_DISABLED):
        self.statusLabel.setText("%12s" % text)
        if running:
            self.statusLabel.setStyleSheet('color: green; margin: 5px')
            self.startButton.setIcon(self.iconPause)
        else:
            self.statusLabel.setStyleSheet('color: rgb(206, 92, 0); margin: 5px')
            self.startButton.setIcon(self.iconStart)

    def _get_rulesTree_item(self, index):
        try:
            return self.rulesTreePanel.topLevelItem(index)
        except Exception:
            return None

    def _add_rulesTree_nodes(self):
        if self._nodes.count() > 0:
            nodesItem = self.rulesTreePanel.topLevelItem(self.RULES_TREE_NODES)
            nodesItem.takeChildren()
            for n in self._nodes.get_nodes():
                nodesItem.addChild(QtWidgets.QTreeWidgetItem([n]))

    def _get_rule(self, rule_name, node_name):
        """
        get rule records, given the name of the rule and the node
        """
        cur_idx = self.tabWidget.currentIndex()
        records = self._db.select("SELECT * from rules WHERE name='%s' AND node='%s'" % (
            rule_name, node_name))
        if records.next() == False:
            print("[stats dialog] edit rule, no records: ", rule_name, node_name)
            self.TABLES[cur_idx]['cmd'].click()
            return None

        return records

    def _get_filter_line_clause(self, idx, text):
        if text == "":
            return ""

        if idx == StatsDialog.TAB_RULES:
            return " WHERE rules.name LIKE '%{0}%' ".format(text)
        elif idx == StatsDialog.TAB_HOSTS or idx == StatsDialog.TAB_PROCS or \
             idx == StatsDialog.TAB_ADDRS or idx == StatsDialog.TAB_PORTS:
            return " WHERE what LIKE '%{0}%' ".format(text)

        return ""

    def _get_limit(self):
        return " " + self.LIMITS[self.limitCombo.currentIndex()]

    def _get_order(self):
        cur_idx = self.tabWidget.currentIndex()
        return " ORDER BY %s %s" % (self.TABLES[cur_idx]['last_order_by'], self.SORT_ORDER[self.TABLES[cur_idx]['last_order_to']])

    def _refresh_active_table(self):
        model = self._get_active_table().model()
        self.setQuery(model, model.query().lastQuery())

    def _get_active_table(self):
        return self.TABLES[self.tabWidget.currentIndex()]['view']

    def _set_active_widgets(self, state, label_txt=""):
        cur_idx = self.tabWidget.currentIndex()
        self.TABLES[cur_idx]['label'].setVisible(state)
        self.TABLES[cur_idx]['label'].setText(label_txt)
        self.TABLES[cur_idx]['cmd'].setVisible(state)
        self.TABLES[cur_idx]['tipLabel'].setVisible(not state)
        if self.TABLES[cur_idx]['filterLine'] != None:
            self.TABLES[cur_idx]['filterLine'].setVisible(not state)
        if self.TABLES[cur_idx].get('cmdCleanStats') != None:
            if cur_idx == StatsDialog.TAB_RULES:
                self.TABLES[cur_idx]['cmdCleanStats'].setVisible(state)
            else:
                self.TABLES[cur_idx]['cmdCleanStats'].setVisible(not state)

        header = self.TABLES[cur_idx]['view'].horizontalHeader()
        if state == True:
            # going to normal state
            self._cfg.setSettings("{0}{1}".format(Config.STATS_VIEW_COL_STATE, cur_idx), header.saveState())
        else:
            # going to details state
            self._cfg.setSettings("{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx), header.saveState())

    def _restore_details_view_columns(self, header, settings_key):
        header.blockSignals(True);

         #header = self.TABLES[cur_idx]['view'].horizontalHeader()
            #col_state = self._cfg.getSettings("{0}{1}_details".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx))
        col_state = self._cfg.getSettings(settings_key)

        if type(col_state) == QtCore.QByteArray:
            header.restoreState(col_state)

        header.blockSignals(False);

    def _restore_rules_tab_widgets(self, active):
        self.delRuleButton.setVisible(not active)
        self.editRuleButton.setVisible(not active)
        self.nodeRuleLabel.setText("")
        self.rulesFilterLine.setVisible(active)
        self.rulesTreePanel.setVisible(active)

        if active:
            self.rulesSplitter.refresh()
            self.comboRulesFilter.setVisible(self.rulesTreePanel.width() == 0)

            items = self.rulesTreePanel.selectedItems()
            if len(items) == 0:
                self._set_rules_filter()
                self._restore_details_view_columns(
                    self.TABLES[self.TAB_RULES]['view'].horizontalHeader(),
                    "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, self.TAB_RULES)
                )
                return

            item_m = self.rulesTreePanel.indexFromItem(items[0], 0)
            parent = item_m.parent()
            if parent != None:
                self._set_rules_filter(parent.row(), item_m.row(), item_m.data())

    def _set_rules_tab_active(self, row, cur_idx, name_idx, node_idx):
        data = row.data()
        self._restore_rules_tab_widgets(False)

        self.comboRulesFilter.setVisible(False)

        r_name = row.model().index(row.row(), name_idx).data()
        node = row.model().index(row.row(), node_idx).data()
        self.nodeRuleLabel.setText(node)
        self.tabWidget.setCurrentIndex(cur_idx)
        self._set_rules_query(rule_name=r_name)

    def _set_events_query(self):
        if self.tabWidget.currentIndex() != self.TAB_MAIN:
            return

        model = self.TABLES[self.TAB_MAIN]['view'].model()
        qstr = self._db.get_query(self.TABLES[self.TAB_MAIN]['name'], self.TABLES[self.TAB_MAIN]['display_fields'])

        filter_text = self.filterLine.text()
        action = ""
        if self.comboAction.currentIndex() == 1:
            action = "Action = \"{0}\"".format(Config.ACTION_ALLOW)
        elif self.comboAction.currentIndex() == 2:
            action = "Action = \"{0}\"".format(Config.ACTION_DENY)

        # FIXME: use prepared statements
        if filter_text == "":
            if action != "":
                qstr += " WHERE " + action
        else:
            if action != "":
                action += " AND "
            qstr += " WHERE " + action + " ("\
                    " Process LIKE '%" + filter_text + "%'" \
                    " OR Destination LIKE '%" + filter_text + "%'" \
                    " OR Rule LIKE '%" + filter_text + "%'" \
                    " OR Node LIKE '%" + filter_text + "%'" \
                    " OR Time = \"" + filter_text + "\" " \
                    " OR Protocol = \"" + filter_text + "\")" \

        qstr += self._get_order() + self._get_limit()
        self.setQuery(model, qstr)

    def _set_nodes_query(self, data):

        s = "AND c.src_ip='%s'" % data if '/' not in data else ''
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "n.last_connection as {0}, " \
                "c.action as {1}, " \
                "count(c.process) as {2}, " \
                "c.uid as {3}, " \
                "c.protocol as {4}, " \
                "c.dst_ip as {5}, " \
                "c.dst_host as {6}, " \
                "c.dst_port as {7}, " \
                "c.process || ' (' || c.pid || ')' as {8}, " \
                "c.process_args as {9}, " \
                "c.process_cwd as CWD " \
            "FROM nodes as n, connections as c " \
            "WHERE n.addr = '{10}' {11} GROUP BY {12}, c.process_args, c.uid, c.dst_ip, c.dst_host, c.dst_port, c.protocol, n.status {13}".format(
                self.COL_STR_LAST_CONNECTION,
                self.COL_STR_ACTION,
                self.COL_STR_HITS,
                self.COL_STR_UID,
                self.COL_STR_PROTOCOL,
                self.COL_STR_DST_IP,
                self.COL_STR_DST_HOST,
                self.COL_STR_DST_PORT,
                self.COL_STR_PROCESS,
                self.COL_STR_PROC_ARGS,
                data, s,
                self.COL_STR_PROCESS,
                self._get_order()))

    def _set_rules_filter(self, parent_row=-1, item_row=0, what=""):
        section = self.FILTER_TREE_APPS

        if parent_row == -1:
            if item_row == self.RULES_TREE_NODES:
                section=self.FILTER_TREE_NODES
                what=""
            else:
                section=self.FILTER_TREE_APPS
                what=""

        elif parent_row == self.RULES_TREE_APPS:
            if item_row == self.RULES_TREE_PERMANENT:
                section=self.FILTER_TREE_APPS
                what=self.RULES_TYPE_PERMANENT
            elif item_row == self.RULES_TREE_TEMPORARY:
                section=self.FILTER_TREE_APPS
                what=self.RULES_TYPE_TEMPORARY

        elif parent_row == self.RULES_TREE_NODES:
            section=self.FILTER_TREE_NODES

        if section == self.FILTER_TREE_APPS:
            if what == self.RULES_TYPE_TEMPORARY:
                what = "WHERE r.duration != '%s'" % Config.DURATION_ALWAYS
            elif what == self.RULES_TYPE_PERMANENT:
                what = "WHERE r.duration = '%s'" % Config.DURATION_ALWAYS
        elif section == self.FILTER_TREE_NODES and what != "":
            what = "WHERE r.node = '%s'" % what

        filter_text = self.TABLES[self.TAB_RULES]['filterLine'].text()
        if filter_text != "":
            if what == "":
                what = "WHERE"
            else:
                what = what + " AND"
            what = what + " r.name LIKE '%{0}%'".format(filter_text)
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT * FROM rules as r %s %s" % (what, self._get_order()))

    def _set_rules_query(self, rule_name="", node=""):
        if node != "":
            node = "c.node = '%s' AND" % node
        if rule_name != "":
            rule_name = "r.name = '%s' AND" % rule_name

        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as {0}, " \
                "r.node as {1}, " \
                "count(c.process) as {2}, " \
                "c.uid as {3}, " \
                "c.protocol as {4}, " \
                "c.dst_port as {5}, " \
                "CASE c.dst_host WHEN ''" \
                "   THEN c.dst_ip " \
                "   ELSE c.dst_host " \
                "END {6}, " \
                "c.process as {7}, " \
                "c.process_args as {8}, " \
                "c.process_cwd as CWD " \
            "FROM rules as r, connections as c " \
            "WHERE {9} {10} r.name = c.rule AND r.node = c.node GROUP BY c.process, c.process_args, c.uid, {11}, c.dst_port {12}".format(
                self.COL_STR_TIME,
                self.COL_STR_NODE,
                self.COL_STR_HITS,
                self.COL_STR_UID,
                self.COL_STR_PROTOCOL,
                self.COL_STR_DST_PORT,
                self.COL_STR_DESTINATION,
                self.COL_STR_PROCESS,
                self.COL_STR_PROC_ARGS,
                node,
                rule_name,
                self.COL_STR_DESTINATION,
                self._get_order()))

    def _set_hosts_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as {0}, " \
                "c.node as {1}, " \
                "count(c.process) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "c.protocol as {5}, " \
                "c.dst_port as {6}, " \
                "c.dst_ip as {7}, " \
                "c.process || ' (' || c.pid || ')' as {8}, " \
                "c.process_args as {9}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {10} " \
            "FROM hosts as h, connections as c " \
            "WHERE h.what = '{11}' AND c.dst_host = h.what GROUP BY c.pid, {12}, c.process_args, c.dst_ip, c.dst_port, c.protocol, c.action, c.node {13}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_DST_PORT,
                          self.COL_STR_DST_IP,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_ARGS,
                          self.COL_STR_RULE,
                          data,
                          self.COL_STR_PROCESS,
                self._get_order()))

    def _set_process_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "CASE c.dst_host WHEN ''" \
                "   THEN c.dst_ip || '  ->  ' || c.dst_port " \
                "   ELSE c.dst_host || '  ->  ' || c.dst_port " \
                "END {5}, " \
                "c.pid as PID, " \
                "c.process_args as {6}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {7} " \
            "FROM procs as p, connections as c " \
            "WHERE p.what = '{8}' AND p.what = c.process " \
                      "GROUP BY c.dst_ip, c.dst_host, c.dst_port, c.uid, c.action, c.node, c.pid, c.process_args {9}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_DESTINATION,
                          self.COL_STR_PROC_ARGS,
                          self.COL_STR_RULE,
                          data,
                          self._get_order()))

        nrows = self._get_active_table().model().rowCount()
        self.cmdProcDetails.setVisible(nrows != 0)

    def _set_addrs_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "c.protocol as {5}, " \
                "CASE c.dst_host WHEN ''" \
                "   THEN c.dst_ip " \
                "   ELSE c.dst_host " \
                "END {6}, " \
                "c.dst_port as {7}, " \
                "c.process || ' (' || c.pid || ')' as {8}, " \
                "c.process_args as {9}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {10} " \
            "FROM addrs as a, connections as c " \
            "WHERE a.what = '{11}' AND c.dst_ip = a.what GROUP BY c.pid, {12}, c.process_args, c.dst_port, {13}, c.protocol, c.action, c.uid, c.node {14}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_DESTINATION,
                          self.COL_STR_DST_PORT,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_ARGS,
                          self.COL_STR_RULE,
                          data,
                          self.COL_STR_PROCESS,
                          self.COL_STR_DESTINATION,
                          self._get_order()))

    def _set_ports_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "c.protocol as {5}, " \
                "c.dst_ip as {6}, " \
                "CASE c.dst_host WHEN ''" \
                "   THEN c.dst_ip " \
                "   ELSE c.dst_host " \
                "END {7}, " \
                "c.process || ' (' || c.pid || ')' as {8}, " \
                "c.process_args as {9}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {10} " \
            "FROM ports as p, connections as c " \
            "WHERE p.what = '{11}' AND c.dst_port = p.what GROUP BY c.pid, {12}, c.process_args, {13}, c.dst_ip, c.protocol, c.action, c.uid, c.node {14}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_DST_IP,
                          self.COL_STR_DESTINATION,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_ARGS,
                          self.COL_STR_RULE,
                          data,
                          self.COL_STR_PROCESS,
                          self.COL_STR_DESTINATION,
                          self._get_order()))

    def _set_users_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.protocol as {4}, " \
                "c.dst_ip as {5}, " \
                "CASE c.dst_host WHEN ''" \
                "   THEN c.dst_ip " \
                "   ELSE c.dst_host " \
                "END {6}, " \
                "c.dst_port as {7}, " \
                "c.process || ' (' || c.pid || ')' as {8}, " \
                "c.process_args as {9}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {10} " \
            "FROM users as u, connections as c " \
            "WHERE u.what = '{11}' AND u.what LIKE '%%(' || c.uid || ')' GROUP BY c.pid, {12}, c.process_args, c.dst_ip, {13}, c.dst_port, c.protocol, c.action, c.node {14}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_DST_IP,
                          self.COL_STR_DESTINATION,
                          self.COL_STR_DST_PORT,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_ARGS,
                          self.COL_STR_RULE,
                          data,
                          self.COL_STR_PROCESS,
                          self.COL_STR_DESTINATION,
                          self._get_order()))

    def _on_save_clicked(self):
        tab_idx = self.tabWidget.currentIndex()

        filename = QtWidgets.QFileDialog.getSaveFileName(self,
                    QC.translate("stats", 'Save as CSV'),
                    self._file_names[tab_idx],
                    'All Files (*);;CSV Files (*.csv)')[0].strip()
        if filename == '':
            return

        with self._lock:
            table = self._tables[tab_idx]
            ncols = table.model().columnCount()
            nrows = table.model().rowCount()
            cols = []

            for col in range(0, ncols):
                cols.append(table.model().headerData(col, QtCore.Qt.Horizontal))

            with open(filename, 'w') as csvfile:
                w = csv.writer(csvfile, dialect='excel')
                w.writerow(cols)

                if tab_idx == self.TAB_MAIN:
                    w.writerows(table.model().dumpRows())
                else:
                    for row in range(0, nrows):
                        values = []
                        for col in range(0, ncols):
                            values.append(table.model().index(row, col).data())
                        w.writerow(values)

    def _setup_table(self, widget, tableWidget, table_name, fields="*", group_by="", order_by="2", sort_direction=SORT_ORDER[1], limit="", resize_cols=(), model=None, delegate=None, verticalScrollBar=None):
        tableWidget.setSortingEnabled(True)
        if model == None:
            model = self._db.get_new_qsql_model()
        if delegate != None:
            tableWidget.setItemDelegate(ColorizedDelegate(self, config=delegate))
        if verticalScrollBar != None:
            tableWidget.setVerticalScrollBar(verticalScrollBar)
        self.setQuery(model, "SELECT " + fields + " FROM " + table_name + group_by + " ORDER BY " + order_by + " " + sort_direction + limit)
        tableWidget.setModel(model)

        header = tableWidget.horizontalHeader()
        if header != None:
            header.sortIndicatorChanged.connect(self._cb_table_header_clicked)

            for _, col in enumerate(resize_cols):
                header.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)

        cur_idx = self.tabWidget.currentIndex()
        self._cfg.setSettings("{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx), header.saveState())
        return tableWidget

    def update_interception_status(self, enabled):
        self.startButton.setDown(enabled)
        self.startButton.setChecked(enabled)
        if enabled:
            self._update_status_label(running=True, text=self.FIREWALL_RUNNING)
        else:
            self._update_status_label(running=False, text=self.FIREWALL_DISABLED)

    # launched from a thread
    def update(self, is_local=True, stats=None, need_query_update=True):
        # lock mandatory when there're multiple clients
        with self._lock:
            if stats is not None:
                self._stats = stats
            # do not update any tab if the window is not visible
            if self.isVisible() and self.isMinimized() == False:
                self._trigger.emit(is_local, need_query_update)

    def update_status(self):
        self.startButton.setDown(self.daemon_connected)
        self.startButton.setChecked(self.daemon_connected)
        self.startButton.setDisabled(not self.daemon_connected)
        if self.daemon_connected:
            self._update_status_label(running=True, text=self.FIREWALL_RUNNING)
        else:
            self._update_status_label(running=False, text=self.FIREWALL_STOPPED)
            self.statusLabel.setStyleSheet('color: red; margin: 5px')

    @QtCore.pyqtSlot(bool, bool)
    def _on_update_triggered(self, is_local, need_query_update=False):
        if self._stats is None:
            self.daemonVerLabel.setText("")
            self.uptimeLabel.setText("")
            self.rulesLabel.setText("")
            self.consLabel.setText("")
            self.droppedLabel.setText("")
        else:
            nodes = self._nodes.count()
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

            if need_query_update:
                self._refresh_active_table()

    # prevent a click on the window's x
    # from quitting the whole application
    def closeEvent(self, e):
        self._save_settings()
        e.accept()
        self.hide()

    def hideEvent(self, e):
        self._save_settings()

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(StatsDialog, self).keyPressEvent(event)

    def setQuery(self, model, q):
        if self._context_menu_active == True:
            return
        with self._lock:
            try:
                model.query().clear()
                model.setQuery(q, self._db_sqlite)
                if model.lastError().isValid():
                    print("setQuery() error: ", model.lastError().text())
            except Exception as e:
                print(self._address, "setQuery() exception: ", e)
            finally:
                self._show_columns()
