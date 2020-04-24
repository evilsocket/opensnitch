import threading
import logging
import datetime
import operator
import sys
import os
import csv
import time

from PyQt5 import Qt, QtCore, QtGui, uic, QtWidgets
from PyQt5.QtSql import QSqlDatabase, QSqlDatabase, QSqlQueryModel, QSqlQuery, QSqlTableModel

import ui_pb2
from database import Database
from config import Config
from version import version
from dialogs.preferences import PreferencesDialog

DIALOG_UI_PATH = "%s/../res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)
class StatsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    RED = QtGui.QColor(0xff, 0x63, 0x47)
    GREEN = QtGui.QColor(0x2e, 0x90, 0x59)

    _trigger = QtCore.pyqtSignal()
    _shown_trigger = QtCore.pyqtSignal()
    _notification_trigger = QtCore.pyqtSignal(ui_pb2.Notification)

    SORT_ORDER = ["ASC", "DESC"]
    LAST_ORDER_TO = 0
    LAST_ORDER_BY = 1
    LIMITS = ["LIMIT 50", "LIMIT 100", "LIMIT 200", "LIMIT 300", ""]
    LAST_GROUP_BY = ""

    COL_NODE   = 1
    COL_ACTION = 2
    COL_DSTIP  = 3
    COL_PROTO  = 4
    COL_PROCS  = 5
    COL_RULES  = 6

    TAB_NODES = 1
    TAB_RULES = 2
    TAB_HOSTS = 3
    TAB_PROCS = 4
    TAB_ADDRS = 5
    TAB_PORTS = 6
    TAB_USERS = 7

    TABLES = {
            0: {
                "name": "connections",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "time as Time, " \
                        "node as Node, " \
                        "action as Action, " \
                        "dst_host || '  ->  ' || dst_port as Destination, " \
                        "protocol as Protocol, " \
                        "process as Process, " \
                        "rule as Rule",
                "group_by": LAST_GROUP_BY
                },
            1: {
                "name": "nodes",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "last_connection as LastConnection, "\
                        "addr as Addr, " \
                        "status as Status, " \
                        "hostname as Hostname, " \
                        "daemon_version as Version, " \
                        "daemon_uptime as Uptime, " \
                        "daemon_rules as Rules," \
                        "cons as Connections," \
                        "cons_dropped as Dropped," \
                        "version as Version" \
                },
            2: {
                "name": "rules",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            3: {
                "name": "hosts",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            4: {
                "name": "procs",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            5: {
                "name": "addrs",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            6: {
                "name": "ports",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            7: {
                "name": "users",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                }
            }

    def __init__(self, parent=None, address=None, dbname="db"):
        super(StatsDialog, self).__init__(parent)
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)
        self.setWindowFlags(QtCore.Qt.Window)
        self.setupUi(self)

        self._db = Database.instance()
        self._db_sqlite = self._db.get_db()
        self._db_name = dbname

        self._cfg = Config.get()

        self.daemon_connected = False

        self._lock = threading.Lock()
        self._address = address
        self._stats = None


        self._prefs_dialog = PreferencesDialog()
        self._trigger.connect(self._on_update_triggered)

        self.nodeLabel.setText("")
        self.nodeLabel.setStyleSheet('color: green;font-size:12pt; font-weight:600;')

        self.startButton.clicked.connect(self._cb_start_clicked)
        self.prefsButton.clicked.connect(self._cb_prefs_clicked)
        self.saveButton.clicked.connect(self._on_save_clicked)
        self.comboAction.currentIndexChanged.connect(self._cb_combo_action_changed)
        self.filterLine.textChanged.connect(self._cb_events_filter_line_changed)
        self.limitCombo.currentIndexChanged.connect(self._cb_limit_combo_changed)
        self.cmdCleanSql.clicked.connect(self._cb_clean_sql_clicked)

        self.TABLES[0]['view'] = self._setup_table(QtWidgets.QTreeView, self.eventsTable, "connections",
                self.TABLES[0]['display_fields'],
                order_by="1",
                group_by=self.TABLES[0]['group_by'],
                resize_cols=(StatsDialog.COL_ACTION, StatsDialog.COL_PROTO, StatsDialog.COL_NODE))
        self.TABLES[1]['view'] = self._setup_table(QtWidgets.QTableView, self.nodesTable, "nodes",
                self.TABLES[1]['display_fields'], order_by="3,2,1")
        self.TABLES[2]['view'] = self._setup_table(QtWidgets.QTableView, self.rulesTable, "rules", order_by="1")
        self.TABLES[3]['view'] = self._setup_table(QtWidgets.QTableView, self.hostsTable, "hosts", order_by="2,1")
        self.TABLES[4]['view'] = self._setup_table(QtWidgets.QTableView, self.procsTable, "procs", order_by="2,1")
        self.TABLES[5]['view'] = self._setup_table(QtWidgets.QTableView, self.addrTable,  "addrs", order_by="2,1")
        self.TABLES[6]['view'] = self._setup_table(QtWidgets.QTableView, self.portsTable, "ports", order_by="2,1")
        self.TABLES[7]['view'] = self._setup_table(QtWidgets.QTableView, self.usersTable, "users", order_by="2,1")

        self.TABLES[1]['label']    = self.nodesLabel
        self.TABLES[1]['tipLabel'] = self.tipNodesLabel
        self.TABLES[2]['label']    = self.ruleLabel
        self.TABLES[2]['tipLabel'] = self.tipRulesLabel
        self.TABLES[3]['label']    = self.hostsLabel
        self.TABLES[3]['tipLabel'] = self.tipHostsLabel
        self.TABLES[4]['label']    = self.procsLabel
        self.TABLES[4]['tipLabel'] = self.tipProcsLabel
        self.TABLES[5]['label']    = self.addrsLabel
        self.TABLES[5]['tipLabel'] = self.tipAddrsLabel
        self.TABLES[6]['label']    = self.portsLabel
        self.TABLES[6]['tipLabel'] = self.tipPortsLabel
        self.TABLES[7]['label']    = self.usersLabel
        self.TABLES[7]['tipLabel'] = self.tipUsersLabel

        self.TABLES[1]['cmd'] = self.cmdNodesBack
        self.TABLES[2]['cmd'] = self.cmdRulesBack
        self.TABLES[3]['cmd'] = self.cmdHostsBack
        self.TABLES[4]['cmd'] = self.cmdProcsBack
        self.TABLES[5]['cmd'] = self.cmdAddrsBack
        self.TABLES[6]['cmd'] = self.cmdPortsBack
        self.TABLES[7]['cmd'] = self.cmdUsersBack

        self.TABLES[0]['view'].doubleClicked.connect(self._cb_main_table_double_clicked)
        for idx in range(1,8):
            self.TABLES[idx]['cmd'].setVisible(False)
            self.TABLES[idx]['cmd'].clicked.connect(lambda: self._cb_cmd_back_clicked(idx))
            self.TABLES[idx]['view'].doubleClicked.connect(self._cb_table_double_clicked)

        self._load_settings()

        self._tables = ( \
            self.TABLES[0]['view'],
            self.TABLES[1]['view'],
            self.TABLES[2]['view'],
            self.TABLES[3]['view'],
            self.TABLES[4]['view'],
            self.TABLES[5]['view'],
            self.TABLES[6]['view'],
            self.TABLES[7]['view']
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

    def showEvent(self, event):
        super(StatsDialog, self).showEvent(event)
        self._shown_trigger.emit()
        window_title = "OpenSnitch Network Statistics - %s " % version
        if self._address is not None:
            window_title = "OpenSnitch Network Statistics for %s" % self._address
            self.nodeLabel.setText(self._address)
        self.setWindowTitle(window_title)

    def get_db(self):
        return self._db

    def _load_settings(self):
        dialog_geometry = self._cfg.getSettings("statsDialog/geometry")
        dialog_last_tab = self._cfg.getSettings("statsDialog/last_tab")
        dialog_general_filter_text = self._cfg.getSettings("statsDialog/general_filter_text")
        dialog_general_filter_action = self._cfg.getSettings("statsDialog/general_filter_action")
        dialog_general_limit_results = self._cfg.getSettings("statsDialog/general_limit_results")
        if dialog_geometry != None:
            self.restoreGeometry(dialog_geometry)
        if dialog_last_tab != None:
            self.tabWidget.setCurrentIndex(int(dialog_last_tab))
        if dialog_general_filter_text != None:
            self.filterLine.setText(dialog_general_filter_text)
        if dialog_general_filter_action != None:
            self.comboAction.setCurrentIndex(int(dialog_general_filter_action))
        if dialog_general_limit_results != None:
            # XXX: a little hack, because if the saved index is 0, the signal is not fired.
            self.limitCombo.setCurrentIndex(4)
            self.limitCombo.setCurrentIndex(int(dialog_general_limit_results))

    def _save_settings(self):
        self._cfg.setSettings("statsDialog/geometry", self.saveGeometry())
        self._cfg.setSettings("statsDialog/last_tab", self.tabWidget.currentIndex())
        self._cfg.setSettings("statsDialog/general_limit_results", self.limitCombo.currentIndex())

    def _cb_table_header_clicked(self, pos, sortIdx):
        model = self._get_active_table().model()
        self.LAST_ORDER_BY = pos+1
        self.LAST_ORDER_TO = sortIdx
        qstr = model.query().lastQuery().split("ORDER BY")[0]
        q = qstr.strip(" ") + self._get_order()
        self.setQuery(model, q)

    def _cb_events_filter_line_changed(self, text):
        model = self.TABLES[0]['view'].model()
        if text != "":
            qstr = self._db.get_query( self.TABLES[0]['name'], self.TABLES[0]['display_fields'] ) + " WHERE " + \
                " Node LIKE '%" + text + "%'" \
                " OR Time = \"" + text + "\" OR Action = \"" + text + "\"" + \
                " OR Protocol = \"" +text + "\" OR Destination LIKE '%" + text + "%'" + \
                " OR Process LIKE '%" + text + "%' OR Rule LIKE '%" + text + "%'" + \
                self.LAST_GROUP_BY + self._get_order() + self._get_limit()
            self.setQuery(model, qstr)
        else:
            self.setQuery(model, self._db.get_query("connections",
                self.TABLES[0]['display_fields']) +
                " " + self.LAST_GROUP_BY +
                " " + self._get_order() + self._get_limit())

        self._cfg.setSettings("statsDialog/general_filter_text", text)

    def _cb_limit_combo_changed(self, idx):
        model = self._get_active_table().model()
        qstr = model.query().lastQuery().split("LIMIT")[0]
        if idx != 4:
            qstr += " LIMIT " + self.limitCombo.currentText()
        self.setQuery(model, qstr)

    def _cb_combo_action_changed(self, idx):
        model = self.TABLES[0]['view'].model()
        qstr = self._db.get_query(self.TABLES[0]['name'], self.TABLES[0]['display_fields'])

        if self.comboAction.currentText() == "-":
            qstr += self.LAST_GROUP_BY + self._get_order() + self._get_limit()
        else:
            action = "Action = '" + self.comboAction.currentText().lower() + "'"
            qstr += " WHERE " + action + self.LAST_GROUP_BY + self._get_order() + self._get_limit()

        self.setQuery(model, qstr)
        self._cfg.setSettings("statsDialog/general_filter_action", idx)

    def _cb_clean_sql_clicked(self):
        self._db.clean(self.TABLES[self.tabWidget.currentIndex()]['name'])

    def _cb_cmd_back_clicked(self, idx):
        cur_idx = self.tabWidget.currentIndex()
        self.TABLES[cur_idx]['label'].setVisible(False)
        self.TABLES[cur_idx]['tipLabel'].setVisible(True)
        self.TABLES[cur_idx]['cmd'].setVisible(False)
        model = self._get_active_table().model()
        if self.LAST_ORDER_BY > 2:
            self.LAST_ORDER_BY = 1
        self.setQuery(model, self._db.get_query(self.TABLES[cur_idx]['name'], self.TABLES[cur_idx]['display_fields']) + self._get_order())

    def _cb_main_table_double_clicked(self, row):
        data = row.data()
        idx = row.column()
        cur_idx = 1
        if idx == 1:
            cur_idx = 1
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_nodes_query(data)
        elif idx == StatsDialog.COL_PROCS:
            cur_idx = 4
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_process_query(data)
        elif idx == StatsDialog.COL_RULES:
            cur_idx = 2
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_rules_query(data)

        self.TABLES[cur_idx]['tipLabel'].setVisible(False)
        self.TABLES[cur_idx]['label'].setVisible(True)
        self.TABLES[cur_idx]['cmd'].setVisible(True)
        self.TABLES[cur_idx]['label'].setText("<b>" + str(data) + "</b>")

    def _cb_table_double_clicked(self, row):
        cur_idx = self.tabWidget.currentIndex()
        if cur_idx == 1 and row.column() != 1:
            return

        self.TABLES[cur_idx]['tipLabel'].setVisible(False)
        self.TABLES[cur_idx]['label'].setVisible(True)
        self.TABLES[cur_idx]['cmd'].setVisible(True)
        self.TABLES[cur_idx]['label'].setText("<b>" + str(row.data()) + "</b>")

        # TODO: add generic widgets for filtering data

        data = row.data()
        if cur_idx == StatsDialog.TAB_NODES:
            self._set_nodes_query(data)
        elif cur_idx == StatsDialog.TAB_RULES:
            self._set_rules_query(data)
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

    def _cb_prefs_clicked(self):
        self._prefs_dialog.show()

    def _cb_start_clicked(self):
        if self.daemon_connected == False:
            self.startButton.setChecked(False)
            return
        self.statusLabel.setStyleSheet('color: green')

        # TODO: move to a new method: node.load_firewall(), unload_firewall()
        notType = ui_pb2.UNLOAD_FIREWALL
        if self.startButton.isChecked():
            self.statusLabel.setText("running")
            notType = ui_pb2.LOAD_FIREWALL
        else:
            self.statusLabel.setText("running/disabled")

        noti = ui_pb2.Notification(clientName="", serverName="", type=notType, data="", rules=[])
        self._notification_trigger.emit(noti)

    def _get_limit(self):
        return " " + self.LIMITS[self.limitCombo.currentIndex()]

    def _get_order(self):
        return " ORDER BY %d %s" % (self.LAST_ORDER_BY, self.SORT_ORDER[self.LAST_ORDER_TO])

    def _refresh_active_table(self):
        model = self._get_active_table().model()
        self.setQuery(model, model.query().lastQuery())

    def _get_active_table(self):
        return self.TABLES[self.tabWidget.currentIndex()]['view']

    def _set_nodes_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "n.last_connection as LastConnection, " \
                "n.addr as Addr, " \
                "n.status as Status, " \
                "c.uid as UserID, " \
                "c.protocol as Protocol, " \
                "c.dst_port as DstPort, " \
                "c.dst_ip as DstIP, " \
                "c.process as Process, " \
                "c.process_args as Args, " \
                "count(c.process) as ProcessesExec " \
            "FROM nodes as n, connections as c " \
            "WHERE n.addr = '%s' GROUP BY c.process,c.dst_host %s" % (data, self._get_order()))

    def _set_rules_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as Time, " \
                "c.node as Node, " \
                "r.name as RuleName, " \
                "r.action as Action, " \
                "r.duration as Duration, " \
                "c.uid as UserID, " \
                "c.protocol as Protocol, " \
                "c.dst_port as DstPort, " \
                "c.dst_ip as DstIP, " \
                "c.process as Process, " \
                "c.process_args as Args, " \
                "count(c.process) as Hits " \
            "FROM rules as r, connections as c " \
            "WHERE r.Name = '%s' AND r.Name = c.rule GROUP BY c.process,c.dst_host %s" % (data, self._get_order()))

    def _set_hosts_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as Time, " \
                "c.node as Node, " \
                "c.action as Action, " \
                "c.uid as UserID, " \
                "c.protocol as Protocol, " \
                "c.dst_port as DstPort, " \
                "c.dst_ip as DstIP, " \
                "c.process as Process, " \
                "c.process_args as Args, " \
                "count(c.process) as Hits, " \
                "c.rule as Rule " \
            "FROM hosts as h, connections as c " \
            "WHERE c.dst_host = h.what AND h.what = '%s' GROUP BY c.process %s" % (data, self._get_order()))

    def _set_process_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as Time, " \
                "c.node as Node, " \
                "c.action as Action, " \
                "c.uid as UserID, " \
                "c.dst_host || '  ->  ' || c.dst_port as Destination, " \
                "c.process as Process, " \
                "c.process_args as Args, " \
                "count(c.dst_host) as Hits, " \
                "c.rule as Rule " \
            "FROM procs as p, connections as c " \
            "WHERE p.what = c.process AND p.what = '%s' GROUP BY c.dst_host %s" % (data, self._get_order()))

    def _set_addrs_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as Time, " \
                "c.node as Node, " \
                "c.action as Action, " \
                "c.uid as UserID, " \
                "c.protocol as Protocol, " \
                "c.dst_port as DstPort, " \
                "c.process as Process, " \
                "c.process_args as Args, " \
                "count(c.dst_ip) as Hits, " \
                "c.rule as Rule " \
            "FROM addrs as a, connections as c " \
                "WHERE c.dst_ip = a.what AND a.what = '%s' GROUP BY c.dst_ip %s" % (data, self._get_order()))

    def _set_ports_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as Time, " \
                "c.node as Node, " \
                "c.action as Action, " \
                "c.uid as UserID, " \
                "c.protocol as Protocol, " \
                "c.dst_ip as DstIP, " \
                "c.dst_port as DstPort, " \
                "c.process as Process, " \
                "c.process_args as Args, " \
                "count(c.dst_ip) as Hits, " \
                "c.rule as Rule " \
            "FROM ports as p, connections as c " \
            "WHERE c.dst_port = p.what AND p.what = '%s' GROUP BY c.dst_ip %s" % (data, self._get_order()))

    def _set_users_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "c.time as Time, " \
                "c.node as Node, " \
                "c.action as Action, " \
                "c.protocol as Protocol, " \
                "c.dst_ip as DstIP, " \
                "c.dst_port as DstPort, " \
                "c.process as Process, " \
                "c.process_args as Args, " \
                "count(c.dst_ip) as Hits, " \
                "c.rule as Rule " \
            "FROM users as u, connections as c " \
            "WHERE u.what = '%s' AND u.what LIKE '%%(' || c.uid || ')' GROUP BY c.dst_ip %s" % (data, self._get_order()))

    # launched from a thread
    def update(self, addr=None, stats=None):
        # lock mandatory when there're multiple clients
        with self._lock:
            if stats is not None:
                self._stats = stats
            # do not update any tab if the window is not visible
            if self.isVisible() and self.isMinimized() == False:
                self._trigger.emit()

    def update_status(self):
        self.startButton.setDown(self.daemon_connected)
        self.startButton.setChecked(self.daemon_connected)
        self.startButton.setDisabled(not self.daemon_connected)
        if self.daemon_connected:
            self.statusLabel.setText("running")
            self.statusLabel.setStyleSheet('color: green')
        else:
            self.statusLabel.setText("not running")
            self.statusLabel.setStyleSheet('color: red')

    def _on_save_clicked(self):
        tab_idx = self.tabWidget.currentIndex()

        filename = QtWidgets.QFileDialog.getSaveFileName(self,
                    'Save as CSV',
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

                for row in range(0, nrows):
                    values = []
                    for col in range(0, ncols):
                        values.append(table.model().index(row, col).data())
                    w.writerow(values)

    def _setup_table(self, widget, tableWidget, table_name, fields="*", group_by="", order_by="2", limit="", resize_cols=(), model=None):
        tableWidget.setSortingEnabled(True)
        if model == None:
            model = QSqlQueryModel()
        self.setQuery(model, "SELECT " + fields + " FROM " + table_name + group_by + " ORDER BY " + order_by + " DESC" + limit)
        tableWidget.setModel(model)

        try:
            header = tableWidget.horizontalHeader()
        except Exception:
            header = tableWidget.header()

        if header != None:
            header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
            header.sortIndicatorChanged.connect(self._cb_table_header_clicked)


        for _, col in enumerate(resize_cols):
            header.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)

        return tableWidget

    def _show_local_stats(self, show):
        self.daemonVerLabel.setVisible(show)
        self.uptimeLabel.setVisible(show)
        self.rulesLabel.setVisible(show)
        self.consLabel.setVisible(show)
        self.droppedLabel.setVisible(show)

    @QtCore.pyqtSlot()
    def _on_update_triggered(self):
        if self._stats is None:
            self.daemonVerLabel.setText("")
            self.uptimeLabel.setText("")
            self.rulesLabel.setText("")
            self.consLabel.setText("")
            self.droppedLabel.setText("")
        else:
            rows = self.TABLES[1]['view'].model().rowCount()
            self._show_local_stats(rows <= 1)
            if rows <= 1:
                self.daemonVerLabel.setText(self._stats.daemon_version)
                self.uptimeLabel.setText(str(datetime.timedelta(seconds=self._stats.uptime)))
                self.rulesLabel.setText("%s" % self._stats.rules)
                self.consLabel.setText("%s" % self._stats.connections)
                self.droppedLabel.setText("%s" % self._stats.dropped)

            self._refresh_active_table()

    # prevent a click on the window's x
    # from quitting the whole application
    def closeEvent(self, e):
        self._save_settings()
        e.ignore()
        self.hide()

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(StatsDialog, self).keyPressEvent(event)

    def setQuery(self, model, q):
        with self._lock:
            model.setQuery(q, self._db_sqlite)
            model.query().clear()
