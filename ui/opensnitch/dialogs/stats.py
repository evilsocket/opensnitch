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

DIALOG_UI_PATH = "%s/../res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)
class StatsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    RED = QtGui.QColor(0xff, 0x63, 0x47)
    GREEN = QtGui.QColor(0x2e, 0x90, 0x59)

    _trigger = QtCore.pyqtSignal()
    SORT_ORDER = ["ASC", "DESC"]
    LAST_ORDER_TO = 1
    LAST_ORDER_BY = 1
    TABLES = {
            0: {
                "name": "connections",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "time as Time, action as Action, dst_host || '  ->  ' || dst_port as Destination, protocol as Protocol, process as Process, rule as Rule"
                },
            1: {
                "name": "rules",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            2: {
                "name": "hosts",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            3: {
                "name": "procs",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            4: {
                "name": "addrs",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            5: {
                "name": "ports",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                },
            6: {
                "name": "users",
                "label": None,
                "tipLabel": None,
                "cmd": None,
                "view": None,
                "display_fields": "*"
                }
            }

    def __init__(self, parent=None, address=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)
        self.setWindowFlags(QtCore.Qt.Window)

        self._db = Database.instance()
        self._db_sqlite = self._db.get_db()

        self._cfg = Config.get()

        self.setupUi(self)

        self.daemon_connected = False

        self._lock = threading.Lock()
        self._address = address
        self._stats = None
        self._trigger.connect(self._on_update_triggered)

        self._save_button = self.findChild(QtWidgets.QToolButton, "saveButton")
        self._save_button.clicked.connect(self._on_save_clicked)
        self._tabs = self.findChild(QtWidgets.QTabWidget, "tabWidget")

        self._status_label = self.findChild(QtWidgets.QLabel, "statusLabel")
        self._version_label = self.findChild(QtWidgets.QLabel, "daemonVerLabel")
        self._uptime_label = self.findChild(QtWidgets.QLabel, "uptimeLabel")
        self._dropped_label = self.findChild(QtWidgets.QLabel, "droppedLabel")
        self._cons_label = self.findChild(QtWidgets.QLabel, "consLabel")
        self._rules_label = self.findChild(QtWidgets.QLabel, "rulesLabel")

        self._combo_action = self.findChild(QtWidgets.QComboBox, "comboAction")
        self._combo_action.currentIndexChanged.connect(self._cb_combo_action_changed)

        self._events_filter_line = self.findChild(QtWidgets.QLineEdit, "filterLine")
        self._events_filter_line.textChanged.connect(self._cb_events_filter_line_changed)

        self.TABLES[0]['view'] = self._setup_table(QtWidgets.QTreeView, "eventsTable", "connections", self.TABLES[0]['display_fields'], order_by="1")
        self.TABLES[1]['view'] = self._setup_table(QtWidgets.QTableView, "rulesTable", "rules", order_by="1")
        self.TABLES[2]['view'] = self._setup_table(QtWidgets.QTableView, "hostsTable", "hosts")
        self.TABLES[3]['view'] = self._setup_table(QtWidgets.QTableView, "procsTable", "procs")
        self.TABLES[4]['view'] = self._setup_table(QtWidgets.QTableView, "addrTable",  "addrs")
        self.TABLES[5]['view'] = self._setup_table(QtWidgets.QTableView, "portsTable", "ports")
        self.TABLES[6]['view'] = self._setup_table(QtWidgets.QTableView, "usersTable", "users")

        self.TABLES[1]['label'] = self.findChild(QtWidgets.QLabel, "ruleLabel")
        self.TABLES[1]['tipLabel'] = self.findChild(QtWidgets.QLabel, "tipRulesLabel")
        self.TABLES[2]['label'] = self.findChild(QtWidgets.QLabel, "hostsLabel")
        self.TABLES[2]['tipLabel'] = self.findChild(QtWidgets.QLabel, "tipHostsLabel")
        self.TABLES[3]['label'] = self.findChild(QtWidgets.QLabel, "procsLabel")
        self.TABLES[3]['tipLabel'] = self.findChild(QtWidgets.QLabel, "tipProcsLabel")
        self.TABLES[4]['label'] = self.findChild(QtWidgets.QLabel, "addrsLabel")
        self.TABLES[4]['tipLabel'] = self.findChild(QtWidgets.QLabel, "tipAddrsLabel")
        self.TABLES[5]['label'] = self.findChild(QtWidgets.QLabel, "portsLabel")
        self.TABLES[5]['tipLabel'] = self.findChild(QtWidgets.QLabel, "tipPortsLabel")
        self.TABLES[6]['label'] = self.findChild(QtWidgets.QLabel, "usersLabel")
        self.TABLES[6]['tipLabel'] = self.findChild(QtWidgets.QLabel, "tipUsersLabel")

        self.TABLES[1]['cmd'] = self.findChild(QtWidgets.QPushButton, "cmdRulesBack")
        self.TABLES[2]['cmd'] = self.findChild(QtWidgets.QPushButton, "cmdHostsBack")
        self.TABLES[3]['cmd'] = self.findChild(QtWidgets.QPushButton, "cmdProcsBack")
        self.TABLES[4]['cmd'] = self.findChild(QtWidgets.QPushButton, "cmdAddrsBack")
        self.TABLES[5]['cmd'] = self.findChild(QtWidgets.QPushButton, "cmdPortsBack")
        self.TABLES[6]['cmd'] = self.findChild(QtWidgets.QPushButton, "cmdUsersBack")

        for idx in range(1,7):
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
            self.TABLES[6]['view']
        )
        self._file_names = ( \
            'events.csv',
            'rules.csv',
            'hosts.csv',
            'procs.csv',
            'addrs.csv',
            'ports.csv',
            'users.csv'
        )

        if address is not None:
            self.setWindowapply_Title("OpenSnitch Network Statistics for %s" % address)

    def _load_settings(self):
        dialog_geometry = self._cfg.getSettings("statsDialog/geometry")
        dialog_last_tab = self._cfg.getSettings("statsDialog/last_tab")
        dialog_general_filter_text = self._cfg.getSettings("statsDialog/general_filter_text")
        dialog_general_filter_action = self._cfg.getSettings("statsDialog/general_filter_action")
        if dialog_geometry != None:
            self.restoreGeometry(dialog_geometry)
        if dialog_last_tab != None:
            self._tabs.setCurrentIndex(int(dialog_last_tab))
        if dialog_general_filter_text != None:
            self._events_filter_line.setText(dialog_general_filter_text)
        if dialog_general_filter_action != None:
            self._combo_action.setCurrentIndex(int(dialog_general_filter_action))

    def _save_settings(self):
        self._cfg.setSettings("statsDialog/geometry", self.saveGeometry())
        self._cfg.setSettings("statsDialog/last_tab", self._tabs.currentIndex())

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
                " Time = \"" + text + "\" OR Action = \"" + text + "\"" + \
                " OR Protocol = \"" +text + "\" OR Destination LIKE '%" + text + "%'" + \
                " OR Process = \"" + text + "\" OR Rule LIKE '%" + text + "%'" + \
                self._get_order()
            self.setQuery(model, qstr)
        else:
            self.setQuery(model, self._db.get_query("connections", self.TABLES[0]['display_fields']) + self._get_order())

        self._cfg.setSettings("statsDialog/general_filter_text", text)

    def _cb_combo_action_changed(self, idx):
        model = self.TABLES[0]['view'].model()
        if self._combo_action.currentText() == "-":
            self.setQuery(model, self._db.get_query("connections", self.TABLES[0]['display_fields']) + self._get_order())
        else:
            action = "Action = '" + self._combo_action.currentText().lower() + "'"
            qstr = self._db.get_query( self.TABLES[0]['name'], self.TABLES[0]['display_fields'] ) + " WHERE " + action + self._get_order()
            self.setQuery(model, qstr)

        self._cfg.setSettings("statsDialog/general_filter_action", idx)

    def _cb_cmd_back_clicked(self, idx):
        cur_idx = self._tabs.currentIndex()
        self.TABLES[cur_idx]['label'].setVisible(False)
        self.TABLES[cur_idx]['tipLabel'].setVisible(True)
        self.TABLES[cur_idx]['cmd'].setVisible(False)
        model = self._get_active_table().model()
        if self.LAST_ORDER_BY > 2:
            self.LAST_ORDER_BY = 1
        self.setQuery(model, self._db.get_query(self.TABLES[cur_idx]['name'], self.TABLES[cur_idx]['display_fields']) + self._get_order())

    def _cb_table_double_clicked(self, row):
        cur_idx = self._tabs.currentIndex()
        if cur_idx == 1 and row.column() != 1:
            return

        self.TABLES[cur_idx]['tipLabel'].setVisible(False)
        self.TABLES[cur_idx]['label'].setVisible(True)
        self.TABLES[cur_idx]['cmd'].setVisible(True)
        self.TABLES[cur_idx]['label'].setText("<b>" + str(row.data()) + "</b>")

        model = self._get_active_table().model()
        data = row.data()
        if cur_idx == 1:
            self.setQuery(model, "SELECT " \
                    "c.time as Time, " \
                    "r.name as RuleName, " \
                    "c.uid as UserID, " \
                    "c.protocol as Protocol, " \
                    "c.dst_port as DstPort, " \
                    "c.dst_ip as DstIP, " \
                    "c.process as Process, " \
                    "c.process_args as Args, " \
                    "count(c.process) as Hits " \
                "FROM rules as r, connections as c " \
                "WHERE r.Name = '%s' AND r.Name = c.rule GROUP BY c.process,c.dst_host %s" % (data, self._get_order()))
        elif cur_idx == 2:
            self.setQuery(model, "SELECT " \
                    "c.uid as UserID, " \
                    "c.protocol as Protocol, " \
                    "c.dst_port as DstPort, " \
                    "c.dst_ip as DstIP, " \
                    "c.process as Process, " \
                    "c.process_args as Args, " \
                    "count(c.process) as Hits " \
                "FROM hosts as h, connections as c " \
                "WHERE c.dst_host = h.what AND h.what = '%s' GROUP BY c.process %s" % (data, self._get_order()))
        elif cur_idx == 3:
            self.setQuery(model, "SELECT " \
                    "c.time as Time, " \
                    "c.dst_host as Destination, " \
                    "c.uid as UserID, " \
                    "c.action as Action, " \
                    "c.process as Process, " \
                    "c.process_args as Args, " \
                    "count(c.dst_host) as Hits " \
                "FROM procs as p, connections as c " \
                "WHERE p.what = c.process AND p.what = '%s' GROUP BY c.dst_host " % data)
        elif cur_idx == 4:
            self.setQuery(model, "SELECT " \
                    "c.uid as UserID, " \
                    "c.protocol as Protocol, " \
                    "c.dst_port as DstPort, " \
                    "c.process as Process, " \
                    "c.process_args as Args, " \
                    "count(c.dst_ip) as Hits " \
                "FROM addrs as a, connections as c " \
                "WHERE c.dst_ip = a.what AND a.what = '%s' GROUP BY c.dst_ip " % data)
        elif cur_idx == 5:
            self.setQuery(model, "SELECT " \
                    "c.uid as UserID, " \
                    "c.protocol as Protocol, " \
                    "c.dst_ip as DstIP, " \
                    "c.dst_port as DstPort, " \
                    "c.process as Process, " \
                    "c.process_args as Args, " \
                    "count(c.dst_ip) as Hits " \
                "FROM ports as p, connections as c " \
                "WHERE c.dst_port = p.what AND p.what = '%s' GROUP BY c.dst_ip " % data)
        elif cur_idx == 6:
            self.setQuery(model, "SELECT " \
                    "c.protocol as Protocol, " \
                    "c.dst_ip as DstIP, " \
                    "c.dst_port as DstPort, " \
                    "c.process as Process, " \
                    "c.process_args as Args, " \
                    "count(c.dst_ip) as Hits " \
                "FROM users as u, connections as c " \
                "WHERE u.what = '%s' AND u.what LIKE '%%(' || c.uid || ')' GROUP BY c.dst_ip" % data)

    def _get_order(self):
        return " ORDER BY %d %s" % (self.LAST_ORDER_BY, self.SORT_ORDER[self.LAST_ORDER_TO])

    def _refresh_active_table(self):
        model = self._get_active_table().model()
        self.setQuery(model, model.query().lastQuery())

    def _get_active_table(self):
        return self.TABLES[self._tabs.currentIndex()]['view']

    def update(self, stats=None):
        with self._lock:
            if stats is not None:
                self._stats = stats
            # do not update any tab if the window is not visible
            if self.isVisible() and self.isMinimized() == False:
                self._trigger.emit()

    def update_status(self):
        if self.daemon_connected:
            self._status_label.setText("running")
            self._status_label.setStyleSheet('color: green')
        else:
            self._status_label.setText("not running")
            self._status_label.setStyleSheet('color: red')

    def _on_save_clicked(self):
        tab_idx = self._tabs.currentIndex()

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

    def _setup_table(self, widget, name, table_name, fields="*", order_by="2"):
        table = self.findChild(widget, name)
        table.setSortingEnabled(True)
        model = QSqlQueryModel()
        self.setQuery(model, "SELECT " + fields + " FROM " + table_name + " ORDER BY " + order_by + " DESC")
        table.setModel(model)

        try:
            header = table.horizontalHeader()
        except Exception:
            header = table.header()

        if header != None:
            header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
            header.sortIndicatorChanged.connect(self._cb_table_header_clicked)


        #for col_idx, _ in enumerate(model.cols()):
        #    header.setSectionResizeMode(col_idx, \
        #            QtWidgets.QHeaderView.Stretch if col_idx == 0 else QtWidgets.QHeaderView.ResizeToContents)
        return table

    @QtCore.pyqtSlot()
    def _on_update_triggered(self):
        if self._stats is None:
            self._version_label.setText("")
            self._uptime_label.setText("")
            self._rules_label.setText("")
            self._cons_label.setText("")
            self._dropped_label.setText("")
        else:
            self._version_label.setText(self._stats.daemon_version)
            self._uptime_label.setText(str(datetime.timedelta(seconds=self._stats.uptime)))
            self._rules_label.setText("%s" % self._stats.rules)
            self._cons_label.setText("%s" % self._stats.connections)
            self._dropped_label.setText("%s" % self._stats.dropped)

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
