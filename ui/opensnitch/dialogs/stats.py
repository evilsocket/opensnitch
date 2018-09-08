import threading
import logging
import datetime
import operator
import sys
import os
import pwd
import csv

from PyQt5 import QtCore, QtGui, uic, QtWidgets

import ui_pb2
from version import version

DIALOG_UI_PATH = "%s/../res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)
class StatsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    RED = QtGui.QColor(0xff, 0x63, 0x47)
    GREEN = QtGui.QColor(0x2e, 0x90, 0x59)

    _trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None, address=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

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
        self._rules_label = self.findChild(QtWidgets.QLabel, "rulesLabel")
        self._cons_label = self.findChild(QtWidgets.QLabel, "consLabel")
        self._dropped_label = self.findChild(QtWidgets.QLabel, "droppedLabel")

        self._events_table = self._setup_table("eventsTable", ("Time", "Action", "Process", "Destination", "Protocol", "Rule" ))
        self._addrs_table = self._setup_table("addrTable", ("IP", "Connections"))
        self._hosts_table = self._setup_table("hostsTable", ("Hostname", "Connections"))
        self._ports_table = self._setup_table("portsTable", ("Port", "Connections"))
        self._users_table = self._setup_table("usersTable", ("User", "Connections"))
        self._procs_table = self._setup_table("procsTable", ("Executable", "Connections"))

        self._tables = ( \
            self._events_table,
            self._hosts_table,
            self._procs_table,
            self._addrs_table,
            self._ports_table,
            self._users_table
        )
        self._file_names = ( \
            'events.csv',
            'hosts.csv',
            'procs.csv',
            'addrs.csv',
            'ports.csv',
            'users.csv'
        )

        if address is not None:
            self.setWindowapply_Title("OpenSnitch Network Statistics for %s" % address)

    def update(self, stats=None):
        with self._lock:
            if stats is not None:
                self._stats = stats
            self._trigger.emit()

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
            ncols = table.columnCount()
            nrows = table.rowCount()
            cols = []

            for col in range(0, ncols):
                cols.append(table.horizontalHeaderItem(col).text())

            with open(filename, 'w') as csvfile:
                w = csv.writer(csvfile, dialect='excel')
                w.writerow(cols)
                
                for row in range(0, nrows):
                    values = []
                    for col in range(0, ncols):
                        values.append(table.item(row, col).text())
                    w.writerow(values)

    def _setup_table(self, name, columns):
        table = self.findChild(QtWidgets.QTableWidget, name)

        ncols = len(columns)
        table.setColumnCount(ncols)
        table.setHorizontalHeaderLabels(columns)

        header = table.horizontalHeader()       
        header.setVisible(True)

        if 'Connections' in columns:
            for col_idx, _ in enumerate(columns):
                header.setSectionResizeMode(col_idx, \
                        QtWidgets.QHeaderView.Stretch if col_idx == 0 else QtWidgets.QHeaderView.ResizeToContents)

        else:
            for col_idx, _ in enumerate(columns):
                header.setSectionResizeMode(col_idx, QtWidgets.QHeaderView.ResizeToContents)

        return table

    def _render_counters_table(self, table, data):
        table.setRowCount(len(data))
        table.setColumnCount(2)
        for row, t in enumerate(sorted(data.items(), key=operator.itemgetter(1), reverse=True)):
            what, hits = t

            item = QtWidgets.QTableWidgetItem(what)
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            table.setItem(row, 0, item)

            item = QtWidgets.QTableWidgetItem("%s" % hits)
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            table.setItem(row, 1, item)


    def _render_events_table(self):
        self._events_table.setRowCount(len(self._stats.events))

        for row, event in enumerate(reversed(self._stats.events)):
            item = QtWidgets.QTableWidgetItem( event.time )
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            self._events_table.setItem(row, 0, item)

            item = QtWidgets.QTableWidgetItem( event.rule.action )
            if event.rule.action == "deny":
                item.setForeground(StatsDialog.RED)
            else:
                item.setForeground(StatsDialog.GREEN)
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            self._events_table.setItem(row, 1, item)

            item = QtWidgets.QTableWidgetItem( event.connection.process_path )
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            self._events_table.setItem(row, 2, item)

            item = QtWidgets.QTableWidgetItem( "%s:%s" % ( \
                    event.connection.dst_host if event.connection.dst_host != "" else event.connection.dst_ip, 
                    event.connection.dst_port ))
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            self._events_table.setItem(row, 3, item)

            item = QtWidgets.QTableWidgetItem( event.connection.protocol )
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            self._events_table.setItem(row, 4, item)

            item = QtWidgets.QTableWidgetItem( event.rule.name )
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            self._events_table.setItem(row, 5, item)

    @QtCore.pyqtSlot()
    def _on_update_triggered(self):
        if self.daemon_connected:
            self._status_label.setText("running")
            self._status_label.setStyleSheet('color: green')
        else:
            self._status_label.setText("not running")
            self._status_label.setStyleSheet('color: red')

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

            self._render_events_table()

            by_users = {}
            if self._address is None:
                for uid, hits in self._stats.by_uid.items():
                    try:
                        pw_name = pwd.getpwuid(int(uid)).pw_name
                    except KeyError:
                        pw_name = "(UID error)"
                    except Exception:
                        pw_name = "error"
                    finally:
                        by_users["%s (%s)" % (pw_name, uid)] = hits
            else:
                by_users = self._stats.by_uid

            self._render_counters_table(self._addrs_table, self._stats.by_address)
            self._render_counters_table(self._hosts_table, self._stats.by_host)
            self._render_counters_table(self._ports_table, self._stats.by_port)
            self._render_counters_table(self._users_table, by_users)
            self._render_counters_table(self._procs_table, self._stats.by_executable)

        self.setFixedSize(self.size())

    # prevent a click on the window's x 
    # from quitting the whole application
    def closeEvent(self, e):
        e.ignore()
        self.hide()

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(StatsDialog, self).keyPressEvent(event)
