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

        self._events_table = self._setup_table("eventsTable", ("Time", "Action", "Process", "Destination", "Protocol", "Rule", "uuid" ))
        self._addrs_table = self._setup_table("addrTable", ("IP", "Connections", "uuid"))
        self._hosts_table = self._setup_table("hostsTable", ("Hostname", "Connections", "uuid"))
        self._ports_table = self._setup_table("portsTable", ("Port", "Connections", "uuid"))
        self._users_table = self._setup_table("usersTable", ("User", "Connections", "uuid"))
        self._procs_table = self._setup_table("procsTable", ("Executable", "Connections", "uuid"))

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

    def _setup_table(self, name, columns):
        table = self.findChild(QtWidgets.QTableView, name)

        ncols = len(columns)
        model = QtGui.QStandardItemModel(self)
        model.setColumnCount(ncols)
        model.setHorizontalHeaderLabels(columns)
        table.setModel(model)
        table.setColumnHidden(ncols-1, True)

        header = table.horizontalHeader()
        header.setVisible(True)

        if 'Connections' in columns:
            for col_idx, _ in enumerate(columns):
                header.setSectionResizeMode(col_idx, \
                        QtWidgets.QHeaderView.Stretch if col_idx == 0 else QtWidgets.QHeaderView.ResizeToContents)

            table.setSortingEnabled(True)
        else:
            table.setSortingEnabled(False)
            for col_idx, _ in enumerate(columns):
                header.setSectionResizeMode(col_idx, QtWidgets.QHeaderView.ResizeToContents)

        return table

    def _populate_counters_table(self, table, data):
        model = table.model()
        for row, t in enumerate(sorted(data.items(), key=operator.itemgetter(1), reverse=True)):
            items = []
            what, hits = t

            items.append(QtGui.QStandardItem(what))
            items.append(QtGui.QStandardItem("%s" % (hits)))
            items.append(QtGui.QStandardItem("%s:%s" % (what, hits)))
            model.insertRow(row, items)

        table.setModel(model)

    def _update_counters_table(self, model, changes):
        for row, data in changes.items():
            what, hits = data
            i = model.index(row, 0)
            model.setData(i, what)
            i = model.index(row, 1)
            model.setData(i, hits)
            i = model.index(row, 3)
            model.setData(i, "%s:%s" % (what, hits))

        return model

    def _insert_counters_table(self, model, newitems):
        for row, data in newitems.items():
            items = []
            what, hits = data
            items.append(QtGui.QStandardItem(what))
            items.append(QtGui.QStandardItem("%s" % (hits)))
            items.append(QtGui.QStandardItem("%s:%s" % (what, hits)))
            model.appendRow(items)

        return model

    def _render_counters_table(self, name, table, data):
        model = table.model()
        cols = model.columnCount()
        rows = model.rowCount()
        if rows == 0:
            self._populate_counters_table(table, data)
            return

        changes = {}
        newitems = {}
        for rd, t in enumerate(sorted(data.items(), key=operator.itemgetter(1), reverse=True)):
            what, hits = t
            idx = model.match(model.index(0, 0), QtCore.Qt.DisplayRole, what, 1, QtCore.Qt.MatchExactly)
            if len(idx) == 0:
                newitems[rd] = t
                continue
            else:
                for r in range(rows):
                    _what = model.index(r, 0).data()
                    _hits = model.index(r, 1).data()
                    if _what == what and (_hits == hits) == False:
                        changes[r] = t
                        break

        if len(changes) == 0 and rows > 0 and len(newitems) == 0:
            return
        elif len(changes) > 0 and rows > 0:
            model = self._update_counters_table(table.model(), changes)
        if len(newitems) > 0 and rows > 0:
            model = self._insert_counters_table(table.model(), newitems)

        table.setModel(model)

    def _render_events_table(self):
        model = self._events_table.model()

        try:
            firstEvent = reversed(self._stats.events)
            firstEvent = firstEvent.__next__()
            idx = model.match(model.index(0,0), QtCore.Qt.DisplayRole, firstEvent.time, 1, QtCore.Qt.MatchExactly)
            if len(idx) == 1:
                return
        except StopIteration:
            pass

        model.removeRows(0, len(self._stats.events))
        for row, event in enumerate(reversed(self._stats.events)):
            items = []

            items.append(QtGui.QStandardItem(event.time))
            itemAction = QtGui.QStandardItem(event.rule.action)
            if event.rule.action == "deny":
                itemAction.setForeground(StatsDialog.RED)
            else:
                itemAction.setForeground(StatsDialog.GREEN)

            items.append(itemAction)

            itemProcess = QtGui.QStandardItem(event.connection.process_path)
            pPath = event.connection.process_path
            for pArgs in event.connection.process_args:
                pPath += "\n    " + pArgs
            itemProcess.setToolTip(pPath)
            items.append(itemProcess)

            items.append(QtGui.QStandardItem("%s:%s" % (
                    event.connection.dst_host if event.connection.dst_host != "" else event.connection.dst_ip,
                    event.connection.dst_port )))
            items.append(QtGui.QStandardItem(event.connection.protocol))
            items.append(QtGui.QStandardItem(event.rule.name))

            model.insertRow(row, items)

        self._events_table.setModel(model)

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

            if self._tabs.currentIndex() == 0:
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

            if self._tabs.currentIndex() == 1:
                self._render_counters_table("hosts", self._hosts_table, self._stats.by_host)
            if self._tabs.currentIndex() == 2:
                self._render_counters_table("procs", self._procs_table, self._stats.by_executable)
            if self._tabs.currentIndex() == 3:
                self._render_counters_table("addrs", self._addrs_table, self._stats.by_address)
            if self._tabs.currentIndex() == 4:
                self._render_counters_table("ports", self._ports_table, self._stats.by_port)
            if self._tabs.currentIndex() == 5:
                self._render_counters_table("users", self._users_table, by_users)

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
