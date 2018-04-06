import threading
import logging
import queue
import datetime
import operator
import sys
import os
import pwd

from PyQt5 import QtCore, QtGui, uic, QtWidgets

import ui_pb2
from version import version

DIALOG_UI_PATH = "%s/../res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)
class StatsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self.setupUi(self)

        self.daemon_connected = False

        self._stats = None
        self._trigger.connect(self._on_update_triggered)

        self._status_label = self.findChild(QtWidgets.QLabel, "statusLabel")
        self._dver_label = self.findChild(QtWidgets.QLabel, "daemonVerLabel")
        self._uiver_label = self.findChild(QtWidgets.QLabel, "uiVerLabel")
        self._uptime_label = self.findChild(QtWidgets.QLabel, "uptimeLabel")
        self._cons_label = self.findChild(QtWidgets.QLabel, "consLabel")
        self._dropped_label = self.findChild(QtWidgets.QLabel, "droppedLabel")
        self._misses_label = self.findChild(QtWidgets.QLabel, "missesLabel")
        self._tcp_label = self.findChild(QtWidgets.QLabel, "tcpLabel")
        self._udp_label = self.findChild(QtWidgets.QLabel, "udpLabel")

        self._addrs_table = self._setup_table("addrTable", ("IP", "Connections"))
        self._hosts_table = self._setup_table("hostsTable", ("Hostname", "Connections"))
        self._ports_table = self._setup_table("portsTable", ("Port", "Connections"))
        self._users_table = self._setup_table("usersTable", ("User", "Connections"))
        self._procs_table = self._setup_table("procsTable", ("Executable", "Connections"))

    def update(self, stats=None):
        if stats is not None:
            self._stats = stats
        self._trigger.emit()

    def _setup_table(self, name, columns):
        table = self.findChild(QtWidgets.QTableWidget, name)
        table.setHorizontalHeaderLabels(columns)
        header = table.horizontalHeader()       
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        return table

    def _render_table(self, table, data):
        table.setRowCount(len(data))
        table.setColumnCount(2)
        row = 0
        sorted_data = sorted(data.items(), key=operator.itemgetter(1), reverse=True)

        for t in sorted_data:
            what, hits = t

            item = QtWidgets.QTableWidgetItem(what)
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            table.setItem(row, 0, item)

            item = QtWidgets.QTableWidgetItem("%s" % hits)
            item.setFlags( QtCore.Qt.ItemIsSelectable |  QtCore.Qt.ItemIsEnabled )
            table.setItem(row, 1, item)

            row = row + 1

    @QtCore.pyqtSlot()
    def _on_update_triggered(self):
        if self.daemon_connected:
            self._status_label.setText("running")
            self._status_label.setStyleSheet('color: green')
        else:
            self._status_label.setText("not running")
            self._status_label.setStyleSheet('color: red')

        self._dver_label.setText(self._stats.daemon_version)
        self._uiver_label.setText(version)
        self._uptime_label.setText(str(datetime.timedelta(seconds=self._stats.uptime)))
        self._cons_label.setText("%s" % self._stats.connections)
        self._dropped_label.setText("%s" % self._stats.dropped)
        self._misses_label.setText("%s" % self._stats.rule_misses)
        self._tcp_label.setText("%s" % self._stats.by_proto['tcp'] or 0)
        self._udp_label.setText("%s" % self._stats.by_proto['udp'] or 0)

        by_users = {}
        for uid, hits in self._stats.by_uid.iteritems():
            by_users["%s (%s)" % (pwd.getpwuid(int(uid)).pw_name, uid)] = hits

        self._render_table(self._addrs_table, self._stats.by_address)
        self._render_table(self._hosts_table, self._stats.by_host)
        self._render_table(self._ports_table, self._stats.by_port)
        self._render_table(self._users_table, by_users)
        self._render_table(self._procs_table, self._stats.by_executable)

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
