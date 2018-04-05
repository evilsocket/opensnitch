import threading
import logging
import queue
import datetime
import sys
import os
import pwd

from PyQt5 import QtCore, QtGui, uic, QtWidgets

import ui_pb2

DIALOG_UI_PATH = "%s/res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)

class StatsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    _trigger = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)

        self.setupUi(self)

        self.setWindowTitle("Statistics")

        self._stats = None
        self._trigger.connect(self._on_update_triggered)

        self._uptime_label = self.findChild(QtWidgets.QLabel, "uptimeLabel")
        self._dns_label = self.findChild(QtWidgets.QLabel, "dnsLabel")
        self._cons_label = self.findChild(QtWidgets.QLabel, "consLabel")
        self._ignored_label = self.findChild(QtWidgets.QLabel, "ignoredLabel")
        self._accepted_label = self.findChild(QtWidgets.QLabel, "acceptedLabel")
        self._dropped_label = self.findChild(QtWidgets.QLabel, "droppedLabel")
        self._hits_label = self.findChild(QtWidgets.QLabel, "hitsLabel")
        self._misses_label = self.findChild(QtWidgets.QLabel, "missesLabel")

    def update(self, stats):
        self._stats = stats
        self._trigger.emit()

    @QtCore.pyqtSlot()
    def _on_update_triggered(self):
        self._uptime_label.setText(str(datetime.timedelta(seconds=self._stats.uptime)))
        self._dns_label.setText("%s" % self._stats.dns_responses)
        self._cons_label.setText("%s" % self._stats.connections)
        self._ignored_label.setText("%s" % self._stats.ignored)
        self._accepted_label.setText("%s" % self._stats.accepted)
        self._dropped_label.setText("%s" % self._stats.dropped)
        self._hits_label.setText("%s" % self._stats.rule_hits)
        self._misses_label.setText("%s" % self._stats.rule_misses)

    # prevent a click on the window's x 
    # from quitting the whole application
    def closeEvent(self, e):
        e.ignore()
        self.hide()

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if not event.key() == QtCore.Qt.Key_Escape:
            super(StatsDialog, self).keyPressEvent(event)
