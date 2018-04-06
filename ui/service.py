from PyQt5 import QtWidgets, QtGui, QtCore

from datetime import datetime
from threading import Thread
import time
import os

import ui_pb2
import ui_pb2_grpc

from version import version
from dialog import Dialog
from stats_dialog import StatsDialog

class UIService(ui_pb2_grpc.UIServicer, QtWidgets.QGraphicsObject):
    _version_warning_trigger = QtCore.pyqtSignal(str, str)
    _status_change_trigger = QtCore.pyqtSignal()

    def __init__(self, app, on_exit):
        super(UIService, self).__init__()

        self._version_warning_shown = False
        self._version_warning_trigger.connect(self._on_diff_versions)
        self._status_change_trigger.connect(self._on_status_change)

        self.connected = False
        self.path = os.path.abspath(os.path.dirname(__file__))
        self.app = app

        # https://stackoverflow.com/questions/40288921/pyqt-after-messagebox-application-quits-why
        self.app.setQuitOnLastWindowClosed(False)

        self.off_image = QtGui.QPixmap(os.path.join(self.path, "res/icon-off.png"))
        self.off_icon = QtGui.QIcon()
        self.off_icon.addPixmap(self.off_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

        self.white_image = QtGui.QPixmap(os.path.join(self.path, "res/icon-white.png"))
        self.white_icon = QtGui.QIcon()
        self.white_icon.addPixmap(self.white_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

        self.red_image = QtGui.QPixmap(os.path.join(self.path, "res/icon-red.png"))
        self.red_icon = QtGui.QIcon()
        self.red_icon.addPixmap(self.red_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

        self.app.setWindowIcon(self.white_icon)

        self.msg = QtWidgets.QMessageBox()

        self.menu = QtWidgets.QMenu()
        self.stats_dialog = StatsDialog()

        statsAction = self.menu.addAction("Statistics")
        statsAction.triggered.connect(lambda: self.stats_dialog.show())
        exitAction = self.menu.addAction("Close")
        exitAction.triggered.connect(on_exit)

        self.tray = QtWidgets.QSystemTrayIcon(self.off_icon)
        self.tray.setContextMenu(self.menu)
        self.tray.show()

        self.dialog = Dialog()
        self.stats_dialog = StatsDialog()
        self.last_ping = None
        self.asking = False
        self.check_thread = Thread(target=self._async_worker)
        self.check_thread.daemon = True
        self.check_thread.start()

    @QtCore.pyqtSlot()
    def _on_status_change(self):
        self.stats_dialog.daemon_connected = self.connected
        self.stats_dialog.update()
        if self.connected:
            self.tray.setIcon(self.white_icon)
        else:
            self.tray.setIcon(self.off_icon)

    @QtCore.pyqtSlot(str, str)
    def _on_diff_versions(self, daemon_ver, ui_ver):
        if self._version_warning_shown == False:
            self.msg.setIcon(QtWidgets.QMessageBox.Warning)
            self.msg.setWindowTitle("OpenSnitch version mismatch!")
            self.msg.setText("You are runnig version <b>%s</b> of the daemon, while the UI is at version <b>%s</b>, they might not be fully compatible." % (daemon_ver, ui_ver))
            self.msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
            self.msg.show()
            self._version_warning_shown = True

    def _async_worker(self):
        was_connected = False

        while True:
            # we didn't see any daemon so far ...
            if self.last_ping is None:
                continue
            # a prompt is being shown, ping is on pause
            elif self.asking is True:
                continue

            # the daemon will ping the ui every second
            # we expect a 3 seconds delay -at most-
            time_not_seen = datetime.now() - self.last_ping
            secs_not_seen = time_not_seen.seconds + time_not_seen.microseconds / 1E6
            self.connected = ( secs_not_seen < 3 )
            if was_connected != self.connected:
                self._status_change_trigger.emit()
                was_connected = self.connected

            time.sleep(1)

    def Ping(self, request, context):
        self.last_ping = datetime.now()
        self.stats_dialog.update(request.stats)

        if request.stats.daemon_version != version:
            self._version_warning_trigger.emit(request.stats.daemon_version, version)

	return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        self.asking = True
        rule = self.dialog.promptUser(request)
        self.asking = False
        return rule
