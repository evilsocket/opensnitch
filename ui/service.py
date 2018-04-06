from PyQt5 import QtWidgets, QtGui

from datetime import datetime
from threading import Thread
import time
import os

import ui_pb2
import ui_pb2_grpc

from dialog import Dialog
from stats_dialog import StatsDialog

class UIService(ui_pb2_grpc.UIServicer):
    def __init__(self, app, on_exit):
        self.connected = False
        self.path = os.path.abspath(os.path.dirname(__file__))
        self.app = app

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

        self.menu = QtWidgets.QMenu()
        self.stats_dialog = StatsDialog()

        statsAction = self.menu.addAction("Statistics")
        statsAction.triggered.connect(self._on_stats)
        exitAction = self.menu.addAction("Close")
        exitAction.triggered.connect(on_exit)

        self.tray = QtWidgets.QSystemTrayIcon(self.off_icon)
        self.tray.setContextMenu(self.menu)
        self.tray.show()

        self.dialog = Dialog()
        self.stats_dialog = StatsDialog()
        self.last_ping = None
        self.asking = False
        self.check_thread = Thread(target=self._check_worker)
        self.check_thread.daemon = True
        self.check_thread.start()

    def _on_stats(self):
        self.stats_dialog.show()

    def _check_worker(self):
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
                self._on_status_change()
                was_connected = self.connected

            time.sleep(1)

    def _on_status_change(self):
        self.stats_dialog.daemon_connected = self.connected
        self.stats_dialog.update()

        # FIXME: this causes a warning message because it doesn't
        # happen on the same thread as UI ... but it works ...
        if self.connected:
            self.tray.setIcon(self.white_icon)
        else:
            self.tray.setIcon(self.off_icon)
        
    def Ping(self, request, context):
        self.last_ping = datetime.now()
        self.stats_dialog.update(request.stats)
	return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        self.asking = True
        rule = self.dialog.promptUser(request)
        self.asking = False
        return rule
