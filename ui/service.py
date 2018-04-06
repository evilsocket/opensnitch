from PyQt5 import QtWidgets, QtGui, QtCore

from datetime import datetime
from threading import Thread
import time
import os

import ui_pb2
import ui_pb2_grpc

from dialogs.prompt import PromptDialog
from dialogs.stats import StatsDialog

from version import version

class UIService(ui_pb2_grpc.UIServicer, QtWidgets.QGraphicsObject):
    _version_warning_trigger = QtCore.pyqtSignal(str, str)
    _status_change_trigger = QtCore.pyqtSignal()

    def __init__(self, app, on_exit):
        super(UIService, self).__init__()

        self._last_ping = None
        self._version_warning_shown = False
        self._asking = False
        self._connected = False
        self._path = os.path.abspath(os.path.dirname(__file__))
        self._app = app
        self._on_exit = on_exit
        self._msg = QtWidgets.QMessageBox()
        self._prompt_dialog = PromptDialog()
        self._stats_dialog = StatsDialog()

        self._setup_slots()
        self._setup_icons()
        self._setup_tray()

        self.check_thread = Thread(target=self._async_worker)
        self.check_thread.daemon = True
        self.check_thread.start()
    
    def _setup_slots(self):
        # https://stackoverflow.com/questions/40288921/pyqt-after-messagebox-application-quits-why
        self._app.setQuitOnLastWindowClosed(False)
        self._version_warning_trigger.connect(self._on_diff_versions)
        self._status_change_trigger.connect(self._on_status_change)

    def _setup_icons(self):
        self.off_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-off.png"))
        self.off_icon = QtGui.QIcon()
        self.off_icon.addPixmap(self.off_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.white_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-white.png"))
        self.white_icon = QtGui.QIcon()
        self.white_icon.addPixmap(self.white_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.red_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-red.png"))
        self.red_icon = QtGui.QIcon()
        self.red_icon.addPixmap(self.red_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

        self._app.setWindowIcon(self.white_icon)

    def _setup_tray(self):
        self._menu = QtWidgets.QMenu()
        self._menu.addAction("Statistics").triggered.connect(lambda: self._stats_dialog.show())
        self._menu.addAction("Close").triggered.connect(self._on_exit)
        self._tray = QtWidgets.QSystemTrayIcon(self.off_icon)
        self._tray.setContextMenu(self._menu)
        self._tray.show()

    @QtCore.pyqtSlot()
    def _on_status_change(self):
        self._stats_dialog.daemon_connected = self._connected
        self._stats_dialog.update()
        if self._connected:
            self._tray.setIcon(self.white_icon)
        else:
            self._tray.setIcon(self.off_icon)

    @QtCore.pyqtSlot(str, str)
    def _on_diff_versions(self, daemon_ver, ui_ver):
        if self._version_warning_shown == False:
            self._msg.setIcon(QtWidgets.QMessageBox.Warning)
            self._msg.setWindowTitle("OpenSnitch version mismatch!")
            self._msg.setText("You are runnig version <b>%s</b> of the daemon, while the UI is at version " + \
                              "<b>%s</b>, they might not be fully compatible." % (daemon_ver, ui_ver))
            self._msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
            self._msg.show()
            self._version_warning_shown = True

    def _async_worker(self):
        was_connected = False

        while True:
            # we didn't see any daemon so far ...
            if self._last_ping is None:
                continue
            # a prompt is being shown, ping is on pause
            elif self._asking is True:
                continue

            # the daemon will ping the ui every second
            # we expect a 3 seconds delay -at most-
            time_not_seen = datetime.now() - self._last_ping
            secs_not_seen = time_not_seen.seconds + time_not_seen.microseconds / 1E6
            self._connected = ( secs_not_seen < 3 )
            if was_connected != self._connected:
                self._status_change_trigger.emit()
                was_connected = self._connected

            time.sleep(1)

    def Ping(self, request, context):
        self._last_ping = datetime.now()
        self._stats_dialog.update(request.stats)

        if request.stats.daemon_version != version:
            self._version_warning_trigger.emit(request.stats.daemon_version, version)

	return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        self._asking = True
        rule = self._prompt_dialog.promptUser(request)
        self._asking = False
        return rule
