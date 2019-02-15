from PyQt5 import QtWidgets, QtGui, QtCore

from datetime import datetime
from threading import Thread, Lock
import time
import os
import socket
import fcntl
import struct
import array
import sys

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

import ui_pb2
import ui_pb2_grpc

from dialogs.prompt import PromptDialog
from dialogs.stats import StatsDialog

from config import Config
from version import version

class UIService(ui_pb2_grpc.UIServicer, QtWidgets.QGraphicsObject):
    _new_remote_trigger = QtCore.pyqtSignal(str, ui_pb2.Statistics)
    _version_warning_trigger = QtCore.pyqtSignal(str, str)
    _status_change_trigger = QtCore.pyqtSignal()

    def __init__(self, app, on_exit, config):
        super(UIService, self).__init__()

        self._cfg = Config.init(config)
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
        self._remote_lock = Lock()
        self._remote_stats = {}

        # make sure we save the configuration if it
        # does not exist as a file yet
        if self._cfg.exists == False:
            self._cfg.save()

        self._setup_interfaces()
        self._setup_slots()
        self._setup_icons()
        self._setup_tray()

        self.check_thread = Thread(target=self._async_worker)
        self.check_thread.daemon = True
        self.check_thread.start()

    # https://gist.github.com/pklaus/289646
    def _setup_interfaces(self):
        max_possible = 128  # arbitrary. raise if needed.
        bytes = max_possible * 32
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array('B', b'\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes, names.buffer_info()[0])
        ))[0]
        namestr = names.tostring()
        self._interfaces = {}
        for i in range(0, outbytes, 40):
            name = namestr[i:i+16].split(b'\0', 1)[0]
            addr = namestr[i+20:i+24]
            self._interfaces[name] = "%d.%d.%d.%d" % (int(addr[0]), int(addr[1]), int(addr[2]), int(addr[3]))

    def _setup_slots(self):
        # https://stackoverflow.com/questions/40288921/pyqt-after-messagebox-application-quits-why
        self._app.setQuitOnLastWindowClosed(False)
        self._version_warning_trigger.connect(self._on_diff_versions)
        self._status_change_trigger.connect(self._on_status_change)
        self._new_remote_trigger.connect(self._on_new_remote)

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
        self._prompt_dialog.setWindowIcon(self.white_icon)

    def _setup_tray(self):
        self._menu = QtWidgets.QMenu()
        self._stats_action = self._menu.addAction("Statistics")
        self._stats_action.triggered.connect(lambda: self._stats_dialog.show())
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
            self._msg.setText(("You are running version <b>%s</b> of the daemon, while the UI is at version " + \
                              "<b>%s</b>, they might not be fully compatible.") % (daemon_ver, ui_ver))
            self._msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
            self._msg.show()
            self._version_warning_shown = True

    @QtCore.pyqtSlot(str,ui_pb2.Statistics)
    def _on_new_remote(self, addr, stats):
        dialog = StatsDialog(address = addr)
        dialog.daemon_connected = True
        dialog.update(stats)
        self._remote_stats[addr] = dialog

        new_act = self._menu.addAction("%s Statistics" % addr)
        new_act.triggered.connect(lambda: self._on_remote_stats_menu(addr))
        self._menu.insertAction(self._stats_action, new_act)
        self._stats_action.setText("Local Statistics")

    def _on_remote_stats_menu(self, address):
        self._remote_stats[address].show()

    def _async_worker(self):
        was_connected = False
        self._status_change_trigger.emit()

        while True:
            time.sleep(1)

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

    def _is_local_request(self, context):
        peer = context.peer()
        if peer.startswith("unix:"):
            return True

        elif peer.startswith("ipv4:"):
            _, addr, _ = peer.split(':')
            for name, ip in self._interfaces.items():
                if addr == ip:
                    return True

        return False

    def Ping(self, request, context):
        if self._is_local_request(context):
            self._last_ping = datetime.now()
            self._stats_dialog.update(request.stats)

            if request.stats.daemon_version != version:
                self._version_warning_trigger.emit(request.stats.daemon_version, version)
        else:
            with self._remote_lock:
                _, addr, _ = context.peer().split(':')
                if addr in self._remote_stats:
                    self._remote_stats[addr].update(request.stats)
                else:
                    self._new_remote_trigger.emit(addr, request.stats)

        return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        self._asking = True
        rule = self._prompt_dialog.promptUser(request, self._is_local_request(context), context.peer())
        self._last_ping = datetime.now()
        self._asking = False
        return rule
