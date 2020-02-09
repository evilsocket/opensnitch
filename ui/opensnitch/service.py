from PyQt5 import QtWidgets, QtGui, QtCore, Qt
from PyQt5.QtSql import QSqlDatabase, QSqlDatabase, QSqlQueryModel, QSqlQuery

from datetime import datetime
from threading import Thread, Lock
import time
import os
import socket
import fcntl
import struct
import array
import sys
import pwd

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

import ui_pb2
import ui_pb2_grpc

from dialogs.prompt import PromptDialog
from dialogs.stats import StatsDialog

from database import Database
from config import Config
from version import version

class UIService(ui_pb2_grpc.UIServicer, QtWidgets.QGraphicsObject):
    _new_remote_trigger = QtCore.pyqtSignal(str, ui_pb2.Statistics)
    _version_warning_trigger = QtCore.pyqtSignal(str, str)
    _status_change_trigger = QtCore.pyqtSignal()

    def __init__(self, app, on_exit):
        super(UIService, self).__init__()
        self._db = Database.instance()

        self._cfg = Config.init()
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

        self._setup_interfaces()
        self._setup_slots()
        self._setup_icons()
        self._setup_tray()

        self.check_thread = Thread(target=self._async_worker)
        self.check_thread.daemon = True
        self.check_thread.start()

        self.last_stats = None

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
        self._stats_dialog._shown_trigger.connect(self._on_stats_dialog_shown)

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
        self.alert_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-alert.png"))
        self.alert_icon = QtGui.QIcon()
        self.alert_icon.addPixmap(self.alert_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

        self._app.setWindowIcon(self.white_icon)
        self._prompt_dialog.setWindowIcon(self.white_icon)

    def _setup_tray(self):
        self._menu = QtWidgets.QMenu()
        self._stats_action = self._menu.addAction("Statistics")

        self._tray = QtWidgets.QSystemTrayIcon(self.off_icon)
        self._tray.setContextMenu(self._menu)

        self._stats_action.triggered.connect(self._show_stats_dialog)
        self._menu.addAction("Close").triggered.connect(self._on_exit)

        self._tray.show()
        if not self._tray.isSystemTrayAvailable():
            self._stats_dialog.show()

    def _show_stats_dialog(self):
        self._tray.setIcon(self.white_icon)
        self._stats_dialog.show()

    @QtCore.pyqtSlot()
    def _on_status_change(self):
        self._stats_dialog.daemon_connected = self._connected
        self._stats_dialog.update_status()
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
        print("_on_new_remote()")
        dialog = StatsDialog(address = addr)
        dialog.daemon_connected = True
        dialog.update(stats)
        self._remote_stats[addr] = dialog

        new_act = self._menu.addAction("%s Statistics" % addr)
        new_act.triggered.connect(lambda: self._on_remote_stats_menu(addr))
        self._menu.insertAction(self._stats_action, new_act)
        self._stats_action.setText("Local Statistics")

    @QtCore.pyqtSlot()
    def _on_stats_dialog_shown(self):
        self._tray.setIcon(self.white_icon)

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

    def _populate_stats(self, db, stats):
        fields = []
        values = []

        for row, event in enumerate(stats.events):
            if self.last_stats != None and event in self.last_stats.events:
                continue
            db.insert("connections",
                    "(time, action, protocol, src_ip, src_port, dst_ip, dst_host, dst_port, uid, process, process_args, rule)",
                    (event.time, event.rule.action, event.connection.protocol, event.connection.src_ip, str(event.connection.src_port),
                        event.connection.dst_ip, event.connection.dst_host, str(event.connection.dst_port),
                        str(event.connection.user_id), event.connection.process_path, " ".join(event.connection.process_args),
                        event.rule.name),
                    action_on_conflict="IGNORE"
                    )
            db.insert("rules",
                    "(time, name, action, duration, operator)",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        event.rule.name, event.rule.action, event.rule.duration,
                        event.rule.operator.operand + ": " + event.rule.operator.data),
                    action_on_conflict="IGNORE")

        fields = []
        values = []
        items = stats.by_host.items()
        last_items = self.last_stats.by_host.items() if self.last_stats != None else ''
        for row, event in enumerate(items):
            if self.last_stats != None and event in last_items:
                continue
            what, hits = event
            fields.append(what)
            values.append(int(hits))
        db.insert_batch("hosts", "(what, hits)", (1,2), fields, values)

        fields = []
        values = []
        items = stats.by_executable.items()
        last_items = self.last_stats.by_executable.items() if self.last_stats != None else ''
        for row, event in enumerate(items):
            if self.last_stats != None and event in last_items:
                continue
            what, hits = event
            fields.append(what)
            values.append(int(hits))
        db.insert_batch("procs", "(what, hits)", (1,2), fields, values)

        fields = []
        values = []
        items = stats.by_address.items()
        last_items = self.last_stats.by_address.items() if self.last_stats != None else ''
        for row, event in enumerate(items):
            if self.last_stats != None and event in last_items:
                continue
            what, hits = event
            fields.append(what)
            values.append(int(hits))
        db.insert_batch("addrs", "(what, hits)", (1,2), fields, values)

        fields = []
        values = []
        items = stats.by_port.items()
        last_items = self.last_stats.by_port.items() if self.last_stats != None else ''
        for row, event in enumerate(items):
            if self.last_stats != None and event in last_items:
                continue
            what, hits = event
            fields.append(what)
            values.append(int(hits))
        db.insert_batch("ports", "(what, hits)", (1,2), fields, values)

        fields = []
        values = []
        items = stats.by_uid.items()
        last_items = self.last_stats.by_uid.items() if self.last_stats != None else ''
        for row, event in enumerate(items):
            if self.last_stats != None and event in last_items:
                continue
            what, hits = event
            pw_name = what
            try:
                pw_name = pwd.getpwuid(int(what)).pw_name + " (" + what + ")"
            except Exception:
                pw_name += " (error)"
            fields.append(pw_name)
            values.append(int(hits))
        db.insert_batch("users", "(what, hits)", (1,2), fields, values)

        self.last_stats = stats

    def Ping(self, request, context):
        if self._is_local_request(context):
            self._last_ping = datetime.now()
            self._populate_stats(self._db, request.stats)
            self._stats_dialog.update(request.stats)

            if request.stats.daemon_version != version:
                self._version_warning_trigger.emit(request.stats.daemon_version, version)
        else:
            with self._remote_lock:
                _, addr, _ = context.peer().split(':')
                if addr in self._remote_stats:
                    self._populate_stats(self._db, request.stats)
                    self._remote_stats[addr].update(request.stats)
                else:
                    self._new_remote_trigger.emit(addr, request.stats)
        return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        self._asking = True
        rule, timeout_triggered = self._prompt_dialog.promptUser(request, self._is_local_request(context), context.peer())
        if timeout_triggered:
            _title = request.process_path
            if _title == "":
                _title = "%s:%d (%s)" % (request.dst_host, request.dst_port, request.protocol)

            self._tray.setIcon(self.alert_icon)
            self._tray.showMessage(_title, "%s action applied\nArguments: %s" % (rule.action, request.process_args), QtWidgets.QSystemTrayIcon.Warning, 0)

        self._last_ping = datetime.now()
        self._asking = False
        return rule
