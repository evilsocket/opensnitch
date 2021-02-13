from PyQt5 import QtWidgets, QtGui, QtCore

from datetime import datetime, timedelta
from threading import Thread, Lock, Event
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

from nodes import Nodes
from config import Config
from version import version
from database import Database

class UIService(ui_pb2_grpc.UIServicer, QtWidgets.QGraphicsObject):
    _new_remote_trigger = QtCore.pyqtSignal(str, ui_pb2.PingRequest)
    _update_stats_trigger = QtCore.pyqtSignal(str, str, ui_pb2.PingRequest)
    _version_warning_trigger = QtCore.pyqtSignal(str, str)
    _status_change_trigger = QtCore.pyqtSignal()

    def __init__(self, app, on_exit):
        super(UIService, self).__init__()

        self._db = Database.instance()
        self._db_sqlite = self._db.get_db()
        self._cfg = Config.init()
        self._last_ping = None
        self._version_warning_shown = False
        self._asking = False
        self._connected = False
        self._path = os.path.abspath(os.path.dirname(__file__))
        self._app = app
        self._on_exit = on_exit
        self._exit = False
        self._msg = QtWidgets.QMessageBox()
        self._prompt_dialog = PromptDialog()
        self._stats_dialog = StatsDialog(dbname="general", db=self._db)
        self._remote_lock = Lock()
        self._remote_stats = {}

        self._setup_interfaces()
        self._setup_slots()
        self._setup_icons()
        self._setup_tray()

        self.check_thread = Thread(target=self._async_worker)
        self.check_thread.daemon = True
        self.check_thread.start()

        self._nodes = Nodes.instance()

        self._last_stats = {}
        self._last_items = {
                'hosts':{},
                'procs':{},
                'addrs':{},
                'ports':{},
                'users':{}
                }

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
        namestr = names.tobytes()
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
        self._update_stats_trigger.connect(self._on_update_stats)
        self._stats_dialog._shown_trigger.connect(self._on_stats_dialog_shown)
        self._stats_dialog._status_changed_trigger.connect(self._on_stats_status_changed)

    def _setup_icons(self):
        self.off_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-off.png"))
        self.off_icon = QtGui.QIcon()
        self.off_icon.addPixmap(self.off_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.white_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-white.svg"))
        self.white_icon = QtGui.QIcon()
        self.white_icon.addPixmap(self.white_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.red_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-red.png"))
        self.red_icon = QtGui.QIcon()
        self.red_icon.addPixmap(self.red_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pause_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-pause.png"))
        self.pause_icon = QtGui.QIcon()
        self.pause_icon.addPixmap(self.pause_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.alert_image = QtGui.QPixmap(os.path.join(self._path, "res/icon-alert.png"))
        self.alert_icon = QtGui.QIcon()
        self.alert_icon.addPixmap(self.alert_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

        self._app.setWindowIcon(self.white_icon)
        self._prompt_dialog.setWindowIcon(self.white_icon)

    def _setup_tray(self):
        self._menu = QtWidgets.QMenu()
        self._stats_action = self._menu.addAction(QtCore.QCoreApplication.translate("contextual_menu","Statistics"))

        self._tray = QtWidgets.QSystemTrayIcon(self.off_icon)
        self._tray.setContextMenu(self._menu)
        self._tray.activated.connect(self._on_tray_icon_activated)

        self._menu.addAction(QtCore.QCoreApplication.translate("contextual_menu", "Help")).triggered.connect(
                lambda: QtGui.QDesktopServices.openUrl(QtCore.QUrl(Config.HELP_URL))
                )

        self._stats_action.triggered.connect(self._show_stats_dialog)
        self._menu.addAction(QtCore.QCoreApplication.translate("contextual_menu", "Close")).triggered.connect(self._on_close)

        self._tray.show()
        if not self._tray.isSystemTrayAvailable():
            self._stats_dialog.show()

    def _on_tray_icon_activated(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.Trigger or reason == QtWidgets.QSystemTrayIcon.MiddleClick:
            if self._stats_dialog.isVisible() and not self._stats_dialog.isMinimized():
                self._stats_dialog.hide()
            elif self._stats_dialog.isVisible() and self._stats_dialog.isMinimized() and not self._stats_dialog.isMaximized():
                self._stats_dialog.hide()
                self._stats_dialog.showNormal()
            elif self._stats_dialog.isVisible() and self._stats_dialog.isMinimized() and self._stats_dialog.isMaximized():
                self._stats_dialog.hide()
                self._stats_dialog.showMaximized()
            else:
                self._stats_dialog.show()

    def _on_close(self):
        self._exit = True
        self._on_exit()

    def _show_stats_dialog(self):
        if self._connected:
            self._tray.setIcon(self.white_icon)
        self._stats_dialog.show()

    @QtCore.pyqtSlot(bool)
    def _on_stats_status_changed(self, paused):
        if paused:
            self._tray.setIcon(self.pause_icon)
        else:
            self._tray.setIcon(self.white_icon)

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

    @QtCore.pyqtSlot(str, str, ui_pb2.PingRequest)
    def _on_update_stats(self, proto, addr, request):
        main_need_refresh, details_need_refresh = self._populate_stats(self._db, proto, addr, request.stats)
        is_local_request = self._is_local_request(proto, addr)
        self._stats_dialog.update(is_local_request, request.stats, main_need_refresh or details_need_refresh)

    @QtCore.pyqtSlot(str, ui_pb2.PingRequest)
    def _on_new_remote(self, addr, request):
        self._remote_stats[addr] = {
                'last_ping': datetime.now(),
                'dialog': StatsDialog(address=addr, dbname=addr, db=self._db)
                }
        self._remote_stats[addr]['dialog'].daemon_connected = True
        self._remote_stats[addr]['dialog'].update(addr, request.stats)
        self._remote_stats[addr]['dialog'].show()

    @QtCore.pyqtSlot()
    def _on_stats_dialog_shown(self):
        if self._connected:
            self._tray.setIcon(self.white_icon)
        else:
            self._tray.setIcon(self.off_icon)

    def _on_remote_stats_menu(self, address):
        self._remote_stats[address]['dialog'].show()

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

    def _check_versions(self, daemon_version):
        lMayor, lMinor, lPatch = version.split(".")
        rMayor, rMinor, rPatch = daemon_version.split(".")
        if lMayor != rMayor or (lMayor == rMayor and lMinor != rMinor):
            self._version_warning_trigger.emit(daemon_version, version)

    def _is_local_request(self, proto, addr):
        if proto == "unix":
            return True

        elif proto == "ipv4" or proto == "ipv6":
            for name, ip in self._interfaces.items():
                if addr == ip:
                    return True

        return False

    def _get_user_id(self, uid):
        pw_name = uid
        try:
            pw_name = pwd.getpwuid(int(uid)).pw_name + " (" + uid + ")"
        except Exception:
            #pw_name += " (error)"
            pass

        return pw_name

    def _get_peer(self, peer):
        """
        server          -> client
        127.0.0.1:50051 -> ipv4:127.0.0.1:52032
        [::]:50051      -> ipv6:[::1]:59680
        0.0.0.0:50051   -> ipv6:[::1]:59654
        """
        return self._nodes.get_addr(peer)

    def _delete_node(self, peer):
        try:
            proto, addr = self._get_peer(peer)
            if addr in self._last_stats:
                del self._last_stats[addr]
            for table in self._last_items:
                if addr in self._last_items[table]:
                    del self._last_items[table][addr]

            self._nodes.update(proto, addr, Nodes.OFFLINE)
            self._nodes.delete(peer)
            self._stats_dialog.update(True, None, True)
        except Exception as e:
            print("_delete_node() exception:", e)

    def _populate_stats(self, db, proto, addr, stats):
        fields = []
        values = []
        main_need_refresh = False
        details_need_refresh = False
        try:
            if db == None:
                print("populate_stats() db None")
                return main_need_refresh, details_need_refresh

            _node = self._nodes.get_node(proto+":"+addr)
            if _node == None:
                return main_need_refresh, details_need_refresh

            # TODO: move to nodes.add_node()
            version  = _node['data'].version if _node != None else ""
            hostname = _node['data'].name if _node != None else ""
            db.insert("nodes",
                    "(addr, status, hostname, daemon_version, daemon_uptime, " \
                            "daemon_rules, cons, cons_dropped, version, last_connection)",
                            (addr, Nodes.ONLINE, hostname, stats.daemon_version, str(timedelta(seconds=stats.uptime)),
                            stats.rules, stats.connections, stats.dropped,
                            version, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

            if addr not in self._last_stats:
                self._last_stats[addr] = []

            for event in stats.events:
                if event.unixnano in self._last_stats[addr]:
                    continue
                main_need_refresh=True
                db.insert("connections",
                        "(time, node, action, protocol, src_ip, src_port, dst_ip, dst_host, dst_port, uid, pid, process, process_args, process_cwd, rule)",
                        (str(datetime.fromtimestamp(event.unixnano/1000000000)), "%s:%s" % (proto, addr), event.rule.action,
                            event.connection.protocol, event.connection.src_ip, str(event.connection.src_port),
                            event.connection.dst_ip, event.connection.dst_host, str(event.connection.dst_port),
                            str(event.connection.user_id), str(event.connection.process_id),
                            event.connection.process_path, " ".join(event.connection.process_args),
                            event.connection.process_cwd, event.rule.name),
                        action_on_conflict="IGNORE"
                        )
                # TODO: move to nodes.add_node()
                # TODO: remove, and add them only ondemand
                db.insert("rules",
                        "(time, node, name, enabled, precedence, action, duration, operator_type, operator_sensitive, operator_operand, operator_data)",
                            (str(datetime.fromtimestamp(event.unixnano/1000000000)),
                                "%s:%s" % (proto, addr),
                                event.rule.name, str(event.rule.enabled), str(event.rule.precedence),
                                event.rule.action, event.rule.duration,
                                event.rule.operator.type, str(event.rule.operator.sensitive),
                                event.rule.operator.operand, event.rule.operator.data),
                          action_on_conflict="REPLACE")

            details_need_refresh = self._populate_stats_details(db, addr, stats)
            self._last_stats[addr] = []
            for event in stats.events:
                self._last_stats[addr].append(event.unixnano)
        except Exception as e:
            print("_populate_stats() exception: ", e)

        return main_need_refresh, details_need_refresh

    def _populate_stats_details(self, db, addr, stats):
        need_refresh = False
        changed = self._populate_stats_events(db, addr, stats, "hosts", ("what", "hits"), (1,2), stats.by_host.items())
        if changed: need_refresh = True
        changed = self._populate_stats_events(db, addr, stats, "procs", ("what", "hits"), (1,2), stats.by_executable.items())
        if changed: need_refresh = True
        changed = self._populate_stats_events(db, addr, stats, "addrs", ("what", "hits"), (1,2), stats.by_address.items())
        if changed: need_refresh = True
        changed = self._populate_stats_events(db, addr, stats, "ports", ("what", "hits"), (1,2), stats.by_port.items())
        if changed: need_refresh = True
        changed = self._populate_stats_events(db, addr, stats, "users", ("what", "hits"), (1,2), stats.by_uid.items())
        if changed: need_refresh = True

        return need_refresh

    def _populate_stats_events(self, db, addr, stats, table, colnames, cols, items):
        fields = []
        values = []
        need_refresh = False
        try:
            if addr not in self._last_items[table].keys():
                self._last_items[table][addr] = {}
            if items == self._last_items[table][addr]:
                return need_refresh

            for row, event in enumerate(items):
                if event in self._last_items[table][addr]:
                    continue
                need_refresh = True
                what, hits = event
                # FIXME: this is suboptimal
                # BUG: there can be users with same id on different machines but with different names
                if table == "users":
                    what = self._get_user_id(what)
                fields.append(what)
                values.append(int(hits))
            # FIXME: default action on conflict is to replace. If there're multiple nodes connected,
            # stats are painted once per node on each update.
            if need_refresh:
                db.insert_batch(table, colnames, cols, fields, values)

            self._last_items[table][addr] = items
        except Exception as e:
            print("details exception: ", e)

        return need_refresh

    def Ping(self, request, context):
        try:
            self._last_ping = datetime.now()
            self._check_versions(request.stats.daemon_version)

            proto, addr = self._get_peer(context.peer())
            # do not update db here, do it on the main thread
            self._update_stats_trigger.emit(proto, addr, request)
            #else:
            #    with self._remote_lock:
            #        # XXX: disable this option for now
            #        # opening several dialogs only updates one of them.
            #        if addr not in self._remote_stats:
            #            self._new_remote_trigger.emit(addr, request)
            #        else:
            #            self._populate_stats(self._remote_stats[addr]['dialog'].get_db(), proto, addr, request.stats)
            #            self._remote_stats[addr]['dialog'].update(addr, request.stats)

        except Exception as e:
            print("Ping exception: ", e)

        return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        self._asking = True
        proto, addr = self._get_peer(context.peer())
        rule, timeout_triggered = self._prompt_dialog.promptUser(request, self._is_local_request(proto, addr), context.peer())
        if timeout_triggered:
            _title = request.process_path
            if _title == "":
                _title = "%s:%d (%s)" % (request.dst_host if request.dst_host != "" else request.dst_ip, request.dst_port, request.protocol)

            self._tray.setIcon(self.alert_icon)
            self._tray.showMessage(_title, "%s action applied\nArguments: %s" % (rule.action, request.process_args), QtWidgets.QSystemTrayIcon.NoIcon, 0)

        self._last_ping = datetime.now()
        self._asking = False

        return rule

    def Subscribe(self, node_config, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        """
        try:
            n = self._nodes.add(context, node_config)
        except Exception as e:
            print("[Notifications] exception adding new node:", e)
            context.cancel()

        return node_config

    def Notifications(self, node_iter, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        """
        proto, addr = self._get_peer(context.peer())
        _node = self._nodes.get_node("%s:%s" % (proto, addr))

        stop_event = Event()
        def _on_client_closed():
            stop_event.set()
            self._delete_node(context.peer())

        context.add_callback(_on_client_closed)

        # TODO: move to notifications.py
        def new_node_message():
            print("new node connected, listening for client responses...", addr)
            while self._exit == False:
                try:
                    if stop_event.is_set():
                        break
                    in_message = next(node_iter)
                    if in_message == None:
                        continue
                    self._nodes.reply_notification(addr, in_message)
                except StopIteration as e:
                    print("[Notifications] Node exited")
                except Exception as e:
                    print("[Notifications] exception new_node_message(): ", addr, e)

        read_thread = Thread(target=new_node_message)
        read_thread.daemon = True
        read_thread.start()

        while self._exit == False:
            if stop_event.is_set():
                break

            try:
                noti = _node['notifications'].get()
                if noti != None:
                    _node['notifications'].task_done()
                    yield noti
            except Exception as e:
                print("[Notifications] exception getting notification from queue:", addr, e)
                context.cancel()

        return node_iter

