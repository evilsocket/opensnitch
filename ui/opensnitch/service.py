from PyQt5 import QtWidgets, QtGui, QtCore

from datetime import datetime, timedelta
from threading import Thread, Lock, Event
import grpc
import os
import sys

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

from opensnitch import ui_pb2
from opensnitch import ui_pb2_grpc

from opensnitch.dialogs.prompt import PromptDialog
from opensnitch.dialogs.stats import StatsDialog

from opensnitch.nodes import Nodes
from opensnitch.config import Config
from opensnitch.version import version
from opensnitch.database import Database
from opensnitch.utils import Utils
from opensnitch.utils import Message
from opensnitch.version import version

class UIService(ui_pb2_grpc.UIServicer, QtWidgets.QGraphicsObject):
    _new_remote_trigger = QtCore.pyqtSignal(str, ui_pb2.PingRequest)
    _update_stats_trigger = QtCore.pyqtSignal(str, str, ui_pb2.PingRequest)
    _version_warning_trigger = QtCore.pyqtSignal(str, str)
    _status_change_trigger = QtCore.pyqtSignal(bool)
    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)
    _show_message_trigger = QtCore.pyqtSignal(str, str, int, int)
    _delete_temp_rule_trigger = QtCore.pyqtSignal(str, str)

    def __init__(self, app, on_exit):
        super(UIService, self).__init__()


        self.MENU_ENTRY_STATS = QtCore.QCoreApplication.translate("contextual_menu", "Statistics")
        self.MENU_ENTRY_FW_ENABLE = QtCore.QCoreApplication.translate("contextual_menu", "Enable")
        self.MENU_ENTRY_FW_DISABLE = QtCore.QCoreApplication.translate("contextual_menu", "Disable")
        self.MENU_ENTRY_HELP = QtCore.QCoreApplication.translate("contextual_menu", "Help")
        self.MENU_ENTRY_CLOSE = QtCore.QCoreApplication.translate("contextual_menu", "Close")

        self._cfg = Config.init()
        self._db = Database.instance()
        db_file=self._cfg.getSettings(self._cfg.DEFAULT_DB_FILE_KEY)
        db_status, db_error = self._db.initialize(
            dbtype=self._cfg.getInt(self._cfg.DEFAULT_DB_TYPE_KEY),
            dbfile=db_file
        )
        if db_status is False:
            Message.ok(
                QtCore.QCoreApplication.translate("preferences", "Warning"),
                QtCore.QCoreApplication.translate("preferences",
                                                  "The DB is corrupted and it's not safe to continue.<br>\
                                                  Remove, backup or recover the file before continuing.<br><br>\
                                                  Corrupted database file: {0}".format(db_file)),
                QtWidgets.QMessageBox.Warning)
            sys.exit(-1)

        self._db_sqlite = self._db.get_db()
        self._last_ping = None
        self._version_warning_shown = False
        self._asking = False
        self._connected = False
        self._fw_enabled = False
        self._path = os.path.abspath(os.path.dirname(__file__))
        self._app = app
        self._on_exit = on_exit
        self._exit = False
        self._msg = QtWidgets.QMessageBox()
        self._prompt_dialog = PromptDialog()
        self._remote_lock = Lock()
        self._remote_stats = {}

        self._setup_interfaces()
        self._setup_icons()
        self._stats_dialog = StatsDialog(dbname="general", db=self._db)
        self._setup_tray()
        self._setup_slots()

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
        namestr, outbytes = Utils.get_interfaces()
        self._interfaces = {}
        for i in range(0, outbytes, 40):
            name = namestr[i:i+16].split(b'\0', 1)[0]
            addr = namestr[i+20:i+24]
            self._interfaces[name] = "%d.%d.%d.%d" % (int(addr[0]), int(addr[1]), int(addr[2]), int(addr[3]))

    def _setup_slots(self):
        # https://stackoverflow.com/questions/40288921/pyqt-after-messagebox-application-quits-why
        self._app.setQuitOnLastWindowClosed(False)
        self._version_warning_trigger.connect(self._on_diff_versions)
        self._new_remote_trigger.connect(self._on_new_remote)
        self._update_stats_trigger.connect(self._on_update_stats)
        self._status_change_trigger.connect(self._on_status_changed)
        self._stats_dialog._shown_trigger.connect(self._on_stats_dialog_shown)
        self._stats_dialog._status_changed_trigger.connect(self._on_stats_status_changed)
        self._show_message_trigger.connect(self._show_systray_message)
        self._delete_temp_rule_trigger.connect(self._delete_temporary_rule)

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
        self._tray = QtWidgets.QSystemTrayIcon(self.off_icon)
        self._tray.setContextMenu(self._menu)
        self._tray.activated.connect(self._on_tray_icon_activated)

        self._menu.addAction(self.MENU_ENTRY_STATS).triggered.connect(self._show_stats_dialog)
        self._menu_enable_fw = self._menu.addAction(self.MENU_ENTRY_FW_DISABLE)
        self._menu_enable_fw.setEnabled(False)
        self._menu_enable_fw.triggered.connect(self._on_enable_interception_clicked)
        self._menu.addAction(self.MENU_ENTRY_HELP).triggered.connect(
                lambda: QtGui.QDesktopServices.openUrl(QtCore.QUrl(Config.HELP_CONFIG_URL))
                )
        self._menu.addAction(self.MENU_ENTRY_CLOSE).triggered.connect(self._on_close)

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
        if self._connected and self._fw_enabled:
            self._tray.setIcon(self.white_icon)
        self._stats_dialog.show()

    @QtCore.pyqtSlot(bool)
    def _on_stats_status_changed(self, enabled):
        self._update_fw_status(enabled)

    @QtCore.pyqtSlot(bool)
    def _on_status_changed(self, enabled):
        self._set_daemon_connected(enabled)

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
            if self._fw_enabled:
                self._tray.setIcon(self.white_icon)
            else:
                self._tray.setIcon(self.pause_icon)
        else:
            self._tray.setIcon(self.off_icon)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _on_notification_reply(self, reply):
        if reply.code == ui_pb2.ERROR:
            self._tray.showMessage("Error",
                                reply.data,
                                QtWidgets.QSystemTrayIcon.Information,
                                5000)

    def _on_remote_stats_menu(self, address):
        self._remote_stats[address]['dialog'].show()

    @QtCore.pyqtSlot(str, str, int, int)
    def _show_systray_message(self, title, body, icon, timeout):
        if icon == QtWidgets.QSystemTrayIcon.NoIcon:
            self._tray.setIcon(self.alert_icon)
        self._tray.showMessage(title, body, icon, timeout)

    def _on_enable_interception_clicked(self):
        self._enable_interception(self._fw_enabled)

    def _update_fw_status(self, enabled):
        """_update_fw_status updates the status of the menu entry
        to disable or enable the firewall of the daemon.
        """
        self._fw_enabled = enabled
        if self._connected == False:
            return

        self._stats_dialog.update_interception_status(enabled)
        if enabled:
            self._tray.setIcon(self.white_icon)
            self._menu_enable_fw.setText(self.MENU_ENTRY_FW_DISABLE)
        else:
            self._tray.setIcon(self.pause_icon)
            self._menu_enable_fw.setText(self.MENU_ENTRY_FW_ENABLE)

    def _set_daemon_connected(self, connected):
        """_set_daemon_connected only updates the connection status of the daemon(s),
        regardless if the fw is enabled or not.
        There're 3 states:
            - daemon connected
            - daemon not connected
            - daemon connected and firewall enabled/disabled
        """
        self._stats_dialog.daemon_connected = connected
        self._connected = connected

        # if there're more than 1 node, override connection status
        if self._nodes.count() >= 1:
            self._connected = True
            self._stats_dialog.daemon_connected = True

        if self._nodes.count() == 1:
            self._menu_enable_fw.setEnabled(True)

        if self._nodes.count() == 0 or self._nodes.count() > 1:
            self._menu_enable_fw.setEnabled(False)

        self._stats_dialog.update_status()

        if self._connected:
            self._tray.setIcon(self.white_icon)
        else:
            self._fw_enabled = False
            self._tray.setIcon(self.off_icon)

    def _enable_interception(self, enable):
        if self._connected == False:
            return
        if self._nodes.count() == 0:
            self._tray.showMessage("No nodes connected",
                                "",
                                QtWidgets.QSystemTrayIcon.Information,
                                5000)
            return
        if self._nodes.count() > 1:
            print("enable interception for all nodes not supported yet")
            return

        if enable:
            nid, noti = self._nodes.stop_interception(_callback=self._notification_callback)
        else:
            nid, noti = self._nodes.start_interception(_callback=self._notification_callback)

        self._fw_enabled = not enable

        self._stats_dialog._status_changed_trigger.emit(not enable)

    def _is_local_request(self, proto, addr):
        if proto == "unix":
            return True

        elif proto == "ipv4" or proto == "ipv6":
            for name, ip in self._interfaces.items():
                if addr == ip:
                    return True

        return False

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
                self._nodes.update_rule_time(
                    str(datetime.fromtimestamp(event.unixnano/1000000000)),
                    event.rule.name,
                    "%s:%s" % (proto, addr)
                )

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
                    what = Utils.get_user_id(what)
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

    def _delete_temporary_rule(self, name, addr):
        self._db.delete_rule(name, addr)

    def Ping(self, request, context):
        try:
            self._last_ping = datetime.now()
            if Utils.check_versions(request.stats.daemon_version):
                self._version_warning_trigger.emit(request.stats.daemon_version, version)

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
        # TODO: allow connections originated from ourselves: os.getpid() == request.pid)
        self._asking = True
        proto, addr = self._get_peer(context.peer())
        rule, timeout_triggered = self._prompt_dialog.promptUser(request, self._is_local_request(proto, addr), context.peer())
        if timeout_triggered:
            _title = request.process_path
            if _title == "":
                _title = "%s:%d (%s)" % (request.dst_host if request.dst_host != "" else request.dst_ip, request.dst_port, request.protocol)


            node_text = "" if self._is_local_request(proto, addr) else "on node {0}:{1}".format(proto, addr)
            self._show_message_trigger.emit(_title,
                                            "{0} action applied {1}\nArguments: {2}"
                                            .format(rule.action, node_text, request.process_args),
                                            QtWidgets.QSystemTrayIcon.NoIcon,
                                            0)

        self._last_ping = datetime.now()
        self._asking = False

        if rule.duration in Config.RULES_DURATION_FILTER:
            self._delete_temporary_rule(rule.name, context.peer())
        else:
            self._nodes.add_rule((datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                                 "{0}:{1}".format(proto, addr),
                                rule.name, str(rule.enabled), str(rule.precedence), rule.action, rule.duration,
                                rule.operator.type, str(rule.operator.sensitive), rule.operator.operand,
                                rule.operator.data)

        return rule

    def Subscribe(self, node_config, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        """
        try:
            proto, addr = self._get_peer(context.peer())
            if self._is_local_request(proto, addr) == False:
                self._show_message_trigger.emit("New node connected",
                                    "({0})".format(context.peer()),
                                    QtWidgets.QSystemTrayIcon.Information,
                                    5000)
            n = self._nodes.add(context, node_config)

            if n != None:
                self._status_change_trigger.emit(True)
                # if there're more than one node, we can't update the status
                # based on the fw status, only if the daemon is running or not
                if self._nodes.count() <= 1:
                    self._update_fw_status(node_config.isFirewallRunning)
                else:
                    self._update_fw_status(True)

        except Exception as e:
            print("[Notifications] exception adding new node:", e)
            context.cancel()

        return node_config

    def Notifications(self, node_iter, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        @doc: https://grpc.io/docs/what-is-grpc/core-concepts/
        """
        proto, addr = self._get_peer(context.peer())
        _node = self._nodes.get_node("%s:%s" % (proto, addr))

        stop_event = Event()
        def _on_client_closed():
            stop_event.set()
            self._delete_node(context.peer())

            self._status_change_trigger.emit(False)
            # TODO: handle the situation when a node disconnects, and the
            # remaining node has the fw disabled.
            #if self._nodes.count() == 1:
            #    nd = self._nodes.get_nodes()
            #    if nd[0].get_config().isFirewallRunning:

            if self._is_local_request(proto, addr) == False:
                self._show_message_trigger.emit("node exited",
                                    "({0})".format(context.peer()),
                                    QtWidgets.QSystemTrayIcon.Information,
                                    5000)

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
                except StopIteration:
                    print("[Notifications] Node {0} exited".format(addr))
                    break
                except grpc.RpcError as e:
                    print("[Notifications] grpc exception new_node_message(): ", addr, in_message)
                except Exception as e:
                    print("[Notifications] unexpected exception new_node_message(): ", addr, e, in_message)

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

