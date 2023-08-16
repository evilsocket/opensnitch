from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import QCoreApplication as QC

from datetime import datetime, timedelta
from threading import Thread, Lock, Event
import grpc
import os
import sys
import json
import copy

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

from opensnitch import ui_pb2
from opensnitch import ui_pb2_grpc

from opensnitch.dialogs.prompt import PromptDialog
from opensnitch.dialogs.stats import StatsDialog

from opensnitch.notifications import DesktopNotifications
from opensnitch.firewall import Rules as FwRules
from opensnitch.nodes import Nodes
from opensnitch.config import Config
from opensnitch.version import version
from opensnitch.database import Database
from opensnitch.utils import Utils, CleanerTask, Themes
from opensnitch.utils import Message, languages
from opensnitch.utils.xdg import Autostart

class UIService(ui_pb2_grpc.UIServicer, QtWidgets.QGraphicsObject):
    _new_remote_trigger = QtCore.pyqtSignal(str, ui_pb2.PingRequest)
    _node_actions_trigger = QtCore.pyqtSignal(dict)
    _update_stats_trigger = QtCore.pyqtSignal(str, str, ui_pb2.PingRequest)
    _add_alert_trigger = QtCore.pyqtSignal(str, str, ui_pb2.Alert)
    _version_warning_trigger = QtCore.pyqtSignal(str, str)
    _status_change_trigger = QtCore.pyqtSignal(bool)
    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)
    _show_message_trigger = QtCore.pyqtSignal(str, str, int, int)

    # .desktop filename located under /usr/share/applications/
    DESKTOP_FILENAME = "opensnitch_ui.desktop"

    def __init__(self, app, on_exit, start_in_bg=False):
        super(UIService, self).__init__()


        self.MENU_ENTRY_STATS = QtCore.QCoreApplication.translate("contextual_menu", "Statistics")
        self.MENU_ENTRY_FW_ENABLE = QtCore.QCoreApplication.translate("contextual_menu", "Enable")
        self.MENU_ENTRY_FW_DISABLE = QtCore.QCoreApplication.translate("contextual_menu", "Disable")
        self.MENU_ENTRY_HELP = QtCore.QCoreApplication.translate("contextual_menu", "Help")
        self.MENU_ENTRY_CLOSE = QtCore.QCoreApplication.translate("contextual_menu", "Close")

        # set of actions that must be performed on the main thread
        self.NODE_ADD = 0
        self.NODE_UPDATE = 1
        self.NODE_DELETE = 2
        self.ADD_RULE = 3
        self.DELETE_RULE = 4

        self._cfg = Config.init()
        self._db = Database.instance()
        db_file=self._cfg.getSettings(self._cfg.DEFAULT_DB_FILE_KEY)
        db_jrnl_wal=self._cfg.getBool(Config.DEFAULT_DB_JRNL_WAL)
        db_status, db_error = self._db.initialize(
            dbtype=self._cfg.getInt(self._cfg.DEFAULT_DB_TYPE_KEY),
            dbfile=db_file,
            dbjrnl_wal=db_jrnl_wal
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
        self._remote_lock = Lock()
        self._remote_stats = {}
        self._autostart = Autostart()

        self.translator = None
        self._init_translation()
        self._themes = Themes()
        self._desktop_notifications = DesktopNotifications()
        self._setup_interfaces()
        self._setup_icons()
        self._prompt_dialog = PromptDialog(appicon=self.white_icon)
        self._stats_dialog = StatsDialog(dbname="general", db=self._db, appicon=self.white_icon)
        self._setup_tray()
        self._setup_slots()

        self._nodes = Nodes.instance()
        self._nodes.reset_status()

        self._last_stats = {}
        self._last_items = {
                'hosts':{},
                'procs':{},
                'addrs':{},
                'ports':{},
                'users':{}
                }

        if not start_in_bg:
            self._show_gui_if_tray_not_available()

        self._cleaner = None
        if self._cfg.getBool(Config.DEFAULT_DB_PURGE_OLDEST):
            self._start_db_cleaner()
        self._cfg.setRulesDurationFilter(
            self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES),
            self._cfg.getInt(self._cfg.DEFAULT_IGNORE_TEMPORARY_RULES)
        )
        if self._cfg.getBool(self._cfg.DEFAULT_IGNORE_RULES):
            self._nodes.delete_rule_by_field(Config.DURATION_FIELD, Config.RULES_DURATION_FILTER)

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
        self._node_actions_trigger.connect(self._on_node_actions)
        self._update_stats_trigger.connect(self._on_update_stats)
        self._add_alert_trigger.connect(self._on_new_alert)
        self._status_change_trigger.connect(self._on_status_changed)
        self._stats_dialog._shown_trigger.connect(self._on_stats_dialog_shown)
        self._stats_dialog._status_changed_trigger.connect(self._on_stats_status_changed)
        self._stats_dialog.settings_saved.connect(self._on_settings_saved)
        self._stats_dialog.close_trigger.connect(self._on_close)
        self._show_message_trigger.connect(self._show_systray_message)

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
        # NOTE: only available since pyqt 5.7
        if hasattr(self._app, "setDesktopFileName"):
            self._app.setDesktopFileName(self.DESKTOP_FILENAME)

    def _setup_tray(self):
        self._tray = QtWidgets.QSystemTrayIcon(self.off_icon)
        self._tray.show()

        self._menu = QtWidgets.QMenu()
        self._tray.setContextMenu(self._menu)
        self._tray.activated.connect(self._on_tray_icon_activated)

        self._menu.addAction(self.MENU_ENTRY_STATS).triggered.connect(self._show_stats_dialog)
        self._menu_enable_fw = self._menu.addAction(self.MENU_ENTRY_FW_DISABLE)
        self._menu_enable_fw.setEnabled(False)
        self._menu_enable_fw.triggered.connect(self._on_enable_interception_clicked)

        self._menu.addSeparator()
        self._menu_autostart = self._menu.addAction("Autostart")
        self._menu_autostart.setCheckable(True)
        self._menu_autostart.setChecked(self._autostart.isEnabled())
        self._menu_autostart.triggered.connect(self._on_switch_autostart)
        self._menu.addSeparator()

        self._menu.addAction(self.MENU_ENTRY_HELP).triggered.connect(
                lambda: QtGui.QDesktopServices.openUrl(QtCore.QUrl(Config.HELP_CONFIG_URL))
                )
        self._menu.addAction(self.MENU_ENTRY_CLOSE).triggered.connect(self._on_close)

        self._menu.aboutToShow.connect(self._on_show_menu)

    def _on_switch_autostart(self):
        try:
            self._autostart.enable(self._menu_autostart.isChecked())
        except Exception as e:
            self._desktop_notifications.show(
                QC.translate("stats", "Warning"),
                QC.translate("stats", str(e))
            )

    def _on_show_menu(self):
        self._menu_autostart.setChecked(self._autostart.isEnabled())

    def _show_gui_if_tray_not_available(self):
        """If the system tray is not available or ready, show the GUI after
        10s. This delay helps to skip showing up the GUI when DEs' autologin is on.
        """
        tray = self._tray
        gui = self._stats_dialog
        def __show_gui():
            if not tray.isSystemTrayAvailable():
                self._show_systray_msg_error()
                gui.show()

        QtCore.QTimer.singleShot(10000, __show_gui)

    def _show_systray_msg_error(self):
        print("")
        print("WARNING: system tray not available. On GNOME you need the extension gnome-shell-extension-appindicator.")
        print("\tRead more:", Config.HELP_SYSTRAY_WARN)
        print("\tIf you want to start OpenSnitch GUI in background even if tray not available, use --background argument.")
        print("")

        hide_msg = self._cfg.getBool(Config.DEFAULT_HIDE_SYSTRAY_WARN)
        if hide_msg:
            return
        self._desktop_notifications.show(
            QC.translate("stats", "WARNING"),
            QC.translate("stats", """System tray not available. Read more:
{0}
""".format(Config.HELP_SYSTRAY_WARN)),
            os.path.join(self._path, "res/icon-white.svg")
        )
        self._cfg.setSettings(Config.DEFAULT_HIDE_SYSTRAY_WARN, True)

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
        self._tray.setIcon(self.off_icon)
        self._app.processEvents()
        self._nodes.stop_notifications()
        self._nodes.update_all(Nodes.OFFLINE)
        self._db.vacuum()
        self._db.optimize()
        self._db.close()
        self._stop_db_cleaner()
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

    @QtCore.pyqtSlot(str, str, ui_pb2.Alert)
    def _on_new_alert(self, proto, addr, alert):
        try:
            is_local = self._is_local_request(proto, addr)

            icon = QtWidgets.QSystemTrayIcon.Information
            _title = QtCore.QCoreApplication.translate("messages", "Info")
            atype = "INFO"
            if alert.type == ui_pb2.Alert.ERROR:
                atype = "ERROR"
                _title = QtCore.QCoreApplication.translate("messages", "Error")
                icon = QtWidgets.QSystemTrayIcon.Critical
            if alert.type == ui_pb2.Alert.WARNING:
                atype = "WARNING"
                _title = QtCore.QCoreApplication.translate("messages", "Warning")
                icon = QtWidgets.QSystemTrayIcon.Warning

            body = ""
            what = "GENERIC"
            if alert.what == ui_pb2.Alert.GENERIC:
                body = alert.text
            elif alert.what == ui_pb2.Alert.KERNEL_EVENT:
                body = "%s\n%s" % (alert.text, alert.proc.path)
                what = "KERNEL EVENT"
            if is_local is False:
                body = "node: {0}:{1}\n\n{2}\n{3}".format(proto, addr, alert.text, alert.proc.path)

            if alert.action == ui_pb2.Alert.SHOW_ALERT:

                urgency = DesktopNotifications.URGENCY_NORMAL
                if alert.priority == ui_pb2.Alert.LOW:
                    urgency = DesktopNotifications.URGENCY_LOW
                elif alert.priority == ui_pb2.Alert.HIGH:
                    urgency = DesktopNotifications.URGENCY_CRITICAL

                self._show_message_trigger.emit(_title, body, icon, urgency)

            else:
                print("PostAlert() unknown alert action:", alert.action)


        except Exception as e:
            print("PostAlert() exception:", e)
            return ui_pb2.MsgResponse(id=1)

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
    def _show_systray_message(self, title, body, icon, urgency):
        def callback_open_clicked(notifObject, action):
            if action == DesktopNotifications.ACTION_ID_OPEN:
                self._stats_dialog.show()
                #self._stats_dialog.raise()
                self._stats_dialog.activateWindow()

        if self._desktop_notifications.are_enabled():
            timeout = self._cfg.getInt(Config.DEFAULT_TIMEOUT_KEY, 15)

            if self._desktop_notifications.is_available() and self._cfg.getInt(Config.NOTIFICATIONS_TYPE, 1) == Config.NOTIFICATION_TYPE_SYSTEM:
                try:
                    self._desktop_notifications.show(
                        title,
                        body,
                        os.path.join(self._path, "res/icon-white.svg"),
                        callback=callback_open_clicked
                    )
                except:
                    self._tray.showMessage(title, body, icon, timeout * 1000)
            else:
                self._tray.showMessage(title, body, icon, timeout * 1000)

        if icon == QtWidgets.QSystemTrayIcon.NoIcon:
            self._tray.setIcon(self.alert_icon)

    def _on_enable_interception_clicked(self):
        self._enable_interception(self._fw_enabled)

    @QtCore.pyqtSlot()
    def _on_settings_saved(self):
        if self._cfg.getBool(Config.DEFAULT_DB_PURGE_OLDEST):
            if self._cleaner != None:
                self._stop_db_cleaner()
            self._start_db_cleaner()
        elif self._cfg.getBool(Config.DEFAULT_DB_PURGE_OLDEST) == False and self._cleaner != None:
            self._stop_db_cleaner()

        theme_idx, theme_name = self._themes.get_saved_theme()
        if theme_idx > 0:
            self._themes.load_theme(self._app)

    def _init_translation(self):
        if self.translator:
            self._app.removeTranslator(self.translator)
        saved_lang = self._cfg.getSettings(Config.DEFAULT_LANGUAGE)
        self.translator = languages.init(saved_lang)
        self._app.installTranslator(self.translator)

    def _stop_db_cleaner(self):
        if self._cleaner != None:
            self._cleaner.stop()
            self._cleaner = None

    def _start_db_cleaner(self):
        def _cleaner_task(db):
            oldest = self._cfg.getInt(self._cfg.DEFAULT_DB_MAX_DAYS, 1)
            db.purge_oldest(oldest)

        interval = self._cfg.getInt(self._cfg.DEFAULT_DB_PURGE_INTERVAL, 5)
        self._cleaner = CleanerTask(interval, _cleaner_task)
        self._cleaner.start()

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
        if proto == "unix" or proto == "unix-abstract":
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

            self._nodes.update(peer, Nodes.OFFLINE)
            self._nodes.delete(peer)
            self._stats_dialog.update(True, None, True)
        except Exception as e:
            print("_delete_node() exception:", e)

    def _populate_stats(self, db, proto, addr, stats):
        main_need_refresh = False
        details_need_refresh = False
        try:
            if db == None:
                print("populate_stats() db None")
                return main_need_refresh, details_need_refresh

            peer = proto+":"+addr
            _node = self._nodes.get_node(peer)
            if _node == None:
                return main_need_refresh, details_need_refresh

            # TODO: move to nodes.add_node()
            version  = _node['data'].version if _node != None else ""
            hostname = _node['data'].name if _node != None else ""
            db.insert("nodes",
                    "(addr, status, hostname, daemon_version, daemon_uptime, " \
                            "daemon_rules, cons, cons_dropped, version, last_connection)",
                            (peer, Nodes.ONLINE, hostname, stats.daemon_version, str(timedelta(seconds=stats.uptime)),
                            stats.rules, stats.connections, stats.dropped,
                            version, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

            if addr not in self._last_stats:
                self._last_stats[addr] = []

            db.transaction()
            for event in stats.events:
                if event.unixnano in self._last_stats[addr]:
                    continue
                main_need_refresh=True
                db.insert("connections",
                        "(time, node, action, protocol, src_ip, src_port, dst_ip, dst_host, dst_port, uid, pid, process, process_args, process_cwd, rule)",
                        (str(datetime.fromtimestamp(event.unixnano/1000000000)), peer, event.rule.action,
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
                    peer
                )
            db.commit()

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

    def _overwrite_nodes_config(self, node_config):
        """Overwrite daemon's DefaultAction value, with the one defined by the GUI.
        It'll only be valid while the daemon is connected to the GUI (it's not saved to disk).
        """
        newconf = copy.deepcopy(node_config)
        _default_action = self._cfg.getInt(self._cfg.DEFAULT_ACTION_KEY)
        try:
            temp_cfg = json.loads(newconf.config)
            if _default_action == Config.ACTION_ALLOW_IDX:
                temp_cfg['DefaultAction'] = Config.ACTION_ALLOW
            else:
                temp_cfg['DefaultAction'] = Config.ACTION_DENY

            print("Setting daemon DefaultAction to:", temp_cfg['DefaultAction'])

            newconf.config = json.dumps(temp_cfg)
        except Exception as e:
            print("error parsing node's configuration:", e)
            return node_config

        return newconf

    @QtCore.pyqtSlot(dict)
    def _on_node_actions(self, kwargs):
        if kwargs['action'] == self.NODE_ADD:
            n, addr = self._nodes.add(kwargs['peer'], kwargs['node_config'])
            if n != None:
                self._nodes.add_fw_rules(
                    addr,
                    FwRules.to_dict(kwargs['node_config'].systemFirewall.SystemRules)
                )
                self._status_change_trigger.emit(True)
                # if there're more than one node, we can't update the status
                # based on the fw status, only if the daemon is running or not
                if self._nodes.count() <= 1:
                    self._update_fw_status(kwargs['node_config'].isFirewallRunning)
                else:
                    self._update_fw_status(True)
        elif kwargs['action'] == self.ADD_RULE:
            rule = kwargs['rule']
            proto, addr = self._get_peer(kwargs['peer'])
            self._nodes.add_rule((datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                                 "{0}:{1}".format(proto, addr),
                                 rule.name, rule.description, str(rule.enabled),
                                 str(rule.precedence), str(rule.nolog), rule.action, rule.duration,
                                 rule.operator.type, str(rule.operator.sensitive), rule.operator.operand,
                                 rule.operator.data,
                                 str(datetime.fromtimestamp(rule.created).strftime("%Y-%m-%d %H:%M:%S"))
                                 )

        elif kwargs['action'] == self.DELETE_RULE:
            self._db.delete_rule(kwargs['name'], kwargs['addr'])

        elif kwargs['action'] == self.NODE_DELETE:
            self._delete_node(kwargs['peer'])


    def PostAlert(self, alert, context):
        proto, addr = self._get_peer(context.peer())
        self._add_alert_trigger.emit(proto, addr, alert)
        return ui_pb2.MsgResponse(id=0)

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
        #def callback(ntf, action, connection):
        # TODO

        #if self._desktop_notifications.support_actions():
        #    self._desktop_notifications.ask(request, callback)

        # TODO: allow connections originated from ourselves: os.getpid() == request.pid)
        self._asking = True
        proto, addr = self._get_peer(context.peer())
        rule, timeout_triggered = self._prompt_dialog.promptUser(request, self._is_local_request(proto, addr), context.peer())
        self._last_ping = datetime.now()
        self._asking = False
        if rule == None:
            return None

        if timeout_triggered:
            _title = request.process_path
            if _title == "":
                _title = "%s:%d (%s)" % (request.dst_host if request.dst_host != "" else request.dst_ip, request.dst_port, request.protocol)


            node_text = "" if self._is_local_request(proto, addr) else "on node {0}:{1}".format(proto, addr)
            self._show_message_trigger.emit(_title,
                                            "{0} action applied {1}\nCommand line: {2}"
                                            .format(rule.action, node_text, " ".join(request.process_args)),
                                            QtWidgets.QSystemTrayIcon.NoIcon,
                                            DesktopNotifications.URGENCY_NORMAL)


        if rule.duration in Config.RULES_DURATION_FILTER:
            self._node_actions_trigger.emit(
                {
                    'action': self.DELETE_RULE,
                    'name': rule.name,
                    'addr': context.peer()
                }
            )
        else:
            self._node_actions_trigger.emit(
                {
                    'action': self.ADD_RULE,
                    'peer': context.peer(),
                    'rule': rule
                }
            )

        return rule

    def Subscribe(self, node_config, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        """
        # if the exit mark is set, don't accept new connections.
        # db vacuum operation may take a lot of time to complete.
        if self._exit:
            context.cancel()
            return
        try:
            self._node_actions_trigger.emit({
                    'action': self.NODE_ADD,
                    'peer': context.peer(),
                    'node_config': node_config
                 })
            # force events processing, to add the node ^ before the
            # Notifications() call arrives.
            self._app.processEvents()

            proto, addr = self._get_peer(context.peer())
            if self._is_local_request(proto, addr) == False:
                self._show_message_trigger.emit(
                    QtCore.QCoreApplication.translate("stats", "New node connected"),
                    "({0})".format(context.peer()),
                    QtWidgets.QSystemTrayIcon.Information,
                    DesktopNotifications.URGENCY_LOW
                )
        except Exception as e:
            print("[Notifications] exception adding new node:", e)
            context.cancel()

        newconf = self._overwrite_nodes_config(node_config)

        return newconf

    def Notifications(self, node_iter, context):
        """
        Accept and collect nodes. It keeps a connection open with each
        client, in order to send them notifications.

        @doc: https://grpc.github.io/grpc/python/grpc.html#service-side-context
        @doc: https://grpc.io/docs/what-is-grpc/core-concepts/
        """
        proto, addr = self._get_peer(context.peer())
        _node = self._nodes.get_node("%s:%s" % (proto, addr))
        if _node == None:
            return

        stop_event = Event()
        def _on_client_closed():
            stop_event.set()
            self._node_actions_trigger.emit(
                {'action': self.NODE_DELETE,
                 'peer': context.peer(),
                 })

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
                                                DesktopNotifications.URGENCY_LOW)

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

    def OpenWindow(self):
        self._stats_dialog.show()
