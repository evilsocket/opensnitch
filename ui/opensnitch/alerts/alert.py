from PyQt5 import QtWidgets, QtCore
from datetime import datetime

from opensnitch import ui_pb2
from opensnitch.database import Database
from opensnitch.notifications import DesktopNotifications
from opensnitch.alerts import _utils

class Alert:
    type = "INFO"
    what = "GENERIC"
    body = "generic alert"
    title = "Info"
    icon = QtWidgets.QSystemTrayIcon.Information
    urgency = DesktopNotifications.URGENCY_NORMAL
    pb_alert = None

    # flag to indicate if the alert was generated locally (same host)
    is_local = True

    def __init__(self, proto, addr, is_local, pb_alert):
        self._db = Database.instance()
        self.proto = proto
        self.addr = addr
        self.is_local = is_local
        self.pb_alert = pb_alert
        self.alert_type = pb_alert.type
        self.body = pb_alert.text

    def build(self):
        self.title = QtCore.QCoreApplication.translate("messages", "Info")

        if self.what == ui_pb2.Alert.KERNEL_EVENT:
            self.body = "%s\n%s" % (self.text, self.proc.path)
            self.what = "KERNEL EVENT"
        if self.what == ui_pb2.Alert.NET_EVENT:
            self.body = "%s\n%s" % (self.text, self.proc.path)
            self.what = "NETWORK EVENT"
        if self.is_local is False:
            self.body = "node: {0}:{1}\n\n{2}\n{3}".format(self.proto, self.addr, self.text, self.proc.path)

        self.icon = _utils.get_icon(self.pb_alert)
        self.urgency = _utils.get_urgency(self.pb_alert)

        if self.type == ui_pb2.Alert.ERROR:
            self.type = "ERROR"
            self.title = QtCore.QCoreApplication.translate("messages", "Error")
            self.icon = QtWidgets.QSystemTrayIcon.Critical
        elif self.type == ui_pb2.Alert.WARNING:
            self.type = "WARNING"
            self.title = QtCore.QCoreApplication.translate("messages", "Warning")
            self.icon = QtWidgets.QSystemTrayIcon.Warning

        if self.priority == ui_pb2.Alert.LOW:
            urgency = DesktopNotifications.URGENCY_LOW
        elif self.priority == ui_pb2.Alert.HIGH:
            urgency = DesktopNotifications.URGENCY_CRITICAL

        return self.title, self.body, self.icon, urgency

    def save(self):
        if self.type == ui_pb2.Alert.GENERIC:
            self._db.insert(
                "alerts",
                "(time, node, type, action, priority, what, body, status)",
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    self.proto+":"+self.addr, self.type, "", "", self.what, self.body, 0
                ))
