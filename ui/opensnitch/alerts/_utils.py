from PyQt5 import QtWidgets, QtGui, QtCore

from opensnitch import ui_pb2
from opensnitch.notifications import DesktopNotifications

def get_urgency(alert):
    urgency = DesktopNotifications.URGENCY_NORMAL
    if alert.priority == ui_pb2.Alert.LOW:
        urgency = DesktopNotifications.URGENCY_LOW
    elif alert.priority == ui_pb2.Alert.HIGH:
        urgency = DesktopNotifications.URGENCY_CRITICAL

    return urgency

def get_icon(alert):
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

    return icon

