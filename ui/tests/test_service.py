from PyQt6 import QtWidgets

from opensnitch.config import Config
from opensnitch.service import UIService


class FakeConfig:
    def __init__(self, timeout):
        self.timeout = timeout

    def getInt(self, key, default=None):
        assert key == Config.DEFAULT_TIMEOUT_KEY
        return self.timeout


class FakeTray:
    def __init__(self):
        self.messages = []

    def showMessage(self, title, body, icon, timeout):
        self.messages.append((title, body, icon, timeout))


class FakeService:
    def __init__(self, timeout):
        self._cfg = FakeConfig(timeout)
        self._tray = FakeTray()

    def _has_desktop_notifications(self):
        return False, Config.NOTIFICATION_TYPE_QT


def test_show_systray_message_without_desktop_notifications_uses_config_timeout():
    service = FakeService(timeout=7)
    icon = QtWidgets.QSystemTrayIcon.MessageIcon.Information

    UIService._show_systray_message(service, "title", "body", icon, urgency=0)

    assert service._tray.messages == [("title", "body", icon, 7000)]
