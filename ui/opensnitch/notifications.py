from PyQt5.QtCore import QCoreApplication as QC
import os
from opensnitch.utils import Utils
from opensnitch.config import Config

class DesktopNotifications():
    """DesktopNotifications display informative pop-ups using the system D-Bus.
    The notifications are handled and configured by the system.

    The notification daemon also decides where to show the notifications, as well
    as how to group them.

    The body of a notification supports markup (if the implementation supports it):
        https://people.gnome.org/~mccann/docs/notification-spec/notification-spec-latest.html#markup
    Basically: <a>, <u>, <b>, <i> and <img>. New lines can be added with the regular \n.

    It also support actions (buttons).

    https://notify2.readthedocs.io/en/latest/
    """

    _cfg = Config.init()

    # list of hints:
    # https://people.gnome.org/~mccann/docs/notification-spec/notification-spec-latest.html#hints
    HINT_DESKTOP_ENTRY = "desktop-entry"
    CATEGORY_NETWORK = "network"

    EXPIRES_DEFAULT = 0
    NEVER_EXPIRES = -1

    URGENCY_LOW = 0
    URGENCY_NORMAL = 1
    URGENCY_CRITICAL = 2

    # must be a string
    ACTION_ID_OPEN = "action-open"
    ACTION_ID_ALLOW = "action-allow"
    ACTION_ID_DENY = "action-deny"

    def __init__(self):
        self.ACTION_OPEN = QC.translate("popups", "Open")
        self.ACTION_ALLOW = QC.translate("popups", "Allow")
        self.ACTION_DENY = QC.translate("popups", "Deny")
        self.IS_LIBNOTIFY_AVAILABLE = True
        self.DOES_SUPPORT_ACTIONS = True

        try:
            import notify2
            self.ntf2 = notify2
            mloop = 'glib'

            # First try to initialise the D-Bus connection with the given
            # mainloop.
            # If it fails, we'll try to initialise it without it.
            try:
                self.ntf2.init("opensnitch", mainloop=mloop)
            except Exception:
                self.DOES_SUPPORT_ACTIONS = False
                self.ntf2.init("opensnitch")

                # usually because dbus mainloop is not initiated, specially
                # with 'qt'
                # FIXME: figure out how to init it, or how to connect to an
                # existing session.
                print("DesktopNotifications(): system doesn't support actions. Available capabilities:")
                print(self.ntf2.get_server_caps())


            # Example: ['actions', 'action-icons', 'body', 'body-markup', 'icon-static', 'persistence', 'sound']
            if ('actions' not in self.ntf2.get_server_caps()):
                self.DOES_SUPPORT_ACTIONS = False

        except Exception as e:
            print("DesktopNotifications not available (install python3-notify2):", e)
            self.IS_LIBNOTIFY_AVAILABLE = False

    def is_available(self):
        return self.IS_LIBNOTIFY_AVAILABLE

    def are_enabled(self):
        return self._cfg.getBool(Config.NOTIFICATIONS_ENABLED, True)

    def support_actions(self):
        """Returns true if the notifications daemon support actions(buttons).
        This depends on 2 factors:
            - If the notification server actually supports it (get_server_caps()).
            - If there's a dbus instance running.
        """
        return self.DOES_SUPPORT_ACTIONS

    def show(self, title, body, icon="dialog-information", urgency=URGENCY_NORMAL, callback=None):
        try:
            ntf = self.ntf2.Notification(title, body, icon)

            ntf.set_urgency(urgency)
            ntf.set_category(self.CATEGORY_NETWORK)
            # used to display our app icon and name.
            # Note: setting this Hint causes some DEs to call opensnitch_ui.desktop file,
            # that as of today, kills and relaunches the current opensnitch-ui process.
            #ntf.set_hint(self.HINT_DESKTOP_ENTRY, "opensnitch_ui")
            if self.DOES_SUPPORT_ACTIONS and callback != None:
                ntf.add_action(self.ACTION_ID_OPEN, self.ACTION_OPEN, callback)
            ntf.show()
        except Exception as e:
            print("[notifications] show() exception:", e)
            raise Exception("[notifications] show() exception:", e)

    # TODO:
    #  - construct a rule with the default configured parameters.
    #  - create a common dialogs/prompt.py:_send_rule(), maybe in utils.py
    def ask(self, connection, timeout, callback):
        c = connection
        title = QC.translate("popups", "New outgoing connection")
        body = c.process_path + "\n"
        body = body + QC.translate("popups", "is connecting to <b>%s</b> on %s port %d") % ( \
            c.dst_host or c.dst_ip,
            c.protocol.upper(),
            c.dst_port )

        ntf = self.ntf2.Notification(title, body, "dialog-warning")
        timeout = self._cfg.getInt(Config.DEFAULT_TIMEOUT_KEY, 15)
        ntf.set_timeout(timeout * 1000)
        ntf.timeout = timeout * 1000
        if self.DOES_SUPPORT_ACTIONS:
            ntf.set_urgency(self.ntf2.URGENCY_CRITICAL)
            ntf.add_action(self.ACTION_ID_ALLOW, self.ACTION_ALLOW, callback, connection)
            ntf.add_action(self.ACTION_ID_DENY, self.ACTION_DENY, callback, connection)
            #ntf.add_action("open-gui", QC.translate("popups", "View"), callback, connection)
        ntf.set_category(self.CATEGORY_NETWORK)
        ntf.set_hint(self.HINT_DESKTOP_ENTRY, "opensnitch_ui")
        ntf.show()
