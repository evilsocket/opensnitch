import os

from PyQt6 import QtGui

from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.plugins.otp_firewall import otpcli


class Otp_firewall(PluginBase):
    """Activates/deactivates the otp-toolkit Linux kernel firewall and shows
    a live view of the keychain (sequence, offset and remaining key bytes
    per contact, per direction).

    Config (all optional, under "config" in the action json):
        otp_bin:          path to the `otp` binary (default: /usr/local/bin/otp)
        otpfwctl_bin:      path to `otpfwctl` (default: /usr/local/bin/otpfwctl)
        otp_home:          keychain working dir (default: ~/.otp)
        poll_interval_ms:  live-update interval while the dialog is open (default: 3000)

    See README.md in this directory for how to enable this plugin.
    """
    name = "Otp_firewall"
    version = "0.1"
    author = "opensnitch"
    created = ""
    modified = ""
    enabled = False
    description = "Activate/deactivate the otp-toolkit firewall and inspect its keychain"

    TYPE = [PluginBase.TYPE_MAIN_DIALOG]

    def __init__(self, config=None):
        config = config or {}
        self.enabled = bool(config.get("enabled") is True)
        plugin_cfg = config.get("config") or {}

        self._otp_bin = otpcli.resolve_bin(plugin_cfg.get("otp_bin"), otpcli.DEFAULT_OTP_BIN)
        self._otpfwctl_bin = otpcli.resolve_bin(plugin_cfg.get("otpfwctl_bin"), otpcli.DEFAULT_OTPFWCTL_BIN)
        self._otp_home = os.path.expanduser(plugin_cfg.get("otp_home") or otpcli.DEFAULT_OTP_HOME)
        try:
            poll_interval_ms = int(plugin_cfg.get("poll_interval_ms"))
        except (TypeError, ValueError):
            poll_interval_ms = 3000
        # clamp to avoid a busy-loop timer on a bad/zero/negative config value
        self._poll_interval_ms = max(poll_interval_ms, 250)

        self._dialog = None
        self._menu_action = None
        self.signal_in.connect(self.cb_signal)

    def configure(self, parent=None):
        if parent is None or self._menu_action is not None:
            return
        actions_button = getattr(parent, "actionsButton", None)
        if actions_button is None:
            return
        menu = actions_button.menu()
        if menu is None:
            return

        quit_action = None
        for act in menu.actions():
            if not act.isSeparator() and (act.text() or "").replace("&", "").strip().lower() == "quit":
                quit_action = act
                break

        self._menu_action = QtGui.QAction("OTP Firewall", menu)
        self._menu_action.triggered.connect(lambda *_: self._open_dialog(parent))
        if quit_action is not None:
            menu.insertAction(quit_action, self._menu_action)
        else:
            acts = menu.actions()
            if acts and not acts[-1].isSeparator():
                menu.addSeparator()
            menu.addAction(self._menu_action)

    def _open_dialog(self, parent):
        from opensnitch.plugins.otp_firewall.dialog import OtpFirewallDialog

        if self._dialog is None:
            appicon = None
            try:
                appicon = parent.windowIcon()
            except Exception:
                pass
            self._dialog = OtpFirewallDialog(
                parent=None, appicon=appicon,
                otp_bin=self._otp_bin, otp_home=self._otp_home,
                otpfwctl_bin=self._otpfwctl_bin,
                poll_interval_ms=self._poll_interval_ms,
            )
        self._dialog.show()
        self._dialog.raise_()
        self._dialog.activateWindow()

    def compile(self):
        pass

    def run(self, parent=None, args=()):
        pass

    def cb_signal(self, signal):
        try:
            if signal.get("signal") == PluginSignal.ENABLE:
                self.enabled = True
            elif signal.get("signal") in (PluginSignal.DISABLE, PluginSignal.STOP):
                self.enabled = False
                # stop the live-refresh timer and let any in-flight poll
                # finish before the app tears down, instead of leaving a
                # QThread running past app shutdown.
                if self._dialog is not None:
                    self._dialog.close()
        except Exception as e:
            print("Plugin.Otp_firewall.cb_signal() exception:", e)
