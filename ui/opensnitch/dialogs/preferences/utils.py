import os
import stat
from PyQt6.QtCore import QCoreApplication as QC
from PyQt6 import QtWidgets

from opensnitch.config import Config
from opensnitch.utils import (
    Message,
    QuickHelp
)

def validate_certs(win):
    try:
        if win.comboAuthType.currentIndex() == win.AUTH_SIMPLE:
            return True

        if win.comboAuthType.currentIndex() > 0 and (win.lineCertFile.text() == "" or win.lineCertKeyFile.text() == ""):
            raise ValueError(QC.translate("preferences", "Certs fields cannot be empty."))

        if oct(stat.S_IMODE(os.lstat(win.lineCertFile.text()).st_mode)) != "0o600":
            set_status_message(
                win,
                QC.translate("preferences", "cert file has excessive permissions, it should have 0600")
            )
        if oct(stat.S_IMODE(os.lstat(win.lineCertFile.text()).st_mode)) != "0o600":
            set_status_message(
                win,
                QC.translate("preferences", "cert key file has excessive permissions, it should have 0600")
            )

        if win.comboAuthType.currentIndex() == win.AUTH_TLS_MUTUAL:
            if oct(stat.S_IMODE(os.lstat(win.lineCACertFile.text()).st_mode)) != "0o600":
                set_status_message(
                    win,
                    QC.translate("preferences", "CA cert file has excessive permissions, it should have 0600")
                )

        return True
    except Exception as e:
        win.changes_needs_restart = None
        set_status_error(win, "certs error: {0}".format(e))
        return False

def needs_restart(win):
    if win.changes_needs_restart:
        Message.ok(win.changes_needs_restart,
            win.restart_msg,
            QtWidgets.QMessageBox.Icon.Warning)
        win.changes_needs_restart = None

def test_notifications(win):
    try:
        win.cmdTestNotifs.setEnabled(False)
        if win.desktop_notifications.is_available() is False:
            set_status_error(
                win,
                QC.translate(
                    "notifications",
                    "System notifications are not available, you need to install python3-notify2."
                ))
            return

        if win.radioSysNotifs.isChecked():
            win.desktop_notifications.show("title", "body")
        else:
            pass
    except Exception as e:
        win.logger.warning("exception testing notifications: %s",repr(e))
    finally:
        win.cmdTestNotifs.setEnabled(True)

def configure_notifications(win):
    if win.desktop_notifications.is_available():
        return
    win.radioSysNotifs.setChecked(False)
    win.radioQtNotifs.setChecked(True)
    set_status_error(
        win,
        QC.translate(
            "notifications",
            "System notifications are not available, you need to install python3-notify2."
        ))
    return

def cmd_spin_clicked(win, widget, operation):
    win.settings_changed = True
    if operation == win.SUM:
        widget.setValue(widget.value() + widget.singleStep())
    else:
        widget.setValue(widget.value() - widget.singleStep())

    if widget == win.popupsCheck:
        enablePopups = widget.value() > 0
        win.popupsCheck.setChecked(not enablePopups)
        win.spinUITimeout.setEnabled(enablePopups)
        win.node_needs_update = True

def config_server_auth_type(win, idx):
    curtype = win.comboAuthType.itemData(win.comboAuthType.currentIndex())
    savedtype = win.cfgMgr.getSettings(Config.AUTH_TYPE)
    if curtype != savedtype:
        win.changes_needs_restart = QC.translate("preferences", "Auth type changed")

    win.lineCACertFile.setEnabled(idx == win.AUTH_TLS_MUTUAL)
    win.lineCertFile.setEnabled(idx >= win.AUTH_TLS_SIMPLE)
    win.lineCertKeyFile.setEnabled(idx >= win.AUTH_TLS_SIMPLE)

def show_help():
    QuickHelp.show(
        QC.translate(
            "preferences",
            "Hover the mouse over the texts to display the help<br><br>Don't forget to visit the wiki: <a href=\"{0}\">{0}</a>"
        ).format(Config.HELP_URL)
    )

def hide_status_label(win):
    win.statusLabel.hide()

def show_status_label(win):
    win.statusLabel.show()

def set_status_error(win, msg):
    show_status_label(win)
    win.statusLabel.setStyleSheet('color: red')
    win.statusLabel.setText(msg)
    QtWidgets.QApplication.processEvents()

def set_status_successful(win, msg):
    show_status_label(win)
    win.statusLabel.setStyleSheet('color: green')
    win.statusLabel.setText(msg)
    QtWidgets.QApplication.processEvents()

def set_status_message(win, msg):
    show_status_label(win)
    win.statusLabel.setStyleSheet('color: darkorange')
    win.statusLabel.setText(msg)
    QtWidgets.QApplication.processEvents()

def reset_status_message(win):
    win.statusLabel.setText("")
    hide_status_label(win)
    # force widgets repainting
    QtWidgets.QApplication.processEvents()


