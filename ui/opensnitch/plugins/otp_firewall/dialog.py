from PyQt6 import QtCore, QtWidgets

from opensnitch.utils import Message
from opensnitch.plugins.otp_firewall import otpcli

STATE_LABELS = {
    otpcli.STATE_NOT_LOADED: "Kernel module not loaded",
    otpcli.STATE_ENABLED: "Enabled",
    otpcli.STATE_DISABLED: "Disabled",
    otpcli.STATE_UNKNOWN: "Unknown",
}

COLUMNS = [
    "Contact",
    "Sent seq", "Sent offset", "Sent remaining",
    "Recv seq", "Recv offset", "Recv remaining",
]


class _SnapshotWorker(QtCore.QThread):
    # contacts is `list | None`: None means the snapshot couldn't be fetched
    # (bad otp_bin/otp_home, timeout...), distinct from an empty keychain.
    ready = QtCore.pyqtSignal(str, object)

    def __init__(self, otp_bin, otp_home):
        super().__init__()
        self._otp_bin = otp_bin
        self._otp_home = otp_home

    def run(self):
        state = otpcli.read_module_state()
        contacts = otpcli.keychain_snapshot(self._otp_bin, self._otp_home)
        self.ready.emit(state, contacts)


class OtpFirewallDialog(QtWidgets.QDialog):

    def __init__(self, parent=None, appicon=None, otp_bin=None, otp_home=None,
                 otpfwctl_bin=None, poll_interval_ms=3000):
        super().__init__(parent)
        if appicon is not None:
            self.setWindowIcon(appicon)
        self.setWindowTitle("OTP Firewall")
        self.resize(720, 360)

        self._otp_bin = otp_bin
        self._otp_home = otp_home
        self._otpfwctl_bin = otpfwctl_bin
        self._poll_interval_ms = poll_interval_ms
        self._worker = None
        self._toggle_proc = None
        self._toggle_in_progress = False

        self._status_label = QtWidgets.QLabel("Unknown")
        self._toggle_button = QtWidgets.QPushButton("Enable")
        # stays disabled until the first snapshot confirms real state, so a
        # click can't fire the wrong (stale-label) enable/disable command
        self._toggle_button.setEnabled(False)
        self._toggle_button.clicked.connect(self._on_toggle_clicked)

        top = QtWidgets.QHBoxLayout()
        top.addWidget(QtWidgets.QLabel("Firewall status:"))
        top.addWidget(self._status_label)
        top.addStretch(1)
        top.addWidget(self._toggle_button)

        self._table = QtWidgets.QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._table)

        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._poll)

    def showEvent(self, event):
        super().showEvent(event)
        self._poll()
        self._timer.start(self._poll_interval_ms)

    def hideEvent(self, event):
        super().hideEvent(event)
        self._timer.stop()

    def closeEvent(self, event):
        self._timer.stop()
        if self._worker is not None:
            # let an in-flight poll's subprocess calls finish (they're each
            # capped at a few seconds) instead of leaving the QThread
            # running past this dialog / the app shutting down.
            self._worker.wait(8000)
        super().closeEvent(event)

    def _poll(self):
        if self._worker is not None and self._worker.isRunning():
            return
        self._worker = _SnapshotWorker(self._otp_bin, self._otp_home)
        self._worker.ready.connect(self._on_snapshot_ready)
        self._worker.start()

    def _on_snapshot_ready(self, state, contacts):
        self._status_label.setText(STATE_LABELS.get(state, state))
        if not self._toggle_in_progress:
            self._toggle_button.setEnabled(state in (otpcli.STATE_ENABLED, otpcli.STATE_DISABLED))
            self._toggle_button.setText("Disable" if state == otpcli.STATE_ENABLED else "Enable")

        if contacts is None:
            self._table.setRowCount(1)
            self._table.setSpan(0, 0, 1, len(COLUMNS))
            self._table.setItem(0, 0, QtWidgets.QTableWidgetItem(
                "Error querying otp (check otp_bin/otp_home configuration)"))
            for col in range(1, len(COLUMNS)):
                self._table.setItem(0, col, QtWidgets.QTableWidgetItem(""))
            return

        selected_name = None
        selected = self._table.selectionModel()
        if selected is not None and selected.selectedRows():
            item = self._table.item(selected.selectedRows()[0].row(), 0)
            if item is not None:
                selected_name = item.text()

        self._table.clearSpans()
        self._table.setRowCount(len(contacts))
        restore_row = None
        for row, c in enumerate(contacts):
            values = [
                c["name"],
                c["enc_sequence"], c["enc_offset"], c["enc_remaining"],
                c["dec_sequence"], c["dec_offset"], c["dec_remaining"],
            ]
            for col, value in enumerate(values):
                self._table.setItem(row, col, QtWidgets.QTableWidgetItem(str(value)))
            if selected_name is not None and c["name"] == selected_name:
                restore_row = row
        if restore_row is not None:
            self._table.selectRow(restore_row)

    def _on_toggle_clicked(self):
        if self._toggle_in_progress:
            return
        enable = self._toggle_button.text() == "Enable"
        argv = otpcli.set_module_state(self._otpfwctl_bin, enable)

        self._toggle_in_progress = True
        self._toggle_button.setEnabled(False)
        if self._toggle_proc is not None:
            self._toggle_proc.deleteLater()
        self._toggle_proc = QtCore.QProcess(self)
        self._toggle_proc.finished.connect(self._on_toggle_finished)
        self._toggle_proc.errorOccurred.connect(self._on_toggle_error)
        self._toggle_proc.start(argv[0], argv[1:])

    def _on_toggle_error(self, _error):
        if not self._toggle_in_progress:
            return
        self._toggle_in_progress = False
        self._toggle_button.setEnabled(True)
        Message.ok(
            "OTP Firewall",
            "Failed to run pkexec/otpfwctl: {0}".format(self._toggle_proc.errorString()),
            QtWidgets.QMessageBox.Icon.Warning,
        )
        self._poll()

    def _on_toggle_finished(self, exit_code, exit_status):
        if not self._toggle_in_progress:
            return
        self._toggle_in_progress = False
        self._toggle_button.setEnabled(True)
        crashed = exit_status == QtCore.QProcess.ExitStatus.CrashExit
        if crashed or exit_code != 0:
            stderr = bytes(self._toggle_proc.readAllStandardError()).decode(errors="replace")
            detail = "crashed" if crashed else "exit {0}".format(exit_code)
            Message.ok(
                "OTP Firewall",
                "Failed to change firewall state ({0}).\n{1}".format(detail, stderr.strip()),
                QtWidgets.QMessageBox.Icon.Warning,
            )
        self._poll()
