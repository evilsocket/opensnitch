from collections.abc import Callable
import queue
import threading
from typing import TYPE_CHECKING, Literal

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.status_log_dialog import (
        StatusLogDialog,
    )

EmptyButtonBehavior = Literal["hide", "show-if-logs"]
MAX_BACKEND_LOGS_PER_UI_TICK = 100


def _set_preview_label_text(
    label: QtWidgets.QLabel,
    *,
    text: str,
    preview_limit: int,
):
    full_text = (text or "").strip()
    if full_text == "":
        label.setText("")
        label.setToolTip("")
        return

    if len(full_text) <= preview_limit:
        label.setText(full_text)
        label.setToolTip(full_text)
        return

    preview = full_text[: preview_limit - 1].rstrip() + "..."
    label.setText(preview)
    label.setToolTip(full_text)


def append_log_entry(
    entries: list[str],
    *,
    message: str,
    error: bool = False,
    level: str | None = None,
    origin: str | None = None,
    dedupe: bool = False,
    last_signature: tuple[str, bool] | None = None,
    timestamp_format: str = "HH:mm:ss",
    limit: int = 200,
):
    full_text = (message or "").strip()
    if full_text == "":
        return

    signature = (full_text, bool(error))
    if dedupe and signature == last_signature:
        return

    timestamp = QtCore.QDateTime.currentDateTime().toString(timestamp_format)
    log_level = level or ("ERROR" if error else "INFO")
    log_origin = (origin or "ui").strip()
    entries.append(f"[{timestamp}] [{log_level}] [{log_origin}] {full_text}")
    if len(entries) > limit:
        del entries[:-limit]


def apply_status_label(
    label: QtWidgets.QLabel,
    *,
    message: str,
    error: bool,
    preview_limit: int,
    inspect_button: QtWidgets.QPushButton | None = None,
    empty_button_behavior: Literal["hide", "show-if-logs"] = "hide",
    log_entry_count: int = 0,
    ok_color: str = "green",
    error_color: str = "red",
):
    label.setStyleSheet(f"color: {error_color if error else ok_color};")
    full_text = (message or "").strip()
    if full_text == "":
        label.setText("")
        label.setToolTip("")
        if inspect_button is not None:
            if empty_button_behavior == "show-if-logs":
                has_logs = log_entry_count > 0
                inspect_button.setVisible(has_logs)
                inspect_button.setEnabled(has_logs)
            else:
                inspect_button.setVisible(False)
                inspect_button.setEnabled(False)
        return full_text

    _set_preview_label_text(
        label,
        text=full_text,
        preview_limit=preview_limit,
    )
    if inspect_button is not None:
        inspect_button.setVisible(True)
        inspect_button.setEnabled(True)
    return full_text


class DialogStatusController:
    def __init__(
        self,
        *,
        label: QtWidgets.QLabel,
        inspect_button: QtWidgets.QPushButton | None,
        preview_limit: int,
        log_limit: int,
        timestamp_format: str,
        ok_color: str,
        error_color: str,
        empty_button_behavior: EmptyButtonBehavior,
    ):
        self._label = label
        self._inspect_button = inspect_button
        self._preview_limit = preview_limit
        self._log_limit = log_limit
        self._timestamp_format = timestamp_format
        self._ok_color = ok_color
        self._error_color = error_color
        self._empty_button_behavior: EmptyButtonBehavior = empty_button_behavior
        self._full_text = ""
        self._log_entries: list[str] = []
        self._last_signature: tuple[str, bool] | None = None
        self._backend_log_sink: Callable[[str, str, str], None] | None = None
        self._backend_sink_queue: queue.SimpleQueue[tuple[str, str, str]] = (
            queue.SimpleQueue()
        )
        self._backend_sink_worker_started = False
        self._backend_to_ui_queue: queue.SimpleQueue[tuple[str, str, str]] = (
            queue.SimpleQueue()
        )
        self._backend_to_ui_timer = QtCore.QTimer(self._label)
        self._backend_to_ui_timer.setInterval(100)
        self._backend_to_ui_timer.timeout.connect(self._drain_backend_to_ui_queue)
        self._backend_to_ui_timer.start()
        self._log_dialog: "StatusLogDialog | None" = None
        self._log_dialog_level_color: Callable[[str], str] | None = None
        self._log_dialog_timestamp_color = ""

    def _start_backend_sink_worker(self) -> None:
        if self._backend_sink_worker_started:
            return
        self._backend_sink_worker_started = True

        def _run() -> None:
            while True:
                message, level, origin = self._backend_sink_queue.get()
                sink = self._backend_log_sink
                if sink is None:
                    continue
                try:
                    sink(message, level, origin)
                except Exception:
                    pass

        th = threading.Thread(
            target=_run,
            name="DialogStatusBackendSink",
            daemon=True,
        )
        th.start()

    def _drain_backend_to_ui_queue(self) -> None:
        for _ in range(MAX_BACKEND_LOGS_PER_UI_TICK):
            try:
                message, level, origin = self._backend_to_ui_queue.get_nowait()
            except queue.Empty:
                return
            self.append_log(
                message,
                level=level,
                origin=origin,
                forward_backend=False,
            )

    @property
    def full_text(self):
        return self._full_text

    @property
    def log_entries(self):
        return self._log_entries

    def log(self, message: str, level: str = "INFO", origin: str = "ui") -> None:
        """Generic slot: connect any pyqtSignal(str, str) directly to this."""
        self.append_log(message, level=level, origin=origin)

    def ingest_backend_log(
        self,
        message: str,
        level: str = "INFO",
        origin: str = "backend",
    ) -> None:
        """Backend -> UI path; enqueue to avoid blocking backend threads."""
        full_text = (message or "").strip()
        if full_text == "":
            return
        self._backend_to_ui_queue.put((full_text, level, origin))

    def set_backend_log_sink(
        self,
        sink: Callable[[str, str, str], None] | None,
    ) -> None:
        self._backend_log_sink = sink
        if sink is not None:
            self._start_backend_sink_worker()

    def debug(self, message: str, origin: str = "ui") -> None:
        self.append_log(message, level="DEBUG", origin=origin)

    def info(self, message: str, origin: str = "ui") -> None:
        self.append_log(message, level="INFO", origin=origin)

    def warn(self, message: str, origin: str = "ui") -> None:
        self.append_log(message, level="WARN", origin=origin)

    def error(self, message: str, origin: str = "ui") -> None:
        self.append_log(message, level="ERROR", origin=origin)

    def trace(self, message: str, origin: str = "ui") -> None:
        self.append_log(message, level="TRACE", origin=origin)

    def append_log(
        self,
        message: str,
        *,
        error: bool = False,
        level: str | None = None,
        origin: str = "ui",
        dedupe: bool = False,
        forward_backend: bool = True,
    ):
        full_text = (message or "").strip()
        if full_text == "":
            return
        resolved_level = (level or ("ERROR" if error else "INFO")).upper()
        append_log_entry(
            self._log_entries,
            message=full_text,
            error=error,
            level=resolved_level,
            origin=origin,
            dedupe=dedupe,
            last_signature=self._last_signature,
            timestamp_format=self._timestamp_format,
            limit=self._log_limit,
        )
        if (
            forward_backend
            and self._backend_log_sink is not None
            and not origin.lower().startswith("backend")
        ):
            self._backend_sink_queue.put((full_text, resolved_level, origin))
        self._refresh_log_dialog_if_open()

    def _refresh_log_dialog_if_open(self) -> None:
        dlg = self._log_dialog
        if dlg is None or not dlg.isVisible():
            return
        if self._log_dialog_level_color is None:
            return
        try:
            dlg.update_entries(
                lines=self._log_entries[:],
                fallback_text=self._full_text,
                level_color=self._log_dialog_level_color,
                timestamp_color=self._log_dialog_timestamp_color,
            )
        except Exception:
            pass

    def set_status(
        self,
        message: str,
        *,
        error: bool = False,
        log: bool = True,
        origin: str = "ui",
    ):
        full_text = apply_status_label(
            self._label,
            message=message,
            error=error,
            preview_limit=self._preview_limit,
            inspect_button=self._inspect_button,
            empty_button_behavior=self._empty_button_behavior,
            log_entry_count=len(self._log_entries),
            ok_color=self._ok_color,
            error_color=self._error_color,
        )
        self._full_text = full_text
        if full_text == "":
            return

        if not log:
            return

        signature = (full_text, bool(error))
        if signature != self._last_signature:
            self.append_log(full_text, error=error, origin=origin)
            self._last_signature = signature

    def show_log_dialog(
        self,
        parent: "QtWidgets.QWidget",
        *,
        title: str,
        level_color: Callable[[str], str],
        timestamp_color: str,
    ) -> None:
        from opensnitch.plugins.list_subscriptions.ui.views.status_log_dialog import (
            StatusLogDialog,
        )
        self._log_dialog_level_color = level_color
        self._log_dialog_timestamp_color = timestamp_color
        dlg = self._log_dialog
        if dlg is None:
            dlg = StatusLogDialog(
                parent,
                title=title,
                lines=self._log_entries[:],
                fallback_text=self._full_text,
                level_color=level_color,
                timestamp_color=timestamp_color,
            )
            dlg.setWindowModality(QtCore.Qt.WindowModality.NonModal)
            dlg.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose, True)
            dlg.destroyed.connect(lambda *_: setattr(self, "_log_dialog", None))
            self._log_dialog = dlg
        else:
            dlg.update_entries(
                lines=self._log_entries[:],
                fallback_text=self._full_text,
                level_color=level_color,
                timestamp_color=timestamp_color,
            )
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()
