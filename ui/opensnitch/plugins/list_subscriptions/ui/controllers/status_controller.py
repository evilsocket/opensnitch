from collections.abc import Callable
from typing import Literal

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets

EmptyButtonBehavior = Literal["hide", "show-if-logs"]


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
    entries.append(f"[{timestamp}] [{log_level}] {full_text}")
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

    @property
    def full_text(self):
        return self._full_text

    @property
    def log_entries(self):
        return self._log_entries

    def append_log(
        self,
        message: str,
        *,
        error: bool = False,
        level: str | None = None,
        dedupe: bool = False,
    ):
        append_log_entry(
            self._log_entries,
            message=message,
            error=error,
            level=level,
            dedupe=dedupe,
            last_signature=self._last_signature,
            timestamp_format=self._timestamp_format,
            limit=self._log_limit,
        )

    def set_status(self, message: str, *, error: bool = False):
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

        signature = (full_text, bool(error))
        if signature != self._last_signature:
            self.append_log(full_text, error=error)
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
        dlg = StatusLogDialog(
            parent,
            title=title,
            lines=self._log_entries[:],
            fallback_text=self._full_text,
            level_color=level_color,
            timestamp_color=timestamp_color,
        )
        dlg.exec()
