import html
import os
from collections.abc import Callable
from typing import Any, TYPE_CHECKING, Final

from opensnitch.plugins.list_subscriptions.ui import (
    QtWidgets,
    load_ui_type,
)

from opensnitch.plugins.list_subscriptions._utils import RES_DIR
from opensnitch.plugins.list_subscriptions.ui.views.helpers import (
    _configure_modal_dialog,
    _wire_copy_close_buttons,
)

STATUS_LOG_DIALOG_UI_PATH: Final[str] = os.path.join(RES_DIR, "status_log_dialog.ui")
StatusLogDialogUI: Final[Any] = load_ui_type(STATUS_LOG_DIALOG_UI_PATH)[0]


class StatusLogDialog(QtWidgets.QDialog, StatusLogDialogUI):
    if TYPE_CHECKING:
        text_view: QtWidgets.QTextEdit
        copy_button: QtWidgets.QPushButton
        close_button: QtWidgets.QPushButton

    def __init__(
        self,
        parent: QtWidgets.QWidget,
        *,
        title: str,
        lines: list[str],
        fallback_text: str,
        level_color: Callable[[str], str],
        timestamp_color: str,
    ):
        super().__init__(parent)
        self.setupUi(self)
        _configure_modal_dialog(self, title=title)

        self.text_view.setReadOnly(True)
        self.text_view.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)
        self.text_view.setFontFamily("monospace")
        self.update_entries(
            lines=lines,
            fallback_text=fallback_text,
            level_color=level_color,
            timestamp_color=timestamp_color,
        )
        # Scroll to the last entry when dialog is shown
        scrollbar = self.text_view.verticalScrollBar()
        if scrollbar is not None:
            scrollbar.setValue(scrollbar.maximum())

        _wire_copy_close_buttons(
            self,
            self.copy_button,
            self.close_button,
            self.text_view,
        )

    @staticmethod
    def _is_near_bottom(scrollbar: QtWidgets.QScrollBar) -> bool:
        return scrollbar.value() >= (scrollbar.maximum() - 2)

    def update_entries(
        self,
        *,
        lines: list[str],
        fallback_text: str,
        level_color: Callable[[str], str],
        timestamp_color: str,
    ) -> None:
        scrollbar = self.text_view.verticalScrollBar()
        if scrollbar is None:
            display_lines = lines[:]
            if not display_lines and (fallback_text or "").strip() != "":
                display_lines = [fallback_text]
            html_text = self._entries_html(display_lines, level_color, timestamp_color)
            self.text_view.setHtml(html_text)
            return

        prev_value = scrollbar.value()
        follow_tail = self._is_near_bottom(scrollbar)

        display_lines = lines[:]
        if not display_lines and (fallback_text or "").strip() != "":
            display_lines = [fallback_text]
        html_text = self._entries_html(display_lines, level_color, timestamp_color)
        self.text_view.setHtml(html_text)

        if follow_tail:
            scrollbar.setValue(scrollbar.maximum())
            return

        scrollbar.setValue(min(prev_value, scrollbar.maximum()))

    @staticmethod
    def _entries_html(
        lines: list[str],
        level_color: Callable[[str], str],
        timestamp_color: str,
    ) -> str:
        html_lines: list[str] = []
        for line in lines:
            text = str(line or "").rstrip("\n")
            if text == "":
                html_lines.append("<span>&nbsp;</span>")
                continue

            level = "INFO"
            timestamp = ""
            remainder = text
            if text.startswith("["):
                timestamp_end = text.find("]")
                if timestamp_end > 0:
                    timestamp = text[1:timestamp_end].strip()
                    remainder = text[timestamp_end + 1 :].lstrip()
            if remainder.startswith("["):
                level_end = remainder.find("]")
                if level_end > 0:
                    level = remainder[1:level_end].strip() or "INFO"
                    remainder = remainder[level_end + 1 :].lstrip()

            level_html = html.escape(level)
            timestamp_html = html.escape(timestamp)
            message_html = html.escape(remainder.lstrip())
            color = level_color(level)
            timestamp_prefix = ""
            if timestamp_html != "":
                timestamp_prefix = (
                    f"<span style=\"color: {timestamp_color};\">[{timestamp_html}]</span> "
                )
            html_lines.append(
                "<span>"
                f"{timestamp_prefix}"
                f"<span style=\"color: {color}; font-weight: 600;\">[{level_html}]</span> "
                f"{message_html}"
                "</span>"
            )

        body = "<br/>".join(html_lines)
        return (
            "<html><body "
            'style="white-space: pre-wrap; font-family: monospace;">'
            f"{body}"
            "</body></html>"
        )

    def exec(self) -> int:
        return int(super().exec())

    def show(self) -> None:
        super().show()
        # Scroll to the last entry when dialog is shown
        scrollbar = self.text_view.verticalScrollBar()
        if scrollbar is not None:
            scrollbar.setValue(scrollbar.maximum())
