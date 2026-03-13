import os
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

TEXT_INSPECT_DIALOG_UI_PATH: Final[str] = os.path.join(RES_DIR, "text_inspect_dialog.ui")
TextInspectDialogUI: Final[Any] = load_ui_type(TEXT_INSPECT_DIALOG_UI_PATH)[0]


class TextInspectDialog(QtWidgets.QDialog, TextInspectDialogUI):
    if TYPE_CHECKING:
        text_view: QtWidgets.QPlainTextEdit
        copy_button: QtWidgets.QPushButton
        close_button: QtWidgets.QPushButton

    def __init__(
        self,
        parent: QtWidgets.QWidget,
        *,
        title: str,
        text: str,
    ):
        super().__init__(parent)
        self._has_content = (text or "").strip() != ""
        if not self._has_content:
            return

        self.setupUi(self)
        _configure_modal_dialog(self, title=title)

        self.text_view.setReadOnly(True)
        self.text_view.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        self.text_view.setPlainText(text)

        _wire_copy_close_buttons(
            self,
            self.copy_button,
            self.close_button,
            self.text_view,
        )

    def exec(self) -> int:
        if not self._has_content:
            return int(QtWidgets.QDialog.DialogCode.Rejected)
        return int(super().exec())
