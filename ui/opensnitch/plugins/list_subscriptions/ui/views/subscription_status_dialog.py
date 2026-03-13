import os
from typing import Any, Final, TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import (
    QtCore,
    QtWidgets,
    QC,
    load_ui_type,
)

from opensnitch.plugins.list_subscriptions._utils import RES_DIR
from opensnitch.plugins.list_subscriptions.ui.views.helpers import _configure_modal_dialog

SUBSCRIPTION_STATUS_DIALOG_UI_PATH: Final[str] = os.path.join(
    RES_DIR, "subscription_status_dialog.ui"
)

SubscriptionStatusDialogUI: Final[Any] = load_ui_type(
    SUBSCRIPTION_STATUS_DIALOG_UI_PATH
)[0]


class SubscriptionStatusDialog(QtWidgets.QDialog, SubscriptionStatusDialogUI):
    ACTION_NONE: Final[str] = "none"
    ACTION_EDIT: Final[str] = "edit"
    ACTION_REFRESH: Final[str] = "refresh"

    if TYPE_CHECKING:
        title_label: QtWidgets.QLabel
        details_scroll: QtWidgets.QScrollArea
        details_container: QtWidgets.QWidget
        buttons_layout: QtWidgets.QHBoxLayout
        refresh_button: QtWidgets.QPushButton
        edit_button: QtWidgets.QPushButton
        close_button: QtWidgets.QPushButton

    def __init__(
        self,
        parent: QtWidgets.QWidget | None,
        name: str,
        url: str,
        filename: str,
        meta: dict[str, str],
    ):
        super().__init__(parent)
        self.setupUi(self)
        self._action = self.ACTION_NONE
        self._url = url
        self._filename = filename
        self._value_labels: dict[str, QtWidgets.QLabel] = {}
        self._refresh_signal: Any = None
        _configure_modal_dialog(
            self,
            title=QC.translate("stats", "Subscription status"),
            size=(700, 440),
        )

        self.title_label.setText(name or filename or url)
        title_font = self.title_label.font()
        title_font.setBold(True)
        self.title_label.setFont(title_font)

        details = QtWidgets.QFormLayout(self.details_container)
        details.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignRight)
        details.setFormAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        details.setHorizontalSpacing(10)
        details.setVerticalSpacing(6)

        self._add_value_row(details, "url", QC.translate("stats", "URL"), url)
        self._add_value_row(
            details,
            "filename",
            QC.translate("stats", "Filename"),
            filename,
        )
        self._add_value_row(
            details,
            "file_present",
            QC.translate("stats", "List file present"),
            meta.get("file_present", ""),
        )
        self._add_value_row(
            details,
            "meta_present",
            QC.translate("stats", "List meta present"),
            meta.get("meta_present", ""),
        )
        self._add_value_row(
            details,
            "state",
            QC.translate("stats", "State"),
            meta.get("state", ""),
        )
        self._add_value_row(
            details,
            "last_checked",
            QC.translate("stats", "Last checked"),
            meta.get("last_checked", ""),
        )
        self._add_value_row(
            details,
            "last_updated",
            QC.translate("stats", "Last updated"),
            meta.get("last_updated", ""),
        )
        self._add_value_row(
            details,
            "failures",
            QC.translate("stats", "Failures"),
            meta.get("failures", ""),
        )
        self._add_value_row(
            details,
            "error",
            QC.translate("stats", "Error"),
            meta.get("error", ""),
        )
        self._add_value_row(
            details,
            "list_path",
            QC.translate("stats", "List path"),
            meta.get("list_path", ""),
        )
        self._add_value_row(
            details,
            "meta_path",
            QC.translate("stats", "Meta path"),
            meta.get("meta_path", ""),
        )

        self.refresh_button.setText(QC.translate("stats", "Refresh"))
        self.edit_button.setText(QC.translate("stats", "Edit"))
        self.close_button.setText(QC.translate("stats", "Close"))
        self.refresh_button.clicked.connect(self.on_refresh)
        self.edit_button.clicked.connect(self.on_edit)
        self.close_button.clicked.connect(self.reject)

    def reject(self):
        self.disconnect_signal()
        super().reject()

    def action(self):
        return self._action

    # -- Meta refresh -------------------------------------------------------

    def connect_to_refresh_signal(self, signal: Any) -> None:
        self._refresh_signal = signal
        signal.connect(self.on_state_refreshed)

    def on_state_refreshed(self, url: str, filename: str, meta: dict[str, str]) -> None:
        if url != self._url or filename != self._filename:
            return
        self.update_meta(meta)

    def update_meta(self, meta: dict[str, str]) -> None:
        fields = (
            "file_present",
            "meta_present",
            "state",
            "last_checked",
            "last_updated",
            "failures",
            "error",
            "list_path",
            "meta_path",
        )
        for key in fields:
            label = self._value_labels.get(key)
            if label is None:
                continue
            label.setText((meta.get(key, "") or "-").strip() or "-")

    def disconnect_signal(self) -> None:
        if self._refresh_signal is not None:
            try:
                self._refresh_signal.disconnect(self.on_state_refreshed)
            except Exception:
                pass
            self._refresh_signal = None

    # -- Actions ------------------------------------------------------------

    def on_refresh(self) -> None:
        self.disconnect_signal()
        self._action = self.ACTION_REFRESH
        self.accept()

    def on_edit(self) -> None:
        self.disconnect_signal()
        self._action = self.ACTION_EDIT
        self.accept()
