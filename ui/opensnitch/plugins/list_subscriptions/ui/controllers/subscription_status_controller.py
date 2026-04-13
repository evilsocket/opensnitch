from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import QtWidgets, QC
from opensnitch.plugins.list_subscriptions.ui.views.subscription_status_dialog import (
    SubscriptionStatusDialog,
)

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class SubscriptionStatusController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns

    def _col(self, key: str):
        return self._cols[key]

    def show_selected_subscription_status(self):
        rows = self._dialog._selection_controller.selected_rows()
        if not rows:
            row = self._dialog.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select a subscription row first."),
                error=True,
            )
            return

        row = rows[0]
        name = self._dialog._table_data_controller.cell_text(row, self._col("name"))
        url = self._dialog._table_data_controller.cell_text(row, self._col("url"))
        filename = self._dialog._table_data_controller.cell_text(
            row,
            self._col("filename"),
        )
        meta = self.meta_snapshot_by_identity(url, filename)
        if meta is None:
            meta = self._dialog._table_data_controller.row_meta_snapshot(row)

        dlg = SubscriptionStatusDialog(
            self._dialog,
            name=name,
            url=url,
            filename=filename,
            meta=meta,
        )
        dlg.connect_to_refresh_signal(
            self._dialog.subscription_state_refreshed
        )
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return

        action = dlg.action()
        if action == SubscriptionStatusDialog.ACTION_EDIT:
            self._dialog._subscription_edit_controller.edit_selected_subscription()
        elif action == SubscriptionStatusDialog.ACTION_REFRESH:
            self._dialog._table_data_controller.refresh_selected_now()

    def find_row_by_identity(self, url: str, filename: str):
        for row in range(self._dialog.table.rowCount()):
            if self._dialog._table_data_controller.cell_text(row, self._col("url")) != url:
                continue
            if (
                self._dialog._table_data_controller.cell_text(
                    row,
                    self._col("filename"),
                )
                != filename
            ):
                continue
            return row
        return -1

    def meta_snapshot_by_identity(self, url: str, filename: str):
        row = self.find_row_by_identity(url, filename)
        if row < 0:
            return None
        return self._dialog._table_data_controller.row_meta_snapshot(row)