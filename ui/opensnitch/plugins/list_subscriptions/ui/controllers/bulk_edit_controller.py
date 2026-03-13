from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets, QC
from opensnitch.plugins.list_subscriptions.ui.views.bulk_edit_dialog import (
    BulkEditDialog,
)
from opensnitch.plugins.list_subscriptions._utils import (
    INTERVAL_UNITS,
    TIMEOUT_UNITS,
    SIZE_UNITS,
    display_str,
    normalize_groups,
)

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class BulkEditController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns

    def _col(self, key: str):
        return self._cols[key]

    def bulk_edit(self, rows: list[int]):
        if not rows:
            return
        dlg = BulkEditDialog(
            self._dialog,
            self._dialog._global_defaults,
            groups=self._dialog._selection_controller.known_groups(),
            selected_count=len(rows),
        )
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        values = dlg.values()
        with self._dialog._table_view_controller.sorting_suspended():
            for row in rows:
                if values.get("enabled") is not None:
                    enabled_item = self._dialog.table.item(row, self._col("enabled"))
                    if enabled_item is None:
                        enabled_item = self._dialog._table_data_controller.new_enabled_item(False)
                        self._dialog.table.setItem(
                            row,
                            self._col("enabled"),
                            enabled_item,
                        )
                    enabled_item.setCheckState(
                        QtCore.Qt.CheckState.Checked
                        if bool(values["enabled"])
                        else QtCore.Qt.CheckState.Unchecked
                    )
                if values.get("groups") is not None:
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("group"),
                        ", ".join(normalize_groups(values["groups"])),
                    )
                if values.get("format") is not None:
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("format"),
                        str(values["format"]),
                    )
                if values.get("apply_interval"):
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("interval"),
                        display_str(values.get("interval")),
                    )
                    interval_units = display_str(values.get("interval_units"))
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("interval_units"),
                        interval_units,
                    )
                    self._dialog._defaults_ui_controller.set_units_combo(
                        row,
                        self._col("interval_units"),
                        INTERVAL_UNITS,
                        interval_units,
                    )
                if values.get("apply_timeout"):
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("timeout"),
                        display_str(values.get("timeout")),
                    )
                    timeout_units = display_str(values.get("timeout_units"))
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("timeout_units"),
                        timeout_units,
                    )
                    self._dialog._defaults_ui_controller.set_units_combo(
                        row,
                        self._col("timeout_units"),
                        TIMEOUT_UNITS,
                        timeout_units,
                    )
                if values.get("apply_max_size"):
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("max_size"),
                        display_str(values.get("max_size")),
                    )
                    max_size_units = display_str(values.get("max_size_units"))
                    self._dialog._table_data_controller.set_text_item(
                        row,
                        self._col("max_size_units"),
                        max_size_units,
                    )
                    self._dialog._defaults_ui_controller.set_units_combo(
                        row,
                        self._col("max_size_units"),
                        SIZE_UNITS,
                        max_size_units,
                    )
                self._dialog._table_data_controller.ensure_row_final_filename(row)
                self._dialog._table_data_controller.update_row_sort_keys(row)
        self._dialog._action_file_controller.save_action_file()
        self._dialog._table_data_controller.refresh_states()
        self._dialog._status_controller.set_status(
            QC.translate("stats", "Updated {0} selected subscriptions.").format(
                len(rows)
            ),
            error=False,
        )