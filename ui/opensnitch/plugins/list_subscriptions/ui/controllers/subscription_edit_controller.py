import os
from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets, QC
from opensnitch.plugins.list_subscriptions.models.subscriptions import (
    MutableSubscriptionSpec,
)
from opensnitch.plugins.list_subscriptions.ui.views.subscription_dialog import (
    SubscriptionDialog,
)
from opensnitch.plugins.list_subscriptions._utils import (
    INTERVAL_UNITS,
    SIZE_UNITS,
    TIMEOUT_UNITS,
    display_str,
    normalize_groups,
    safe_filename,
    strip_or_none,
)

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class SubscriptionEditController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns

    def _col(self, key: str):
        return self._cols[key]

    def add_subscription_row(self):
        dlg = SubscriptionDialog(
            self._dialog,
            self._dialog._global_defaults,
            groups=self._dialog._selection_controller.known_groups(),
            sub=MutableSubscriptionSpec.from_dict(
                {"enabled": True},
                defaults=self._dialog._global_defaults,
                require_url=False,
                ensure_suffix=False,
            ),
            title="New subscription",
        )
        dlg.log_message.connect(self._dialog._status_controller.log)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return

        sub = dlg.subscription_spec()
        with self._dialog._table_view_controller.sorting_suspended():
            self._dialog._table_data_controller.append_row(sub)
            row = self._dialog.table.rowCount() - 1
            _, changed = self._dialog._table_data_controller.ensure_row_final_filename(row)
        if changed:
            self._dialog._table_data_controller.refresh_states()

        if not os.path.exists(self._dialog._action_path):
            self._dialog._action_file_controller.create_action_file()
        self._dialog._action_file_controller.save_action_file()
        self._dialog._selection_controller.update_selected_actions_state()

    def edit_selected_subscription(self):
        row = self._dialog.table.currentRow()
        if row < 0:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select a subscription row first."), error=True
            )
            return
        with self._dialog._table_view_controller.sorting_suspended():
            enabled_item = self._dialog.table.item(row, self._col("enabled"))
            if enabled_item is None:
                enabled_item = self._dialog._table_data_controller.new_enabled_item(False)
                self._dialog.table.setItem(row, self._col("enabled"), enabled_item)

        interval_ok, interval_val = self._dialog._table_data_controller.optional_int_from_text(
            self._dialog._table_data_controller.cell_text(row, self._col("interval")),
            "Interval",
            row=row,
        )
        timeout_ok, timeout_val = self._dialog._table_data_controller.optional_int_from_text(
            self._dialog._table_data_controller.cell_text(row, self._col("timeout")),
            "Timeout",
            row=row,
        )
        max_size_ok, max_size_val = self._dialog._table_data_controller.optional_int_from_text(
            self._dialog._table_data_controller.cell_text(row, self._col("max_size")),
            "Max size",
            row=row,
        )
        if not interval_ok or not timeout_ok or not max_size_ok:
            return
        sub = MutableSubscriptionSpec(
            enabled=enabled_item.checkState() == QtCore.Qt.CheckState.Checked,
            name=self._dialog._table_data_controller.cell_text(row, self._col("name")),
            url=self._dialog._table_data_controller.cell_text(row, self._col("url")),
            filename=self._dialog._table_data_controller.cell_text(
                row, self._col("filename")
            ),
            format=self._dialog._table_data_controller.cell_text(
                row, self._col("format")
            ) or "hosts",
            groups=normalize_groups(
                self._dialog._table_data_controller.cell_text(row, self._col("group"))
            ),
            interval=interval_val,
            interval_units=strip_or_none(
                self._dialog._table_data_controller.cell_text(
                    row, self._col("interval_units")
                )
            ),
            timeout=timeout_val,
            timeout_units=strip_or_none(
                self._dialog._table_data_controller.cell_text(
                    row, self._col("timeout_units")
                )
            ),
            max_size=max_size_val,
            max_size_units=strip_or_none(
                self._dialog._table_data_controller.cell_text(
                    row, self._col("max_size_units")
                )
            ),
        )
        meta = self._dialog._table_data_controller.row_meta_snapshot(row)
        dlg = SubscriptionDialog(
            self._dialog,
            self._dialog._global_defaults,
            groups=self._dialog._selection_controller.known_groups(),
            sub=sub,
            meta=meta,
            title="Edit subscription",
        )
        dlg.log_message.connect(self._dialog._status_controller.log)
        dlg._subscription_dialog_controller.connect_to_refresh_signal(
            self._dialog.subscription_state_refreshed
        )
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        updated = dlg.subscription_spec()

        with self._dialog._table_view_controller.sorting_suspended():
            enabled_item = self._dialog.table.item(row, self._col("enabled"))
            if enabled_item is None:
                enabled_item = self._dialog._table_data_controller.new_enabled_item(False)
                self._dialog.table.setItem(row, self._col("enabled"), enabled_item)
            enabled_item.setCheckState(
                QtCore.Qt.CheckState.Checked
                if bool(updated.enabled)
                else QtCore.Qt.CheckState.Unchecked
            )
            enabled_item.setData(
                QtCore.Qt.ItemDataRole.UserRole, 1 if bool(updated.enabled) else 0
            )
            self._dialog._table_data_controller.set_text_item(
                row, self._col("name"), updated.name
            )
            self._dialog._table_data_controller.set_text_item(
                row, self._col("url"), updated.url
            )
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("filename"),
                safe_filename(updated.filename),
            )
            self._dialog._table_data_controller.set_text_item(
                row, self._col("format"), updated.format
            )
            self._dialog._table_data_controller.set_text_item(
                row, self._col("group"), ", ".join(normalize_groups(updated.groups))
            )
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("interval"),
                display_str(updated.interval),
            )
            interval_units_val = display_str(updated.interval_units)
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("interval_units"),
                interval_units_val,
            )
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("timeout"),
                display_str(updated.timeout),
            )
            timeout_units_val = display_str(updated.timeout_units)
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("timeout_units"),
                timeout_units_val,
            )
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("max_size"),
                display_str(updated.max_size),
            )
            max_size_units_val = display_str(updated.max_size_units)
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("max_size_units"),
                max_size_units_val,
            )
            self._dialog._defaults_ui_controller.set_units_combo(
                row, self._col("interval_units"), INTERVAL_UNITS, interval_units_val
            )
            self._dialog._defaults_ui_controller.set_units_combo(
                row, self._col("timeout_units"), TIMEOUT_UNITS, timeout_units_val
            )
            self._dialog._defaults_ui_controller.set_units_combo(
                row, self._col("max_size_units"), SIZE_UNITS, max_size_units_val
            )
            _, changed = self._dialog._table_data_controller.ensure_row_final_filename(row)
            self._dialog._table_data_controller.update_row_sort_keys(row)
        self._dialog._action_file_controller.save_action_file()
        self._dialog._table_data_controller.refresh_states()
        if changed:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Subscription updated and filename normalized."),
                error=False,
            )
        else:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Subscription updated."), error=False
            )

    def edit_action_clicked(self):
        rows = self._dialog._selection_controller.selected_rows()
        if len(rows) == 0:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select one or more subscriptions first."),
                error=True,
            )
            return
        if len(rows) == 1:
            self.edit_selected_subscription()
            return
        self._dialog._bulk_edit_controller.bulk_edit(rows)

    def remove_selected_subscription(self):
        rows = self._dialog._selection_controller.selected_rows()
        if not rows:
            row = self._dialog.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select one or more subscription rows first."),
                error=True,
            )
            return
        for row in sorted(rows, reverse=True):
            self._dialog.table.removeRow(row)
        self._dialog._action_file_controller.save_action_file()
        self._dialog._table_data_controller.refresh_states()
        self._dialog._selection_controller.update_selected_actions_state()
        self._dialog._status_controller.set_status(
            QC.translate("stats", "Selected subscriptions removed."), error=False
        )

    def handle_table_item_double_clicked(self, item: QtWidgets.QTableWidgetItem):
        if item is not None:
            self._dialog.table.selectRow(item.row())
        self.edit_selected_subscription()
