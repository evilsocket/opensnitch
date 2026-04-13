from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import QC
from opensnitch.plugins.list_subscriptions._utils import normalize_groups

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class SelectionController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns

    def _col(self, key: str):
        return self._cols[key]

    def selected_rows(self):
        idx = self._dialog.table.selectionModel()
        if idx is None:
            return []
        return sorted({i.row() for i in idx.selectedRows()})

    def update_selected_actions_state(self):
        count = len(self.selected_rows())
        has_selection = count > 0
        self._dialog.edit_sub_button.setEnabled(has_selection)
        self._dialog.remove_sub_button.setEnabled(has_selection)
        self._dialog.refresh_now_button.setEnabled(
            has_selection
            and not self._dialog._pending_refresh_keys
            and not self._dialog._active_refresh_keys
        )
        self._dialog.create_rule_button.setEnabled(has_selection)
        if count == 1:
            self._dialog.create_rule_button.setText(QC.translate("stats", "Rules"))
        else:
            self._dialog.create_rule_button.setText(
                QC.translate("stats", "Create rule")
            )

    def open_rules_action(self):
        rows = self.selected_rows()
        if not rows:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select a subscription row first."),
                error=True,
            )
            return
        if len(rows) == 1:
            self._dialog._rules_attachment_controller.show_attached_rules_dialog()
            return
        self._dialog._rules_editor_controller.create_rule_from_selected()

    def open_selected_inspector(self):
        rows = self.selected_rows()
        if not rows:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select a subscription row first."),
                error=True,
            )
            return
        if hasattr(self._dialog, "_inspect_collapsed"):
            self._dialog._inspect_collapsed = False
        self._dialog._inspector_controller.update_inspector_panel()

    def known_groups(self):
        groups: set[str] = set()
        for row in range(self._dialog.table.rowCount()):
            for g in normalize_groups(
                self._dialog._table_data_controller.cell_text(row, self._col("group"))
            ):
                if g not in ("", "all"):
                    groups.add(g)
        return sorted(groups)