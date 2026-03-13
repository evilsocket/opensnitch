from typing import TYPE_CHECKING, Any

from opensnitch.plugins.list_subscriptions.ui import QtWidgets, QC

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class ContextMenuController:
    def __init__(self, *, dialog: "ListSubscriptionsDialog"):
        self._dialog = dialog

    def open_table_context_menu(self, pos: Any):
        rows = self._dialog._selection_controller.selected_rows()
        if not rows:
            row = self._dialog.table.rowAt(pos.y())
            if row >= 0:
                self._dialog.table.selectRow(row)
                rows = [row]

        menu = QtWidgets.QMenu(self._dialog.table)
        viewport = self._dialog.table.viewport()
        if viewport is None:
            return

        if not rows:
            act_reset_sort = menu.addAction(QC.translate("stats", "Reset sorting"))
            act_reset_widths = menu.addAction(
                QC.translate("stats", "Reset column widths")
            )
            chosen = QtWidgets.QMenu.exec(
                menu.actions(),
                viewport.mapToGlobal(pos),
                None,
                menu,
            )
            if chosen is act_reset_sort:
                self._dialog._table_view_controller.reset_table_sort_for_current_tab()
            elif chosen is act_reset_widths:
                self._dialog._table_view_controller.reset_table_column_widths_for_current_tab()
            return

        if len(rows) == 1:
            act_inspect = menu.addAction(QC.translate("stats", "Inspect"))
            act_edit = menu.addAction(QC.translate("stats", "Edit"))
            act_remove = menu.addAction(QC.translate("stats", "Delete"))
            act_refresh = menu.addAction(QC.translate("stats", "Refresh"))
            act_rule = menu.addAction(QC.translate("stats", "Rules"))
            menu.addSeparator()
            act_reset_sort = menu.addAction(QC.translate("stats", "Reset sorting"))
            act_reset_widths = menu.addAction(
                QC.translate("stats", "Reset column widths")
            )
            chosen = QtWidgets.QMenu.exec(
                menu.actions(),
                viewport.mapToGlobal(pos),
                None,
                menu,
            )
            if chosen is act_inspect:
                self._dialog._selection_controller.open_selected_inspector()
            elif chosen is act_edit:
                self._dialog._subscription_edit_controller.edit_selected_subscription()
            elif chosen is act_remove:
                self._dialog.remove_selected_subscription()
            elif chosen is act_refresh:
                self._dialog._table_data_controller.refresh_selected_now()
            elif chosen is act_rule:
                self._dialog._rules_attachment_controller.show_attached_rules_dialog()
            elif chosen is act_reset_sort:
                self._dialog._table_view_controller.reset_table_sort_for_current_tab()
            elif chosen is act_reset_widths:
                self._dialog._table_view_controller.reset_table_column_widths_for_current_tab()
            return

        act_inspect = menu.addAction(QC.translate("stats", "Inspect"))
        act_edit = menu.addAction(QC.translate("stats", "Edit"))
        act_remove = menu.addAction(QC.translate("stats", "Delete"))
        act_refresh = menu.addAction(QC.translate("stats", "Refresh"))
        act_rule = menu.addAction(QC.translate("stats", "Create rule"))
        menu.addSeparator()
        act_reset_sort = menu.addAction(QC.translate("stats", "Reset sorting"))
        act_reset_widths = menu.addAction(QC.translate("stats", "Reset column widths"))
        chosen = QtWidgets.QMenu.exec(
            menu.actions(),
            viewport.mapToGlobal(pos),
            None,
            menu,
        )
        if chosen is act_inspect:
            self._dialog._selection_controller.open_selected_inspector()
        elif chosen is act_edit:
            self._dialog._bulk_edit_controller.bulk_edit(rows)
        elif chosen is act_remove:
            self._dialog.remove_selected_subscription()
        elif chosen is act_refresh:
            self._dialog._table_data_controller.refresh_selected_now()
        elif chosen is act_rule:
            self._dialog._rules_editor_controller.create_rule_from_selected()
        elif chosen is act_reset_sort:
            self._dialog._table_view_controller.reset_table_sort_for_current_tab()
        elif chosen is act_reset_widths:
            self._dialog._table_view_controller.reset_table_column_widths_for_current_tab()