from contextlib import contextmanager
from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class TableViewController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns

    def _col(self, key: str):
        return self._cols[key]

    def _visible_columns(self) -> list[int]:
        return [
            col
            for col in range(self._dialog.table.columnCount())
            if not self._dialog.table.isColumnHidden(col)
        ]

    def _expand_visible_columns_to_viewport(self, base_widths: dict[int, int]) -> None:
        visible_cols = [col for col in self._visible_columns() if col in base_widths]
        if not visible_cols:
            return

        viewport_width = self._dialog.table.viewport().width()
        if viewport_width <= 0:
            return

        min_total = sum(max(1, int(base_widths.get(col, 1))) for col in visible_cols)
        if viewport_width <= min_total:
            return

        extra = viewport_width - min_total
        add_each = extra // len(visible_cols)
        remainder = extra % len(visible_cols)

        for idx, col in enumerate(visible_cols):
            target = max(1, int(base_widths.get(col, 1))) + add_each
            if idx < remainder:
                target += 1
            self._dialog.table.setColumnWidth(col, target)

    @contextmanager
    def sorting_suspended(self):
        header = self._dialog.table.horizontalHeader()
        sorting_enabled = self._dialog.table.isSortingEnabled()
        sort_section = header.sortIndicatorSection() if header is not None else -1
        sort_order = (
            header.sortIndicatorOrder()
            if header is not None
            else QtCore.Qt.SortOrder.AscendingOrder
        )
        self._dialog.table.setSortingEnabled(False)
        try:
            yield
        finally:
            self._dialog.table.setSortingEnabled(sorting_enabled)
            if sorting_enabled and header is not None and sort_section >= 0:
                self._dialog.table.sortItems(sort_section, sort_order)
            self.apply_table_view_mode()

    def on_table_view_tab_changed(self, index: int):
        monitoring = index == 0
        always_hidden = {
            self._col("interval"),
            self._col("interval_units"),
            self._col("timeout"),
            self._col("timeout_units"),
            self._col("max_size"),
            self._col("max_size_units"),
            self._col("file"),
            self._col("meta"),
            self._col("rule_attached"),
        }
        monitoring_only = {
            self._col("state"),
            self._col("last_checked"),
            self._col("last_updated"),
        }
        config_only = {
            self._col("enabled"),
            self._col("url"),
            self._col("filename"),
            self._col("format"),
            self._col("group"),
        }
        for col in range(self._dialog.table.columnCount()):
            if col in always_hidden:
                self._dialog.table.setColumnHidden(col, True)
            elif col in monitoring_only:
                self._dialog.table.setColumnHidden(col, not monitoring)
            elif col in config_only:
                self._dialog.table.setColumnHidden(col, monitoring)
        self.apply_table_column_sizing(index)
        self.apply_table_view_mode(index, set_sort=True)
        self._dialog._inspector_controller.update_inspector_panel()

    def apply_table_column_sizing(self, index: int | None = None):
        header = self._dialog.table.horizontalHeader()
        if header is None:
            return

        monitoring = (
            index == 0
            if index is not None
            else self._dialog._table_tab_bar.currentIndex() == 0
        )
        tab_index = 0 if monitoring else 1
        resized_columns = self._dialog._user_resized_columns_by_tab.get(tab_index, set())

        header.setStretchLastSection(False)
        self._dialog._applying_table_column_sizing = True
        base_widths: dict[int, int] = {}

        try:
            if monitoring:
                # Monitoring: all visible data columns are user-resizable.
                header.setSectionResizeMode(self._col("name"), QtWidgets.QHeaderView.ResizeMode.Interactive)
                header.setSectionResizeMode(self._col("state"), QtWidgets.QHeaderView.ResizeMode.Interactive)
                header.setSectionResizeMode(
                    self._col("last_checked"), QtWidgets.QHeaderView.ResizeMode.Interactive
                )
                header.setSectionResizeMode(
                    self._col("last_updated"), QtWidgets.QHeaderView.ResizeMode.Interactive
                )
                if self._col("name") not in resized_columns:
                    self._dialog.table.setColumnWidth(self._col("name"), 260)
                if self._col("state") not in resized_columns:
                    self._dialog.table.setColumnWidth(self._col("state"), 140)
                if self._col("last_checked") not in resized_columns:
                    self._dialog.table.setColumnWidth(self._col("last_checked"), 260)
                if self._col("last_updated") not in resized_columns:
                    self._dialog.table.setColumnWidth(self._col("last_updated"), 260)
                for col in self._visible_columns():
                    base_widths[col] = self._dialog.table.columnWidth(col)
                self._expand_visible_columns_to_viewport(base_widths)
                return

            # Config: keep URL flexible, reserve enough space for frequently edited fields.
            header.setSectionResizeMode(self._col("enabled"), QtWidgets.QHeaderView.ResizeMode.Fixed)
            header.setSectionResizeMode(self._col("name"), QtWidgets.QHeaderView.ResizeMode.Interactive)
            header.setSectionResizeMode(self._col("url"), QtWidgets.QHeaderView.ResizeMode.Interactive)
            header.setSectionResizeMode(self._col("filename"), QtWidgets.QHeaderView.ResizeMode.Interactive)
            header.setSectionResizeMode(self._col("format"), QtWidgets.QHeaderView.ResizeMode.Interactive)
            header.setSectionResizeMode(self._col("group"), QtWidgets.QHeaderView.ResizeMode.Interactive)

            if self._col("name") not in resized_columns:
                self._dialog.table.setColumnWidth(self._col("name"), 220)
            if self._col("url") not in resized_columns:
                self._dialog.table.setColumnWidth(self._col("url"), 380)
            if self._col("filename") not in resized_columns:
                self._dialog.table.setColumnWidth(self._col("filename"), 220)
            if self._col("format") not in resized_columns:
                self._dialog.table.setColumnWidth(self._col("format"), 120)
            if self._col("group") not in resized_columns:
                self._dialog.table.setColumnWidth(self._col("group"), 180)

            for col in self._visible_columns():
                base_widths[col] = self._dialog.table.columnWidth(col)
            self._expand_visible_columns_to_viewport(base_widths)
        finally:
            self._dialog._applying_table_column_sizing = False

    def on_table_section_resized(self, logical_index: int, _old_size: int, _new_size: int):
        if self._dialog._applying_table_column_sizing:
            return
        if logical_index < 0 or logical_index >= self._dialog.table.columnCount():
            return
        if self._dialog.table.isColumnHidden(logical_index):
            return
        if not hasattr(self._dialog, "_table_tab_bar"):
            return
        tab_index = self._dialog._table_tab_bar.currentIndex()
        self._dialog._user_resized_columns_by_tab.setdefault(tab_index, set()).add(logical_index)

    def reset_table_column_widths_for_current_tab(self):
        if not hasattr(self._dialog, "_table_tab_bar"):
            return
        tab_index = self._dialog._table_tab_bar.currentIndex()
        self._dialog._user_resized_columns_by_tab.pop(tab_index, None)
        self.apply_table_column_sizing(tab_index)

    def reset_table_sort_for_current_tab(self):
        if not hasattr(self._dialog, "_table_tab_bar"):
            return
        tab_index = self._dialog._table_tab_bar.currentIndex()
        self.apply_table_view_mode(tab_index, set_sort=True)

    def apply_table_view_mode(self, index: int | None = None, *, set_sort: bool = False):
        if not hasattr(self._dialog, "_table_tab_bar"):
            return
        monitoring = (
            index == 0
            if index is not None
            else self._dialog._table_tab_bar.currentIndex() == 0
        )
        for row in range(self._dialog.table.rowCount()):
            enabled_item = self._dialog.table.item(row, self._col("enabled"))
            enabled = enabled_item is not None and (
                enabled_item.checkState() == QtCore.Qt.CheckState.Checked
            )
            self._dialog.table.setRowHidden(row, monitoring and not enabled)

        if not set_sort:
            return
        header = self._dialog.table.horizontalHeader()
        if header is None:
            return
        if monitoring:
            sort_col = self._col("state")
            sort_order = QtCore.Qt.SortOrder.AscendingOrder
        else:
            sort_col = self._col("enabled")
            sort_order = QtCore.Qt.SortOrder.AscendingOrder
        header.setSortIndicator(sort_col, sort_order)
        if self._dialog.table.isSortingEnabled():
            self._dialog.table.sortItems(sort_col, sort_order)
