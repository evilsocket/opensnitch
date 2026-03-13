import os
from collections.abc import Callable
from typing import Any, TYPE_CHECKING, Final

from opensnitch.plugins.list_subscriptions.ui import (
    QtCore,
    QtWidgets,
    QC,
    load_ui_type,
)

from opensnitch.plugins.list_subscriptions._utils import RES_DIR
from opensnitch.plugins.list_subscriptions.ui.views.helpers import _configure_modal_dialog
from opensnitch.plugins.list_subscriptions.ui.widgets.table_widgets import (
    SortableTableWidgetItem,
)

ATTACHED_RULES_DIALOG_UI_PATH: Final[str] = os.path.join(
    RES_DIR, "attached_rules_dialog.ui"
)

AttachedRulesDialogUI: Final[Any] = load_ui_type(ATTACHED_RULES_DIALOG_UI_PATH)[0]

ATTACHED_RULE_ENTRY_ROLE = int(QtCore.Qt.ItemDataRole.UserRole) + 1


class AttachedRulesDialog(QtWidgets.QDialog, AttachedRulesDialogUI):
    if TYPE_CHECKING:
        rules_table: QtWidgets.QTableWidget
        create_button: QtWidgets.QPushButton
        edit_button: QtWidgets.QPushButton
        toggle_button: QtWidgets.QPushButton
        remove_button: QtWidgets.QPushButton
        close_button: QtWidgets.QPushButton

    def __init__(
        self,
        parent: QtWidgets.QWidget,
        *,
        get_attached_rules: Callable[[], list[dict[str, Any]]],
        on_create_rule: Callable[[], None],
        on_edit_rule: Callable[[dict[str, Any]], None],
        on_toggle_rule: Callable[[dict[str, Any]], None],
        on_remove_rule: Callable[[dict[str, Any]], None],
    ):
        super().__init__(parent)
        self._get_attached_rules = get_attached_rules
        self._on_create_rule = on_create_rule
        self._on_edit_rule = on_edit_rule
        self._on_toggle_rule = on_toggle_rule
        self._on_remove_rule = on_remove_rule

        self.setupUi(self)
        self._build_ui()
        self._refresh_table()

    def _configure_rules_table(self) -> None:
        self.rules_table.setColumnCount(6)
        self.rules_table.setHorizontalHeaderLabels(
            [
                QC.translate("stats", "Rule"),
                QC.translate("stats", "Node"),
                QC.translate("stats", "Status"),
                QC.translate("stats", "Single sub"),
                QC.translate("stats", "All"),
                QC.translate("stats", "Groups"),
            ]
        )
        self.rules_table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.rules_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.rules_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setSortingEnabled(True)

        vertical_header = self.rules_table.verticalHeader()
        if vertical_header is not None:
            vertical_header.setVisible(False)

        header = self.rules_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(False)
            header.setSortIndicatorShown(True)
            header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
            for column in (1, 2, 3, 4):
                header.setSectionResizeMode(
                    column,
                    QtWidgets.QHeaderView.ResizeMode.ResizeToContents,
                )
            header.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeMode.Interactive)
            header.setSortIndicator(0, QtCore.Qt.SortOrder.AscendingOrder)

        self.rules_table.setColumnWidth(5, 180)

    def _build_ui(self):
        _configure_modal_dialog(
            self,
            title=QC.translate("stats", "Attached rules"),
            size=(760, 420),
        )
        self._configure_rules_table()
        self.rules_table.itemDoubleClicked.connect(lambda _item: self._edit_selected())
        self.rules_table.itemSelectionChanged.connect(self._update_action_buttons)

        self.create_button.setText(QC.translate("stats", "Create rule"))
        self.edit_button.setText(QC.translate("stats", "Edit selected"))
        self.toggle_button.setText(QC.translate("stats", "Disable"))
        self.remove_button.setText(QC.translate("stats", "Remove"))
        self.close_button.setText(QC.translate("stats", "Close"))

        self.create_button.clicked.connect(self._create_rule)
        self.edit_button.clicked.connect(self._edit_selected)
        self.toggle_button.clicked.connect(self._toggle_selected)
        self.remove_button.clicked.connect(self._remove_selected)
        self.close_button.clicked.connect(self.accept)

    def _create_rule(self):
        self.accept()
        self._on_create_rule()

    def _selected_entry(self):
        row = self.rules_table.currentRow()
        if row < 0:
            return None
        item = self.rules_table.item(row, 0)
        if item is None:
            return None
        entry = item.data(ATTACHED_RULE_ENTRY_ROLE)
        if not isinstance(entry, dict):
            return None
        addr = str(entry.get("addr", "")).strip()
        name = str(entry.get("name", "")).strip()
        if addr == "" or name == "":
            return None
        return {
            "addr": addr,
            "name": name,
            "enabled": bool(entry.get("enabled", True)),
        }

    def _populate_table(self, aggregated_rules: list[dict[str, Any]]):
        header = self.rules_table.horizontalHeader()
        sort_column = 0
        sort_order = QtCore.Qt.SortOrder.AscendingOrder
        if header is not None:
            current_sort_column = header.sortIndicatorSection()
            if 0 <= current_sort_column < self.rules_table.columnCount():
                sort_column = current_sort_column
            sort_order = header.sortIndicatorOrder()
        selected_entry = self._selected_entry()

        self.rules_table.setSortingEnabled(False)
        self.rules_table.clearContents()
        self.rules_table.setRowCount(len(aggregated_rules))

        for row, entry in enumerate(aggregated_rules):
            state_text = (
                QC.translate("stats", "enabled")
                if bool(entry.get("enabled", True))
                else QC.translate("stats", "disabled")
            )
            groups_text = ", ".join(entry.get("groups", [])) or "-"
            row_values = [
                (
                    QtWidgets.QTableWidgetItem(str(entry.get("name", "")).strip()),
                    None,
                ),
                (
                    SortableTableWidgetItem(str(entry.get("addr", "")).strip()),
                    str(entry.get("addr", "")).strip().lower(),
                ),
                (
                    SortableTableWidgetItem(state_text),
                    0 if bool(entry.get("enabled", True)) else 1,
                ),
                (
                    SortableTableWidgetItem(
                        QC.translate("stats", "yes") if bool(entry.get("single")) else "-"
                    ),
                    0 if bool(entry.get("single")) else 1,
                ),
                (
                    SortableTableWidgetItem(
                        QC.translate("stats", "yes") if bool(entry.get("all")) else "-"
                    ),
                    0 if bool(entry.get("all")) else 1,
                ),
                (
                    SortableTableWidgetItem(groups_text),
                    [group.lower() for group in entry.get("groups", [])],
                ),
            ]
            for column, (item, sort_key) in enumerate(row_values):
                if column == 0:
                    item.setData(ATTACHED_RULE_ENTRY_ROLE, entry)
                if sort_key is not None:
                    item.setData(QtCore.Qt.ItemDataRole.UserRole, sort_key)
                item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
                self.rules_table.setItem(row, column, item)

        self.rules_table.setSortingEnabled(True)
        self.rules_table.sortItems(sort_column, sort_order)

        if self.rules_table.rowCount() <= 0:
            self._update_action_buttons()
            return

        if selected_entry is not None:
            selected_addr = str(selected_entry.get("addr", "")).strip()
            selected_name = str(selected_entry.get("name", "")).strip()
            for row in range(self.rules_table.rowCount()):
                item = self.rules_table.item(row, 0)
                if item is None:
                    continue
                entry = item.data(ATTACHED_RULE_ENTRY_ROLE)
                if not isinstance(entry, dict):
                    continue
                row_addr = str(entry.get("addr", "")).strip()
                row_name = str(entry.get("name", "")).strip()
                if row_addr == selected_addr and row_name == selected_name:
                    self.rules_table.selectRow(row)
                    self._update_action_buttons()
                    return

        self.rules_table.selectRow(0)
        self._update_action_buttons()

    def _refresh_table(self):
        self._populate_table(self._get_attached_rules())

    def _update_toggle_button(self):
        entry = self._selected_entry()
        if entry is None:
            self.toggle_button.setEnabled(False)
            self.toggle_button.setText(QC.translate("stats", "Disable"))
            return

        self.toggle_button.setEnabled(True)
        if bool(entry.get("enabled", True)):
            self.toggle_button.setText(QC.translate("stats", "Disable"))
        else:
            self.toggle_button.setText(QC.translate("stats", "Enable"))

    def _update_action_buttons(self):
        entry = self._selected_entry()
        has_selection = entry is not None
        self.edit_button.setEnabled(has_selection)
        self.remove_button.setEnabled(has_selection)
        self._update_toggle_button()

    def _edit_selected(self):
        entry = self._selected_entry()
        if entry is None:
            return
        self._on_edit_rule(entry)

    def _toggle_selected(self):
        entry = self._selected_entry()
        if entry is None:
            return
        self._on_toggle_rule(entry)
        self._refresh_table()

    def _remove_selected(self):
        entry = self._selected_entry()
        if entry is None:
            return
        self._on_remove_rule(entry)
        self._refresh_table()
