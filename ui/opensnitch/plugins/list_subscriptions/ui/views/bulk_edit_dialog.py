import logging
import os
from typing import Any, TYPE_CHECKING, Final

from opensnitch.plugins.list_subscriptions.ui import (
    QtCore,
    QtWidgets,
    QC,
    load_ui_type,
)

from opensnitch.plugins.list_subscriptions.ui.views.helpers import (
    _apply_section_bar_style,
    _apply_footer_separator_style,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.helpers import (
    _configure_spin_and_units,
    _set_optional_field_tooltips,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.toggle_switch_widget import (
    ToggleSwitch,
)
from opensnitch.plugins.list_subscriptions.models.global_defaults import (
    GlobalDefaults,
)
from opensnitch.plugins.list_subscriptions._utils import (
    RES_DIR,
    INTERVAL_UNITS,
    TIMEOUT_UNITS,
    SIZE_UNITS,
    normalize_group,
    normalize_groups,
)


BULK_EDIT_DIALOG_UI_PATH: Final[str] = os.path.join(RES_DIR, "bulk_edit_dialog.ui")

BulkEditDialogUI: Final[Any] = load_ui_type(BULK_EDIT_DIALOG_UI_PATH)[0]

logger: Final[logging.Logger] = logging.getLogger(__name__)


class BulkEditDialog(QtWidgets.QDialog, BulkEditDialogUI):
    if TYPE_CHECKING:
        rootLayout: QtWidgets.QVBoxLayout
        buttons_layout: QtWidgets.QHBoxLayout
        changes_section_bar: QtWidgets.QFrame
        changes_section_label: QtWidgets.QLabel
        selection_hint_label: QtWidgets.QLabel
        changes_tree: QtWidgets.QTreeWidget
        enabled_value: QtWidgets.QCheckBox
        group_value: QtWidgets.QComboBox
        format_value: QtWidgets.QComboBox
        interval_spin: QtWidgets.QSpinBox
        interval_units: QtWidgets.QComboBox
        timeout_spin: QtWidgets.QSpinBox
        timeout_units: QtWidgets.QComboBox
        max_size_spin: QtWidgets.QSpinBox
        max_size_units: QtWidgets.QComboBox
        error_label: QtWidgets.QLabel
        footer_separator_line: QtWidgets.QFrame
        cancel_button: QtWidgets.QPushButton
        save_button: QtWidgets.QPushButton
        _defaults: GlobalDefaults
        _groups: list[str]

    def __init__(
        self,
        parent: QtWidgets.QWidget | None,
        defaults: GlobalDefaults,
        groups: list[str] | None = None,
        selected_count: int | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(QC.translate("stats", "Edit selected subscriptions"))
        self._defaults = defaults
        self._groups = groups or []
        self._selected_count = selected_count
        self._field_items: dict[str, QtWidgets.QTreeWidgetItem] = {}
        self._build_ui()

    def _build_ui(self):
        self.setupUi(self)
        self.error_label.setStyleSheet("color: red;")
        self.rootLayout.setContentsMargins(0, 0, 0, 0)
        self.rootLayout.setSpacing(0)
        self.selection_hint_label.setContentsMargins(12, 10, 12, 8)
        self.changes_tree.setContentsMargins(0, 0, 0, 0)
        self.buttons_layout.setContentsMargins(12, 10, 12, 12)
        self.buttons_layout.setSpacing(8)
        _apply_section_bar_style(
            self,
            self.changes_section_bar,
            self.changes_section_label,
        )
        _apply_footer_separator_style(self, self.footer_separator_line)
        self.error_label.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Preferred,
        )
        self.error_label.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        if self._selected_count is not None:
            self.selection_hint_label.setText(
                QC.translate(
                    "stats",
                    "Choose which changes to apply to {0} selected subscriptions.",
                ).format(self._selected_count)
            )
        self.changes_tree.setRootIsDecorated(False)
        self.changes_tree.setUniformRowHeights(False)
        self.changes_tree.setItemsExpandable(False)
        self.changes_tree.setAllColumnsShowFocus(False)
        self.changes_tree.setIndentation(0)
        self.changes_tree.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.NoSelection
        )
        header = self.changes_tree.header()
        if header is not None:
            header.setStretchLastSection(True)
            header.setSectionResizeMode(
                0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
            )
            header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch)
        expanding = QtWidgets.QSizePolicy.Policy.Expanding
        fixed = QtWidgets.QSizePolicy.Policy.Fixed

        self.enabled_value = ToggleSwitch(QC.translate("stats", "Enabled"))
        self.enabled_value.setSizePolicy(expanding, fixed)

        self.group_value = QtWidgets.QComboBox()
        self.group_value.setEditable(True)
        self.group_value.setSizePolicy(expanding, fixed)
        self.group_value.setEditable(True)
        self.group_value.setToolTip(
            QC.translate(
                "stats",
                "Optional explicit groups. Every subscription is always included in the global 'all' rules directory.",
            )
        )
        self.format_value = QtWidgets.QComboBox()
        self.format_value.setSizePolicy(expanding, fixed)
        self.interval_spin = QtWidgets.QSpinBox()
        self.interval_spin.setSizePolicy(expanding, fixed)
        self.interval_units = QtWidgets.QComboBox()
        self.interval_units.setSizePolicy(fixed, fixed)
        self.timeout_spin = QtWidgets.QSpinBox()
        self.timeout_spin.setSizePolicy(expanding, fixed)
        self.timeout_units = QtWidgets.QComboBox()
        self.timeout_units.setSizePolicy(fixed, fixed)
        self.max_size_spin = QtWidgets.QSpinBox()
        self.max_size_spin.setSizePolicy(expanding, fixed)
        self.max_size_units = QtWidgets.QComboBox()
        self.max_size_units.setSizePolicy(fixed, fixed)
        unit_combo_width = 132
        self.interval_units.setMinimumWidth(unit_combo_width)
        self.timeout_units.setMinimumWidth(unit_combo_width)
        self.max_size_units.setMinimumWidth(unit_combo_width)

        self.cancel_button.clicked.connect(self.reject)
        self.save_button.clicked.connect(self.validate_then_accept)

        self.enabled_value.setChecked(True)
        self.group_value.clear()
        for g in self._groups:
            ng = normalize_group(g)
            if ng not in ("", "all"):
                self.group_value.addItem(ng)
        self.group_value.setCurrentText("")
        self.format_value.clear()
        self.format_value.addItems(("hosts",))
        _configure_spin_and_units(
            self.interval_spin,
            self.interval_units,
            value=0,
            unit_value=self._defaults.interval_units,
            allowed_units=INTERVAL_UNITS,
            fallback_unit="hours",
            special_value_text=QC.translate(
                "stats", "Use global default ({0} {1})"
            ).format(
                self._defaults.interval,
                self._defaults.interval_units,
            ),
        )
        _configure_spin_and_units(
            self.timeout_spin,
            self.timeout_units,
            value=0,
            unit_value=self._defaults.timeout_units,
            allowed_units=TIMEOUT_UNITS,
            fallback_unit="seconds",
            special_value_text=QC.translate(
                "stats", "Use global default ({0} {1})"
            ).format(
                self._defaults.timeout,
                self._defaults.timeout_units,
            ),
        )
        _configure_spin_and_units(
            self.max_size_spin,
            self.max_size_units,
            value=0,
            unit_value=self._defaults.max_size_units,
            allowed_units=SIZE_UNITS,
            fallback_unit="MB",
            special_value_text=QC.translate(
                "stats", "Use global default ({0} {1})"
            ).format(
                self._defaults.max_size,
                self._defaults.max_size_units,
            ),
        )

        self._add_change_row(
            "enabled", QC.translate("stats", "Enabled"), self.enabled_value
        )
        self._add_change_row(
            "groups", QC.translate("stats", "Groups"), self.group_value
        )
        self._add_change_row(
            "format", QC.translate("stats", "Format"), self.format_value
        )
        self._add_change_row(
            "interval",
            QC.translate("stats", "Interval"),
            self._build_compound_editor(self.interval_spin, self.interval_units),
        )
        self._add_change_row(
            "timeout",
            QC.translate("stats", "Timeout"),
            self._build_compound_editor(self.timeout_spin, self.timeout_units),
        )
        self._add_change_row(
            "max_size",
            QC.translate("stats", "Max size"),
            self._build_compound_editor(self.max_size_spin, self.max_size_units),
        )
        self.changes_tree.itemChanged.connect(self.handle_item_changed)

        self.interval_spin.valueChanged.connect(self.sync_optional_fields_state)
        self.timeout_spin.valueChanged.connect(self.sync_optional_fields_state)
        self.max_size_spin.valueChanged.connect(self.sync_optional_fields_state)
        _set_optional_field_tooltips(
            self.interval_spin,
            self.interval_units,
            self.timeout_spin,
            self.timeout_units,
            self.max_size_spin,
            self.max_size_units,
            inherit_wording=False,
        )
        self.sync_apply_fields_state()
        self.sync_optional_fields_state()
        self.resize(760, 420)

    def _build_compound_editor(
        self, primary: QtWidgets.QWidget, secondary: QtWidgets.QWidget
    ):
        container = QtWidgets.QWidget(self.changes_tree)
        layout = QtWidgets.QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(primary, 1)
        layout.addWidget(secondary, 0)
        return container

    def _add_change_row(self, key: str, label: str, editor: QtWidgets.QWidget):
        item = QtWidgets.QTreeWidgetItem(self.changes_tree)
        item.setText(0, label)
        item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(0, QtCore.Qt.CheckState.Unchecked)
        self.changes_tree.setItemWidget(item, 1, editor)
        self._field_items[key] = item

    # -- Field apply state --------------------------------------------------

    def is_field_applied(self, key: str) -> bool:
        item = self._field_items.get(key)
        if item is None:
            return False
        return item.checkState(0) == QtCore.Qt.CheckState.Checked

    def handle_item_changed(self, item: QtWidgets.QTreeWidgetItem, column: int) -> None:
        if column != 0:
            return
        self.sync_apply_fields_state()

    def sync_optional_fields_state(self) -> None:
        self.interval_units.setEnabled(
            self.is_field_applied("interval") and self.interval_spin.value() > 0
        )
        self.timeout_units.setEnabled(
            self.is_field_applied("timeout") and self.timeout_spin.value() > 0
        )
        self.max_size_units.setEnabled(
            self.is_field_applied("max_size") and self.max_size_spin.value() > 0
        )

    def sync_apply_fields_state(self) -> None:
        self.enabled_value.setEnabled(self.is_field_applied("enabled"))
        self.group_value.setEnabled(self.is_field_applied("groups"))
        self.format_value.setEnabled(self.is_field_applied("format"))
        self.interval_spin.setEnabled(self.is_field_applied("interval"))
        self.timeout_spin.setEnabled(self.is_field_applied("timeout"))
        self.max_size_spin.setEnabled(self.is_field_applied("max_size"))
        self.sync_optional_fields_state()

    # -- Validation ---------------------------------------------------------

    def validate_then_accept(self) -> None:
        if not any(self.is_field_applied(key) for key in self._field_items):
            self.error_label.setText(
                QC.translate("stats", "Select at least one field to apply.")
            )
            return
        self.error_label.setText("")
        self.accept()

    # -- Result extraction --------------------------------------------------

    def values(self) -> dict[str, Any]:
        return {
            "enabled": (
                self.enabled_value.isChecked()
                if self.is_field_applied("enabled")
                else None
            ),
            "groups": (
                normalize_groups(self.group_value.currentText())
                if self.is_field_applied("groups")
                else None
            ),
            "format": (
                (self.format_value.currentText() or "hosts").strip().lower()
                if self.is_field_applied("format")
                else None
            ),
            "apply_interval": self.is_field_applied("interval"),
            "interval": int(self.interval_spin.value()) or None,
            "interval_units": (
                self.interval_units.currentText()
                if self.interval_spin.value() > 0
                else None
            ),
            "apply_timeout": self.is_field_applied("timeout"),
            "timeout": int(self.timeout_spin.value()) or None,
            "timeout_units": (
                self.timeout_units.currentText()
                if self.timeout_spin.value() > 0
                else None
            ),
            "apply_max_size": self.is_field_applied("max_size"),
            "max_size": int(self.max_size_spin.value()) or None,
            "max_size_units": (
                self.max_size_units.currentText()
                if self.max_size_spin.value() > 0
                else None
            ),
        }
