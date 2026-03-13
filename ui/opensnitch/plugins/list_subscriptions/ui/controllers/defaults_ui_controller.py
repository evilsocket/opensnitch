from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import QtWidgets, QC
from opensnitch.plugins.list_subscriptions.ui.widgets.helpers import _configure_spin_and_units
from opensnitch.plugins.list_subscriptions._utils import (
    INTERVAL_UNITS,
    SIZE_UNITS,
    TIMEOUT_UNITS,
    normalize_unit,
)

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class DefaultsUiController:
    def __init__(self, *, dialog: "ListSubscriptionsDialog"):
        self._dialog = dialog

    def reload_nodes(self):
        self._dialog.nodes_combo.blockSignals(True)
        self._dialog.nodes_combo.clear()
        for addr in self._dialog._nodes.get_nodes():
            self._dialog.nodes_combo.addItem(addr, addr)
        self._dialog.nodes_combo.blockSignals(False)

    def apply_defaults_to_widgets(self):
        _configure_spin_and_units(
            self._dialog.default_interval_spin,
            self._dialog.default_interval_units,
            value=int(self._dialog._global_defaults.interval),
            unit_value=self._dialog._global_defaults.interval_units,
            allowed_units=INTERVAL_UNITS,
            fallback_unit="hours",
            min_value=1,
        )
        _configure_spin_and_units(
            self._dialog.default_timeout_spin,
            self._dialog.default_timeout_units,
            value=int(self._dialog._global_defaults.timeout),
            unit_value=self._dialog._global_defaults.timeout_units,
            allowed_units=TIMEOUT_UNITS,
            fallback_unit="seconds",
            min_value=1,
        )
        _configure_spin_and_units(
            self._dialog.default_max_size_spin,
            self._dialog.default_max_size_units,
            value=int(self._dialog._global_defaults.max_size),
            unit_value=self._dialog._global_defaults.max_size_units,
            allowed_units=SIZE_UNITS,
            fallback_unit="MB",
            min_value=1,
        )
        self._dialog.default_user_agent.setText(
            (self._dialog._global_defaults.user_agent or "").strip()
        )

    def set_units_combo(
        self, row: int, col: int, allowed: tuple[str, ...], value: str | None
    ):
        combo = QtWidgets.QComboBox()
        combo.addItem("")
        combo.addItems(allowed)
        combo.setToolTip(
            QC.translate(
                "stats",
                "Leave blank to inherit the global default for this subscription.",
            )
        )
        if value is None or value.strip() == "":
            combo.setCurrentIndex(0)
        else:
            combo.setCurrentText(normalize_unit(value, allowed, allowed[0]))
        self._dialog.table.setCellWidget(row, col, combo)