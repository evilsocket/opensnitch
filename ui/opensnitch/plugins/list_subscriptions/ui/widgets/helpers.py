from collections.abc import Sequence

from opensnitch.plugins.list_subscriptions.ui import QtWidgets, QC


def _set_optional_field_tooltips(
    interval_spin: QtWidgets.QWidget,
    interval_units: QtWidgets.QWidget,
    timeout_spin: QtWidgets.QWidget,
    timeout_units: QtWidgets.QWidget,
    max_size_spin: QtWidgets.QWidget,
    max_size_units: QtWidgets.QWidget,
    *,
    inherit_wording: bool,
):
    if inherit_wording:
        interval_spin.setToolTip(
            QC.translate("stats", "Set to 0 to inherit the global interval.")
        )
        interval_units.setToolTip(
            QC.translate("stats", "Used only when the interval override is set.")
        )
        timeout_spin.setToolTip(
            QC.translate("stats", "Set to 0 to inherit the global timeout.")
        )
        timeout_units.setToolTip(
            QC.translate("stats", "Used only when the timeout override is set.")
        )
        max_size_spin.setToolTip(
            QC.translate("stats", "Set to 0 to inherit the global max size.")
        )
        max_size_units.setToolTip(
            QC.translate("stats", "Used only when the max size override is set.")
        )
        return
    interval_spin.setToolTip(
        QC.translate(
            "stats",
            "Set to 0 to clear the interval override and use the global default.",
        )
    )
    interval_units.setToolTip(
        QC.translate("stats", "Used only when an interval override is applied.")
    )
    timeout_spin.setToolTip(
        QC.translate(
            "stats",
            "Set to 0 to clear the timeout override and use the global default.",
        )
    )
    timeout_units.setToolTip(
        QC.translate("stats", "Used only when a timeout override is applied.")
    )
    max_size_spin.setToolTip(
        QC.translate(
            "stats",
            "Set to 0 to clear the max size override and use the global default.",
        )
    )
    max_size_units.setToolTip(
        QC.translate("stats", "Used only when a max size override is applied.")
    )


def _configure_spin_and_units(
    spin: QtWidgets.QSpinBox,
    units_combo: QtWidgets.QComboBox,
    *,
    value: int,
    unit_value: str | None,
    allowed_units: Sequence[str],
    fallback_unit: str,
    min_value: int = 0,
    max_value: int = 999999,
    special_value_text: str | None = None,
):
    spin.setRange(min_value, max_value)
    if special_value_text is not None:
        spin.setSpecialValueText(special_value_text)
    spin.setValue(max(min_value, int(value)))
    units_combo.clear()
    units_combo.addItems(tuple(allowed_units))
    normalized = (unit_value or "").strip().lower()
    current_unit = fallback_unit
    for unit in allowed_units:
        if unit.lower() == normalized:
            current_unit = unit
            break
    units_combo.setCurrentText(
        current_unit
    )
