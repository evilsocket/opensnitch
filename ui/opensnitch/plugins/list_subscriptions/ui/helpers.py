import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Keep static typing deterministic for linters/IDEs.
    # Runtime still supports both PyQt6/PyQt5 below.
    from PyQt6 import QtCore, QtGui, QtWidgets, uic
    from PyQt6.QtCore import QCoreApplication as QC
    from PyQt6.uic.load_ui import loadUiType as load_ui_type
else:
    if "PyQt6" in sys.modules:
        from PyQt6 import QtCore, QtGui, QtWidgets, uic
        from PyQt6.QtCore import QCoreApplication as QC
        from PyQt6.uic.load_ui import loadUiType as load_ui_type
    elif "PyQt5" in sys.modules:
        from PyQt5 import QtCore, QtGui, QtWidgets, uic
        from PyQt5.QtCore import QCoreApplication as QC

        load_ui_type = uic.loadUiType
    else:
        try:
            from PyQt6 import QtCore, QtGui, QtWidgets, uic
            from PyQt6.QtCore import QCoreApplication as QC
            from PyQt6.uic.load_ui import loadUiType as load_ui_type
        except Exception:
            from PyQt5 import QtCore, QtGui, QtWidgets, uic  # noqa: F401
            from PyQt5.QtCore import QCoreApplication as QC

            load_ui_type = uic.loadUiType


def _is_dark_palette(widget: QtWidgets.QWidget):
    return widget.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128


def _section_background_color_name(widget: QtWidgets.QWidget):
    bg_role = (
        QtGui.QPalette.ColorRole.AlternateBase
        if _is_dark_palette(widget)
        else QtGui.QPalette.ColorRole.Button
    )
    return widget.palette().color(bg_role).name()


def _section_border_color_name(widget: QtWidgets.QWidget):
    border_role = (
        QtGui.QPalette.ColorRole.Midlight
        if _is_dark_palette(widget)
        else QtGui.QPalette.ColorRole.Mid
    )
    return widget.palette().color(border_role).name()


def _footer_separator_color_name(widget: QtWidgets.QWidget):
    footer_role = (
        QtGui.QPalette.ColorRole.Midlight
        if _is_dark_palette(widget)
        else QtGui.QPalette.ColorRole.Dark
    )
    return widget.palette().color(footer_role).name()


def _apply_section_bar_style(
    widget: QtWidgets.QWidget,
    container: QtWidgets.QFrame,
    label: QtWidgets.QLabel,
    *,
    right_border: bool = False,
    expanding_label: bool = False,
):
    bg = _section_background_color_name(widget)
    border = _section_border_color_name(widget)
    text = widget.palette().color(QtGui.QPalette.ColorRole.WindowText).name()
    font = label.font()
    font.setPointSizeF(font.pointSizeF() + 1.0)
    label.setFont(font)
    container.setSizePolicy(
        QtWidgets.QSizePolicy.Policy.Expanding,
        QtWidgets.QSizePolicy.Policy.Fixed,
    )
    label.setSizePolicy(
        QtWidgets.QSizePolicy.Policy.Expanding
        if expanding_label
        else QtWidgets.QSizePolicy.Policy.Preferred,
        QtWidgets.QSizePolicy.Policy.Fixed,
    )
    border_right = f"border-right: 1px solid {border};" if right_border else ""
    container.setStyleSheet(
        "QFrame {"
        f"background-color: {bg};"
        f"border-top: 1px solid {border};"
        f"border-bottom: 1px solid {border};"
        f"{border_right}"
        "}"
    )
    label.setStyleSheet(
        "QLabel {"
        f"color: {text};"
        "background: transparent;"
        "padding: 3px 10px;"
        "border: 0;"
        "}"
    )


def _apply_footer_separator_style(widget: QtWidgets.QWidget, separator: QtWidgets.QFrame):
    footer_color = _footer_separator_color_name(widget)
    separator.setFixedHeight(1)
    separator.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
    separator.setStyleSheet(
        f"QFrame {{ color: {footer_color}; background-color: {footer_color}; }}"
    )


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
