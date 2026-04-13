from typing import Any

from opensnitch.plugins.list_subscriptions.ui import (
    QtCore,
    QtGui,
    QtWidgets,
    QC,
)


def _section_border_color_name(widget: QtWidgets.QWidget):
    dark_palette = (
        widget.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128
    )
    border_role = (
        QtGui.QPalette.ColorRole.Midlight
        if dark_palette
        else QtGui.QPalette.ColorRole.Mid
    )
    return widget.palette().color(border_role).name()


def _apply_section_bar_style(
    widget: QtWidgets.QWidget,
    container: QtWidgets.QFrame,
    label: QtWidgets.QLabel,
    *,
    right_border: bool = False,
    expanding_label: bool = False,
):
    dark_palette = (
        widget.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128
    )
    bg_role = (
        QtGui.QPalette.ColorRole.AlternateBase
        if dark_palette
        else QtGui.QPalette.ColorRole.Button
    )
    bg = widget.palette().color(bg_role).name()
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
    dark_palette = (
        widget.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128
    )
    footer_role = (
        QtGui.QPalette.ColorRole.Midlight
        if dark_palette
        else QtGui.QPalette.ColorRole.Dark
    )
    footer_color = widget.palette().color(footer_role).name()
    separator.setFixedHeight(1)
    separator.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
    separator.setStyleSheet(
        f"QFrame {{ color: {footer_color}; background-color: {footer_color}; }}"
    )


def _configure_modal_dialog(
    dialog: QtWidgets.QDialog,
    *,
    title: str | None = None,
    size: tuple[int, int] | None = None,
):
    if title is not None:
        dialog.setWindowTitle(title)
    dialog.setWindowModality(QtCore.Qt.WindowModality.WindowModal)
    if size is not None:
        dialog.resize(size[0], size[1])


def _wire_copy_close_buttons(
    dialog: QtWidgets.QDialog,
    copy_button: QtWidgets.QPushButton,
    close_button: QtWidgets.QPushButton,
    text_view: Any,
):
    copy_button.setText(QC.translate("stats", "Copy"))
    close_button.setText(QC.translate("stats", "Close"))
    copy_button.clicked.connect(lambda: text_view.selectAll())
    copy_button.clicked.connect(lambda: text_view.copy())
    close_button.clicked.connect(dialog.accept)


