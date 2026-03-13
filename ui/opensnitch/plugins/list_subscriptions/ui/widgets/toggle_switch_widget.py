from opensnitch.plugins.list_subscriptions.ui import (
    QtCore,
    QtGui,
    QtWidgets,
    QC,
)


class ToggleSwitch(QtWidgets.QCheckBox):
    def __init__(
        self,
        text: str = "",
        parent: QtWidgets.QWidget | None = None,
    ):
        super().__init__(text, parent)
        self._base_text = text
        self._track_width = 38
        self._track_height = 22
        self._thumb_diameter = 16
        self._label_gap = 8
        self._outer_padding = 4
        self._paint_margin = 1.5
        self._focus_margin = 2.0
        self.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Preferred,
            QtWidgets.QSizePolicy.Policy.Fixed,
        )
        self.setContentsMargins(
            self._outer_padding,
            self._outer_padding,
            self._outer_padding,
            self._outer_padding,
        )
        self.toggled.connect(self._refresh_geometry)
        font = self.font()
        font.setBold(True)
        self.setFont(font)
        self._refresh_geometry(self.isChecked())

    def sizeHint(self) -> QtCore.QSize:
        metrics = self.fontMetrics()
        label_text = self._display_text()
        text_width = metrics.horizontalAdvance(label_text) if label_text else 0
        width = self._track_width + int(self._focus_margin * 2) + text_width
        if text_width:
            width += self._label_gap
        margins = self.contentsMargins()
        width += margins.left() + margins.right()
        height = max(
            metrics.height(),
            self._track_height + int(self._focus_margin * 2),
        )
        height += margins.top() + margins.bottom()
        return QtCore.QSize(width, height)

    def minimumSizeHint(self) -> QtCore.QSize:
        return self.sizeHint()

    def hitButton(self, pos: QtCore.QPoint) -> bool:
        return self.rect().contains(pos)

    def _refresh_geometry(self, _checked: bool):
        self.setMinimumHeight(self.sizeHint().height())
        self.updateGeometry()
        self.update()

    def _display_text(self) -> str:
        base = (self._base_text or "").strip()
        if base.lower() == "enable list subscriptions plugin":
            state = QC.translate(
                "stats",
                "enabled" if self.isChecked() else "disabled",
            )
            return QC.translate(
                "stats",
                "List subscriptions plugin {0}",
            ).format(state)
        if base.lower() in {"enabled", "disabled"}:
            return QC.translate(
                "stats",
                "Enabled" if self.isChecked() else "Disabled",
            )
        return base

    def paintEvent(self, event: QtGui.QPaintEvent):  # type: ignore[override]
        del event
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        margins = self.contentsMargins()
        content_rect = self.rect().adjusted(
            margins.left(),
            margins.top(),
            -margins.right(),
            -margins.bottom(),
        )
        _draw_toggle_switch(
            painter,
            self.palette(),
            QtCore.QRectF(content_rect),
            checked=self.isChecked(),
            enabled=self.isEnabled(),
            text=self._display_text(),
            bold_text=True,
            focused=self.hasFocus(),
            track_width=float(self._track_width),
            track_height=float(self._track_height),
            thumb_diameter=float(self._thumb_diameter),
            label_gap=float(self._label_gap),
            paint_margin=float(self._paint_margin),
            focus_margin=float(self._focus_margin),
        )


def _draw_toggle_switch(
    painter: QtGui.QPainter,
    palette: QtGui.QPalette,
    rect: QtCore.QRectF,
    *,
    checked: bool,
    enabled: bool,
    text: str = "",
    bold_text: bool = False,
    focused: bool = False,
    track_width: float = 38.0,
    track_height: float = 22.0,
    thumb_diameter: float = 16.0,
    label_gap: float = 8.0,
    paint_margin: float = 1.5,
    focus_margin: float = 2.0,
):
    is_dark = palette.color(QtGui.QPalette.ColorRole.Window).lightness() < 128
    if enabled:
        off_role = (
            QtGui.QPalette.ColorRole.Midlight
            if is_dark
            else QtGui.QPalette.ColorRole.Mid
        )
        border_role = (
            QtGui.QPalette.ColorRole.Light if is_dark else QtGui.QPalette.ColorRole.Dark
        )
        track_color = (
            palette.color(QtGui.QPalette.ColorRole.Highlight)
            if checked
            else palette.color(off_role)
        )
        thumb_color = palette.color(QtGui.QPalette.ColorRole.Base)
        text_color = palette.color(QtGui.QPalette.ColorRole.WindowText)
        border_color = palette.color(border_role)
    else:
        track_color = palette.color(QtGui.QPalette.ColorRole.Dark)
        thumb_color = palette.color(QtGui.QPalette.ColorRole.Mid)
        text_color = palette.color(QtGui.QPalette.ColorRole.Mid)
        border_color = palette.color(QtGui.QPalette.ColorRole.Mid)

    track_x = rect.left() + paint_margin + focus_margin
    track_y = rect.top() + (rect.height() - track_height) / 2.0 + paint_margin
    track_rect = QtCore.QRectF(
        track_x,
        track_y,
        track_width - (paint_margin * 2.0),
        track_height - (paint_margin * 2.0),
    )
    thumb_margin = (track_rect.height() - thumb_diameter) / 2.0
    thumb_left_off = track_rect.left() + thumb_margin
    thumb_left_on = track_rect.right() - thumb_margin - thumb_diameter
    thumb_rect = QtCore.QRectF(
        thumb_left_on if checked else thumb_left_off,
        track_rect.top() + thumb_margin,
        thumb_diameter,
        thumb_diameter,
    )
    radius = track_rect.height() / 2.0

    border_pen = QtGui.QPen(border_color)
    border_pen.setWidth(1)
    painter.setPen(border_pen)
    painter.setBrush(track_color)
    painter.drawRoundedRect(track_rect, radius, radius)
    painter.setBrush(thumb_color)
    painter.drawEllipse(thumb_rect)

    if text:
        text_rect = QtCore.QRectF(
            track_rect.right() + label_gap,
            rect.top(),
            max(0.0, rect.right() - track_rect.right() - label_gap),
            rect.height(),
        )
        painter.setPen(text_color)
        font = painter.font()
        font.setBold(bold_text)
        painter.setFont(font)
        painter.drawText(
            text_rect,
            int(
                QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
            ),
            text,
        )

    if focused:
        focus_pen = QtGui.QPen(palette.color(QtGui.QPalette.ColorRole.Highlight))
        focus_pen.setWidth(1)
        painter.setPen(focus_pen)
        painter.setBrush(QtCore.Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(
            track_rect.adjusted(
                -focus_margin,
                -focus_margin,
                focus_margin,
                focus_margin,
            ),
            radius + focus_margin,
            radius + focus_margin,
        )


def _replace_checkbox_with_toggle(
    checkbox: QtWidgets.QCheckBox,
) -> ToggleSwitch:
    toggle = ToggleSwitch(checkbox.text(), checkbox.parentWidget())
    toggle.setObjectName(checkbox.objectName())
    toggle.setChecked(checkbox.isChecked())
    toggle.setEnabled(checkbox.isEnabled())
    toggle.setToolTip(checkbox.toolTip())
    toggle.setStatusTip(checkbox.statusTip())
    toggle.setWhatsThis(checkbox.whatsThis())
    toggle.setAccessibleName(checkbox.accessibleName())
    toggle.setAccessibleDescription(checkbox.accessibleDescription())
    toggle.setSizePolicy(checkbox.sizePolicy())
    toggle.setMinimumSize(checkbox.minimumSize())
    toggle.setMaximumSize(checkbox.maximumSize())
    margins = checkbox.contentsMargins()
    toggle.setContentsMargins(
        max(toggle.contentsMargins().left(), margins.left()),
        max(toggle.contentsMargins().top(), margins.top()),
        max(toggle.contentsMargins().right(), margins.right()),
        max(toggle.contentsMargins().bottom(), margins.bottom()),
    )
    parent = checkbox.parentWidget()
    layout = parent.layout() if parent is not None else None
    if layout is not None:
        layout.replaceWidget(checkbox, toggle)
    checkbox.hide()
    checkbox.deleteLater()
    return toggle
