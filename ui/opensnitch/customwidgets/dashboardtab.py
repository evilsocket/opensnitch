import os
import datetime
from PyQt6 import QtCore, QtWidgets, QtGui
from PyQt6.QtSql import QSqlQuery


class _ChartColors:
    BG = QtGui.QColor("#1e1e2e")
    CARD_BG = QtGui.QColor("#313244")
    BORDER = QtGui.QColor("#45475a")
    TEXT = QtGui.QColor("#cdd6f4")
    TEXT_DIM = QtGui.QColor("#a6adc8")
    TEXT_MUTED = QtGui.QColor("#585b70")
    BLUE = QtGui.QColor("#89b4fa")
    GREEN = QtGui.QColor("#a6e3a1")
    RED = QtGui.QColor("#f38ba8")
    PEACH = QtGui.QColor("#fab387")
    MAUVE = QtGui.QColor("#cba6f7")
    TEAL = QtGui.QColor("#94e2d5")
    YELLOW = QtGui.QColor("#f9e2af")
    PINK = QtGui.QColor("#f5c2e7")
    SKY = QtGui.QColor("#89dceb")
    LAVENDER = QtGui.QColor("#b4befe")

    SERIES = [BLUE, GREEN, RED, PEACH, MAUVE, TEAL, YELLOW, PINK, SKY, LAVENDER]
    SKELETON = QtGui.QColor("#45475a")
    SKELETON_HI = QtGui.QColor("#585b70")


class _SkeletonMixin:
    """Pulsing skeleton loading state for chart widgets."""

    def _init_skeleton(self):
        self._loading = True
        self._pulse_alpha = 0.0
        self._pulse_dir = 1
        self._pulse_timer = QtCore.QTimer(self)
        self._pulse_timer.timeout.connect(self._pulse_tick)
        self._pulse_timer.setInterval(40)
        self._pulse_timer.start()

    def _pulse_tick(self):
        if not self._loading:
            return
        self._pulse_alpha += 0.04 * self._pulse_dir
        if self._pulse_alpha >= 1.0:
            self._pulse_alpha = 1.0
            self._pulse_dir = -1
        elif self._pulse_alpha <= 0.0:
            self._pulse_alpha = 0.0
            self._pulse_dir = 1
        self.update()

    def _stop_loading(self):
        if self._loading:
            self._loading = False
            self._pulse_timer.stop()

    def _draw_skeleton(self, p, w, h, rects):
        """Draw pulsing skeleton bars. rects is list of (x, y, w, h, radius)."""
        base = _ChartColors.SKELETON
        hi = _ChartColors.SKELETON_HI
        r = int(base.red() + (hi.red() - base.red()) * self._pulse_alpha)
        g = int(base.green() + (hi.green() - base.green()) * self._pulse_alpha)
        b = int(base.blue() + (hi.blue() - base.blue()) * self._pulse_alpha)
        color = QtGui.QColor(r, g, b)
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(color)
        for rect in rects:
            x, y, rw, rh, rad = rect
            p.drawRoundedRect(QtCore.QRectF(x, y, rw, rh), rad, rad)


class _BarChartWidget(_SkeletonMixin, QtWidgets.QWidget):
    """Horizontal bar chart for top-N items."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._items = []
        self._row_rects = []
        self._display_names = []
        self.setMinimumHeight(180)
        self.setMouseTracking(True)
        self._init_skeleton()

    def set_data(self, items):
        self._items = items[:8]
        self._stop_loading()
        self.update()

    def mouseMoveEvent(self, event):
        pos = event.position() if hasattr(event, 'position') else event.localPos()
        for i, rect in enumerate(self._row_rects):
            if rect.contains(pos):
                full_name = self._display_names[i] if i < len(self._display_names) else ""
                count = self._items[i][1] if i < len(self._items) else ""
                QtWidgets.QToolTip.showText(event.globalPosition().toPoint() if hasattr(event, 'globalPosition') else event.globalPos(),
                                            f"{full_name}  —  {count}")
                return
        QtWidgets.QToolTip.hideText()

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # title
        title_font = QtGui.QFont()
        title_font.setPointSize(10)
        title_font.setWeight(QtGui.QFont.Weight.Bold)
        p.setFont(title_font)
        p.setPen(_ChartColors.TEXT)
        p.drawText(QtCore.QPointF(12, 20), self._title)

        if not self._items:
            if self._loading:
                rects = []
                for i in range(5):
                    y = 36 + i * 26
                    rects.append((12, y, 80, 10, 3))
                    rects.append((100, y, w * (0.6 - i * 0.08), 10, 3))
                self._draw_skeleton(p, w, h, rects)
            p.end()
            return

        bar_top = 32
        bar_area_h = h - bar_top - 8
        max_val = max(item[1] for item in self._items) if self._items else 1
        bar_h = min(int(bar_area_h / len(self._items)) - 4, 22)

        body_font = QtGui.QFont()
        body_font.setPointSize(8)
        p.setFont(body_font)
        fm = QtGui.QFontMetrics(body_font)

        display_names = []
        for name, _count in self._items:
            dn = os.path.basename(name) if '/' in name else name
            display_names.append(dn)
        self._display_names = display_names
        self._row_rects = []
        max_label_px = max((fm.horizontalAdvance(n) for n in display_names), default=0) + 16
        label_w = min(max_label_px, w * 0.4)
        label_w = max(label_w, 80)
        val_margin = fm.horizontalAdvance("00000") + 12
        bar_w_max = w - label_w - val_margin

        for i, (name, count) in enumerate(self._items):
            y = bar_top + i * (bar_h + 4)
            self._row_rects.append(QtCore.QRectF(0, y, w, bar_h + 4))
            color = _ChartColors.SERIES[i % len(_ChartColors.SERIES)]

            # label — elide to fit
            p.setPen(_ChartColors.TEXT_DIM)
            display_name = display_names[i]
            avail = label_w - 24
            elided = fm.elidedText(display_name, QtCore.Qt.TextElideMode.ElideRight, int(avail))
            p.drawText(QtCore.QPointF(12, y + bar_h - 4), elided)

            # bar
            bw = (count / max_val) * bar_w_max if max_val > 0 else 0
            bar_rect = QtCore.QRectF(label_w, y + 2, bw, bar_h - 4)
            bar_color = QtGui.QColor(color)
            bar_color.setAlpha(180)
            p.setPen(QtCore.Qt.PenStyle.NoPen)
            p.setBrush(bar_color)
            p.drawRoundedRect(bar_rect, 3, 3)

            # value
            p.setPen(_ChartColors.TEXT_DIM)
            p.drawText(QtCore.QPointF(label_w + bw + 6, y + bar_h - 4), str(count))

        p.end()


class _ToggleSwitch(QtWidgets.QWidget):
    """Custom-painted toggle switch with sliding knob."""

    toggled = QtCore.pyqtSignal(bool)

    def __init__(self, left_text="24h", right_text="12h", parent=None):
        super().__init__(parent)
        self._on = False
        self._left = left_text
        self._right = right_text
        self._knob_x = 0.0
        self._anim = QtCore.QPropertyAnimation(self, b"knob_pos")
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QtCore.QEasingCurve.Type.InOutCubic)
        self.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        self._font = QtGui.QFont()
        self._font.setPointSize(8)
        fm = QtGui.QFontMetrics(self._font)
        tw = max(fm.horizontalAdvance(left_text), fm.horizontalAdvance(right_text))
        self.setFixedSize(tw * 2 + 36, 18)

    def _get_knob_pos(self):
        return self._knob_x

    def _set_knob_pos(self, val):
        self._knob_x = val
        self.update()

    knob_pos = QtCore.pyqtProperty(float, _get_knob_pos, _set_knob_pos)

    def isChecked(self):
        return self._on

    def mousePressEvent(self, event):
        self._on = not self._on
        self._anim.stop()
        self._anim.setStartValue(self._knob_x)
        self._anim.setEndValue(1.0 if self._on else 0.0)
        self._anim.start()
        self.toggled.emit(self._on)

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setFont(self._font)
        fm = QtGui.QFontMetrics(self._font)

        lw = fm.horizontalAdvance(self._left)
        rw = fm.horizontalAdvance(self._right)

        # left label
        p.setPen(_ChartColors.TEXT if not self._on else _ChartColors.TEXT_MUTED)
        p.drawText(QtCore.QPointF(0, h - 4), self._left)

        # track
        track_x = lw + 6
        track_w = w - lw - rw - 12
        track_h = 12
        track_y = (h - track_h) / 2
        track_r = track_h / 2

        if self._on:
            track_color = QtGui.QColor(137, 180, 250, 80)
        else:
            track_color = QtGui.QColor(255, 255, 255, 30)
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(track_color)
        p.drawRoundedRect(QtCore.QRectF(track_x, track_y, track_w, track_h), track_r, track_r)

        # knob
        knob_r = 4
        knob_min_x = track_x + knob_r + 2
        knob_max_x = track_x + track_w - knob_r - 2
        knob_cx = knob_min_x + self._knob_x * (knob_max_x - knob_min_x)
        knob_cy = h / 2

        if self._on:
            knob_color = QtGui.QColor("#89b4fa")
        else:
            knob_color = QtGui.QColor("#cdd6f4")
        p.setBrush(knob_color)
        p.drawEllipse(QtCore.QPointF(knob_cx, knob_cy), knob_r, knob_r)

        # right label
        p.setPen(_ChartColors.TEXT if self._on else _ChartColors.TEXT_MUTED)
        p.drawText(QtCore.QPointF(w - rw, h - 4), self._right)

        p.end()


class _TimelineWidget(_SkeletonMixin, QtWidgets.QWidget):
    """Area chart showing connections over time."""

    time_format_changed = QtCore.pyqtSignal()

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._allowed_data = []
        self._blocked_data = []
        self._labels = []
        self._has_data = []
        self._chart_left = 0
        self._chart_right = 0
        self._chart_top = 0
        self._chart_bottom = 0
        self._use_12h = False
        self.setMinimumHeight(160)
        self.setMouseTracking(True)
        self._init_skeleton()

        self._fmt_toggle = _ToggleSwitch("24h", "12h", self)
        self._fmt_toggle.toggled.connect(self._toggle_format)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fmt_toggle.move(self.width() - self._fmt_toggle.width() - 8, 2)

    def _toggle_format(self, checked):
        self._use_12h = checked
        self.time_format_changed.emit()

    def set_data(self, allowed, blocked, labels, has_data=None):
        self._allowed_data = allowed
        self._blocked_data = blocked
        self._labels = labels
        self._has_data = has_data if has_data else [True] * len(allowed)
        self._stop_loading()
        self.update()

    def mouseMoveEvent(self, event):
        pos = event.position() if hasattr(event, 'position') else event.localPos()
        n = len(self._allowed_data)
        cl, cr = self._chart_left, self._chart_right
        if n < 2 or cr <= cl or pos.x() < cl or pos.x() > cr or pos.y() < self._chart_top or pos.y() > self._chart_bottom:
            QtWidgets.QToolTip.hideText()
            return
        frac = (pos.x() - cl) / (cr - cl)
        idx = max(0, min(int(round(frac * (n - 1))), n - 1))
        parts = []
        if idx < len(self._labels):
            parts.append(self._labels[idx])
        if idx < len(self._has_data) and not self._has_data[idx]:
            parts.append("No data")
        else:
            if idx < len(self._allowed_data):
                parts.append(f"Allowed: {self._allowed_data[idx]}")
            if idx < len(self._blocked_data):
                parts.append(f"Blocked: {self._blocked_data[idx]}")
        gp = event.globalPosition().toPoint() if hasattr(event, 'globalPosition') else event.globalPos()
        QtWidgets.QToolTip.showText(gp, "\n".join(parts))

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # title
        title_font = QtGui.QFont()
        title_font.setPointSize(10)
        title_font.setWeight(QtGui.QFont.Weight.Bold)
        p.setFont(title_font)
        p.setPen(_ChartColors.TEXT)
        p.drawText(QtCore.QPointF(12, 20), self._title)

        if not self._allowed_data and not self._blocked_data:
            if self._loading:
                rects = [(12, h - 30, w - 24, 2, 1)]
                import random
                random.seed(42)
                for i in range(8):
                    x = 12 + i * ((w - 24) / 8)
                    bh = 20 + random.random() * (h * 0.5)
                    rects.append((x + 2, h - 30 - bh, (w - 24) / 8 - 4, bh, 2))
                self._draw_skeleton(p, w, h, rects)
            else:
                p.setPen(_ChartColors.TEXT_MUTED)
                body_font = QtGui.QFont()
                body_font.setPointSize(9)
                p.setFont(body_font)
                p.drawText(QtCore.QPointF(12, 50), "No connection data yet")
            p.end()
            return

        chart_left = 12
        chart_right = w - 12
        chart_top = 32
        chart_bottom = h - 24
        chart_w = chart_right - chart_left
        chart_h = chart_bottom - chart_top
        self._chart_left = chart_left
        self._chart_right = chart_right
        self._chart_top = chart_top
        self._chart_bottom = chart_bottom

        v_has_data = self._has_data if self._has_data else [True] * len(self._allowed_data)

        all_vals = self._allowed_data + self._blocked_data
        max_val = max(all_vals) if all_vals and max(all_vals) > 0 else 1

        # grid lines
        p.setPen(QtGui.QPen(QtGui.QColor(69, 71, 90, 40), 0.5))
        for frac in [0.25, 0.5, 0.75]:
            gy = chart_bottom - frac * chart_h
            p.drawLine(QtCore.QPointF(chart_left, gy), QtCore.QPointF(chart_right, gy))

        # axis label
        label_font = QtGui.QFont()
        label_font.setPointSize(7)
        p.setFont(label_font)
        p.setPen(_ChartColors.TEXT_MUTED)
        p.drawText(QtCore.QPointF(chart_left + 2, chart_top + 10), str(max_val))

        n = len(self._allowed_data)
        if n < 2:
            p.end()
            return

        step_px = chart_w / max(n - 1, 1)

        # no-data hatching (Grafana-style diagonal stripes)
        for i in range(n):
            if i < len(v_has_data) and not v_has_data[i]:
                x0 = chart_left + i * step_px - step_px * 0.5
                x1 = chart_left + i * step_px + step_px * 0.5
                x0 = max(x0, chart_left)
                x1 = min(x1, chart_right)
                p.save()
                p.setClipRect(QtCore.QRectF(x0, chart_top, x1 - x0, chart_h))
                stripe_color = QtGui.QColor(69, 71, 90, 25)
                pen = QtGui.QPen(stripe_color, 1)
                p.setPen(pen)
                gap = 6
                sx = int(x0) - int(chart_h)
                while sx < int(x1) + int(chart_h):
                    p.drawLine(QtCore.QPointF(sx, chart_bottom),
                               QtCore.QPointF(sx + chart_h, chart_top))
                    sx += gap
                p.restore()

        def make_points(data):
            pts = []
            for i, v in enumerate(data):
                x = chart_left + i * step_px
                y = chart_bottom - (v / max_val) * chart_h
                pts.append(QtCore.QPointF(x, y))
            return pts

        def draw_area(pts, color):
            if len(pts) < 2:
                return
            fill = QtGui.QPainterPath()
            fill.moveTo(pts[0].x(), chart_bottom)
            for pt in pts:
                fill.lineTo(pt)
            fill.lineTo(pts[-1].x(), chart_bottom)
            fill.closeSubpath()
            fc = QtGui.QColor(color)
            fc.setAlpha(40)
            p.fillPath(fill, fc)
            pen = QtGui.QPen(color, 1.5)
            p.setPen(pen)
            for i in range(len(pts) - 1):
                p.drawLine(pts[i], pts[i + 1])

        allowed_pts = make_points(self._allowed_data)
        blocked_pts = make_points(self._blocked_data)
        draw_area(allowed_pts, _ChartColors.GREEN)
        draw_area(blocked_pts, _ChartColors.RED)

        # time labels — space dynamically to avoid overlap
        p.setFont(label_font)
        p.setPen(_ChartColors.TEXT_MUTED)
        if self._labels:
            lbl_fm = QtGui.QFontMetrics(label_font)
            max_lbl_w = max((lbl_fm.horizontalAdvance(l) for l in self._labels), default=30) + 12
            max_visible = max(int(chart_w / max_lbl_w), 2)
            lbl_step_i = max(len(self._labels) // max_visible, 1)
            lbl_y = h - 4
            for i in range(0, len(self._labels), lbl_step_i):
                lx = chart_left + i * step_px
                lbl_text = self._labels[i]
                lbl_w = lbl_fm.horizontalAdvance(lbl_text)
                if lx + lbl_w > chart_right:
                    break
                p.drawText(QtCore.QPointF(lx, lbl_y), lbl_text)

        # legend — next to the title
        legend_y = 18
        legend_font = QtGui.QFont()
        legend_font.setPointSize(8)
        p.setFont(legend_font)
        fm = QtGui.QFontMetrics(legend_font)

        title_fm = QtGui.QFontMetrics(title_font)
        lx = 12 + title_fm.horizontalAdvance(self._title) + 20
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(_ChartColors.GREEN)
        p.drawEllipse(QtCore.QPointF(lx, legend_y - 3), 4, 4)
        p.setPen(_ChartColors.TEXT_DIM)
        p.drawText(QtCore.QPointF(lx + 8, legend_y), "Allowed")

        lx2 = lx + 8 + fm.horizontalAdvance("Allowed") + 16
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(_ChartColors.RED)
        p.drawEllipse(QtCore.QPointF(lx2, legend_y - 3), 4, 4)
        p.setPen(_ChartColors.TEXT_DIM)
        p.drawText(QtCore.QPointF(lx2 + 8, legend_y), "Blocked")

        p.end()


class _DonutWidget(_SkeletonMixin, QtWidgets.QWidget):
    """Donut/ring chart for allow vs block ratio."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._allowed = 0
        self._blocked = 0
        self._cx = 0
        self._cy = 0
        self._radius = 0
        self.setMinimumSize(140, 140)
        self.setMouseTracking(True)
        self._init_skeleton()

    def set_data(self, allowed, blocked):
        self._allowed = allowed
        self._blocked = blocked
        self._stop_loading()
        self.update()

    def mouseMoveEvent(self, event):
        pos = event.position() if hasattr(event, 'position') else event.localPos()
        total = self._allowed + self._blocked
        if total == 0 or self._radius == 0:
            QtWidgets.QToolTip.hideText()
            return
        dx = pos.x() - self._cx
        dy = pos.y() - self._cy
        dist = (dx * dx + dy * dy) ** 0.5
        inner_r = self._radius * 0.7
        if inner_r < dist < self._radius:
            import math
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0:
                angle += 360
            norm = (90 - angle) % 360
            allowed_deg = (self._allowed / total) * 360
            gp = event.globalPosition().toPoint() if hasattr(event, 'globalPosition') else event.globalPos()
            if norm <= allowed_deg:
                pct = int(self._allowed / total * 100)
                QtWidgets.QToolTip.showText(gp, f"Allowed: {self._allowed}  ({pct}%)")
            else:
                pct = int(self._blocked / total * 100)
                QtWidgets.QToolTip.showText(gp, f"Blocked: {self._blocked}  ({pct}%)")
        else:
            QtWidgets.QToolTip.hideText()

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        title_font = QtGui.QFont()
        title_font.setPointSize(10)
        title_font.setWeight(QtGui.QFont.Weight.Bold)
        p.setFont(title_font)
        p.setPen(_ChartColors.TEXT)
        p.drawText(QtCore.QPointF(12, 20), self._title)

        total = self._allowed + self._blocked
        if total == 0:
            if self._loading:
                cx, cy = w / 2, (h + 20) / 2
                r = min(w, h - 30) / 2 - 12
                base = _ChartColors.SKELETON
                hi = _ChartColors.SKELETON_HI
                rv = int(base.red() + (hi.red() - base.red()) * self._pulse_alpha)
                gv = int(base.green() + (hi.green() - base.green()) * self._pulse_alpha)
                bv = int(base.blue() + (hi.blue() - base.blue()) * self._pulse_alpha)
                color = QtGui.QColor(rv, gv, bv)
                pen = QtGui.QPen(color, r * 0.3)
                pen.setCapStyle(QtCore.Qt.PenCapStyle.FlatCap)
                p.setPen(pen)
                p.setBrush(QtCore.Qt.BrushStyle.NoBrush)
                p.drawEllipse(QtCore.QPointF(cx, cy), r - r * 0.15, r - r * 0.15)
            else:
                p.setPen(_ChartColors.TEXT_MUTED)
                body_font = QtGui.QFont()
                body_font.setPointSize(9)
                p.setFont(body_font)
                p.drawText(QtCore.QPointF(12, 50), "No data")
            p.end()
            return

        cx = w / 2
        cy = (h + 20) / 2
        radius = min(w, h - 30) / 2 - 12
        thickness = radius * 0.3
        self._cx = cx
        self._cy = cy
        self._radius = radius

        outer = QtCore.QRectF(cx - radius, cy - radius, radius * 2, radius * 2)
        inner_r = radius - thickness

        allowed_angle = int((self._allowed / total) * 360 * 16)
        blocked_angle = 360 * 16 - allowed_angle

        # allowed arc
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(_ChartColors.GREEN)
        p.drawPie(outer, 90 * 16, allowed_angle)

        # blocked arc
        p.setBrush(_ChartColors.RED)
        p.drawPie(outer, 90 * 16 + allowed_angle, blocked_angle)

        # inner circle to make donut
        p.setBrush(_ChartColors.BG)
        p.drawEllipse(QtCore.QPointF(cx, cy), inner_r, inner_r)

        # center text
        pct = int(self._allowed / total * 100) if total > 0 else 0
        center_font = QtGui.QFont()
        center_font.setPointSize(14)
        center_font.setWeight(QtGui.QFont.Weight.Bold)
        p.setFont(center_font)
        p.setPen(_ChartColors.GREEN)
        fm = QtGui.QFontMetrics(center_font)
        txt = f"{pct}%"
        p.drawText(QtCore.QPointF(cx - fm.horizontalAdvance(txt) / 2, cy + 5), txt)

        sub_font = QtGui.QFont()
        sub_font.setPointSize(7)
        p.setFont(sub_font)
        p.setPen(_ChartColors.TEXT_MUTED)
        fm2 = QtGui.QFontMetrics(sub_font)
        sub = "allowed"
        p.drawText(QtCore.QPointF(cx - fm2.horizontalAdvance(sub) / 2, cy + 18), sub)

        p.end()


class _ProtocolWidget(_SkeletonMixin, QtWidgets.QWidget):
    """Mini horizontal stacked bar for protocol breakdown."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._items = []
        self.setMinimumHeight(100)
        self._init_skeleton()

    def set_data(self, items):
        self._items = items[:6]
        self._stop_loading()
        self.update()

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        title_font = QtGui.QFont()
        title_font.setPointSize(10)
        title_font.setWeight(QtGui.QFont.Weight.Bold)
        p.setFont(title_font)
        p.setPen(_ChartColors.TEXT)
        p.drawText(QtCore.QPointF(12, 20), self._title)

        if not self._items:
            if self._loading:
                self._draw_skeleton(p, w, h, [
                    (12, 34, w - 24, 16, 4),
                    (12, 60, 50, 10, 3),
                    (80, 60, 50, 10, 3),
                    (148, 60, 50, 10, 3),
                ])
                p.end()
                return
            p.end()
            return

        total = sum(c for _, c in self._items)
        if total == 0:
            p.end()
            return

        bar_y = 34
        bar_h = 16
        bar_left = 12
        bar_w = w - 24
        x = bar_left

        p.setPen(QtCore.Qt.PenStyle.NoPen)
        for i, (name, count) in enumerate(self._items):
            seg_w = (count / total) * bar_w
            color = _ChartColors.SERIES[i % len(_ChartColors.SERIES)]
            p.setBrush(color)
            if i == 0:
                p.drawRoundedRect(QtCore.QRectF(x, bar_y, seg_w, bar_h), 4, 4)
            elif i == len(self._items) - 1:
                p.drawRoundedRect(QtCore.QRectF(x, bar_y, seg_w, bar_h), 4, 4)
            else:
                p.drawRect(QtCore.QRectF(x, bar_y, seg_w, bar_h))
            x += seg_w

        # legend
        legend_font = QtGui.QFont()
        legend_font.setPointSize(8)
        p.setFont(legend_font)
        lx = 12
        ly = bar_y + bar_h + 18
        for i, (name, count) in enumerate(self._items):
            color = _ChartColors.SERIES[i % len(_ChartColors.SERIES)]
            p.setPen(QtCore.Qt.PenStyle.NoPen)
            p.setBrush(color)
            p.drawRoundedRect(QtCore.QRectF(lx, ly - 8, 10, 10), 2, 2)
            p.setPen(_ChartColors.TEXT_DIM)
            label = f"{name} ({count})"
            p.drawText(QtCore.QPointF(lx + 14, ly), label)
            fm = QtGui.QFontMetrics(legend_font)
            lx += fm.horizontalAdvance(label) + 22
            if lx > w - 50:
                lx = 12
                ly += 16

        p.end()


class DashboardTab(QtWidgets.QWidget):
    """Full dashboard tab with charts — queries the connections DB."""

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self.setObjectName("dashboardTab")

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # top row: timeline + donut
        top = QtWidgets.QHBoxLayout()
        self._timeline = _TimelineWidget("Connection Activity")
        self._timeline.time_format_changed.connect(self._update_timeline)
        self._donut = _DonutWidget("Allow / Block")
        self._donut.setMaximumWidth(220)
        top.addWidget(self._timeline, 3)
        top.addWidget(self._donut, 1)
        layout.addLayout(top, 2)

        # middle row: top apps + top destinations
        mid = QtWidgets.QHBoxLayout()
        self._top_apps = _BarChartWidget("Top Applications")
        self._top_dests = _BarChartWidget("Top Destinations")
        mid.addWidget(self._top_apps, 1)
        mid.addWidget(self._top_dests, 1)
        layout.addLayout(mid, 2)

        # bottom row: protocols + ports
        bot = QtWidgets.QHBoxLayout()
        self._protocols = _ProtocolWidget("Protocols")
        self._top_ports = _BarChartWidget("Top Ports")
        bot.addWidget(self._protocols, 1)
        bot.addWidget(self._top_ports, 1)
        layout.addLayout(bot, 1)

        self._refresh_timer = QtCore.QTimer(self)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.setInterval(10000)

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh()
        self._refresh_timer.start()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._refresh_timer.stop()

    def refresh(self):
        if self._db is None or not self._db.isOpen():
            return
        self._update_timeline()
        self._update_donut()
        self._update_top_apps()
        self._update_top_dests()
        self._update_protocols()
        self._update_top_ports()

    def _query(self, sql):
        q = QSqlQuery(self._db)
        q.exec(sql)
        rows = []
        while q.next():
            row = []
            for i in range(q.record().count()):
                row.append(q.value(i))
            rows.append(row)
        return rows

    def _update_timeline(self):
        cutoff = (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H")
        rows = self._query(
            "SELECT substr(time, 1, 13) as hour, action, COUNT(*) "
            "FROM connections WHERE time >= '{}' GROUP BY hour, action ORDER BY hour".format(cutoff)
        )
        hours = {}
        for hour, action, count in rows:
            if hour not in hours:
                hours[hour] = {'allowed': 0, 'blocked': 0}
            if action and action.lower() in ('deny', 'drop', 'reject'):
                hours[hour]['blocked'] += count
            else:
                hours[hour]['allowed'] += count

        now = datetime.datetime.now().replace(minute=0, second=0, microsecond=0)
        all_hours = []
        for i in range(23, -1, -1):
            all_hours.append(now - datetime.timedelta(hours=i))

        use_12h = self._timeline._use_12h
        allowed = []
        blocked = []
        formatted = []
        has_data = []
        for dt in all_hours:
            key_space = dt.strftime("%Y-%m-%d %H")
            key_t = dt.strftime("%Y-%m-%dT%H")
            data = hours.get(key_space) or hours.get(key_t)
            if data:
                allowed.append(data['allowed'])
                blocked.append(data['blocked'])
                has_data.append(True)
            else:
                allowed.append(0)
                blocked.append(0)
                has_data.append(False)
            if use_12h:
                formatted.append(dt.strftime("%-I:%M %p"))
            else:
                formatted.append(dt.strftime("%H:%M"))
        self._timeline.set_data(allowed, blocked, formatted, has_data)

        total_a = sum(allowed)
        total_b = sum(blocked)
        self._donut.set_data(total_a, total_b)

    def _update_donut(self):
        pass

    def _update_top_apps(self):
        rows = self._query(
            "SELECT process, COUNT(*) as cnt FROM connections "
            "GROUP BY process ORDER BY cnt DESC LIMIT 8"
        )
        self._top_apps.set_data([(r[0] or "unknown", r[1]) for r in rows])

    def _update_top_dests(self):
        rows = self._query(
            "SELECT COALESCE(NULLIF(dst_host,''), dst_ip) as dest, COUNT(*) as cnt "
            "FROM connections GROUP BY dest ORDER BY cnt DESC LIMIT 8"
        )
        self._top_dests.set_data([(r[0] or "unknown", r[1]) for r in rows])

    def _update_protocols(self):
        rows = self._query(
            "SELECT protocol, COUNT(*) as cnt FROM connections "
            "GROUP BY protocol ORDER BY cnt DESC LIMIT 6"
        )
        self._protocols.set_data([(r[0] or "other", r[1]) for r in rows])

    def _update_top_ports(self):
        rows = self._query(
            "SELECT dst_port, COUNT(*) as cnt FROM connections "
            "GROUP BY dst_port ORDER BY cnt DESC LIMIT 8"
        )
        port_names = {'443': '443 HTTPS', '80': '80 HTTP', '53': '53 DNS',
                      '22': '22 SSH', '993': '993 IMAPS', '587': '587 SMTP',
                      '8443': '8443 HTTPS', '5222': '5222 XMPP'}
        items = [(port_names.get(str(r[0]), str(r[0])), r[1]) for r in rows]
        self._top_ports.set_data(items)
