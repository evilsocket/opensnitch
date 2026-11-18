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


class _BarChartWidget(QtWidgets.QWidget):
    """Horizontal bar chart for top-N items."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._items = []
        self.setMinimumHeight(180)

    def set_data(self, items):
        self._items = items[:8]
        self.update()

    def paintEvent(self, event):
        if not self._items:
            return
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

        bar_top = 32
        bar_area_h = h - bar_top - 8
        max_val = max(item[1] for item in self._items) if self._items else 1
        bar_h = min(int(bar_area_h / len(self._items)) - 4, 22)
        label_w = min(w * 0.3, 140)
        bar_w_max = w - label_w - 70

        body_font = QtGui.QFont()
        body_font.setPointSize(8)
        p.setFont(body_font)
        fm = QtGui.QFontMetrics(body_font)

        for i, (name, count) in enumerate(self._items):
            y = bar_top + i * (bar_h + 4)
            color = _ChartColors.SERIES[i % len(_ChartColors.SERIES)]

            # label
            p.setPen(_ChartColors.TEXT_DIM)
            display_name = os.path.basename(name) if '/' in name else name
            if fm.horizontalAdvance(display_name) > label_w - 8:
                while fm.horizontalAdvance(display_name + "...") > label_w - 8 and len(display_name) > 3:
                    display_name = display_name[:-1]
                display_name += "..."
            p.drawText(QtCore.QPointF(12, y + bar_h - 4), display_name)

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


class _TimelineWidget(QtWidgets.QWidget):
    """Area chart showing connections over time."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._allowed_data = []
        self._blocked_data = []
        self._labels = []
        self.setMinimumHeight(160)

    def set_data(self, allowed, blocked, labels):
        self._allowed_data = allowed
        self._blocked_data = blocked
        self._labels = labels
        self.update()

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
        p.drawText(QtCore.QPointF(chart_right - 30, chart_top + 10), str(max_val))

        n = max(len(self._allowed_data), len(self._blocked_data))
        if n < 2:
            p.end()
            return

        def make_points(data):
            pts = []
            step = chart_w / max(len(data) - 1, 1)
            for i, v in enumerate(data):
                x = chart_left + i * step
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

        # time labels
        p.setFont(label_font)
        p.setPen(_ChartColors.TEXT_MUTED)
        if self._labels:
            step = max(len(self._labels) // 6, 1)
            lbl_step = chart_w / max(len(self._labels) - 1, 1)
            for i in range(0, len(self._labels), step):
                lx = chart_left + i * lbl_step
                p.drawText(QtCore.QPointF(lx, h - 4), self._labels[i])

        # legend
        legend_y = 18
        legend_font = QtGui.QFont()
        legend_font.setPointSize(8)
        p.setFont(legend_font)
        fm = QtGui.QFontMetrics(legend_font)

        lx = w - 160
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(_ChartColors.GREEN)
        p.drawEllipse(QtCore.QPointF(lx, legend_y - 3), 4, 4)
        p.setPen(_ChartColors.TEXT_DIM)
        p.drawText(QtCore.QPointF(lx + 8, legend_y), "Allowed")

        lx2 = lx + fm.horizontalAdvance("Allowed") + 20
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(_ChartColors.RED)
        p.drawEllipse(QtCore.QPointF(lx2, legend_y - 3), 4, 4)
        p.setPen(_ChartColors.TEXT_DIM)
        p.drawText(QtCore.QPointF(lx2 + 8, legend_y), "Blocked")

        p.end()


class _DonutWidget(QtWidgets.QWidget):
    """Donut/ring chart for allow vs block ratio."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._allowed = 0
        self._blocked = 0
        self.setMinimumSize(140, 140)

    def set_data(self, allowed, blocked):
        self._allowed = allowed
        self._blocked = blocked
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

        total = self._allowed + self._blocked
        if total == 0:
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


class _ProtocolWidget(QtWidgets.QWidget):
    """Mini horizontal stacked bar for protocol breakdown."""

    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self._title = title
        self._items = []
        self.setMinimumHeight(100)

    def set_data(self, items):
        self._items = items[:6]
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
        self._refresh_timer.setInterval(5000)

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
        rows = self._query(
            "SELECT substr(time, 1, 13) as hour, action, COUNT(*) "
            "FROM connections GROUP BY hour, action ORDER BY hour"
        )
        hours = {}
        for hour, action, count in rows:
            if hour not in hours:
                hours[hour] = {'allowed': 0, 'blocked': 0}
            if action and action.lower() in ('deny', 'drop', 'reject'):
                hours[hour]['blocked'] += count
            else:
                hours[hour]['allowed'] += count

        sorted_hours = sorted(hours.keys())[-24:]
        allowed = [hours[h]['allowed'] for h in sorted_hours]
        blocked = [hours[h]['blocked'] for h in sorted_hours]
        labels = [h[-5:] if len(h) >= 5 else h for h in sorted_hours]
        self._timeline.set_data(allowed, blocked, labels)

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
        port_names = {'443': 'HTTPS (443)', '80': 'HTTP (80)', '53': 'DNS (53)',
                      '22': 'SSH (22)', '993': 'IMAPS (993)', '587': 'SMTP (587)',
                      '8443': 'Alt-HTTPS (8443)', '5222': 'XMPP (5222)'}
        items = [(port_names.get(str(r[0]), str(r[0])), r[1]) for r in rows]
        self._top_ports.set_data(items)
