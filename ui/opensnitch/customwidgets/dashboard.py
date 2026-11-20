import datetime
import time
from PyQt6 import QtCore, QtWidgets, QtGui


class DashboardCard(QtWidgets.QFrame):
    """Stat card with embedded sparkline background, Grafana-style."""

    def __init__(self, title, color="#89b4fa", object_name="card", parent=None):
        super().__init__(parent)
        self.setObjectName(object_name)
        self.setMinimumHeight(60)
        self.setMaximumHeight(75)
        self.setMinimumWidth(100)

        self._title = title
        self._value = ""
        self._color = QtGui.QColor(color)
        self._data = []
        self._max_points = 60
        self._loading = True
        self._dirty = False
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

    def set_value(self, value, has_data=True):
        self._value = str(value)
        if self._loading and has_data:
            self._loading = False
            self._pulse_timer.stop()
        self._dirty = True

    def add_point(self, value):
        self._data.append(value)
        if len(self._data) > self._max_points:
            self._data = self._data[-self._max_points:]
        self._dirty = True

    def set_data(self, data):
        self._data = list(data[-self._max_points:])
        self._dirty = True

    def flush(self):
        if self._dirty:
            self._dirty = False
            self.update()

    def paintEvent(self, event):
        w, h = self.width(), self.height()
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        # card background
        bg = QtGui.QColor("#313244")
        border = QtGui.QColor("#45475a")
        p.setPen(QtGui.QPen(border, 1))
        p.setBrush(bg)
        p.drawRoundedRect(QtCore.QRectF(0.5, 0.5, w - 1, h - 1), 8, 8)

        # sparkline fill (behind text)
        if len(self._data) >= 2:
            max_val = max(self._data) if max(self._data) > 0 else 1
            spark_h = h * 0.55
            spark_top = h - spark_h
            margin_x = 8

            points = []
            step = (w - 2 * margin_x) / max(len(self._data) - 1, 1)
            for i, val in enumerate(self._data):
                x = margin_x + i * step
                y = h - 4 - (val / max_val) * (spark_h - 8)
                points.append(QtCore.QPointF(x, y))

            # gradient fill
            gradient = QtGui.QLinearGradient(0, spark_top, 0, h)
            fill_c = QtGui.QColor(self._color)
            fill_c.setAlpha(50)
            gradient.setColorAt(0, fill_c)
            fill_c.setAlpha(10)
            gradient.setColorAt(1, fill_c)

            fill_path = QtGui.QPainterPath()
            fill_path.moveTo(points[0].x(), h)
            for pt in points:
                fill_path.lineTo(pt)
            fill_path.lineTo(points[-1].x(), h)
            fill_path.closeSubpath()

            p.setPen(QtCore.Qt.PenStyle.NoPen)
            p.setBrush(QtGui.QBrush(gradient))
            p.setClipRect(QtCore.QRectF(0, 0, w, h))
            p.drawPath(fill_path)
            p.setClipping(False)

            # sparkline stroke
            line_c = QtGui.QColor(self._color)
            line_c.setAlpha(140)
            pen = QtGui.QPen(line_c, 1.5)
            pen.setCapStyle(QtCore.Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(QtCore.Qt.PenJoinStyle.RoundJoin)
            p.setPen(pen)
            for i in range(len(points) - 1):
                p.drawLine(points[i], points[i + 1])

        # title
        title_font = QtGui.QFont()
        title_font.setPointSize(8)
        title_font.setWeight(QtGui.QFont.Weight.DemiBold)
        p.setFont(title_font)
        p.setPen(QtGui.QColor("#a6adc8"))
        p.drawText(QtCore.QPointF(12, 18), self._title)

        if self._loading:
            base = QtGui.QColor("#45475a")
            hi = QtGui.QColor("#585b70")
            r = int(base.red() + (hi.red() - base.red()) * self._pulse_alpha)
            g = int(base.green() + (hi.green() - base.green()) * self._pulse_alpha)
            b = int(base.blue() + (hi.blue() - base.blue()) * self._pulse_alpha)
            p.setPen(QtCore.Qt.PenStyle.NoPen)
            p.setBrush(QtGui.QColor(r, g, b))
            p.drawRoundedRect(QtCore.QRectF(12, 30, 70, 14), 3, 3)
            p.end()
            return

        # value
        value_font = QtGui.QFont()
        value_font.setPointSize(16)
        value_font.setWeight(QtGui.QFont.Weight.Bold)
        p.setFont(value_font)
        p.setPen(self._color)
        p.drawText(QtCore.QPointF(12, 44), self._value)

        # timeframe hint
        hint_font = QtGui.QFont()
        hint_font.setPointSize(6)
        p.setFont(hint_font)
        p.setPen(QtGui.QColor("#585b70"))
        p.drawText(QtCore.QPointF(w - 40, h - 5), "60 min")

        p.end()


class DashboardWidget(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dashboardFrame")
        self.setStyleSheet(
            "QFrame#dashboardFrame {"
            "  background-color: #181825;"
            "  border: 1px solid #313244;"
            "  border-radius: 8px;"
            "  padding: 2px;"
            "}"
        )
        self.setMaximumHeight(80)
        self.setMinimumHeight(65)

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(6)

        self.card_connections = DashboardCard("CONNECTIONS", "#89b4fa", "cardConnections", parent=self)
        self.card_allowed = DashboardCard("ALLOWED", "#a6e3a1", "cardAllowed", parent=self)
        self.card_blocked = DashboardCard("BLOCKED", "#f38ba8", "cardBlocked", parent=self)
        self.card_bandwidth = DashboardCard("UPTIME", "#fab387", "cardBandwidth", parent=self)

        layout.addWidget(self.card_connections, 1)
        layout.addWidget(self.card_allowed, 1)
        layout.addWidget(self.card_blocked, 1)
        layout.addWidget(self.card_bandwidth, 1)

        self._max_buckets = 60
        self._buckets_conn = [0] * self._max_buckets
        self._buckets_allowed = [0] * self._max_buckets
        self._buckets_blocked = [0] * self._max_buckets
        self._bucket_minute = -1
        self._prev_conn = -1
        self._prev_allowed = -1
        self._prev_blocked = -1

        self._daemon_uptime = 0
        self._uptime_base_time = 0.0
        self._uptime_ticker = QtCore.QTimer(self)
        self._uptime_ticker.timeout.connect(self._tick_uptime)
        self._uptime_ticker.setInterval(1000)

    def _tick_uptime(self):
        elapsed = time.monotonic() - self._uptime_base_time
        total = int(self._daemon_uptime + elapsed)
        uptime_str = str(datetime.timedelta(seconds=total))
        self.card_bandwidth.set_value(uptime_str, True)
        self.card_bandwidth.flush()

    def update_stats(self, connections=0, dropped=0, uptime_seconds=0):
        has_data = connections > 0 or dropped > 0 or uptime_seconds > 0
        allowed = connections - dropped if connections >= dropped else 0
        self.card_connections.set_value(f"{connections:,}", has_data)
        self.card_allowed.set_value(f"{allowed:,}", has_data)
        self.card_blocked.set_value(f"{dropped:,}", has_data)

        if uptime_seconds > 0:
            self._daemon_uptime = uptime_seconds
            self._uptime_base_time = time.monotonic()
            if not self._uptime_ticker.isActive():
                self._uptime_ticker.start()
            uptime_str = str(datetime.timedelta(seconds=uptime_seconds))
            self.card_bandwidth.set_value(uptime_str, True)

        now_min = int(time.time()) // 60

        if self._prev_conn < 0:
            self._prev_conn = connections
            self._prev_allowed = allowed
            self._prev_blocked = dropped
            self._bucket_minute = now_min
            self._flush_cards()
            return

        delta_c = max(0, connections - self._prev_conn)
        delta_a = max(0, allowed - self._prev_allowed)
        delta_b = max(0, dropped - self._prev_blocked)

        if now_min != self._bucket_minute:
            self._buckets_conn.append(0)
            self._buckets_allowed.append(0)
            self._buckets_blocked.append(0)
            self._buckets_conn = self._buckets_conn[-self._max_buckets:]
            self._buckets_allowed = self._buckets_allowed[-self._max_buckets:]
            self._buckets_blocked = self._buckets_blocked[-self._max_buckets:]
            self._bucket_minute = now_min

        self._buckets_conn[-1] += delta_c
        self._buckets_allowed[-1] += delta_a
        self._buckets_blocked[-1] += delta_b

        self._prev_conn = connections
        self._prev_allowed = allowed
        self._prev_blocked = dropped

        self.card_connections.set_data(self._buckets_conn)
        self.card_allowed.set_data(self._buckets_allowed)
        self.card_blocked.set_data(self._buckets_blocked)
        self._flush_cards()

    def _flush_cards(self):
        self.card_connections.flush()
        self.card_allowed.flush()
        self.card_blocked.flush()
        self.card_bandwidth.flush()
