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
        self._value = "0"
        self._color = QtGui.QColor(color)
        self._data = []
        self._max_points = 60

    def set_value(self, value):
        self._value = str(value)
        self.update()

    def add_point(self, value):
        self._data.append(value)
        if len(self._data) > self._max_points:
            self._data = self._data[-self._max_points:]
        self.update()

    def set_data(self, data):
        self._data = list(data[-self._max_points:])
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

        # value
        value_font = QtGui.QFont()
        value_font.setPointSize(16)
        value_font.setWeight(QtGui.QFont.Weight.Bold)
        p.setFont(value_font)
        p.setPen(self._color)
        p.drawText(QtCore.QPointF(12, 44), self._value)

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

        self._connections_history = []
        self._allowed_history = []
        self._blocked_history = []

    def update_stats(self, connections=0, dropped=0, uptime=""):
        allowed = connections - dropped if connections >= dropped else 0
        self.card_connections.set_value(f"{connections:,}")
        self.card_allowed.set_value(f"{allowed:,}")
        self.card_blocked.set_value(f"{dropped:,}")
        self.card_bandwidth.set_value(uptime)

        self._connections_history.append(connections)
        self._allowed_history.append(allowed)
        self._blocked_history.append(dropped)

        self.card_connections.set_data(self._connections_history)
        self.card_allowed.set_data(self._allowed_history)
        self.card_blocked.set_data(self._blocked_history)
