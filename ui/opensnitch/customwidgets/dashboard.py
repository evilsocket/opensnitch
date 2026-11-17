import os
from PyQt6 import QtCore, QtWidgets, QtGui


class DashboardCard(QtWidgets.QFrame):
    def __init__(self, title, color="#89b4fa", object_name="card", parent=None):
        super().__init__(parent)
        self.setObjectName(object_name)
        self.setMinimumHeight(50)
        self.setMaximumHeight(70)
        self.setMinimumWidth(80)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(1)

        self._title_label = QtWidgets.QLabel(title)
        self._title_label.setObjectName("cardTitle")
        self._title_label.setStyleSheet(
            "font-size: 10px; font-weight: 600; color: #a6adc8; "
            "text-transform: uppercase; background: transparent;"
        )
        layout.addWidget(self._title_label)

        self._value_label = QtWidgets.QLabel("0")
        self._value_label.setObjectName("cardValue")
        self._value_label.setStyleSheet(
            f"font-size: 18px; font-weight: 700; color: {color}; background: transparent;"
        )
        layout.addWidget(self._value_label)

        self.setStyleSheet(
            f"QFrame#{object_name} {{"
            "  background-color: #313244;"
            "  border: 1px solid #45475a;"
            "  border-radius: 8px;"
            "}"
        )

    def set_value(self, value):
        self._value_label.setText(str(value))


class SparklineWidget(QtWidgets.QWidget):
    def __init__(self, color="#89b4fa", max_points=60, parent=None):
        super().__init__(parent)
        self._color = QtGui.QColor(color)
        self._max_points = max_points
        self._data = []
        self.setMinimumHeight(30)
        self.setMaximumHeight(30)
        self.setMinimumWidth(40)

    def add_point(self, value):
        self._data.append(value)
        if len(self._data) > self._max_points:
            self._data = self._data[-self._max_points:]
        try:
            self.update()
        except RuntimeError:
            pass

    def set_data(self, data):
        self._data = list(data[-self._max_points:])
        try:
            self.update()
        except RuntimeError:
            pass

    def paintEvent(self, event):
        if len(self._data) < 2:
            return

        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        margin = 2

        max_val = max(self._data) if max(self._data) > 0 else 1
        min_val = 0

        points = []
        step = (w - 2 * margin) / max(len(self._data) - 1, 1)
        for i, val in enumerate(self._data):
            x = margin + i * step
            y = h - margin - ((val - min_val) / (max_val - min_val)) * (h - 2 * margin)
            points.append(QtCore.QPointF(x, y))

        gradient = QtGui.QLinearGradient(0, 0, 0, h)
        fill_color = QtGui.QColor(self._color)
        fill_color.setAlpha(60)
        gradient.setColorAt(0, fill_color)
        fill_color.setAlpha(0)
        gradient.setColorAt(1, fill_color)

        fill_path = QtGui.QPainterPath()
        fill_path.moveTo(points[0].x(), h)
        for p in points:
            fill_path.lineTo(p)
        fill_path.lineTo(points[-1].x(), h)
        fill_path.closeSubpath()
        painter.fillPath(fill_path, QtGui.QBrush(gradient))

        pen = QtGui.QPen(self._color, 1.5)
        pen.setCapStyle(QtCore.Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(QtCore.Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        for i in range(len(points) - 1):
            painter.drawLine(points[i], points[i + 1])

        painter.end()


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
        self.setMinimumHeight(60)

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(6)

        self.card_connections = DashboardCard("CONNECTIONS", "#89b4fa", "cardConnections", parent=self)
        self.card_allowed = DashboardCard("ALLOWED", "#a6e3a1", "cardAllowed", parent=self)
        self.card_blocked = DashboardCard("BLOCKED", "#f38ba8", "cardBlocked", parent=self)
        self.card_bandwidth = DashboardCard("UPTIME", "#fab387", "cardBandwidth", parent=self)

        self.sparkline_conn = SparklineWidget("#89b4fa", parent=self)
        self.sparkline_allowed = SparklineWidget("#a6e3a1", parent=self)
        self.sparkline_blocked = SparklineWidget("#f38ba8", parent=self)

        layout.addWidget(self.card_connections, 1)
        layout.addWidget(self.sparkline_conn, 0)
        layout.addWidget(self.card_allowed, 1)
        layout.addWidget(self.sparkline_allowed, 0)
        layout.addWidget(self.card_blocked, 1)
        layout.addWidget(self.sparkline_blocked, 0)
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

        self.sparkline_conn.set_data(self._connections_history)
        self.sparkline_allowed.set_data(self._allowed_history)
        self.sparkline_blocked.set_data(self._blocked_history)
