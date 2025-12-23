#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.import sys

from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QSizePolicy,
    QVBoxLayout
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt

class IconTextItem(QWidget):
    """builds a widget with an icon and a  label below the icon, vertically aligned."""
    def __init__(self, icon: QIcon, text: str, parent=None, size=24):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 5, 0, 5)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(size, size))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)

        text_label = QLabel(text)
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text_label.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)

        layout.addWidget(icon_label)
        layout.addWidget(text_label)
