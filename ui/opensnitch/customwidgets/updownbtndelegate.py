from PyQt5 import Qt, QtCore
from PyQt5.QtGui import QRegion
from PyQt5.QtWidgets import QItemDelegate, QAbstractItemView, QPushButton, QWidget, QVBoxLayout, QSizePolicy
from PyQt5.QtCore import pyqtSignal

class UpDownButtonDelegate(QItemDelegate):
    clicked = pyqtSignal(int, QtCore.QModelIndex)

    UP=-1
    DOWN=1

    def paint(self, painter, option, index):
        if (
            isinstance(self.parent(), QAbstractItemView)
            and self.parent().model() is index.model()
        ):
            self.parent().openPersistentEditor(index)

    def createEditor(self, parent, option, index):
        w = QWidget(parent)
        w.setContentsMargins(0, 0, 0, 0)
        w.setAutoFillBackground(True)

        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)

        btnUp = QPushButton(parent)
        btnUp.setText("⇡")
        btnUp.setFlat(True)
        btnUp.clicked.connect(lambda: self._cb_button_clicked(self.UP, index))

        btnDown = QPushButton(parent)
        btnDown.setText("⇣")
        btnDown.setFlat(True)
        btnDown.clicked.connect(lambda: self._cb_button_clicked(self.DOWN, index))

        layout.addWidget(btnUp)
        layout.addWidget(btnDown)
        return w

    def _cb_button_clicked(self, action, idx):
        self.clicked.emit(action, idx)

    def updateEditorGeometry(self, editor, option, index):
        rect = QtCore.QRect(option.rect)
        minWidth = editor.minimumSizeHint().width()
        if rect.width() < minWidth:
            rect.setWidth(minWidth)
        editor.setGeometry(rect)
        # create a new mask based on the option rectangle, then apply it
        mask = QRegion(0, 0, option.rect.width(), option.rect.height())
        editor.setProperty('offMask', mask)
        editor.setMask(mask)
