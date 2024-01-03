
from opensnitch.config import Config
from PyQt5 import QtCore, QtWidgets, QtGui

class InfoWindow(QtWidgets.QDialog):
    """Display a text on a small dialog.
    """
    def __init__(self, parent):
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.Tool)
        self.setContentsMargins(0, 0, 0, 0)

        self._cfg = Config.get()

        self.layout = QtWidgets.QVBoxLayout(self)
        self._textedit = QtWidgets.QTextEdit()
        # hide cursor
        self._textedit.setCursorWidth(0)
        self._textedit.setViewportMargins(QtCore.QMargins(0,0,0,0))
        self._textedit.setMinimumSize(300, 325)
        self._textedit.setReadOnly(True)
        self._textedit.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard)
        self._textedit.setAutoFillBackground(True)
        self._textedit.setStyleSheet("QLabel { background: yellow }")

        self.layout.addWidget(self._textedit)

        self._load_settings()

    def closeEvent(self, ev):
        self._save_settings()
        ev.accept()
        self.hide()

    def _load_settings(self):
        saved_geometry = self._cfg.getSettings(Config.INFOWIN_GEOMETRY)
        if saved_geometry is not None:
            self.restoreGeometry(saved_geometry)

    def _save_settings(self):
        self._cfg.setSettings(Config.INFOWIN_GEOMETRY, self.saveGeometry())

    def showText(self, text):
        self._load_settings()

        self._textedit.setText(text)
        #self.resize(self.tooltip_textedit.sizeHint())

        pos = QtGui.QCursor.pos()
        win_size = self.size()
        # center dialog on cursor, relative to the parent widget.
        x_off = (int(win_size.width()/2))
        y_off = (int(win_size.height()/2))
        point = QtCore.QPoint(
            pos.x()-x_off, pos.y()-y_off
        )
        self.move(point.x(), point.y())

        self.show()

    def showHtml(self, text):
        self._load_settings()

        self._textedit.setHtml(text)

        pos = QtGui.QCursor.pos()
        win_size = self.size()
        # center dialog on cursor, relative to the parent widget.
        x_off = (int(win_size.width()/2))
        y_off = (int(win_size.height()/2))
        point = QtCore.QPoint(
            pos.x()-x_off, pos.y()-y_off
        )
        self.move(point.x(), point.y())

        self.show()
