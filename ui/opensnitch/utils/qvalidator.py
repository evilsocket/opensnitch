
from PyQt5 import QtCore, QtGui

class RestrictChars(QtGui.QValidator):
    result = QtCore.pyqtSignal(object)

    def __init__(self, restricted_chars, *args, **kwargs):
        QtGui.QValidator.__init__(self, *args, **kwargs)
        self._restricted_chars = restricted_chars

    def validate(self, value, pos):
        # allow to delete all characters
        if len(value) == 0:
            return QtGui.QValidator.Intermediate, value, pos

        # user can type characters or paste them.
        # pos value when pasting can be any number, depending on where did the
        # user paste the characters.
        for char in self._restricted_chars:
            if char in value:
                self.result.emit(QtGui.QValidator.Invalid)
                return QtGui.QValidator.Invalid, value, pos

        self.result.emit(QtGui.QValidator.Acceptable)
        return QtGui.QValidator.Acceptable, value, pos
