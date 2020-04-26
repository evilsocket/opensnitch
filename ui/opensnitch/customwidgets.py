from PyQt5 import Qt, QtCore
from PyQt5.QtGui import QColor, QPen, QBrush
from PyQt5.QtSql import QSqlDatabase, QSqlQueryModel

class ColorizedDelegate(Qt.QItemDelegate):
    def __init__(self, parent=None, *args, config=None):
        Qt.QItemDelegate.__init__(self, parent, *args)
        self._config = config
        self._alignment = QtCore.Qt.AlignLeft | QtCore.Qt.AlignHCenter

    def paint(self, painter, option, index):
        if not index.isValid():
            return super().paint(painter, option, index)
        
        nocolor=True

        value = index.data(QtCore.Qt.DisplayRole)
        for _, what in enumerate(self._config):
            if what == value:
                nocolor=False
                painter.save()
                painter.setPen(self._config[what])
                if 'alignment' in self._config:
                    self._alignment = self._config['alignment']

                if option.state & Qt.QStyle.State_Selected:
                    painter.setBrush(painter.brush())
                    painter.setPen(painter.pen())
                painter.drawText(option.rect, self._alignment, value)
                painter.restore()

        if nocolor == True:
            super().paint(painter, option, index)

class ColorizedQSqlQueryModel(QSqlQueryModel):
    """
        model=CustomQSqlQueryModel(
            modelData=
                {
                'colorize': 
                      {'offline': (QColor(QtCore.Qt.red), 2)},
                'alignment': { Qt.AlignLeft, 2 }
                }
            )
    """
    RED   = QColor(QtCore.Qt.red)
    GREEN = QColor(QtCore.Qt.green)

    def __init__(self, modelData={}):
        QSqlQueryModel.__init__(self)
        self._model_data = modelData

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return QSqlQueryModel.data(self, index, role)

        column = index.column()
        row = index.row()

        if role == QtCore.Qt.TextAlignmentRole:
            return QtCore.Qt.AlignCenter
        if role == QtCore.Qt.TextColorRole:
            for _, what in enumerate(self._model_data):
                d = QSqlQueryModel.data(self, self.index(row, self._model_data[what][1]), QtCore.Qt.DisplayRole)
                if column == self._model_data[what][1] and what in d:
                    return self._model_data[what][0]

        return QSqlQueryModel.data(self, index, role)
