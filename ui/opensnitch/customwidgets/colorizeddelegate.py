from PyQt5 import Qt, QtCore
from PyQt5.QtWidgets import QApplication

# PyQt5 >= v5.15.8 (28/01/2023) (#821)
if hasattr(Qt, 'QItemDelegate'):
    from PyQt5.Qt import QItemDelegate, QStyleOptionViewItem
else:
    from PyQt5.QtWidgets import QItemDelegate, QStyleOptionViewItem

class ColorizedDelegate(QItemDelegate):
    HMARGIN = 0
    VMARGIN = 1

    def __init__(self, parent=None, *args, actions={}):
        QItemDelegate.__init__(self, parent, *args)
        self._actions = actions
        self.modelColumns = parent.model().columnCount()
        self._style = QApplication.style()

    def setConfig(self, actions):
        self._actions = actions

    #@profile_each_line
    def paint(self, painter, option, index):
        """Override default widget style to personalize it with our own.
        """
        if self._actions.get('actions') == None:
            return super().paint(painter, option, index)
        if not index.isValid():
            return super().paint(painter, option, index)
        cellValue = index.data(QtCore.Qt.DisplayRole)
        if cellValue == None:
            return super().paint(painter, option, index)

        # initialize new QStyleOptionViewItem with the default options of this
        # cell.
        option = QStyleOptionViewItem(option)

        # by default use item's default attributes.
        # if we modify any of them, set it to False
        nocolor=True

        # don't call these functions in for-loops
        cellRect = QtCore.QRect(option.rect)
        curColumn = index.column()
        curRow = index.row()
        cellAlignment = option.displayAlignment
        defaultPen = painter.pen()
        defaultBrush = painter.brush()

        self._style = QApplication.style()
        # get default margins in order to respect them.
        # option.widget is the QTableView
        hmargin = self._style.pixelMetric(
            self._style.PM_FocusFrameHMargin, None, option.widget
        ) + 1
        vmargin = self._style.pixelMetric(
            self._style.PM_FocusFrameVMargin, None, option.widget
        ) + 1

        # set default margins for this cell
        cellRect.adjust(hmargin, vmargin, -painter.pen().width(), -painter.pen().width())

        for a in self._actions['actions']:
            action = self._actions['actions'][a]
            modified = action.run(
                             (painter,
                              option,
                              index,
                              self._style,
                              self.modelColumns,
                              curRow,
                              curColumn,
                              defaultPen,
                              defaultBrush,
                              cellAlignment,
                              cellRect,
                              cellValue)
                             )
            if modified[0]:
                nocolor=False

        if nocolor:
            super().paint(painter, option, index)
