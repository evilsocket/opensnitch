from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel
from opensnitch.customwidgets.generictableview import GenericTableModel
from opensnitch.utils import sockets

class NetstatTableModel(GenericTableModel):

    def __init__(self, tableName, headerLabels):
        super().__init__(tableName, headerLabels)

        self.COL_STATE = 1
        self.COL_PROTO = 6
        self.COL_FAMILY = 8

    def data(self, index, role=Qt.DisplayRole):
        """Paint rows with the data stored in self.items"""
        if role == Qt.DisplayRole or role == Qt.EditRole:
            items_count = len(self.items)
            if index.isValid() and items_count > 0 and index.row() < items_count:
                try:
                    # FIXME: protocol UDP + state CLOSE == state LISTEN
                    if index.column() == self.COL_STATE:
                        return sockets.State[self.items[index.row()][index.column()]]
                    elif index.column() == self.COL_PROTO:
                        return sockets.Proto[self.items[index.row()][index.column()]]
                    elif index.column() == self.COL_FAMILY:
                        return sockets.Family[self.items[index.row()][index.column()]]
                    return self.items[index.row()][index.column()]
                except Exception as e:
                    print("[socketsmodel] exception:", e, index.row(), index.column())
        return QStandardItemModel.data(self, index, role)
