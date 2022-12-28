
from PyQt5.QtSql import QSqlQuery

from opensnitch.utils import AsnDB
from opensnitch.customwidgets.generictableview import GenericTableModel
from PyQt5.QtCore import QCoreApplication as QC

class AddressTableModel(GenericTableModel):

    def __init__(self, tableName, headerLabels):
        super().__init__(tableName, headerLabels)
        self.asndb = AsnDB.instance()
        self.reconfigureColumns()

    def reconfigureColumns(self):
        self.headerLabels = []
        self.setHorizontalHeaderLabels(self.headerLabels)
        self.headerLabels.append(QC.translate("stats", "What", ""))
        self.headerLabels.append(QC.translate("stats", "Hits", ""))
        self.headerLabels.append(QC.translate("stats", "Network name", ""))
        self.setHorizontalHeaderLabels(self.headerLabels)
        self.setColumnCount(len(self.headerLabels))
        self.lastColumnCount = len(self.headerLabels)

    def setQuery(self, q, db):
        self.origQueryStr = q
        self.db = db

        if self.prevQueryStr != self.origQueryStr:
            self.realQuery = QSqlQuery(q, db)

        self.realQuery.exec_()
        self.realQuery.last()

        queryRows = max(0, self.realQuery.at()+1)
        self.totalRowCount = queryRows
        self.setRowCount(self.totalRowCount)

        queryColumns = self.realQuery.record().count()
        if self.asndb.is_available() and queryColumns < 3:
            self.reconfigureColumns()
        else:
            # update view's columns
            if queryColumns != self.lastColumnCount:
                self.setModelColumns(queryColumns)

        self.prevQueryStr = self.origQueryStr
        self.rowCountChanged.emit()

    def fillVisibleRows(self, q, upperBound, force=False):
        super().fillVisibleRows(q, upperBound, force)

        if self.asndb.is_available() == True and self.columnCount() <= 3:
            for n, col in enumerate(self.items):
                try:
                    if len(col) < 2:
                        continue
                    col[2] = self.asndb.get_asn(col[0])
                except:
                    col[2] = ""
                finally:
                    self.items[n] = col
            self.lastItems = self.items
