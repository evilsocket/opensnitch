
from PyQt6.QtSql import QSqlQuery

from opensnitch.utils import AsnDB
from opensnitch.customwidgets.generictableview import GenericTableModel
from PyQt6.QtCore import QCoreApplication as QC

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

    def lastQuery(self):
        return self.origQueryStr

    def update_col_count(self):
        queryColumns = self.realQuery.record().count()
        if self.asndb.is_available() and queryColumns < 3:
            self.reconfigureColumns()
        else:
            # update view's columns
            if queryColumns != self.lastColumnCount:
                self.setModelColumns(queryColumns)

    def setQuery(self, q, db, binds=None):
        self.origQueryStr = q
        self.db = db

        if self.prevQueryStr != self.origQueryStr:
            self.realQuery = QSqlQuery(q, db)

        if binds is not None:
            self.realQuery.prepare(self.origQueryStr)
            for idx, v in binds:
                self.realQuery.bindValue(idx, v)

        self.realQuery.exec()
        self.realQuery.last()

        self.update_row_count()
        self.update_col_count()

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
