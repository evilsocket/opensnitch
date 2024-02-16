
from PyQt5 import QtCore
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtSql import QSqlQuery, QSqlError
from PyQt5.QtWidgets import QTableView, QAbstractSlider, QItemDelegate, QAbstractItemView, QPushButton, QWidget, QVBoxLayout
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.nodes import Nodes
from opensnitch.firewall import Firewall
from opensnitch.customwidgets.updownbtndelegate import UpDownButtonDelegate

class FirewallTableModel(QStandardItemModel):
    rowCountChanged = pyqtSignal()
    columnCountChanged = pyqtSignal(int)
    rowsUpdated = pyqtSignal(int, tuple)
    rowsReordered = pyqtSignal(int, str, str, int, int) # filter, addr, key, old_pos, new_pos

    tableName = ""
    # total row count which must de displayed in the view
    totalRowCount = 0
    # last column count to compare against with
    lastColumnCount = 0

    FILTER_ALL = 0
    FILTER_BY_NODE = 1
    FILTER_BY_TABLE = 2
    FILTER_BY_CHAIN = 3
    FILTER_BY_QUERY = 4
    activeFilter = FILTER_ALL

    UP_BTN = -1
    DOWN_BTN = 1

    COL_BTNS = 0
    COL_UUID = 1
    COL_ADDR = 2
    COL_CHAIN_NAME = 3
    COL_CHAIN_TABLE = 4
    COL_CHAIN_FAMILY = 5
    COL_CHAIN_HOOK = 6
    COL_ENABLED = 7
    COL_DESCRIPTION = 8
    COL_PARMS = 9
    COL_ACTION = 10
    COL_ACTION_PARMS = 11

    headersAll = [
        "", # buttons
        "", # uuid
        QC.translate("firewall", "Node", ""),
        QC.translate("firewall", "Name", ""),
        QC.translate("firewall", "Table", ""),
        QC.translate("firewall", "Family", ""),
        QC.translate("firewall", "Hook", ""),
        QC.translate("firewall", "Enabled", ""),
        QC.translate("firewall", "Description", ""),
        QC.translate("firewall", "Parameters", ""),
        QC.translate("firewall", "Action", ""),
        QC.translate("firewall", "ActionParms", ""),
    ]

    items = []
    lastRules = []
    position = 0

    def __init__(self, tableName):
        self.tableName = tableName
        self._nodes = Nodes.instance()
        self._fw = Firewall.instance()
        self.lastColumnCount = len(self.headersAll)
        self.lastQueryArgs = ()

        QStandardItemModel.__init__(self, 0, self.lastColumnCount)
        self.setHorizontalHeaderLabels(self.headersAll)

    def filterByNode(self, addr):
        self.activeFilter = self.FILTER_BY_NODE
        self.fillVisibleRows(0, True, addr)

    def filterAll(self):
        self.activeFilter = self.FILTER_ALL
        self.fillVisibleRows(0, True)

    def filterByTable(self, addr, name, family):
        self.activeFilter = self.FILTER_BY_TABLE
        self.fillVisibleRows(0, True, addr, name, family)

    def filterByChain(self, addr, table, family, chain, hook):
        self.activeFilter = self.FILTER_BY_CHAIN
        self.fillVisibleRows(0, True, addr, table, family, chain, hook)

    def filterByQuery(self, query):
        self.activeFilter = self.FILTER_BY_QUERY
        self.fillVisibleRows(0, True, query)

    def reorderRows(self, action, row):
        if (row.row()+action == self.rowCount() and action == self.DOWN_BTN) or \
                (row.row() == 0 and action == self.UP_BTN):
            return

        # XXX: better use moveRow()?
        newRow = []
        # save the row we're about to overwrite
        for c in range(self.columnCount()):
            item = self.index(row.row()+action, c)
            itemText = item.data()
            newRow.append(itemText)
        # overwrite next item with current data
        for c in range(self.columnCount()):
            curItem = self.index(row.row(), c).data()
            nextIdx = self.index(row.row()+action, c)
            self.setData(nextIdx, curItem, QtCore.Qt.DisplayRole)
        # restore row with the overwritten data
        for i, nr in enumerate(newRow):
            idx = self.index(row.row(), i)
            self.setData(idx, nr, QtCore.Qt.DisplayRole)

        self.rowsReordered.emit(
            self.activeFilter,
            self.index(row.row()+action, self.COL_ADDR).data(), # address
            self.index(row.row()+action, self.COL_UUID).data(), # key
            row.row(),
            row.row()+action)

    def refresh(self, force=False):
        self.fillVisibleRows(0, force, *self.lastQueryArgs)

    #Some QSqlQueryModel methods must be mimiced so that this class can serve as a drop-in replacement
    #mimic QSqlQueryModel.query()
    def query(self):
        return self

    #mimic QSqlQueryModel.query().lastError()
    def lastError(self):
        return QSqlError()

    #mimic QSqlQueryModel.clear()
    def clear(self):
        self.items = []
        self.removeColumns(0, self.lastColumnCount)
        self.setColumnCount(0)
        self.setRowCount(0)

    # set columns based on query's fields
    def setModelColumns(self, headers):
        count = len(headers)
        self.clear()
        self.setHorizontalHeaderLabels(headers)
        self.lastColumnCount = count
        self.setColumnCount(self.lastColumnCount)
        self.columnCountChanged.emit(count)

    def query(self):
        return QSqlQuery()

    def setQuery(self, q, db, args=None):
        self.refresh()

    def nextRecord(self, offset):
        self.position += 1

    def prevRecord(self, offset):
        self.position -= 1

    def fillVisibleRows(self, upperBound, force, *data):
        if self.activeFilter == self.FILTER_BY_NODE and len(data) == 0:
                return

        cols = []
        rules = []
        #don't trigger setItem's signals for each cell, instead emit dataChanged for all cells
        self.blockSignals(True)
        # mandatory for rows refreshing
        self.layoutAboutToBeChanged.emit()

        if self.activeFilter == self.FILTER_BY_NODE:
            rules = self._fw.get_node_rules(data[0])
            self.setModelColumns(self.headersAll)
        elif self.activeFilter == self.FILTER_BY_TABLE:
            rules = self._fw.filter_by_table(data[0], data[1], data[2])
            self.setModelColumns(self.headersAll)
        elif self.activeFilter == self.FILTER_BY_CHAIN:
            rules = self._fw.filter_by_chain(data[0], data[1], data[2], data[3], data[4])
            self.setModelColumns(self.headersAll)
        elif self.activeFilter == self.FILTER_BY_QUERY:
            rules = self._fw.filter_rules(data[0])
            self.setModelColumns(self.headersAll)
        else:
            self.setModelColumns(self.headersAll)
            rules = self._fw.get_rules()

        self.addRows(rules)

        self.blockSignals(False)
        if self.lastRules != rules or force == True:
            self.layoutChanged.emit()
            self.totalRowCount = len(rules)
            self.setRowCount(self.totalRowCount)
            self.rowsUpdated.emit(self.activeFilter, data)
            self.dataChanged.emit(self.createIndex(0,0), self.createIndex(self.rowCount(), self.columnCount()))

        self.lastRules = rules
        self.lastQueryArgs = data
        del cols
        del rules

    def addRows(self, rules):
        self.items = []
        for rows in rules:
            cols = []
            cols.append(QStandardItem("")) # buttons column
            for cl in rows:
                item = QStandardItem(cl)
                item.setData(cl, QtCore.Qt.UserRole+1)
                cols.append(item)
            self.appendRow(cols)

    def dumpRows(self):
        for rule in self.lastRules:
            print(rule)

class FirewallTableView(QTableView):
    # how many rows can potentially be displayed in viewport
    # the actual number of rows currently displayed may be less than this
    maxRowsInViewport = 0
    rowsReordered = pyqtSignal(str) # addr

    def __init__(self, parent):
        QTableView.__init__(self, parent)
        self._fw = Firewall.instance()
        self._fw.rules.rulesUpdated.connect(self._cb_fw_rules_updated)

        self.verticalHeader().setVisible(True)
        self.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignCenter)
        self.horizontalHeader().setStretchLastSection(True)

        # FIXME: if the firewall being used is iptables, hide the column to
        # reorder rules, it's not supported.
        updownBtn = UpDownButtonDelegate(self)
        self.setItemDelegateForColumn(0, updownBtn)
        updownBtn.clicked.connect(self._cb_fw_rule_position_changed)

    def _cb_fw_rules_updated(self):
        self.model().refresh(True)

    def _cb_column_count_changed(self, num):
        for i in range(num):
            self.resizeColumnToContents(i)

    def _cb_fw_rule_position_changed(self, action, row):
        self.model().reorderRows(action, row)

    def _cb_rows_reordered(self, view, node_addr, uuid, old_pos, new_pos):
        if self._fw.swap_rules(view, node_addr, uuid, old_pos, new_pos):
            self.rowsReordered.emit(node_addr)

    #@QtCore.pyqtSlot(int, tuple)
    def _cb_rows_updated(self, view, data):
        for c in range(self.model().rowCount()):
            self.setColumnHidden(c, False)
            #self.horizontalHeader().setSectionResizeMode(
            #    c, QHeaderView.ResizeToContents
            #)

        self.setColumnHidden(FirewallTableModel.COL_BTNS, True)
        self.setColumnHidden(FirewallTableModel.COL_UUID, True)
        if view >= self.model().FILTER_BY_NODE:
            # hide address column
            self.setColumnHidden(FirewallTableModel.COL_ADDR, True)
        if view >= self.model().FILTER_BY_TABLE:
            self.setColumnHidden(FirewallTableModel.COL_CHAIN_TABLE, True)
            self.setColumnHidden(FirewallTableModel.COL_CHAIN_FAMILY, True)
        if view >= self.model().FILTER_BY_CHAIN:
            # hide chain's name, family and hook
            self.setColumnHidden(FirewallTableModel.COL_CHAIN_NAME, True)
            self.setColumnHidden(FirewallTableModel.COL_CHAIN_HOOK, True)
            self.setColumnHidden(FirewallTableModel.COL_BTNS, False)

    def filterAll(self):
        self.model().filterAll()

    def filterByNode(self, addr):
        self.model().filterByNode(addr)

    def filterByTable(self, addr, name, family):
        self.model().filterByTable(addr, name, family)

    def filterByChain(self, addr, table, family, chain, hook):
        self.model().filterByChain(addr, table, family, chain, hook)

    def filterByQuery(self, query):
        self.model().filterByQuery(query)

    def refresh(self):
        self.model().refresh(True)

    def clearSelection(self):
        pass

    def copySelection(self):
        selection = self.selectedIndexes()
        if not selection:
            return None
        rows = []
        row = []
        lastRow = 0
        for idx in selection:
            if idx.row() == lastRow:
                row.append(self.model().index(idx.row(), idx.column()).data())
            else:
                row = []
                lastRow = idx.row()
                rows.append(row)
        return rows

    def setModel(self, model):
        super().setModel(model)
        self.horizontalHeader().sortIndicatorChanged.disconnect()
        self.setSortingEnabled(True)
        self.model().columnCountChanged.connect(self._cb_column_count_changed)
        model.rowsUpdated.connect(self._cb_rows_updated)
        model.rowsReordered.connect(self._cb_rows_reordered)

    def setTrackingColumn(self, col):
        pass
