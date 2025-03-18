from PyQt5.QtGui import QColor, QStandardItemModel, QStandardItem
from PyQt5.QtSql import QSqlQueryModel, QSqlQuery, QSql
from PyQt5.QtWidgets import QTableView, QAbstractSlider
from PyQt5.QtCore import QItemSelectionRange, QItemSelectionModel, QItemSelection, pyqtSignal, QEvent, Qt
import time
import math

from PyQt5.QtCore import QCoreApplication as QC

class GenericTableModel(QStandardItemModel):
    rowCountChanged = pyqtSignal()
    beginViewPortRefresh = pyqtSignal()
    endViewPortRefresh = pyqtSignal()

    db = None
    tableName = ""
    # total row count which must de displayed in the view
    totalRowCount = 0
    #
    lastColumnCount = 0

    # original query string before we modify it
    origQueryStr = QSqlQuery()
    # previous original query string; used to check if the query has changed
    prevQueryStr = ''
    # modified query object
    realQuery = QSqlQuery()

    items = []
    lastItems = []

    def __init__(self, tableName, headerLabels):
        self.tableName = tableName
        self.headerLabels = headerLabels
        self.lastColumnCount = len(self.headerLabels)
        QStandardItemModel.__init__(self, 0, self.lastColumnCount)
        self.setHorizontalHeaderLabels(self.headerLabels)

    #Some QSqlQueryModel methods must be mimiced so that this class can serve as a drop-in replacement
    #mimic QSqlQueryModel.query()
    def query(self):
        return self

    #mimic QSqlQueryModel.query().lastQuery()
    def lastQuery(self):
        return self.origQueryStr

    #mimic QSqlQueryModel.query().lastError()
    def lastError(self):
        return self.realQuery.lastError()

    #mimic QSqlQueryModel.clear()
    def clear(self):
        pass

    def rowCount(self, index=None):
        """ensures that only the needed rows is created"""
        return len(self.items)

    def data(self, index, role=Qt.DisplayRole):
        """Paint rows with the data stored in self.items
        """
        if role == Qt.DisplayRole or role == Qt.EditRole:
            items_count = len(self.items)
            if index.isValid() and items_count > 0 and index.row() < items_count:
                return self.items[index.row()][index.column()]
        return QStandardItemModel.data(self, index, role)

    # set columns based on query's fields
    def setModelColumns(self, newColumns):
        # Avoid firing signals while reconfiguring the view, it causes
        # segfaults.
        self.blockSignals(True);

        self.headerLabels = []
        self.removeColumns(0, self.lastColumnCount)
        self.setHorizontalHeaderLabels(self.headerLabels)
        for col in range(0, newColumns):
            self.headerLabels.append(self.realQuery.record().fieldName(col))
        self.lastColumnCount = newColumns
        self.setHorizontalHeaderLabels(self.headerLabels)
        self.setColumnCount(len(self.headerLabels))

        self.blockSignals(False);

    def setQuery(self, q, db):
        self.origQueryStr = q
        self.db = db
        #print("q:", q)

        if self.prevQueryStr != self.origQueryStr:
            self.realQuery = QSqlQuery(q, db)

        self.realQuery.exec_()
        self.realQuery.last()

        queryRows = max(0, self.realQuery.at()+1)
        self.totalRowCount = queryRows
        self.setRowCount(self.totalRowCount)

        # update view's columns
        queryColumns = self.realQuery.record().count()
        if queryColumns != self.lastColumnCount:
            self.setModelColumns(queryColumns)

        self.prevQueryStr = self.origQueryStr
        self.rowCountChanged.emit()

    def nextRecord(self, offset):
        cur_pos = self.realQuery.at()
        q.seek(max(cur_pos, cur_pos+offset))

    def prevRecord(self, offset):
        cur_pos = self.realQuery.at()
        q.seek(min(cur_pos, cur_pos-offset))

    def refreshViewport(self, scrollValue, maxRowsInViewport, force=False):
        """Refresh the viewport with data from the db.
        Before making any changes, emit a signal which will perform several operations
        (save current selected row, etc).
        force var will force a refresh if the scrollbar is at the top or bottom of the
        viewport, otherwise skip it to allow rows analyzing without refreshing.
        """
        if not force:
            return

        self.beginViewPortRefresh.emit()
        # set records position to last, in order to get correctly the number of
        # rows.
        self.realQuery.last()
        rowsFound = max(0, self.realQuery.at()+1)
        if scrollValue == 0 or self.realQuery.at() == QSql.BeforeFirstRow:
            self.realQuery.seek(QSql.BeforeFirstRow)
        elif self.realQuery.at() == QSql.AfterLastRow:
            self.realQuery.seek(rowsFound - maxRowsInViewport)
        else:
            self.realQuery.seek(min(scrollValue-1, self.realQuery.at()))

        upperBound = min(maxRowsInViewport, rowsFound)
        self.setRowCount(self.totalRowCount)

        # only visible rows will be filled with data, and only if we're not
        # updating the viewport already.
        if force and (upperBound > 0 or self.realQuery.at() < 0):
            self.fillVisibleRows(self.realQuery, upperBound, force)
        self.endViewPortRefresh.emit()

    def fillVisibleRows(self, q, upperBound, force=False):
        rowsLabels = []
        self.setVerticalHeaderLabels(rowsLabels)

        self.items = []
        cols = []
        #don't trigger setItem's signals for each cell, instead emit dataChanged for all cells
        for x in range(0, upperBound):
            q.next()
            if q.at() < 0:
                # if we don't set query to a valid record here, it gets stucked
                # forever at -2/-1.
                q.seek(upperBound)
                break
            rowsLabels.append(str(q.at()+1))
            cols = []
            for col in range(0, len(self.headerLabels)):
                cols.append(str(q.value(col)))

            self.items.append(cols)

        self.setVerticalHeaderLabels(rowsLabels)
        if self.lastItems != self.items or force == True:
            self.dataChanged.emit(self.createIndex(0,0), self.createIndex(upperBound, len(self.headerLabels)))
        self.lastItems = self.items
        del cols

    def dumpRows(self):
        rows = []
        q = QSqlQuery(self.db)
        q.exec(self.origQueryStr)
        q.seek(QSql.BeforeFirstRow)
        while True:
            q.next()
            if q.at() == QSql.AfterLastRow:
                break
            row = []
            for col in range(0, len(self.headerLabels)):
                row.append(q.value(col))
            rows.append(row)
        return rows

    def copySelectedRows(self, start=QSql.BeforeFirstRow, end=QSql.AfterLastRow):
        rows = []
        lastAt = self.realQuery.at()
        self.realQuery.seek(start)
        while True:
            self.realQuery.next()
            if self.realQuery.at() == QSql.AfterLastRow or len(rows) >= end:
                break
            row = []
            for col in range(0, len(self.headerLabels)):
                row.append(self.realQuery.value(col))
            rows.append(row)
        self.realQuery.seek(lastAt)
        return rows

class GenericTableView(QTableView):
    # how many rows can potentially be displayed in viewport
    # the actual number of rows currently displayed may be less than this
    maxRowsInViewport = 0
    vScrollBar = None

    def __init__(self, parent):
        QTableView.__init__(self, parent)
        self.mousePressed = False
        self.shiftPressed = False
        self.ctrlPressed = False
        self.selectedRows = {}
        self.trackingCol = 0

        #eventFilter to catch key up/down events and wheel events
        self.verticalHeader().setVisible(True)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.horizontalHeader().setStretchLastSection(True)
        #the built-in vertical scrollBar of this view is always off
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.installEventFilter(self)

    def setVerticalScrollBar(self, vScrollBar):
        self.vScrollBar = vScrollBar
        self.vScrollBar.valueChanged.connect(self.onScrollbarValueChanged)
        self.vScrollBar.setVisible(False)

    def setModel(self, model):
        super().setModel(model)
        model.rowCountChanged.connect(self.onRowCountChanged)
        model.beginViewPortRefresh.connect(self.onBeginViewportRefresh)
        model.endViewPortRefresh.connect(self.onEndViewportRefresh)
        self.horizontalHeader().sortIndicatorChanged.disconnect()
        self.setSortingEnabled(False)

    def setTrackingColumn(self, col):
        """column used to track a selected row while scrolling on this table"""
        self.trackingCol = col

    def getRowCells(self, row):
        cols = []
        for i in range(0, self.model().columnCount()):
            c = self.model().index(row, i)
            cols.append(c.data())
        return cols

    def clear(self):
        pass

    def refresh(self):
        self.calculateRowsInViewport()
        self.model().setRowCount(min(self.maxRowsInViewport, self.model().totalRowCount))
        self.model().refreshViewport(self.vScrollBar.value(), self.maxRowsInViewport, force=True)

    def forceViewRefresh(self):
        return (self.vScrollBar.minimum() == self.vScrollBar.value() or self.vScrollBar.maximum() == self.vScrollBar.value())

    def calculateRowsInViewport(self):
        rowHeight = self.verticalHeader().defaultSectionSize()
        # we don't want partial-height rows in viewport, hence .floor()
        self.maxRowsInViewport = math.floor(self.viewport().height() / rowHeight)+1

    def scrollViewport(self, row):
        maxVal = self.maxRowsInViewport-1
        if row >= maxVal:
            pos = self.vScrollBar.value() + 1
            self.vScrollBar.setValue(pos)
            return pos
        elif row == 0:
            pos = max(0, self.vScrollBar.value() - 1)
            self.vScrollBar.setValue(pos)
            return pos

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self.mousePressed = False
        for idx in self.selectionModel().selectedRows(self.trackingCol):
            if idx.data() not in self.selectedRows.keys():
                self.selectedRows[idx.data()] = self.getRowCells(idx.row())

        # TODO: handle selection ranges when Shift is pressed
        self._selectSavedIndex()

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        self.handleMouseMoveEvent(event.pos())

    def handleMouseMoveEvent(self, pos):
        item = self.indexAt(pos)
        if item == None:
            return

        maxVal = self.maxRowsInViewport-1
        clickedItem = self.model().index(item.row(), self.trackingCol)
        if clickedItem.data() != None:
            if clickedItem.data() not in self.selectedRows.keys():
                self.selectedRows[clickedItem.data()] = self.getRowCells(item.row())

        if self.mousePressed:
            scrollPos = self.scrollViewport(item.row())
            if pos != None:
                return

            nextItem = self.model().index(scrollPos, self.trackingCol)
            if clickedItem.data() not in self.selectedRows.keys():
                self.selectedRows[nextItem.data()] = self.getRowCells(nextItem.row())

    # save the selected index, to preserve selection when moving around.
    def mousePressEvent(self, event):
        # we need to call upper class to paint selections properly
        super().mousePressEvent(event)
        if event.button() != Qt.LeftButton:
            return

        item = self.indexAt(event.pos())
        row = self.rowAt(self.trackingCol)
        if item == None:
            return

        clickedItem = self.model().index(item.row(), self.trackingCol)
        if clickedItem.data() == None:
            return

        self.mousePressed = True
        flags = QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent

        # 1. if ctrl is pressed, select / deselect current row
        # 2. if ctrl is not pressed:
        #   1. discard previous selection
        #   2. select current line if it's not selected. Deselect it otherwise.
        # 3. if ctrl is not pressed and there's more than one row selected, and
        # the clicked row is selected: discard selection, and select current
        # clicked row.
        rowSelected = clickedItem.data() in self.selectedRows.keys()
        if self.ctrlPressed:
            if rowSelected:
                del self.selectedRows[clickedItem.data()]
                flags = QItemSelectionModel.Rows | QItemSelectionModel.Deselect
        else:
            deselectCurRow = len(self.selectedRows.keys()) == 1
            self.selectionModel().clear()
            self.selectedRows = {}
            if rowSelected and deselectCurRow:
                #del self.selectedRows[clickedItem.data()]
                flags = QItemSelectionModel.Rows | QItemSelectionModel.Deselect
            else:
                self.selectedRows[clickedItem.data()] = self.getRowCells(item.row())

        self.selectionModel().setCurrentIndex(
            clickedItem,
            flags
        )

    def onBeginViewportRefresh(self):
        # if the selected row due to scrolling up/down doesn't match with the
        # saved index, deselect the row, because the saved index is out of the
        # view.
        pass

    def onEndViewportRefresh(self):
        if not self.mousePressed and not self.shiftPressed:
            self.selectionModel().clear()
        self._selectSavedIndex()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        #refresh the viewport data based on new geometry
        self.refresh()

    def onRowCountChanged(self):
        totalCount = self.model().totalRowCount
        self.vScrollBar.setVisible(True if totalCount > self.maxRowsInViewport else False)

        self.vScrollBar.setMinimum(0)
        # we need to substract the displayed rows to the total rows, to scroll
        # down correctly.
        self.vScrollBar.setMaximum(max(0, totalCount - self.maxRowsInViewport+1))

        self.model().refreshViewport(self.vScrollBar.value(), self.maxRowsInViewport, force=self.forceViewRefresh())

    def clearSelection(self):
        self.selectionModel().reset()
        self.selectionModel().clearCurrentIndex()

    def copySelection(self):
        model = self.selectionModel()
        curModel = self.model()
        selection = model.selectedRows()
        if not selection:
            return None

        rows = []
        for k in self.selectedRows:
            rows.append(self.selectedRows[k])
        return rows

    def getCurrentIndex(self):
        return self.selectionModel().currentIndex().internalId()

    def selectItem(self, _data, _column):
        """Select a row based on the data displayed on the given column.
        """
        items = self.model().findItems(_data, column=_column)
        if len(items) > 0:
            self.selectionModel().setCurrentIndex(
                items[0].index(),
                QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent
            )

    def _selectSavedIndex(self):
        sel = QItemSelection()

        for text in self.selectedRows.keys():
            items = self.model().findItems(text, column=self.trackingCol)
            if len(items) == 0:
                continue

            for i in items:
                sel.append(QItemSelectionRange(i.index()))
            self.selectionModel().select(sel, QItemSelectionModel.Select | QItemSelectionModel.Rows)

    def _selectLastRow(self):
        internalId = self.getCurrentIndex()
        self.selectionModel().setCurrentIndex(
            self.model().createIndex(self.maxRowsInViewport-2, self.trackingCol, internalId),
            QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent
        )

    def _selectRow(self, pos):
        internalId = self.getCurrentIndex()
        self.selectionModel().setCurrentIndex(
            self.model().createIndex(pos, self.trackingCol, internalId),
            QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent
        )

    def onScrollbarValueChanged(self, vSBNewValue):
        self.model().refreshViewport(vSBNewValue, self.maxRowsInViewport, force=True)

    def onKeyUp(self):
        curIdx = self.selectionModel().currentIndex()
        if not self.shiftPressed:
            self.selectedRows = {}
        self.selectedRows[curIdx.data()] = self.getRowCells(curIdx.row())

        if self.selectionModel().currentIndex().row() == 0:
            self.vScrollBar.setValue(max(0, self.vScrollBar.value() - 1))

    def onKeyDown(self):
        curIdx = self.selectionModel().currentIndex()
        curRow = curIdx.row()
        if not self.shiftPressed:
            self.selectedRows = {}
        self.selectedRows[curIdx.data()] = self.getRowCells(curRow)

        if curRow >= self.maxRowsInViewport-2:
            self.onKeyPageDown()
            self._selectRow(0)
        else:
            self._selectRow(curRow)

    def onKeyHome(self):
        self.vScrollBar.setValue(0)
        if not self.mousePressed and self.shiftPressed:
            self.selectionModel().clear()

    def onKeyEnd(self):
        self.vScrollBar.setValue(self.vScrollBar.maximum())
        if not self.mousePressed and self.shiftPressed:
            self.selectionModel().clear()
        self._selectLastRow()

    def onKeyPageUp(self):
        newValue = max(0, self.vScrollBar.value() - self.maxRowsInViewport)
        self.vScrollBar.setValue(newValue)

    def onKeyPageDown(self):
        if self.vScrollBar.isVisible() == False:
            return

        newValue = self.vScrollBar.value() + (self.maxRowsInViewport-2)
        self.vScrollBar.setValue(newValue)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.KeyRelease:
            if event.key() == Qt.Key_Shift:
                self.shiftPressed = False
            if event.key() == Qt.Key_Control:
                self.ctrlPressed = False

        elif event.type() == QEvent.KeyPress:
            # FIXME: setValue() does not update the scrollbars correctly in
            # some pyqt versions.
            if event.key() == Qt.Key_Up:
                self.onKeyUp()
            elif event.key() == Qt.Key_Down:
                self.onKeyDown()
            elif event.key() == Qt.Key_Home:
                self.onKeyHome()
            elif event.key() == Qt.Key_End:
                self.onKeyEnd()
            elif event.key() == Qt.Key_PageUp:
                self.onKeyPageUp()
            elif event.key() == Qt.Key_PageDown:
                self.onKeyPageDown()
            elif event.key() == Qt.Key_Escape:
                self.selectionModel().clear()
                self.selectedRows = {}
            elif event.key() == Qt.Key_Shift:
                self.shiftPressed = True
            elif event.key() == Qt.Key_Control:
                self.ctrlPressed = True

        elif event.type() == QEvent.Wheel:
            self.vScrollBar.wheelEvent(event)
            return True

        return super(GenericTableView, self).eventFilter(obj, event)
