import math
import threading

from PyQt6.QtGui import QStandardItemModel
from PyQt6.QtSql import QSqlQuery, QSql
from PyQt6.QtWidgets import QTableView
from PyQt6.QtCore import (
    QItemSelectionRange,
    QItemSelectionModel,
    QItemSelection,
    QModelIndex,
    pyqtSignal,
    QEvent,
    Qt)

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
    origQueryStr = ""
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

    def headers(self):
        return self.headerLabels

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

    def refresh(self):
        self.realQuery.exec()
        #self._update_row_count()
        #self._update_col_count()

    def rowCount(self, index=None):
        """ensures that only the needed rows is created"""
        return len(self.items)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        """Paint rows with the data stored in self.items
        """
        if role == Qt.ItemDataRole.DisplayRole or role == Qt.ItemDataRole.EditRole:
            items_count = len(self.items)
            if index.isValid() and items_count > 0 and index.row() < items_count:
                return self.items[index.row()][index.column()]
        return QStandardItemModel.data(self, index, role)

    def update_row_count(self):
        queryRows = max(0, self.realQuery.at()+1)
        self.totalRowCount = queryRows
        self.setRowCount(self.totalRowCount)

    def update_col_count(self):
      # update view's columns
        queryColumns = self.realQuery.record().count()
        if queryColumns != self.lastColumnCount:
            self.setModelColumns(queryColumns)

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
        if scrollValue == 0 or self.realQuery.at() == QSql.Location.BeforeFirstRow.value:
            self.realQuery.seek(QSql.Location.BeforeFirstRow.value)
        elif self.realQuery.at() == QSql.Location.AfterLastRow.value:
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
                val = q.value(col)
                if val is None:
                    val = ""
                cols.append(str(val))

            self.items.append(cols)

        self.setVerticalHeaderLabels(rowsLabels)
        if self.lastItems != self.items or force == True:
            self.dataChanged.emit(self.createIndex(0,0), self.createIndex(upperBound, len(self.headerLabels)))
        self.lastItems = self.items
        del cols

    def dumpRows(self, nolimits=False, first_row=QSql.Location.BeforeFirstRow.value, last_row=QSql.Location.AfterLastRow.value):
        if first_row is None or last_row is None:
            return
        rows = []
        qstr = self.origQueryStr
        if nolimits:
            qstr = self.origQueryStr.split("LIMIT")[0]
        self.realQuery.exec(qstr)
        # reset records position, in order to get correctly the number of
        # rows.
        self.realQuery.first()
        self.realQuery.seek(first_row)
        while self.realQuery.next():
            if self.realQuery.at() == last_row:
                break
            row = []
            for col in range(0, len(self.headerLabels)):
                row.append(self.realQuery.value(col))
            rows.append(row)
        return rows

    def copySelectedRows(self, start=QSql.Location.BeforeFirstRow.value, end=QSql.Location.AfterLastRow.value):
        rows = []
        lastAt = self.realQuery.at()
        self.realQuery.seek(start)
        while True:
            self.realQuery.next()
            if self.realQuery.at() == QSql.Location.AfterLastRow.value or len(rows) >= end:
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
    # make this state global, so it survives signals (?)
    # (onBegin/EndViewportRefresh)
    mousePressed = False

    def __init__(self, parent):
        QTableView.__init__(self, parent)
        self._lock = threading.RLock()

        self.shiftPressed = False
        self.ctrlPressed = False
        self.keySelectAll = False
        self.trackingCol = 0
        self._rows_selection = {}
        # first and last row selected with shift pressed
        self._first_row_selected = None
        self._last_row_selected = None
        # flag to avoid excessive refreshes
        self._last_height = 0

        #eventFilter to catch key up/down events and wheel events
        self.verticalHeader().setVisible(True)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        self.horizontalHeader().setStretchLastSection(True)
        #the built-in vertical scrollBar of this view is always off
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
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

    # FIXME: some columns may have the same value on different nodes
    # like rule name zzz on nodes 1, 2 and 3.
    def setTrackingColumn(self, col):
        """column used to track a selected row while scrolling on this table"""
        self.trackingCol = col

    def getRowCells(self, row):
        cols = []
        for i in range(0, self.model().columnCount()):
            c = self.model().index(row, i)
            cols.append(c.data())
        return cols

    def selectDbRows(self, first, last):
        """get rows range from the db"""
        selrows = self.model().dumpRows(first_row=first, last_row=last)
        if selrows is None:
            return
        self._rows_selection = {}
        for rid, row in enumerate(selrows):
            key = row[self.trackingCol]
            self._rows_selection[key] = row
            idx = self.model().index(rid, self.trackingCol)
            self.selectionModel().setCurrentIndex(
                idx,
                QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.SelectCurrent
            )
        self.selectIndices()

    def getMinViewportRow(self):
        """get the first row of the viewport. Starts from 1"""
        return self.vScrollBar.value()+1

    def getMaxViewportRow(self):
        """get the total rows relative to the viewport"""
        return self.vScrollBar.value() + self.maxRowsInViewport

    def getViewportRowPos(self, row):
        """get the row position relative to the viewport"""
        return self.getMinViewportRow() + row

    def clear(self):
        self.keySelectAll = False

    def refresh(self):
        self.calculateRowsInViewport()
        self.model().setRowCount(min(self.maxRowsInViewport, self.model().totalRowCount))
        self.model().refreshViewport(self.vScrollBar.value(), self.maxRowsInViewport, force=True)
        # XXX: on PyQt6 we need to update the viewport explicitely.
        self.viewport().update()

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

        return None

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        GenericTableView.mousePressed = False
        if event.button() != Qt.MouseButton.LeftButton:
            return
        pos = event.pos()
        row = self.rowAt(pos.y())
        viewport_row = self.getViewportRowPos(row)

        # when the mouse goes off the viewport while dragging, row is -1.
        # in this scenario, set a valid last row.
        if self._last_row_selected is None and (row == -1 and viewport_row == 0):
            self._last_row_selected = self._first_row_selected
            self._first_row_selected = 0
        elif self._last_row_selected is None and (row == -1 and viewport_row+self.maxRowsInViewport == self.getMaxViewportRow()):
            self._last_row_selected = self.getMaxViewportRow()+1

        if self._first_row_selected is None:
            self._first_row_selected = viewport_row
        if self._last_row_selected is None:
            self._last_row_selected = viewport_row

        # invert the selection after moving up
        if self._first_row_selected > self._last_row_selected:
            last = self._first_row_selected
            first = self._last_row_selected
            self._last_row_selected = last
            self._first_row_selected = first

        if self.shiftPressed:
            self.handleShiftPressed()
            return

        if self._first_row_selected == self._last_row_selected:
            return

        first_row = self._first_row_selected-2
        self.selectDbRows(first_row, self._last_row_selected)

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        pos = event.pos()
        row = self.rowAt(pos.y())
        item = self.indexAt(pos)

        if item is None:
            return

        clickedItem = self.model().index(row, self.trackingCol)
        if clickedItem.data() is None:
            return
        self.handleMouseMoveEvent(row, clickedItem, self.selectionModel().isRowSelected(row, QModelIndex()))

    # save the selected index, to preserve selection when moving around.
    def mousePressEvent(self, event):
        # we need to call upper class to paint selections properly
        super().mousePressEvent(event)
        GenericTableView.mousePressed = True
        rightBtnPressed = event.button() != Qt.MouseButton.LeftButton
        if rightBtnPressed:
            return

        self.keySelectAll = False
        if not self.shiftPressed:
            self._first_row_selected = None
            self._last_row_selected = None

        pos = event.pos()
        item = self.indexAt(pos)
        row = self.rowAt(pos.y())
        if item is None:
            return

        clickedItem = self.model().index(row, self.trackingCol)
        if clickedItem.data() is None:
            return

        flags = QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.SelectCurrent

        # 1. if ctrl is pressed, select / deselect current row
        # 2. if shift is pressed, select the first and last row of the range.
        #    The selection will be selected on mouseReleaseEvent() ->
        #    handleShiftPressed() -> selectIndidces()
        # 3. if ctrl and shift is not pressed:
        #   1. discard previous selection
        #   2. select current line if it's not selected. Deselect it otherwise.
        # 4. if ctrl is not pressed and there's more than one row selected, and
        # the clicked row is selected: discard selection, and select current
        # clicked row.
        # 5. if Left button has not been pressed, do not discard the selection.
        rowSelected = clickedItem.data() in self._rows_selection.keys()
        if rowSelected and rightBtnPressed:
            return

        viewport_row = self.getViewportRowPos(row)
        if self._first_row_selected is None:
            self._first_row_selected = viewport_row
        if self._last_row_selected is None:
            self._last_row_selected = viewport_row

        if self.ctrlPressed:
            if rowSelected:
                del self._rows_selection[clickedItem.data()]
                flags = QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.Deselect
                if self.ctrlPressed:
                    self._first_row_selected = None
            else:
                self._rows_selection[clickedItem.data()] = self.getRowCells(row)
        elif self.shiftPressed:
            if self._last_row_selected is None:
                self._last_row_selected = viewport_row

            # update the first or last row depending on the direction the row
            # has been selected.
            if viewport_row < self._first_row_selected:
                self._first_row_selected = viewport_row
            if viewport_row > self._first_row_selected:
                self._last_row_selected = viewport_row
        else:
            deselectCurRow = len(self._rows_selection.keys()) == 1 and not rightBtnPressed
            # discard current selection:
            # - if the user right clicked on a row not part of a selection.
            # - if the user clicked on a row, and there's only one row
            # selected.
            # - if the user clicked on a row already selected.
            if (not rowSelected and rightBtnPressed) or not rightBtnPressed or deselectCurRow:
                self.clearSelection()
                self._first_row_selected = viewport_row
            if rowSelected and deselectCurRow and not rightBtnPressed:
                self._first_row_selected = None
                flags = QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.Deselect
            else:
                self._rows_selection[clickedItem.data()] = self.getRowCells(row)

        self.selectionModel().setCurrentIndex(
            clickedItem,
            flags
        )

    def handleShiftPressed(self):
        # in the viewport, the rows start at 1, but in the db at 0
        first_row = self._first_row_selected-2
        self.selectDbRows(first_row, self._last_row_selected)

    def handleMouseMoveEvent(self, row, clickedItem, selected):
        if not selected:
            if clickedItem.data() in self._rows_selection.keys():
                del self._rows_selection[clickedItem.data()]
        else:
            self._rows_selection[clickedItem.data()] = self.getRowCells(row)

        # handle scrolling the view while dragging the mouse.
        if GenericTableView.mousePressed:
            self.scrollViewport(row)

    def onBeginViewportRefresh(self):
        # if the selected row due to scrolling up/down doesn't match with the
        # saved index, deselect the row, because the saved index is out of the
        # view.
        pass

    def onEndViewportRefresh(self):
        with self._lock:
            if not GenericTableView.mousePressed and not self.shiftPressed:
                self.selectionModel().clear()
            self.selectIndices()
            self.viewport().update()

    def resizeEvent(self, event):
        super(GenericTableView, self).resizeEvent(event)
        # refresh the viewport data based on new geometry.
        # If the height has not changed, we don't need to refresh the view.
        if self._last_height != self.verticalHeader().height():
            self._last_height = self.verticalHeader().height()
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
        self.keySelectAll = False
        self.shiftPressed = False
        self.ctrlPressed = False
        self.selectionModel().clear()
        self.selectionModel().reset()
        self.selectionModel().clearCurrentIndex()
        self._rows_selection = {}
        self._first_row_selected = None
        self._last_row_selected = None

    def selectedRows(self, limit=""):
        if self.keySelectAll:
            return self.model().dumpRows(nolimits=True)

        model = self.selectionModel()
        curModel = self.model()
        selection = model.selectedRows()
        if not selection:
            return None

        rows = []
        for k in self._rows_selection:
            rows.append(self._rows_selection[k])
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
                QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.SelectCurrent
            )

    def selectIndices(self):
        sel = QItemSelection()

        # XXX: a key can be duplicated. For example rule with the same name on
        # different nodes.
        for text in self._rows_selection.keys():
            items = self.model().findItems(text, column=self.trackingCol)
            if len(items) == 0:
                continue

            for i in items:
                sel.append(QItemSelectionRange(i.index()))
        self.selectionModel().clear()
        self.selectionModel().select(sel, QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)

    def _selectLastRow(self):
        internalId = self.getCurrentIndex()
        self.selectionModel().setCurrentIndex(
            self.model().createIndex(self.maxRowsInViewport-2, self.trackingCol, internalId),
            QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.SelectCurrent
        )

    def _selectRow(self, pos):
        internalId = self.getCurrentIndex()
        self.selectionModel().setCurrentIndex(
            self.model().createIndex(pos, self.trackingCol, internalId),
            QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.SelectCurrent
        )

    def onScrollbarValueChanged(self, vSBNewValue):
        self.model().refreshViewport(vSBNewValue, self.maxRowsInViewport, force=True)

    def onKeyUp(self):
        curIdx = self.selectionModel().currentIndex()
        if not self.shiftPressed:
            self._rows_selection = {}
        self._rows_selection[curIdx.data()] = self.getRowCells(curIdx.row())
        viewport_row = self.getViewportRowPos(curIdx.row())
        self._last_row_selected = viewport_row
        if self._first_row_selected is None:
            self._first_row_selected = viewport_row

        if self.selectionModel().currentIndex().row() == 0:
            self.vScrollBar.setValue(max(0, self.vScrollBar.value() - 1))

    def onKeyDown(self):
        curIdx = self.selectionModel().currentIndex()
        curRow = curIdx.row()
        if not self.shiftPressed:
            self._rows_selection = {}
        self._rows_selection[curIdx.data()] = self.getRowCells(curRow)

        newValue = self.vScrollBar.value()
        if curRow >= self.maxRowsInViewport-2:
            self.vScrollBar.setValue(newValue+1)
            self._selectLastRow()

    def onKeyHome(self):
        self._last_row_selected = self._first_row_selected
        self._first_row_selected = 0
        self.vScrollBar.setValue(0)
        if not GenericTableView.mousePressed and not self.shiftPressed:
            self.selectionModel().clear()
        if self.shiftPressed:
            self.selectDbRows(self._first_row_selected-1, self._last_row_selected)
        self._selectRow(0)

    def onKeyEnd(self):
        self.vScrollBar.setValue(self.vScrollBar.maximum())
        if not GenericTableView.mousePressed and not self.shiftPressed and not self.ctrlPressed:
            self.selectionModel().clear()
        self._last_row_selected = self.getMaxViewportRow()
        if self.shiftPressed:
            self.selectDbRows(self._first_row_selected-2, self._last_row_selected)
        self._selectLastRow()

    def onKeyPageUp(self):
        newValue = max(0, self.vScrollBar.value() - self.maxRowsInViewport)
        self.vScrollBar.setValue(newValue)

    def onKeyPageDown(self):
        if self.vScrollBar.isVisible() == False:
            return

        newValue = self.vScrollBar.value() + (self.maxRowsInViewport-2)
        self.vScrollBar.setValue(newValue)

    def onKeySpace(self):
        if self.vScrollBar.isVisible() == False:
            return

        newValue = self.vScrollBar.value() + (self.maxRowsInViewport-2)
        self.vScrollBar.setValue(newValue)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.KeyRelease:
            if event.key() == Qt.Key.Key_Shift:
                self.shiftPressed = False
            if event.key() == Qt.Key.Key_Control:
                self.ctrlPressed = False

        elif event.type() == QEvent.Type.KeyPress:
            # FIXME: setValue() does not update the scrollbars correctly in
            # some pyqt versions.
            if event.key() == Qt.Key.Key_Up:
                self.onKeyUp()
            elif event.key() == Qt.Key.Key_Down:
                self.onKeyDown()
            elif event.key() == Qt.Key.Key_Home:
                self.onKeyHome()
            elif event.key() == Qt.Key.Key_End:
                self.onKeyEnd()
            elif event.key() == Qt.Key.Key_PageUp:
                self.onKeyPageUp()
            elif event.key() == Qt.Key.Key_PageDown:
                self.onKeyPageDown()
            elif event.key() == Qt.Key.Key_Escape:
                self.clearSelection()
            elif event.key() == Qt.Key.Key_Shift:
                self.shiftPressed = True
            elif event.key() == Qt.Key.Key_Control:
                self.ctrlPressed = True
            elif event.key() == Qt.Key.Key_Space:
                self.onKeySpace()
            elif event.key() == Qt.Key.Key_A:
                self.keySelectAll = True

        elif event.type() == QEvent.Type.Wheel:
            self.vScrollBar.wheelEvent(event)
            return True

        return super(GenericTableView, self).eventFilter(obj, event)
