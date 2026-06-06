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
    QTimer,
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

    queryLimit = 0
    queryOffset = 0

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

    def getLimitQuery(self, offset, forward=True):
        if "LIMIT" not in self.origQueryStr:
            self.origQueryStr += f" LIMIT {self.queryLimit} OFFSET {self.queryOffset}"

        parts = self.origQueryStr.split("LIMIT")
        qstr = parts[0].strip()
        limit = parts[1].strip()
        parts = limit.split(" ")
        limit_n = int(parts[0])

        qstr = f"{qstr} LIMIT {limit_n}"

        if "OFFSET" in parts:
            if forward:
                offset = int(parts[2]) + offset
            else:
                offset = int(parts[2]) - offset
                offset = max(offset, 0)
        qstr = f"{qstr} OFFSET {offset}"

        return qstr, limit_n

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

    def total(self):
        q = QSqlQuery(self.db)
        q.exec(f"SELECT count(rowid) FROM {self.tableName}")
        q.next()
        num = q.value(0)
        if num is None:
            return 0
        return num

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

    def setQuery(self, q, db, binds=None, limit=None, offset=None):
        tmpQuery = self.realQuery
        if self.prevQueryStr != q:
            tmpQuery = QSqlQuery(q, db)

        if binds is not None:
            tmpQuery.prepare(q)
            for idx, v in binds:
                tmpQuery.bindValue(idx, v)

        ok = tmpQuery.exec()
        if not ok:
            return
        # this call is mandatory, the query must be positioned on a valid
        # record. Otherwise it'll segfault or won't display any data.
        tmpQuery.last()

        if offset is not None:
            self.queryOffset = offset
        if limit is not None:
            self.queryLimit = limit
        self.origQueryStr = q
        self.db = db

        if self.prevQueryStr != self.origQueryStr:
            self.realQuery = tmpQuery

        self.update_row_count()
        self.update_col_count()

        self.prevQueryStr = self.origQueryStr
        self.rowCountChanged.emit()

    def nextRecord(self, offset):
        qstr, self.queryLimit = self.getLimitQuery(offset, forward=True)
        if qstr is not None:
            self.queryOffset += self.queryLimit
            self.setQuery(qstr, self.db, limit=self.queryLimit, offset=self.queryOffset)
            return self.queryLimit, self.queryOffset

        return offset, 0

    def prevRecord(self, offset):
        qstr, self.queryLimit = self.getLimitQuery(offset, forward=False)
        if qstr is not None:
            self.queryOffset = max(0, self.queryOffset - self.queryLimit)
            self.setQuery(qstr, self.db, limit=self.queryLimit, offset=self.queryOffset)
            return self.queryLimit, self.queryOffset

        return offset, 0

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
        at = self.realQuery.at()
        rowsFound = max(0, self.queryOffset+at+1)
        if scrollValue == 0 or self.realQuery.at() == QSql.Location.BeforeFirstRow.value:
            self.realQuery.seek(QSql.Location.BeforeFirstRow.value)
        elif at == QSql.Location.AfterLastRow.value:
            self.realQuery.seek(QSql.Location.BeforeFirstRow.value)
            self.realQuery.seek(rowsFound - maxRowsInViewport)
        else:
            self.realQuery.seek(min(scrollValue-1, at))

        upperBound = min(maxRowsInViewport, rowsFound)

        # only visible rows will be filled with data, and only if we're not
        # updating the viewport already.
        if force and (upperBound > 0 or at < 0):
            self.fillVisibleRows(self.realQuery, upperBound, force)
        self.endViewPortRefresh.emit()

    def fillVisibleRows(self, q, upperBound, force=False):
        rowsLabels = []

        self.items = []
        cols = []
        header_count = self.columnCount()
        #don't trigger setItem's signals for each cell, instead emit dataChanged for all cells
        offidx = self.queryOffset
        for x in range(0, upperBound):
            if not q.next():
                break
            if q.at() < 0:
                # if we don't set query to a valid record here, it gets stucked
                # forever at -2/-1.
                q.seek(upperBound)
                break
            rowsLabels.append(str(offidx+q.at()+1))
            cols = []
            for col in range(0, header_count):
                val = q.value(col)
                if val is None:
                    val = ""
                cols.append(str(val))

            self.items.append(cols)

        self.setVerticalHeaderLabels(rowsLabels)
        if self.lastItems != self.items or force is True:
            self.dataChanged.emit(self.createIndex(0,0), self.createIndex(upperBound, header_count))
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
        header_count = self.columnCount()
        while self.realQuery.next():
            if self.realQuery.at() == last_row:
                break
            row = []
            for col in range(0, header_count):
                row.append(self.realQuery.value(col))
            rows.append(row)
        return rows

    def copySelectedRows(self, start=QSql.Location.BeforeFirstRow.value, end=QSql.Location.AfterLastRow.value):
        rows = []
        lastAt = self.realQuery.at()
        self.realQuery.seek(start)
        header_count = self.columnCount()
        while True:
            self.realQuery.next()
            if self.realQuery.at() == QSql.Location.AfterLastRow.value or len(rows) >= end:
                break
            row = []
            for col in range(0, header_count):
                row.append(self.realQuery.value(col))
            rows.append(row)
        self.realQuery.seek(lastAt)
        return rows

class GenericTableView(QTableView):
    vScrollBar = None

    def __init__(self, parent):
        QTableView.__init__(self, parent)
        self._lock = threading.RLock()

        # how many rows can potentially be displayed in viewport.
        # the actual number of rows currently displayed may be less than this
        self.maxRowsInViewport = 0
        self.mousePressed = False
        self.shiftPressed = False
        self.ctrlPressed = False
        self.keySelectAll = False
        self.trackingCol = 0

        # current selected rows
        self._rows_selection = set()

        # tracking-column text of the current (focused) row, used to
        # restore currentIndex after a viewport refresh
        self._current_row_text = None

        # first and last row selected with shift pressed
        self._first_row_selected = None
        self._last_row_selected = None

        # flag to avoid excessive refreshes
        self._last_height = 0

        self.verticalHeader().setVisible(True)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        self.horizontalHeader().setStretchLastSection(True)
        # the built-in vertical scrollBar of this view is always off
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # eventFilter to catch key up/down events and wheel events
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

    def selectAll(self):
        super().selectAll()
        self.keySelectAll = True
        self.selectDbRows(QSql.Location.BeforeFirstRow.value, QSql.Location.AfterLastRow.value)

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
        self._rows_selection.clear()
        for row in selrows:
            self._rows_selection.add(row[self.trackingCol])
        # the visual selection of the visible rows is applied by
        # selectIndices(); selecting db-range positions here would
        # highlight wrong viewport rows when the range is scrolled.
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
        # Note: on PyQt6 we need to update the viewport explicitely.
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
        self.mousePressed = False
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

        if self.ctrlPressed:
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
        rightBtnPressed = event.button() != Qt.MouseButton.LeftButton
        self.mousePressed = not rightBtnPressed

        self.keySelectAll = False
        if not self.shiftPressed:
            self._first_row_selected = None
            self._last_row_selected = None

        pos = event.pos()
        item = self.indexAt(pos)
        row = self.rowAt(pos.y())

        clickedItem = self.model().index(row, self.trackingCol)
        if not item.isValid() or clickedItem.data() is None:
            # Qt clears the visual selection when pressing on an empty
            # area; keep the tracked selection in sync, otherwise menu
            # actions keep operating on rows no longer highlighted.
            if not self.ctrlPressed:
                self._rows_selection.clear()
                self._current_row_text = None
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
        rowSelected = clickedItem.data() in self._rows_selection
        if rowSelected and rightBtnPressed:
            return

        viewport_row = self.getViewportRowPos(row)
        if self._first_row_selected is None:
            self._first_row_selected = viewport_row
        if self._last_row_selected is None:
            self._last_row_selected = viewport_row

        if self.ctrlPressed:
            if rowSelected:
                self._rows_selection.remove(clickedItem.data())
                flags = QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.Deselect
                if self.ctrlPressed:
                    self._first_row_selected = None
            else:
                self._rows_selection.add(clickedItem.data())
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
            deselectCurRow = len(self._rows_selection) == 1 and not rightBtnPressed
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
                self._rows_selection.add(clickedItem.data())

        self.selectionModel().setCurrentIndex(
            clickedItem,
            flags
        )
        isDeselect = bool(flags & QItemSelectionModel.SelectionFlag.Deselect)
        self._current_row_text = None if isDeselect else clickedItem.data()

    def handleShiftPressed(self):
        # in the viewport, the rows start at 1, but in the db at 0
        first_row = self._first_row_selected-2
        self.selectDbRows(first_row, self._last_row_selected)

    def handleMouseMoveEvent(self, row, clickedItem, selected):
        # this code serves to highlight rows while selecting rows by dragging
        # the mouse.
        if not selected:
            if clickedItem.data() in self._rows_selection:
                self._rows_selection.remove(clickedItem.data())
        else:
            self._rows_selection.add(clickedItem.data())

        self._last_row_selected = self.getViewportRowPos(row)
        # handle scrolling the view while dragging the mouse.
        self.scrollViewport(row)

    def onBeginViewportRefresh(self):
        # if the selected row due to scrolling up/down doesn't match with the
        # saved index, deselect the row, because the saved index is out of the
        # view.
        pass

    def onEndViewportRefresh(self):
        with self._lock:
            if not self.mousePressed and not self.shiftPressed and not self.keySelectAll:
                self.selectionModel().clear()
            if self.keySelectAll:
                self.selectDbRows(QSql.Location.BeforeFirstRow.value, QSql.Location.AfterLastRow.value)
            else:
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
        offset = self.model().queryOffset
        vmax = max(0, totalCount - self.maxRowsInViewport+1)
        if totalCount < self.maxRowsInViewport and offset > 0:
            vmax = self.maxRowsInViewport-5
        showScroll = False
        # we don't need to show the scrollbar if all the items fit in the
        # viewport.
        # However, if the user paginated the view and the last items fit in the
        # viewport, we still need to show the scrollbar to allow go back to the
        # previous view.
        if totalCount > self.maxRowsInViewport or (totalCount < self.maxRowsInViewport and offset > 0):
            showScroll = True
        self.vScrollBar.setVisible(showScroll)

        self.vScrollBar.setMinimum(0)
        # one scrollbar step is one row
        self.vScrollBar.setMaximum(vmax)
        self.model().refreshViewport(self.vScrollBar.value(), self.maxRowsInViewport, force=self.forceViewRefresh())

    def clearSelection(self):
        self.keySelectAll = False
        self.shiftPressed = False
        self.ctrlPressed = False
        self.selectionModel().clear()
        self.selectionModel().reset()
        self.selectionModel().clearCurrentIndex()
        self._rows_selection.clear()
        self._current_row_text = None
        self._first_row_selected = None
        self._last_row_selected = None

    def selectedRows(self, limit=""):
        if self.keySelectAll:
            return self.model().dumpRows(nolimits=True)
        if len(self._rows_selection) == 0:
            return

        # viewport_rows contains all the rows of the current query, regardless if
        # they're displayed in the view or not.
        viewport_rows = self.model().dumpRows()
        if viewport_rows is None:
            return
        rows = []
        for row in viewport_rows:
            cell = row[self.trackingCol]
            if cell not in self._rows_selection:
                continue
            rows.append(row)
        viewport_rows = None
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
        for text in self._rows_selection:
            items = self.model().findItems(text, column=self.trackingCol)
            if len(items) == 0:
                continue

            for i in items:
                sel.append(QItemSelectionRange(i.index()))
        self.selectionModel().clear()
        self.selectionModel().select(sel, QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
        self._restoreCurrentIndex()

    def _restoreCurrentIndex(self):
        """Re-apply the current (focused) row after the viewport has been
        refreshed. selectionModel().clear() drops currentIndex, so keyboard
        navigation would lose its position on every refresh otherwise.
        """
        if self._current_row_text is None:
            return
        items = self.model().findItems(self._current_row_text, column=self.trackingCol)
        if len(items) == 0:
            return
        self.selectionModel().setCurrentIndex(
            items[0].index(),
            QItemSelectionModel.SelectionFlag.NoUpdate
        )

    def _syncSelectionFromCurrentRow(self):
        """Sync the tracked rows with the row that became current after Qt
        processed a navigation key press. The view handles the key AFTER
        our eventFilter runs, so reading currentIndex there returns the row
        the user navigated AWAY from, leaving the tracked selection (and
        thus context-menu actions) one row behind the visible selection.
        """
        if self.ctrlPressed:
            # ctrl+navigation moves the current row without changing the
            # selection
            return
        curIdx = self.selectionModel().currentIndex()
        if not curIdx.isValid():
            return
        rowText = self.model().index(curIdx.row(), self.trackingCol).data()
        if rowText is None:
            return
        if not self.shiftPressed:
            self._rows_selection.clear()
        self._rows_selection.add(rowText)
        self._current_row_text = rowText

    def _selectLastRow(self):
        internalId = self.getCurrentIndex()
        self.selectionModel().setCurrentIndex(
            self.model().createIndex(self.maxRowsInViewport-1, self.trackingCol, internalId),
            QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.SelectCurrent
        )

    def _selectRow(self, pos):
        internalId = self.getCurrentIndex()
        self.selectionModel().setCurrentIndex(
            self.model().createIndex(pos, self.trackingCol, internalId),
            QItemSelectionModel.SelectionFlag.Rows | QItemSelectionModel.SelectionFlag.SelectCurrent
        )

    def onScrollbarValueChanged(self, vSBNewValue):
        totalRows = self.model().totalRowCount
        offset = self.model().queryOffset
        limit = self.model().queryLimit
        if vSBNewValue == self.vScrollBar.maximum() and totalRows == limit:
            self.vScrollBar.blockSignals(True)
            # position the scrollbar before querying the db, and avoid firing
            # an onScrollbarValueChanged event.
            self.vScrollBar.setValue(0)
            self.vScrollBar.blockSignals(False)
            self.model().nextRecord(limit)
        elif vSBNewValue == 0 and offset != 0:
            self.model().prevRecord(limit)
            # the scrollbar in this case must be positioned after the query,
            # in order to override it.
            self.vScrollBar.blockSignals(True)
            self.vScrollBar.setValue(self.vScrollBar.maximum())
            self.vScrollBar.blockSignals(False)
        else:
            self.model().refreshViewport(vSBNewValue, self.maxRowsInViewport, force=True)

    def onKeyUp(self):
        curIdx = self.selectionModel().currentIndex()
        viewport_row = self.getViewportRowPos(curIdx.row())
        self._last_row_selected = viewport_row
        if self._first_row_selected is None:
            self._first_row_selected = viewport_row

        offset = self.model().queryOffset
        if curIdx.row() == 0:
            self.vScrollBar.setValue(max(0, self.vScrollBar.value() - 1))
        if curIdx.row() == 0 and viewport_row+offset-1 == offset:
            self._selectLastRow()

    def onKeyDown(self):
        curIdx = self.selectionModel().currentIndex()
        curRow = curIdx.row()
        viewport_row = self.getViewportRowPos(curRow)

        newValue = self.vScrollBar.value()

        limit = self.model().queryLimit
        if curRow >= self.maxRowsInViewport-2:
            # this change will fire onScrollbarValueChanged, which will refresh the
            # view (the rows and the rows numbers)
            self.vScrollBar.setValue(newValue+1)
            self._selectLastRow()
        # wrap the selection to the first row after paginating to the next
        # records window. The query offset cancels out on both sides of the
        # comparison, so checking against the limit alone is enough.
        if viewport_row == limit:
            self._selectRow(0)

    def onKeyHome(self):
        self._last_row_selected = self._first_row_selected
        self._first_row_selected = 0
        self.vScrollBar.blockSignals(True)
        self.vScrollBar.setValue(0)
        self.vScrollBar.blockSignals(False)
        if not self.mousePressed and not self.shiftPressed:
            self.selectionModel().clear()
        if self.shiftPressed:
            self.selectDbRows(self._first_row_selected-1, self._last_row_selected)
        self._selectRow(0)

    def onKeyEnd(self):
        self.vScrollBar.setValue(self.vScrollBar.maximum())
        if not self.mousePressed and not self.shiftPressed and not self.ctrlPressed:
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
                QTimer.singleShot(0, self._syncSelectionFromCurrentRow)
            elif event.key() == Qt.Key.Key_Down:
                self.onKeyDown()
                QTimer.singleShot(0, self._syncSelectionFromCurrentRow)
            elif event.key() == Qt.Key.Key_Home:
                self.onKeyHome()
                QTimer.singleShot(0, self._syncSelectionFromCurrentRow)
            elif event.key() == Qt.Key.Key_End:
                self.onKeyEnd()
                QTimer.singleShot(0, self._syncSelectionFromCurrentRow)
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

        elif event.type() == QEvent.Type.Wheel:
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                hBar = self.horizontalScrollBar()
                delta = event.angleDelta().y()
                step = hBar.singleStep() * 2
                hBar.setValue(hBar.value() - (step if delta > 0 else -step))
                return True

            if event.angleDelta().y() != 0:
                self.vScrollBar.wheelEvent(event)
                return True

        return super(GenericTableView, self).eventFilter(obj, event)
