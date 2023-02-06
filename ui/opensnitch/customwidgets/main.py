from PyQt5 import QtCore
from PyQt5.QtGui import QColor, QStandardItemModel, QStandardItem
from PyQt5.QtSql import QSqlQueryModel, QSqlQuery, QSql
from PyQt5.QtWidgets import QTableView
from PyQt5.QtCore import QItemSelectionModel, pyqtSignal, QEvent
import time
import math

from PyQt5.QtCore import QCoreApplication as QC
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

class ConnectionsTableModel(QStandardItemModel):
    rowCountChanged = pyqtSignal()

    #max rowid in the db; starts with 1, not with 0
    maxRowId = 0
    #previous total number of rows in the db when the filter was applied
    prevFiltRowCount = 0
    #total number of rows in the db when the filter was not applied
    prevNormRowCount = 0
    #total row count which must de displayed in the view
    totalRowCount = 0
    #new rows which must be added to the top of the rows displayed in the view
    prependedRowCount = 0

    db = None
    #original query string before we modify it
    origQueryStr = QSqlQuery()
    #modified query object
    realQuery = QSqlQuery()
    #previous original query string; used to check if the query has changed
    prevQueryStr = ''
    #whether or not the original query has a filter (a WHERE condition)
    isQueryFilter = False
    limit = None

    #a map for fast lookup or rows when filter is enabled
    #contains ranges of rowids and count of filter hits
    #range format {'from': <rowid>, 'to': <rowid>, 'hits':<int>}
    #including the 'from' rowid up to but NOT including the 'to' rowid
    map = []
    rangeSize = 1000
    #all unique/distinct values for each column will be stored here
    distinct = {'time':[], 'process':[], 'dst_host':[], 'dst_ip':[], 'dst_port':[], 'rule':[], 'node':[], 'protocol':[]}
    #what was the last rowid\time when the distinct value were updates
    distinctLastRowId = 0
    distinctLastUpdateTime = time.time()

    def __init__(self):
        self.headerLabels = [
            QC.translate("stats", "Time", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Node", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Action", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Destination", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Protocol", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Process", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Rule", "This is a word, without spaces and symbols.").replace(" ", ""),
        ]
        QStandardItemModel.__init__(self, 0, len(self.headerLabels))
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

    def setQuery(self, q, db):
        self.origQueryStr = q
        self.db = db
        maxRowIdQuery = QSqlQuery(db)
        maxRowIdQuery.setForwardOnly(True)
        maxRowIdQuery.exec("SELECT MAX(rowid) FROM connections")
        maxRowIdQuery.first()
        value = maxRowIdQuery.value(0)
        self.maxRowId = 0 if value == '' else int(value)
        self.updateDistinctIfNeeded()
        self.limit = int(q.split(' ')[-1]) if q.split(' ')[-2] == 'LIMIT' else None
        self.isQueryFilter = True if ("LIKE '%" in q and "LIKE '% %'" not in q) or 'Action = "' in q else False

        self.realQuery = QSqlQuery(db)
        isTotalRowCountChanged = False
        isQueryChanged = False
        if self.prevQueryStr != q:
            isQueryChanged = True
        if self.isQueryFilter:
            if isQueryChanged:
                self.buildMap()
            largestRowIdInMap = self.map[0]['from']
            newRowsCount = self.maxRowId - largestRowIdInMap
            self.prependedRowCount = 0

            if newRowsCount > 0:
                starttime = time.time()
                self.realQuery.setForwardOnly(True)
                for offset in range(0, newRowsCount, self.rangeSize):
                    lowerBound = largestRowIdInMap + offset
                    upperBound = min(lowerBound + self.rangeSize, self.maxRowId)
                    part1, part2 = q.split('ORDER')
                    qStr = part1 + 'AND rowid>'+ str(lowerBound) + ' AND rowid<=' + str(upperBound) + ' ORDER' + part2
                    self.realQuery.exec(qStr)
                    self.realQuery.last()
                    rowsInRange = max(0, self.realQuery.at()+1)
                    if self.map[0]['from'] - self.map[0]['to'] < self.rangeSize:
                        #consolidate with the previous range; we don't want many small ranges
                        self.map[0]['from'] = upperBound
                        self.map[0]['hits'] += rowsInRange
                    else:
                        self.map.insert(0, {'from':upperBound, 'to':lowerBound, 'hits':rowsInRange})
                    self.prependedRowCount += rowsInRange
                    if time.time() - starttime > 0.5:
                        #dont freeze the UI when fetching too many recent rows
                        break

            self.totalRowCount = 0
            for i in self.map:
                self.totalRowCount += i['hits']
            if self.totalRowCount != self.prevFiltRowCount:
                isTotalRowCountChanged = True
                self.prevFiltRowCount = self.totalRowCount
        else: #self.isQueryFilter == False
            self.prependedRowCount = self.maxRowId - self.prevNormRowCount
            self.totalRowCount = self.maxRowId
            if self.totalRowCount != self.prevNormRowCount:
                isTotalRowCountChanged = True
                self.prevNormRowCount = self.totalRowCount

        self.prevQueryStr = self.origQueryStr
        if isTotalRowCountChanged or self.prependedRowCount > 0 or isQueryChanged:
            self.rowCountChanged.emit()

    #fill self.map with data
    def buildMap(self):
        self.map = []
        q = QSqlQuery(self.db)
        q.setForwardOnly(True)
        self.updateDistinctIfNeeded(True)
        filterStr = self.getFilterStr()
        actionStr = self.getActionStr()
        #we only want to know the count of matching rows
        qStr = "SELECT COUNT(*) from connections WHERE (rowid> :lowerBound AND rowid<= :upperBound)"
        if actionStr:
            qStr += ' AND ' + actionStr
        matchStr = self.getMatch(filterStr) if filterStr else None
        if matchStr:
            qStr += ' AND ' + matchStr
        qStr += ' LIMIT ' + str(self.limit) if self.limit else ''
        q.prepare(qStr)

        totalRows = 0
        for offset in range(self.maxRowId, -1, -self.rangeSize):
            upperBound = offset
            lowerBound = max(0, upperBound - self.rangeSize)
            if (not filterStr and actionStr) or (filterStr and matchStr):
                #either 1) only action was present or 2) filter which has a match (with or without action)
                q.bindValue(":lowerBound", str(lowerBound))
                q.bindValue(":upperBound", str(upperBound))
                q.exec_()
                q.first()
                rowsInRange = int(q.value(0))
            else:
                rowsInRange = 0
            totalRows += rowsInRange
            self.map.append({'from':upperBound, 'to':lowerBound, 'hits':rowsInRange})
            if self.limit and totalRows >= self.limit:
                break

    #periodically keep track of all distinct values for each column
    #this is needed in order to build efficient queries when the filter is applied
    def updateDistinctIfNeeded(self, force=False):
        if (not force and (time.time() - self.distinctLastUpdateTime) < 10) or self.maxRowId == self.distinctLastRowId:
            return
        if (self.maxRowId < self.distinctLastRowId):
            #the db has been cleared, re-init the values
            self.distinctLastRowId = 0
            self.distinct = {'time':[], 'process':[], 'dst_host':[], 'dst_ip':[], 'dst_port':[], 'rule':[], 'node':[], 'protocol':[]}
        q = QSqlQuery(self.db)
        q.setForwardOnly(True)
        for column in self.distinct.keys():
            q.exec('SELECT DISTINCT ' + column + ' FROM connections WHERE rowid>'
            + str(self.distinctLastRowId) + ' AND rowid<=' + str(self.maxRowId))
            while q.next():
                if q.value(0) not in self.distinct[column]:
                    self.distinct[column].append(q.value(0))
        self.distinctLastRowId =self.maxRowId
        self.distinctLastUpdateTime = time.time()

    #refresh the viewport with data from the db
    #"value" is vertical scrollbar's value
    def refreshViewport(self, value, maxRowsInViewport):
        q = QSqlQuery(self.db)
        #sequential number of topmost/bottommost rows in viewport (numbering starts from the bottom with 1 not with 0)
        botRowNo = max(1, self.totalRowCount - (value + maxRowsInViewport-1))
        topRowNo = min(botRowNo + maxRowsInViewport-1, self.totalRowCount)

        if not self.isQueryFilter:
            part1, part2 = self.origQueryStr.split('ORDER')
            qStr = part1 + 'WHERE rowid>='+ str(botRowNo) + ' AND rowid<=' + str(topRowNo) + ' ORDER' + part2
        else:
            self.updateDistinctIfNeeded(True)
            #replace query part between WHERE and ORDER
            qStr = self.origQueryStr.split('WHERE')[0] + ' WHERE '
            actionStr = self.getActionStr()
            if actionStr:
                qStr += actionStr + " AND "
            #find inside the map the range(s) in which top and bottom rows are located
            total, offsetInRange, botRowFound, topRowFound = 0, None, False, False
            ranges = [{'from':0, 'to':0, 'hits':0}]
            for i in reversed(self.map):
                if total + i['hits'] >= botRowNo:
                    botRowFound = True
                if total + i['hits'] >= topRowNo:
                    topRowFound = True
                if botRowFound and i['hits'] > 0:
                    if i['to'] == ranges[-1]['from']:
                        #merge two adjacent ranges
                        ranges[-1]['from'] = i['from']
                        ranges[-1]['hits'] += i['hits']
                    else:
                        ranges.append(i.copy())
                if topRowFound:
                    offsetInRange = i['hits'] - (topRowNo - total)
                    break
                total += i['hits']

            rangeStr = ''
            if len(ranges) > 0:
                rangeStr = '('
                for r in ranges:
                    rangeStr += '(rowid>' + str(r['to']) + ' AND rowid<=' + str(r['from']) + ') OR '
                rangeStr = rangeStr[:-3] #remove trailing 'OR '
                rangeStr += ') AND '
            qStr += rangeStr

            filterStr = self.getFilterStr()
            matchStr = self.getMatch(filterStr) if filterStr else None
            if matchStr:
                qStr += matchStr + " AND "
            qStr = qStr[:-4] #remove trailing ' AND'
            qStr += ' ORDER '+ self.origQueryStr.split('ORDER')[1]

        q.exec(qStr)
        q.last()
        rowsFound = max(0, q.at()+1)
        if not self.isQueryFilter:
            q.seek(QSql.BeforeFirstRow)
        else:
            #position the db cursor on topRowNo
            q.seek(QSql.BeforeFirstRow if offsetInRange == 0 else offsetInRange-1)
        upperBound = min(maxRowsInViewport, rowsFound)
        self.setRowCount(upperBound)
        #only visible rows will be filled with data
        if upperBound > 0:
            #don't trigger setItem's signals for each cell, instead emit dataChanged for all cells
            self.blockSignals(True)
            for x in range(0, upperBound):
                q.next()
                for col in range(0, len(self.headerLabels)):
                    self.setItem(x, col, QStandardItem(q.value(col)))
            self.blockSignals(False)
            self.dataChanged.emit(self.createIndex(0,0), self.createIndex(upperBound, len(self.headerLabels)))

    #form a condition string for the query: if filterStr is (partially) present in any of the columns
    def getMatch (self, filterStr):
        match = {}
        for column in self.distinct.keys():
            match[column] = []
            for value in self.distinct[column]:
                if filterStr in value:
                    match[column].append(value)
        matchStr = None
        if any([match[col] for col in match]):
            matchStr = '( '
            if match['time']:
                matchStr += "time IN ('" + "','".join(match['time']) + "') OR"
            if match['process']:
                matchStr += "process IN ('" + "','".join(match['process']) + "') OR"
            if match['dst_host']:
                matchStr += " (dst_host != '' AND dst_host IN ('" + "','".join(match['dst_host']) + "') ) OR"
            if match['dst_ip']:
                matchStr += " (dst_host = '' AND dst_ip IN ('" + "','".join(match['dst_ip']) + "') ) OR"
            if match['dst_port']:
                matchStr += " dst_port IN ('" + "','".join(match['dst_port']) + "') OR"
            if match['rule']:
                matchStr += " rule IN ('" + "','".join(match['rule']) + "') OR"
            if match['node']:
                matchStr += " node IN ('" + "','".join(match['node']) + "') OR"
            if match['protocol']:
                matchStr += " protocol IN ('" + "','".join(match['protocol']) + "') OR"
            matchStr = matchStr[:-2] #remove trailing 'OR'
            matchStr += ' )'
        return matchStr

    #extract the filter string if any
    def getFilterStr(self):
        filterStr = None
        if "LIKE '%" in self.origQueryStr:
            filterStr = self.origQueryStr.split("LIKE '%")[1].split("%")[0]
        return filterStr

    #extract the action string if any
    def getActionStr(self):
        actionStr = None
        if 'WHERE Action = "' in self.origQueryStr:
            actionCond = self.origQueryStr.split('WHERE Action = "')[1].split('"')[0]
            actionStr = "action = '"+actionCond+"'"
        return actionStr

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

class ConnectionsTableView(QTableView):
    # how many rows can potentially be displayed in viewport
    # the actual number of rows currently displayed may be less than this
    maxRowsInViewport = 0
    #vertical scroll bar
    vScrollBar = None

    def __init__(self, parent):
        QTableView.__init__(self, parent)
        #eventFilter to catch key up/down events and wheel events
        self.installEventFilter(self)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignCenter)
        self.horizontalHeader().setStretchLastSection(True)
        #the built-in vertical scrollBar of this view is always off
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

    def setVerticalScrollBar(self, vScrollBar):
        self.vScrollBar = vScrollBar
        self.vScrollBar.valueChanged.connect(self.onValueChanged)
        self.vScrollBar.setVisible(False)

    def setModel(self, model):
        super().setModel(model)
        model.rowCountChanged.connect(self.onRowCountChanged)
        model.rowsInserted.connect(self.onRowsInsertedOrRemoved)
        model.rowsRemoved.connect(self.onRowsInsertedOrRemoved)
        self.horizontalHeader().sortIndicatorChanged.disconnect()
        self.setSortingEnabled(False)

    #model().rowCount() is always <= self.maxRowsInViewport
    #stretch the bottom row; we don't want partial-height rows at the bottom
    #this will only trigger if rowCount value was changed
    def onRowsInsertedOrRemoved(self, parent, start, end):
        if self.model().rowCount() == self.maxRowsInViewport:
            self.verticalHeader().setStretchLastSection(True)
        else:
            self.verticalHeader().setStretchLastSection(False)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        #refresh the viewport data based on new geometry
        self.calculateRowsInViewport()
        self.model().setRowCount(min(self.maxRowsInViewport, self.model().totalRowCount))
        self.model().refreshViewport(self.vScrollBar.value(), self.maxRowsInViewport)

    def calculateRowsInViewport(self):
        rowHeight = self.verticalHeader().defaultSectionSize()
        #we don't want partial-height rows in viewport, hence .floor()
        self.maxRowsInViewport = math.floor(self.viewport().height() / rowHeight)

    def onValueChanged(self, vSBNewValue):
        savedIndex = self.selectionModel().currentIndex()
        self.model().refreshViewport(vSBNewValue, self.maxRowsInViewport)
        #restore selection which was removed by model's refreshing the data
        self.selectionModel().setCurrentIndex(savedIndex, QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)

    # if ( scrollbar at the top or row limit set):
    #   let new rows "push down" older rows without changing the scrollbar position
    # else:
    #   don't update data in viewport, only change scrollbar position.
    def onRowCountChanged(self):
        totalCount = self.model().totalRowCount
        scrollBar = self.vScrollBar
        scrollBar.setVisible(True if totalCount > self.maxRowsInViewport else False)
        scrollBarValue = scrollBar.value()
        if self.model().limit:
            newValue = min(scrollBarValue, self.model().limit - self.maxRowsInViewport)
            scrollBar.setMinimum(0)
            scrollBar.setMaximum( min(totalCount, self.model().limit) - self.maxRowsInViewport)
            if scrollBarValue != newValue:
                #setValue does not trigger valueChanged if new value is the same as old
                scrollBar.setValue(newValue)
            else:
                scrollBar.valueChanged.emit(newValue)
        else:
            scrollBar.setMinimum(0)
            scrollBar.setMaximum(max(0, totalCount - self.maxRowsInViewport))
            if scrollBarValue == 0:
                scrollBar.valueChanged.emit(0)
            elif scrollBarValue > 0:
                if self.model().prependedRowCount == 0:
                    scrollBar.valueChanged.emit(scrollBarValue)
                else:
                    scrollBar.setValue(scrollBarValue + self.model().prependedRowCount)

    def onKeyUp(self):
        if self.selectionModel().currentIndex().row() == 0:
            self.vScrollBar.setValue(self.vScrollBar.value() - 1)

    def onKeyDown(self):
        if self.selectionModel().currentIndex().row() == self.maxRowsInViewport - 1:
            self.vScrollBar.setValue(self.vScrollBar.value() + 1)

    def onKeyHome(self):
        self.vScrollBar.setValue(0)
        self.selectionModel().setCurrentIndex(self.model().createIndex(0, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)

    def onKeyEnd(self):
        self.vScrollBar.setValue(self.vScrollBar.maximum())
        self.selectionModel().setCurrentIndex(self.model().createIndex(min(self.maxRowsInViewport, self.model().totalRowCount) - 1, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)

    def onKeyPageUp(self):
        #scroll up only when on the first row
        if self.selectionModel().currentIndex().row() != 0:
            return
        self.vScrollBar.setValue(self.vScrollBar.value() - self.maxRowsInViewport)

    def onKeyPageDown(self):
        #scroll down only when on the last row
        if self.selectionModel().currentIndex().row() != self.maxRowsInViewport - 1:
            return
        self.vScrollBar.setValue(self.vScrollBar.value() + self.maxRowsInViewport)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Up:
                self.onKeyUp()
            elif event.key() == QtCore.Qt.Key_Down:
                self.onKeyDown()
            elif event.key() == QtCore.Qt.Key_Home:
                self.onKeyHome()
            elif event.key() == QtCore.Qt.Key_End:
                self.onKeyEnd()
            elif event.key() == QtCore.Qt.Key_PageUp:
                self.onKeyPageUp()
            elif event.key() == QtCore.Qt.Key_PageDown:
                self.onKeyPageDown()
        elif event.type() == QEvent.Wheel:
            self.vScrollBar.wheelEvent(event)
        return False
