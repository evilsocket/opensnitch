from PyQt5 import Qt, QtCore
from PyQt5.QtGui import QColor, QStandardItemModel, QStandardItem

# PyQt5 >= v5.15.8 (#821)
if hasattr(Qt, 'QStyle'):
    from PyQt5.Qt import QStyle
else:
    from PyQt5.QtWidgets import QStyle

class Highlight():
    """Customizes QTablewView cells via QItemDelegates.
    Format:
    [
        {
            'text': {"allow", "True", "online"},
            'cols': {1,4,5},
            'color': "green",
            'bgcolor': None,
            'alignment': ["center"],
            #"margins': [0, 0]
            #'font': {}
        },
    ]

    text: will match any of the given texts.
    cols: look for patterns on these columns.
    color: colorizes the color of the text.
    bgcolor: colorizes the background color of the cell.
    etc.
    """

    NAME = "highlight"

    MARGINS = "margins"
    ALIGNMENT = "alignment"
    # QtCore.Qt.AlignCenter
    ALIGN_CENTER = "center"
    # QtCore.Qt.AlignHCenter
    ALIGN_HCENTER = "hcenter"
    # QtCore.Qt.AlignVCenter
    ALIGN_VCENTER = "vcenter"

    COLOR = "color"
    BGCOLOR = "bgcolor"
    FONT = "font"
    CELLS = "cells"
    ROWS = "rows"
    COLS = "cols"
    TEXT = "text"

    def __init__(self, config):
        # original json config received
        self._config = config
        self._last_visited_row = -1
        self._rowcells = ""

    def compile(self):
        """transform json items to Qt objects.
        These items are transformed:
            - color (to QColor), bgcolor (to QColor), alignment (to Qt.Align*),
            font (to QFont TODO)

            Return the original json object transformed.
        """
        # cells, rows
        for idx in self._config:
            cells = self._config[idx]
            for cell in cells:
                for item in cell:
                    # colors
                    if (item == Highlight.COLOR or item == Highlight.BGCOLOR):
                        if cell[item] != "" and cell[item] is not None:
                            cell[item] = QColor(cell[item])
                        else:
                            cell[item] = None

                    # alignments
                    if item == Highlight.ALIGNMENT:
                        cell[item] = self.getAlignment(cell[item])

                    # fonts
                    if item == Highlight.FONT:
                        self.getFont(cell[item])

        return self._config


    def run(self, args):
        """Highlight cells or rows based on patterns.

        Return if the cell was modified.

        Keyword arguments:
            args -- tuple of options.
        """
        painter = args[0]
        option = args[1]
        index = args[2]
        style = args[3]
        modelColumns = args[4]
        curRow = args[5]
        curColumn = args[6]
        defaultPen = args[7]
        defaultBrush = args[8]
        cellAlignment = args[9]
        cellRect = args[10]
        cellValue = args[11]

        # signal that this cell has been modified
        modified = False

        cells = self._config.get(Highlight.CELLS)
        rows = self._config.get(Highlight.ROWS)

        if cells:
            for cell in cells:
                if curColumn not in cell[Highlight.COLS]:
                    continue
                if cellValue not in cell[Highlight.TEXT]:
                    continue
# TODO
#                if cell['operator'] == 'simple' and cellValue != cell['text']:
#                    continue
#                elif cell['text'] not in cellValue:
#                    continue

                cellColor = cell.get(Highlight.COLOR)
                cellBgColor = cell.get(Highlight.BGCOLOR)
                if cell.get(Highlight.ALIGNMENT) != None:
                    cellAlignment = cell[Highlight.ALIGNMENT]
                if cell.get(Highlight.MARGINS) != None:
                    cellRect.adjust(
                        int(cell[Highlight.MARGINS][self.HMARGIN]),
                        int(cell[Highlight.MARGINS][self.VMARGIN]),
                        -defaultPen.width(),
                        -defaultPen.width()
                    )

                modified=True
                self.paintCell(
                    style,
                    painter,
                    option,
                    defaultPen,
                    cellAlignment,
                    cellRect,
                    cellColor,
                    cellBgColor,
                    cellValue)

        if len(rows) == 0:
            return (modified,)

        # get row's cells only for the first cell of the row,
        # then reuse them for the rest of the cells of the current row.
        if curRow != self._last_visited_row:
            self._rowcells = " ".join(
                [index.sibling(curRow, col).data() for col in range(0, modelColumns)]
            )
        self._last_visited_row = curRow

        for row in rows:
            skip = True
            for text in row[Highlight.TEXT]:
                if text in self._rowcells:
                    skip = False
            if skip:
                continue

            cellColor = row.get(Highlight.COLOR)
            cellBgColor = row.get(Highlight.BGCOLOR)
            if row.get(Highlight.ALIGNMENT) != None:
                cellAlignment = row[Highlight.ALIGNMENT]
            if row.get(Highlight.MARGINS) != None:
                cellRect.adjust(
                    int(row[Highlight.MARGINS][self.HMARGIN]),
                    int(row[Highlight.MARGINS][self.VMARGIN]),
                    -defaultPen.width(),
                    -defaultPen.width()
                )

            modified=True
            self.paintCell(
                style,
                painter,
                option,
                defaultPen,
                cellAlignment,
                cellRect,
                cellColor,
                cellBgColor,
                cellValue)

        return (modified,)

    def paintCell(self, style, painter, option, defaultPen, cellAlignment, cellRect, cellColor, cellBgColor, cellValue):
        cellSelected = option.state & QStyle.State_Selected

        painter.save()
        # don't customize selected state
        if not cellSelected:
            if cellBgColor != None:
                painter.fillRect(option.rect, cellBgColor)

            if cellColor is not None:
                defaultPen.setColor(cellColor)
        painter.setPen(defaultPen)

        # setting option.displayAlignment has no effect here, so we need to
        # draw the text.
        # FIXME: Drawing the text though, the background color of the SelectedState is
        # altered.
        # If we called super().paint(), modifying option.palette.* would be
        # enough to change the text color, but it wouldn't be aligned:
        # option.palette.setColor(QPalette.Text, cellColor)
        style.drawItemText(painter, cellRect, cellAlignment, option.palette, True, cellValue)
        painter.restore()

    def getAlignment(self, alignments):
        alignFlags = 0
        for align in alignments:
            if align == Highlight.ALIGN_CENTER:
                alignFlags |= QtCore.Qt.AlignCenter
            elif align == Highlight.ALIGN_HCENTER:
                alignFlags |= QtCore.Qt.AlignHCenter
            elif align == Highlight.ALIGN_VCENTER:
                alignFlags |= QtCore.Qt.AlignVCenter

        if alignFlags == 0:
            return None

        return alignFlags

    def getFont(self, font):
        # TODO
        pass
