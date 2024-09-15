from PyQt5 import Qt, QtCore
from PyQt5.QtGui import QColor

from opensnitch.plugins import PluginBase, PluginSignal

# PyQt5 >= v5.15.8 (#821)
if hasattr(Qt, 'QStyle'):
    from PyQt5.Qt import QStyle
else:
    from PyQt5.QtWidgets import QStyle


class Highlight(PluginBase):
    """Customizes QTablewView cells via QItemDelegates.
    Format:
    "highlight": {
      "cells": [
        {
          "text": ["allow", "True"],
          "cols": [3, 4],
          "color": "green",
          "bgcolor": "",
          "alignment": ["center"]
        }
      ]
      "rows":[
        {
          "text": ["False"],
          "cols": [3],
          "color": "black",
          "bgcolor": "darkgray"
        }
      ]
    }

    cells: rules will be applied only on individual cells.
    rows: rules will be applied to rows on the given columns.

    Fields:
      text: will match any of the given texts (the comparison is an OR operation).
      cols: look for patterns on these columns.
      color: colorizes the color of the text.
      bgcolor: colorizes the background color of the cell.
    etc.

    Color names: https://doc.qt.io/qt-6/qcolor.html#predefined-colors

    Notes:
     - There're 3 default configurations that are applied on the views:
         - commonDelegateConfig, defaultRulesDelegateConfig and
         defaultFWDelegateConfig

        Creating/Copying these configurations under
        XDG_CONFIG_HOME/.config/opensnitch/actions/ allows to overwrite and hence
        personalize the views highlighting colors.

     - The order of the "rules" are applied from top to bottom, meaning that
     the last "rule" of the "cells" or "rows" arrays will override previous
     rules if there're conflicts. For example:

     [Rules tab]
        Action | Name                | Enabled | ...
         deny  | allow-always-telnet |  False  | ...

    Config:
       "rows": [
          {
              "text": ["False"],
              "cols": [3],
              "color": "black",
              "bgcolor": "darkgray"
          },
          {
              "text": ["allow"],
              "cols": [4],
              "color": "white",
              "bgcolor": "green"
          }
       ]

    In this example, the background color of this row will always be green,
    because the latest "rule" will be the one that will be applied.
    It may have more sense to put the first "rule" last, to properly colorize
    not enabled rules.

    """
    name = "Highlight"
    version = "0.1"
    author = "opensnitch"
    created = ""
    modified = ""
    #enabled = True

    # where this plugin is allowed
    TYPE = [PluginBase.TYPE_VIEWS]

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


    def __init__(self, config=None):
        # original json config received
        self._config = config
        self._last_visited_row = -1
        self._rowcells = ""
        self.signal_in.connect(self.cb_signal)

    def get_name(self):
        return self.name

    def is_enabled(self):
        return self.enabled

    def set_enabled(self, enable):
        self.enabled = enable

    def get_description(self):
        return self.description

    def configure(self):
        # TODO: allow to configure rules from the GUI
        #  - add button(s) to the rules editor dialog, to allow choose a color
        #  for a row based on patterns.
        #  - create a dialog to configure new rules.
        pass

    def _compile(self, what):
        cell_list = self._config.get(what)
        if cell_list == None:
            print("highlight plugin: configuration has no '{0}' configuration".format(what))
            return
        for cell in cell_list:
            for item in cell:
                # colors
                if (item == Highlight.COLOR or item == Highlight.BGCOLOR):
                    if cell[item] != "" and cell[item] is not None:
                        try:
                            cell[item] = QColor(cell[item])
                        except Exception as e:
                            cell[item] = None
                    else:
                        cell[item] = None

                # alignments
                if item == Highlight.ALIGNMENT:
                    cell[item] = self.getAlignment(cell[item])

                # TODO: fonts
                #if item == Highlight.FONT:
                #    cell[item] = self.getFont(cell[item])

        return self._config

    def compile(self):
        """transform json items to Qt objects.
        These items are transformed:
            - color (to QColor), bgcolor (to QColor), alignment (to Qt.Align*),
            font (to QFont TODO)

            Return the original json object transformed.
        """
        self._config = self._compile(Highlight.CELLS)
        self._config = self._compile(Highlight.ROWS)
        return self._config

    def run(self, parent, args):
        """Highlight cells or rows based on patterns.

        Return if the cell was modified.

        Keyword arguments:
            args -- tuple of options.
        """
        #parent == ColorizedDelegate
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
        #print(type(self), ">", type(parent), ">", type(option.widget))

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
                    index,
                    defaultPen,
                    defaultBrush,
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
            try:
                # TODO: check for NoneType
                self._rowcells = " ".join(
                    [index.sibling(curRow, col).data() for col in range(0, modelColumns)]
                )
            except:
                pass
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
                index,
                defaultPen,
                defaultBrush,
                cellAlignment,
                cellRect,
                cellColor,
                cellBgColor,
                cellValue)

        return (modified,)

    def paintCell(self,
                  style,
                  painter,
                  option,
                  index,
                  defaultPen,
                  defaultBrush,
                  cellAlignment,
                  cellRect,
                  cellColor,
                  cellBgColor,
                  cellValue):
        cellSelected = option.state & QStyle.State_Selected

        painter.save()
        # don't customize selected state
        if not cellSelected:
            if cellBgColor:
                painter.fillRect(option.rect, cellBgColor)

            if cellColor:
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

    def stop(self):
        pass

    def cb_signal(self, signal):
        #print("Plugin.signal received:", self.name, signal)
        try:
            if signal['signal'] == PluginSignal.ENABLE:
                self.enabled = True
        except Exception as e:
            print("Plugin.Highlight.cb_signal() exception:", e)
