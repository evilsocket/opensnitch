#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.import sys

from PyQt6.QtWidgets import (
    QCompleter
)

class Completer(QCompleter):
    def __init__(self, parent=None):
        QCompleter.__init__(self, parent)

    def pathFromIndex(self, modelIdx):
        keyword = QCompleter.pathFromIndex(self, modelIdx)
        path = self.widget().text()

        lst = str(self.widget().text()).split(' ')
        if len(lst) == 0:
            return path

        if len(lst) == 1:
            return path.replace(lst[0], keyword)

        partial = lst[:-1]
        if len(partial) > 0 and partial[1] in keyword:
            path = path.replace(partial[1], keyword)
            return path
        if len(partial) > 0 and partial[1] not in keyword:
            path = '%s %s' % (' '.join(partial), keyword)
            return path
        if keyword not in path:
            path = '%s%s' % (' '.join(lst[:-1]), keyword)
            return path

        return path

    def splitPath(self, path):
        path = str(path.split('.')[-1]).lstrip(' ')
        return [path]
