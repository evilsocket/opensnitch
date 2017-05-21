# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
from PyQt5 import QtWidgets
import queue
import sys
import os

from .desktop_parser import LinuxDesktopParser
from .dialog import Dialog


# TODO: Implement tray icon and menu.
# TODO: Implement rules editor.
RESOURCES_PATH = "%s/resources/" % os.path.dirname(
    sys.modules[__name__].__file__)
DIALOG_UI_PATH = "%s/dialog.ui" % RESOURCES_PATH


class QtApp:
    def __init__(self, connection_futures, rules):
        self.desktop_parser = LinuxDesktopParser()
        self.app = QtWidgets.QApplication([])
        self.connection_queue = queue.Queue()
        self.rules = rules
        self.dialog = Dialog(self, connection_futures, self.desktop_parser)

    def run(self):
        self.app.exec()

    def prompt_user(self, connection):
        self.connection_queue.put(connection)
        self.dialog.add_connection_signal.emit()
