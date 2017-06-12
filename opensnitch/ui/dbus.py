# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Adam Hose
# adis@blad.is
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
from collections import namedtuple
from PyQt5 import QtCore, QtDBus
import logging


UIConnection = namedtuple('UIConnection', (
    'id',
    'hostname',
    'dst_port',
    'dst_addr',
    'proto',
    'app_pid',
    'app_path',
    'app_cmdline',
))


class DBusHandler(QtCore.QObject):

    def __init__(self, app, parent):
        self.parent = parent
        self.app = app
        super().__init__(app)

        self.__dbus = QtDBus.QDBusConnection.sessionBus()
        self.__dbus.registerObject('/', self)
        self.interface = QtDBus.QDBusInterface(
            'io.opensnitch.service',
            '/',
            'io.opensnitch.service',
            self.__dbus)

        if not self.interface.isValid():
            raise RuntimeError('Could not connect to dbus')
        logging.info('Connected to dbus service')

        sig_connect = self.__dbus.connect(
            'io.opensnitch.service',
            '/',
            'io.opensnitch.service',
            'prompt',
            self.prompt_user)
        if not sig_connect:
            raise RuntimeError('Could not connect dbus signal')
        logging.info('Connected dbus signal')

    @QtCore.pyqtSlot(QtDBus.QDBusMessage)
    def prompt_user(self, msg):
        args = msg.arguments()
        connection = UIConnection(*args)
        self.parent.connection_queue.put(connection)
        self.parent.dialog.add_connection_signal.emit()
