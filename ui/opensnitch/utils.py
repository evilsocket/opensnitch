
from PyQt5 import QtCore, QtWidgets, QtGui
from opensnitch.version import version
from opensnitch.database import Database
from opensnitch.config import Config
from threading import Thread, Event
import pwd
import socket
import fcntl
import struct
import array

class CleanerTask(Thread):
    interval = 1
    stop_flag = None
    callback = None

    def __init__(self, _interval, _callback):
        Thread.__init__(self)
        self.interval = _interval
        self.stop_flag = Event()
        self.callback = _callback
        self._cfg = Config.init()

        # We need to instantiate a new QsqlDatabase object with a unique name,
        # because it's not thread safe:
        # "A connection can only be used from within the thread that created it."
        # https://doc.qt.io/qt-5/threads-modules.html#threads-and-the-sql-module
        # The filename and type is the same, the one chosen by the user.
        self.db = Database("db-cleaner")
        self.db_status, db_error = self.db.initialize(
            dbtype=self._cfg.getInt(self._cfg.DEFAULT_DB_TYPE_KEY),
            dbfile=self._cfg.getSettings(self._cfg.DEFAULT_DB_FILE_KEY)
        )

    def run(self):
        if self.db_status == False:
            return
        while not self.stop_flag.wait(self.interval):
            if self.stop_flag.is_set():
                break
            self.callback(self.db)

    def stop(self):
        self.stop_flag.set()

class QuickHelp():
    @staticmethod
    def show(help_str):
        QtWidgets.QToolTip.showText(QtGui.QCursor.pos(), help_str)

class Utils():
    @staticmethod
    def check_versions(daemon_version):
        lMayor, lMinor, lPatch = version.split(".")
        rMayor, rMinor, rPatch = daemon_version.split(".")
        return lMayor != rMayor or (lMayor == rMayor and lMinor != rMinor)

    @staticmethod
    def get_user_id(uid):
        pw_name = uid
        try:
            pw_name = pwd.getpwuid(int(uid)).pw_name + " (" + uid + ")"
        except Exception:
            #pw_name += " (error)"
            pass

        return pw_name

    @staticmethod
    def get_interfaces():
        max_possible = 128  # arbitrary. raise if needed.
        bytes = max_possible * 32
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array('B', b'\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes, names.buffer_info()[0])
        ))[0]
        return names.tobytes(), outbytes

class Message():

    @staticmethod
    def ok(title, message, icon):
        msgBox = QtWidgets.QMessageBox()
        msgBox.setText("<b>{0}</b><br><br>{1}".format(title, message))
        msgBox.setIcon(icon)
        msgBox.setModal(True)
        msgBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msgBox.exec_()

    @staticmethod
    def yes_no(title, message, icon):
        msgBox = QtWidgets.QMessageBox()
        msgBox.setText(title)
        msgBox.setIcon(icon)
        msgBox.setModal(True)
        msgBox.setInformativeText(message)
        msgBox.setStandardButtons(QtWidgets.QMessageBox.Cancel | QtWidgets.QMessageBox.Yes)
        msgBox.setDefaultButton(QtWidgets.QMessageBox.Cancel)
        return msgBox.exec_()

class FileDialog():

    @staticmethod
    def save(parent):
        options = QtWidgets.QFileDialog.Options()
        fileName, _ = QtWidgets.QFileDialog.getSaveFileName(parent, "", "","All Files (*)", options=options)
        return fileName

    @staticmethod
    def select(parent):
        options = QtWidgets.QFileDialog.Options()
        fileName, _ = QtWidgets.QFileDialog.getOpenFileName(parent, "", "","All Files (*)", options=options)
        return fileName

    @staticmethod
    def select_dir(parent, current_dir):
        options = QtWidgets.QFileDialog.Options()
        fileName = QtWidgets.QFileDialog.getExistingDirectory(parent, "", current_dir, options)
        return fileName

