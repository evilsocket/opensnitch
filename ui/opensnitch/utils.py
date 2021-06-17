
from PyQt5 import QtCore, QtWidgets
from opensnitch.version import version
import pwd
import socket
import fcntl
import struct
import array

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

