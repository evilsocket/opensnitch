
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
import os, sys, glob

class AsnDB():
    __instance = None
    asndb = None

    @staticmethod
    def instance():
        if AsnDB.__instance == None:
            AsnDB.__instance = AsnDB()
        return AsnDB.__instance

    def __init__(self):
        self.ASN_AVAILABLE = True
        self.load()

    def is_available(self):
        return self.ASN_AVAILABLE

    def load(self):
        """Load the ASN DB from disk.

        It'll try to load it from user's opensnitch directory if these file exist:
            - ~/.config/opensnitch/ipasn_db.dat.gz
            - ~/.config/opensnitch/asnames.json
        Otherwise it'll try to load it from python3-pyasn package.
        """
        try:
            if self.asndb != None:
                return

            import pyasn

            IPASN_DB_PATH = os.path.expanduser('~/.config/opensnitch/ipasn_db.dat.gz')
            # .gz not supported for asnames
            AS_NAMES_FILE_PATH = os.path.expanduser('~/.config/opensnitch/asnames.json')

            # if the user hasn't downloaded an updated ipasn db, use the one
            # shipped with the python3-pyasn package
            if os.path.isfile(IPASN_DB_PATH) == False:
                IPASN_DB_PATH = '/usr/lib/python3/dist-packages/data/ipasn_20140513_v12.dat.gz'
            if os.path.isfile(AS_NAMES_FILE_PATH) == False:
                AS_NAMES_FILE_PATH = '/usr/lib/python3/dist-packages/data/asnames.json'

            print("using IPASN DB:", IPASN_DB_PATH)
            self.asndb = pyasn.pyasn(IPASN_DB_PATH, as_names_file=AS_NAMES_FILE_PATH)
        except Exception as e:
            self.ASN_AVAILABLE = False
            print("exception loading ipasn db:", e)
            print("Install python3-pyasn to display IP's network name.")


    def lookup(self, ip):
        """Lookup the IP in the ASN DB.

        Return the net range and the prefix if found, otherwise nothing.
        """
        try:
            return self.asndb.lookup(ip)
        except Exception:
            return "", ""

    def get_as_name(self, asn):
        """Get the ASN name given a network range.

        Return the name of the network if found, otherwise nothing.
        """
        try:
            asname = self.asndb.get_as_name(asn)
            if asname == None:
                asname = ""
            return asname
        except Exception:
            return ""

    def get_asn(self, ip):
        try:
            asn, prefix = self.lookup(ip)
            return self.get_as_name(asn)
        except Exception:
            return ""

class Themes():
    """Change GUI's appearance using qt-material lib.
    https://github.com/UN-GCPDS/qt-material
    """
    THEMES_PATH = [
        os.path.expanduser("~/.config/opensnitch/"),
        os.path.dirname(sys.modules[__name__].__file__)
    ]
    __instance = None

    AVAILABLE = False
    try:
        from qt_material import apply_stylesheet as qtmaterial_apply_stylesheet
        from qt_material import list_themes as qtmaterial_themes
        AVAILABLE = True
    except Exception:
        print("Themes not available. Install qt-material if you want to change GUI's appearance: pip3 install qt-material.")

    @staticmethod
    def instance():
        if Themes.__instance == None:
            Themes.__instance = Themes()
        return Themes.__instance

    def __init__(self):
        self._cfg = Config.get()
        theme = self._cfg.getInt(self._cfg.DEFAULT_THEME, 0)

    def available(self):
        return Themes.AVAILABLE

    def get_saved_theme(self):
        if not Themes.AVAILABLE:
            return 0, ""

        theme = self._cfg.getSettings(self._cfg.DEFAULT_THEME)
        if theme != "" and theme != None:
            # 0 == System
            return self.list_themes().index(theme)+1, theme
        return 0, ""

    def save_theme(self, theme_idx, theme):
        if not Themes.AVAILABLE:
            return

        if theme_idx == 0:
            self._cfg.setSettings(self._cfg.DEFAULT_THEME, "")
        else:
            self._cfg.setSettings(self._cfg.DEFAULT_THEME, theme)

    def load_theme(self, app):
        if not Themes.AVAILABLE:
            return

        try:
            theme_idx, theme_name = self.get_saved_theme()
            if theme_name != "":
                invert = "light" in theme_name
                print("Using theme:", theme_idx, theme_name, "inverted:", invert)
                # TODO: load {theme}.xml.extra and .xml.css for further
                # customizations.
                Themes.qtmaterial_apply_stylesheet(app, theme=theme_name,  invert_secondary=invert)
        except Exception as e:
            print("Themes.load_theme() exception:", e)

    def list_local_themes(self):
        themes = []
        if not Themes.AVAILABLE:
            return themes

        try:
            for tdir in self.THEMES_PATH:
                themes += glob.glob(tdir + "/themes/*.xml")
        except Exception:
            pass
        finally:
            return themes

    def list_themes(self):
        themes = self.list_local_themes()
        if not Themes.AVAILABLE:
            return themes

        themes += Themes.qtmaterial_themes()
        return themes

class CleanerTask(Thread):
    interval = 1
    stop_flag = None
    callback = None

    def __init__(self, _interval, _callback):
        Thread.__init__(self, name="cleaner_db_thread")
        self.interval = _interval * 60
        self.stop_flag = Event()
        self.callback = _callback
        self._cfg = Config.init()

        # We need to instantiate a new QsqlDatabase object with a unique name,
        # because it's not thread safe:
        # "A connection can only be used from within the thread that created it."
        # https://doc.qt.io/qt-5/threads-modules.html#threads-and-the-sql-module
        # The filename and type is the same, the one chosen by the user.
        self.db = Database("db-cleaner-connection")
        self.db_status, db_error = self.db.initialize(
            dbtype=self._cfg.getInt(self._cfg.DEFAULT_DB_TYPE_KEY),
            dbfile=self._cfg.getSettings(self._cfg.DEFAULT_DB_FILE_KEY)
        )

    def run(self):
        if self.db_status == False:
            return
        while not self.stop_flag.is_set():
            self.stop_flag.wait(self.interval)
            self.callback(self.db)

    def stop(self):
        self.stop_flag.set()
        self.db.close()

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

