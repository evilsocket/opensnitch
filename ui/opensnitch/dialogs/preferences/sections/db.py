from PyQt6.QtCore import QCoreApplication as QC
from PyQt6 import QtWidgets

from opensnitch.config import Config
from opensnitch.database import Database
from opensnitch.utils import Message

def save_config(win):
    dbtype = win.comboDBType.currentIndex()
    db_name = win.cfgMgr.getSettings(win.cfgMgr.DEFAULT_DB_FILE_KEY)

    if win.dbLabel.text() != "" and \
            (win.comboDBType.currentIndex() != win.dbType or db_name != win.dbLabel.text()):
        win.changes_needs_restart = QC.translate("preferences", "DB type changed")

    if win.comboDBType.currentIndex() != Database.DB_TYPE_MEMORY:
        if win.dbLabel.text() != "":
            db_name = win.dbLabel.text()
        else:
            Message.ok(
                QC.translate("preferences", "Warning"),
                QC.translate("preferences", "You must select a file for the database<br>or choose \"In memory\" type."),
                QtWidgets.QMessageBox.Icon.Warning)
            win.dbLabel.setText("")
            return False
    else:
        db_name = Database.DB_IN_MEMORY

    win.cfgMgr.setSettings(Config.DEFAULT_DB_FILE_KEY, db_name)
    win.cfgMgr.setSettings(Config.DEFAULT_DB_TYPE_KEY, dbtype)
    win.cfgMgr.setSettings(Config.DEFAULT_DB_PURGE_OLDEST, bool(win.checkDBMaxDays.isChecked()))
    win.cfgMgr.setSettings(Config.DEFAULT_DB_MAX_DAYS, int(win.spinDBMaxDays.value()))
    win.cfgMgr.setSettings(Config.DEFAULT_DB_PURGE_INTERVAL, int(win.spinDBPurgeInterval.value()))
    win.cfgMgr.setSettings(Config.DEFAULT_DB_JRNL_WAL, bool(win.checkDBJrnlWal.isChecked()))
    win.dbType = win.comboDBType.currentIndex()

    return True

def enable_db_cleaner_options(win, enable, db_max_days):
    win.checkDBMaxDays.setChecked(enable)
    win.spinDBMaxDays.setEnabled(enable)
    win.spinDBPurgeInterval.setEnabled(enable)
    win.labelDBPurgeInterval.setEnabled(enable)
    win.labelDBPurgeDays.setEnabled(enable)
    win.labelDBPurgeMinutes.setEnabled(enable)
    win.cmdDBMaxDaysUp.setEnabled(enable)
    win.cmdDBMaxDaysDown.setEnabled(enable)
    win.cmdDBPurgesUp.setEnabled(enable)
    win.cmdDBPurgesDown.setEnabled(enable)

def enable_db_jrnl_wal(win, enable, db_jrnl_wal):
    win.checkDBJrnlWal.setChecked(db_jrnl_wal)
    win.checkDBJrnlWal.setEnabled(enable)

def type_changed(win):
    isDBMem = win.comboDBType.currentIndex() == Database.DB_TYPE_MEMORY
    win.dbFileButton.setVisible(not isDBMem)
    win.dbLabel.setVisible(not isDBMem)
    win.checkDBMaxDays.setChecked(win.cfgMgr.getBool(Config.DEFAULT_DB_PURGE_OLDEST))
    win.checkDBJrnlWal.setEnabled(not isDBMem)
    win.checkDBJrnlWal.setChecked(False)
