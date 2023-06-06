#
# pytest -v tests/dialogs/test_ruleseditor.py
#
import os
import time
import json
from PyQt5 import QtCore, QtWidgets, QtGui

from opensnitch.config import Config
from opensnitch.dialogs.preferences import PreferencesDialog

class TestPreferences():

    @classmethod
    def reset_settings(self):
        try:
            os.remove(os.environ['HOME'] + "/.config/opensnitch/settings.conf")
        except Exception:
            pass

    @classmethod
    def setup_method(self):
        white_icon = QtGui.QIcon("../res/icon-white.svg")
        self.reset_settings()
        self.prefs = PreferencesDialog(appicon=white_icon)
        self.prefs.show()

    def run(self, qtbot):
        def handle_dialog():
            qtbot.mouseClick(self.prefs.applyButton, QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.prefs.acceptButton, QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(500, handle_dialog)
        self.prefs.exec_()

    def test_save_popups_settings(self, qtbot):
        """ Test saving UI related settings.
        """
        qtbot.addWidget(self.prefs)

        self.prefs.comboUIAction.setCurrentIndex(Config.ACTION_ALLOW_IDX)
        self.prefs.comboUITarget.setCurrentIndex(2)
        self.prefs.comboUIDuration.setCurrentIndex(4)
        self.prefs.comboUIDialogPos.setCurrentIndex(2)
        self.prefs.spinUITimeout.setValue(30)
        self.prefs.showAdvancedCheck.setChecked(True)
        self.prefs.uidCheck.setChecked(True)

        self.run(qtbot)

        assert self.prefs._cfg.getInt(self.prefs._cfg.DEFAULT_ACTION_KEY) == Config.ACTION_ALLOW_IDX and self.prefs.comboUIAction.currentText() == Config.ACTION_ALLOW
        assert self.prefs._cfg.getInt(self.prefs._cfg.DEFAULT_TARGET_KEY) == 2
        assert self.prefs._cfg.getInt(self.prefs._cfg.DEFAULT_DURATION_KEY) == 4
        assert self.prefs._cfg.getInt(self.prefs._cfg.DEFAULT_TIMEOUT_KEY) == 30
        assert self.prefs._cfg.getInt(self.prefs._cfg.DEFAULT_POPUP_POSITION) == 2
        assert self.prefs._cfg.getBool(self.prefs._cfg.DEFAULT_POPUP_ADVANCED) == True
        assert self.prefs._cfg.getBool(self.prefs._cfg.DEFAULT_POPUP_ADVANCED_UID) == True

    def test_save_ui_settings(self, qtbot):
        self.prefs.checkUIRules.setChecked(True)
        self.prefs.comboUIRules.setCurrentIndex(1)
        self.prefs.checkHideNode.setChecked(False)
        self.prefs.checkHideProto.setChecked(False)

        self.run(qtbot)

        assert self.prefs._cfg.getBool(self.prefs._cfg.DEFAULT_IGNORE_RULES) == True and  self.prefs._cfg.getInt(self.prefs._cfg.DEFAULT_IGNORE_TEMPORARY_RULES) == 1
        cols = self.prefs._cfg.getSettings(Config.STATS_SHOW_COLUMNS)
        assert cols == ['0','2','3','5','6']

    def test_save_node_settings(self, qtbot, capsys):
        self.prefs.comboNodeAction.setCurrentIndex(Config.ACTION_ALLOW_IDX)
        self.prefs.comboNodeMonitorMethod.setCurrentIndex(2)
        self.prefs.comboNodeLogLevel.setCurrentIndex(5)
        self.prefs.checkNodeLogUTC.setChecked(False)
        self.prefs.checkNodeLogMicro.setChecked(True)
        self.prefs.checkInterceptUnknown.setChecked(True)
        self.prefs.tabWidget.setCurrentIndex(self.prefs.TAB_NODES)
        self.prefs._node_needs_update = True

        self.run(qtbot)

        assert len(self.prefs._notifications_sent) == 1
        for n in self.prefs._notifications_sent:
            conf = json.loads(self.prefs._notifications_sent[n].data)
            assert conf['InterceptUnknown'] == True
            assert conf['ProcMonitorMethod'] == "audit"
            assert conf['LogLevel'] == 5
            assert conf['LogUTC'] == False
            assert conf['LogMicro'] == True
            assert conf['DefaultAction'] == "allow"

# TODO: click on the QMessageDialog
#
#    def test_save_db_settings(self, qtbot, monkeypatch, capsys):
#        self.prefs.comboDBType.setCurrentIndex(1)
#        self.prefs.dbLabel.setText('/tmp/test.db')
#
#        def handle_dialog():
#            qtbot.mouseClick(self.prefs.applyButton, QtCore.Qt.LeftButton)
#            # after saving the settings, a warning dialog must appear, informing
#            # the user to restart the GUI
#            time.sleep(.5)
#            msgbox = QtWidgets.QApplication.activeModalWidget()
#            try:
#                assert msgbox != None
#                okBtn = msgbox.button(QtWidgets.QMessageBox.Ok)
#                qtbot.mouseClick(okBtn, QtCore.Qt.LeftButton)
#            except Exception as e:
#                print("test_save_db_Settings() exception:", e)
#            qtbot.mouseClick(self.prefs.acceptButton, QtCore.Qt.LeftButton)
#
#        QtCore.QTimer.singleShot(500, handle_dialog)
#        self.prefs.exec_()

#        assert self.prefs._cfg.getInt(Config.DEFAULT_DB_TYPE_KEY) == 1
#        assert self.prefs._cfg.getSettings(Config.DEFAULT_DB_FILE_KEY) == '/tmp/test.db'

    def test_load_ui_settings(self, qtbot, capsys):
        """ reTest saved settings (load_settings()).
        On dialog show up the widgets must be configured properly, with the settings
        configured in previous tests.
        """
        self.prefs.checkUIRules.setChecked(False)
        self.prefs.comboUIRules.setCurrentIndex(0)
        self.prefs.comboUITarget.setCurrentIndex(0)
        self.prefs.comboUIDuration.setCurrentIndex(0)
        self.prefs.checkHideNode.setChecked(True)
        self.prefs.checkHideProto.setChecked(True)

        def handle_dialog():
            qtbot.mouseClick(self.prefs.cancelButton, QtCore.Qt.LeftButton)
        QtCore.QTimer.singleShot(500, handle_dialog)

        self.prefs.exec_()
        self.prefs.show()

        print(self.prefs._cfg.getBool(self.prefs._cfg.DEFAULT_IGNORE_RULES))

        assert self.prefs.comboUIAction.currentIndex() == Config.ACTION_ALLOW_IDX and self.prefs.comboUIAction.currentText() == Config.ACTION_ALLOW
        assert self.prefs.checkUIRules.isChecked() == True
        assert self.prefs.comboUIRules.currentIndex() == 1
        assert self.prefs.comboUITarget.currentIndex() == 2
        assert self.prefs.comboUIDuration.currentIndex() == 4 and self.prefs.comboUIDuration.currentText() == Config.DURATION_30m
        assert self.prefs.comboUIDialogPos.currentIndex() == 2
        assert self.prefs.spinUITimeout.value() == 30
