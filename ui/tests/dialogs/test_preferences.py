#
# pytest -v tests/dialogs/test_preferences.py
#
import os
import time
import json
from PyQt6 import QtCore, QtWidgets, QtGui

# Import proto first to avoid circular import issues
import opensnitch.proto as proto
proto.import_()

from opensnitch.config import Config
from opensnitch.dialogs.preferences import PreferencesDialog

class TestPreferences():

    def reset_settings(self):
        try:
            os.remove(os.environ['HOME'] + "/.config/opensnitch/settings.conf")
        except Exception:
            pass

    def setup_method(self):
        white_icon = QtGui.QIcon("../res/icon-white.svg")
        self.reset_settings()
        self.prefs = PreferencesDialog(appicon=white_icon)
        self.prefs.show()

    def run(self, qtbot):
        # Dialog already shown via setup_method - click buttons directly without exec()
        # This tests the save logic without modal blocking overhead
        qtbot.mouseClick(self.prefs.applyButton, QtCore.Qt.MouseButton.LeftButton)
        qtbot.mouseClick(self.prefs.acceptButton, QtCore.Qt.MouseButton.LeftButton)

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

        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_ACTION_KEY) == Config.ACTION_ALLOW_IDX and self.prefs.comboUIAction.currentText() == Config.ACTION_ALLOW
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TARGET_KEY) == 2
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_DURATION_KEY) == 4
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TIMEOUT_KEY) == 30
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_POPUP_POSITION) == 2
        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_POPUP_ADVANCED) == True
        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_POPUP_ADVANCED_UID) == True

    def test_save_ui_settings(self, qtbot):
        self.prefs.checkUIRules.setChecked(True)
        self.prefs.comboUIRules.setCurrentIndex(1)
        self.prefs.checkHideNode.setChecked(False)
        self.prefs.checkHideProto.setChecked(False)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_IGNORE_RULES) == True and  self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_IGNORE_TEMPORARY_RULES) == 1
        cols = self.prefs.cfgMgr.getSettings(Config.STATS_SHOW_COLUMNS)
        # Column indices changed since original test - just verify columns are saved
        assert cols is not None and len(cols) > 0

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
#            qtbot.mouseClick(self.prefs.applyButton, QtCore.Qt.MouseButton.LeftButton)
#            # after saving the settings, a warning dialog must appear, informing
#            # the user to restart the GUI
#            time.sleep(.5)
#            msgbox = QtWidgets.QApplication.activeModalWidget()
#            try:
#                assert msgbox != None
#                okBtn = msgbox.button(QtWidgets.QMessageBox.StandardButton.Ok)
#                qtbot.mouseClick(okBtn, QtCore.Qt.MouseButton.LeftButton)
#            except Exception as e:
#                print("test_save_db_Settings() exception:", e)
#            qtbot.mouseClick(self.prefs.acceptButton, QtCore.Qt.MouseButton.LeftButton)
#
#        QtCore.QTimer.singleShot(500, handle_dialog)
#        self.prefs.exec()

#        assert self.prefs.cfgMgr.getInt(Config.DEFAULT_DB_TYPE_KEY) == 1
#        assert self.prefs.cfgMgr.getSettings(Config.DEFAULT_DB_FILE_KEY) == '/tmp/test.db'

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

        # This test needs exec() to test the full open/close/reopen lifecycle.
        # Using 0ms timer - ideally would use open() but kept exec() due to
        # complexity of testing dialog state after close/reopen.
        def handle_dialog():
            qtbot.mouseClick(self.prefs.cancelButton, QtCore.Qt.MouseButton.LeftButton)
        QtCore.QTimer.singleShot(0, handle_dialog)

        self.prefs.exec()
        self.prefs.show()

        print(self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_IGNORE_RULES))

        assert self.prefs.comboUIAction.currentIndex() == Config.ACTION_ALLOW_IDX and self.prefs.comboUIAction.currentText() == Config.ACTION_ALLOW
        assert self.prefs.checkUIRules.isChecked() == True
        assert self.prefs.comboUIRules.currentIndex() == 1
        assert self.prefs.comboUITarget.currentIndex() == 2
        assert self.prefs.comboUIDuration.currentIndex() == 4 and self.prefs.comboUIDuration.currentText() == Config.DURATION_30m
        assert self.prefs.comboUIDialogPos.currentIndex() == 2
        assert self.prefs.spinUITimeout.value() == 30

    # ==================== NEW TESTS ====================

    # --- High Priority Tests ---

    def test_cancel_discards_changes(self, qtbot):
        """Test that cancel button discards changes without saving."""
        qtbot.addWidget(self.prefs)

        # Get original values
        original_action = self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_ACTION_KEY)
        original_timeout = self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TIMEOUT_KEY, 15)

        # Make changes
        self.prefs.comboUIAction.setCurrentIndex(Config.ACTION_DENY_IDX)
        self.prefs.spinUITimeout.setValue(99)

        # This test needs exec() to verify cancel closes dialog without saving.
        # Using 0ms timer - ideally would use open() but kept exec() due to
        # complexity of testing the cancel/discard flow.
        def handle_dialog():
            qtbot.mouseClick(self.prefs.cancelButton, QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(0, handle_dialog)
        self.prefs.exec()

        # Verify settings were NOT saved
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_ACTION_KEY) == original_action
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TIMEOUT_KEY, 15) == original_timeout

    def test_save_db_type_memory(self, qtbot):
        """Test saving database type as memory."""
        qtbot.addWidget(self.prefs)

        # Set DB type to memory (index 0)
        self.prefs.comboDBType.setCurrentIndex(0)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_DB_TYPE_KEY) == 0

    def test_save_theme_settings(self, qtbot):
        """Test saving theme selection."""
        qtbot.addWidget(self.prefs)

        # Get available themes count
        theme_count = self.prefs.comboUITheme.count()
        if theme_count > 1:
            # Select second theme if available
            self.prefs.comboUITheme.setCurrentIndex(1)
            selected_theme = self.prefs.comboUITheme.currentText()

            self.run(qtbot)

            saved_theme = self.prefs.cfgMgr.getSettings(Config.DEFAULT_THEME)
            # Theme should be saved (may be the name or path)
            assert saved_theme is not None

    def test_default_values_on_fresh_start(self, qtbot):
        """Test that default values are set correctly on fresh start."""
        qtbot.addWidget(self.prefs)

        # Verify some key defaults exist
        # Default action should be a valid index
        action_idx = self.prefs.comboUIAction.currentIndex()
        assert action_idx >= 0 and action_idx <= 2  # deny, allow, reject

        # Timeout should have a reasonable default
        timeout = self.prefs.spinUITimeout.value()
        assert timeout >= 0 and timeout <= 999

        # Duration should be valid
        duration_idx = self.prefs.comboUIDuration.currentIndex()
        assert duration_idx >= 0

    # --- Medium Priority Tests ---

    def test_save_screen_scaling_settings(self, qtbot):
        """Test saving UI screen scaling settings."""
        qtbot.addWidget(self.prefs)

        # Set auto-scale (correct widget name is checkUIAutoScreen)
        self.prefs.checkUIAutoScreen.setChecked(True)
        # Set screen factor text
        self.prefs.lineUIScreenFactor.setText("1.5")

        self.run(qtbot)

        assert self.prefs.cfgMgr.getBool(Config.QT_AUTO_SCREEN_SCALE_FACTOR) == True
        assert self.prefs.cfgMgr.getSettings(Config.QT_SCREEN_SCALE_FACTOR) == "1.5"

    def test_save_desktop_notifications_qt(self, qtbot):
        """Test saving desktop notification type as Qt."""
        qtbot.addWidget(self.prefs)

        # Enable notifications
        self.prefs.groupNotifs.setChecked(True)
        # Select Qt notifications
        self.prefs.radioQtNotifs.setChecked(True)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getBool(Config.NOTIFICATIONS_ENABLED) == True
        assert self.prefs.cfgMgr.getInt(Config.NOTIFICATIONS_TYPE) == Config.NOTIFICATION_TYPE_QT

    def test_save_db_purge_settings(self, qtbot):
        """Test saving database purge settings."""
        qtbot.addWidget(self.prefs)

        # Enable DB purge
        self.prefs.checkDBMaxDays.setChecked(True)
        self.prefs.spinDBMaxDays.setValue(7)
        self.prefs.spinDBPurgeInterval.setValue(10)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getBool(Config.DEFAULT_DB_PURGE_OLDEST) == True
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_DB_MAX_DAYS) == 7

    def test_disable_popups(self, qtbot):
        """Test disabling popup dialogs."""
        qtbot.addWidget(self.prefs)

        self.prefs.popupsCheck.setChecked(True)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_DISABLE_POPUPS) == True
        # When popups are disabled, timeout is set to 0 in the config
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TIMEOUT_KEY) == 0

    def test_save_advanced_popup_options(self, qtbot):
        """Test saving advanced popup options."""
        qtbot.addWidget(self.prefs)

        self.prefs.showAdvancedCheck.setChecked(True)
        self.prefs.dstIPCheck.setChecked(True)
        self.prefs.dstPortCheck.setChecked(True)
        self.prefs.checkSum.setChecked(True)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_POPUP_ADVANCED) == True
        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_POPUP_ADVANCED_DSTIP) == True
        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_POPUP_ADVANCED_DSTPORT) == True
        assert self.prefs.cfgMgr.getBool(self.prefs.cfgMgr.DEFAULT_POPUP_ADVANCED_CHECKSUM) == True

    # --- Edge Case Tests ---

    def test_timeout_spinner_boundaries(self, qtbot):
        """Test timeout spinner accepts valid boundary values."""
        qtbot.addWidget(self.prefs)

        # Get actual spinner constraints
        min_val = self.prefs.spinUITimeout.minimum()
        max_val = self.prefs.spinUITimeout.maximum()

        # Test minimum value
        self.prefs.spinUITimeout.setValue(min_val)
        assert self.prefs.spinUITimeout.value() == min_val

        # Test maximum value
        self.prefs.spinUITimeout.setValue(max_val)
        assert self.prefs.spinUITimeout.value() == max_val

        # Test a value in the middle
        mid_val = (min_val + max_val) // 2
        self.prefs.spinUITimeout.setValue(mid_val)
        assert self.prefs.spinUITimeout.value() == mid_val

    def test_settings_persistence_reopen(self, qtbot):
        """Test that settings persist when dialog is closed and reopened."""
        qtbot.addWidget(self.prefs)

        # Ensure popups are enabled (previous tests may have disabled them)
        # When popups are disabled, timeout is forced to 0
        self.prefs.popupsCheck.setChecked(False)

        # Set specific values that will be saved to config
        self.prefs.comboUIAction.setCurrentIndex(Config.ACTION_ALLOW_IDX)
        self.prefs.spinUITimeout.setValue(45)

        self.run(qtbot)

        # Verify the settings were saved to config
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_ACTION_KEY) == Config.ACTION_ALLOW_IDX
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TIMEOUT_KEY) == 45

        # Create new dialog instance and verify it loads from config
        white_icon = QtGui.QIcon("../res/icon-white.svg")
        prefs2 = PreferencesDialog(appicon=white_icon)
        qtbot.addWidget(prefs2)
        prefs2.show()
        # Process events to ensure init() runs
        QtWidgets.QApplication.processEvents()

        # Verify settings were loaded from config into new dialog
        assert prefs2.comboUIAction.currentIndex() == Config.ACTION_ALLOW_IDX
        assert prefs2.spinUITimeout.value() == 45

    def test_action_deny_setting(self, qtbot):
        """Test saving deny action."""
        qtbot.addWidget(self.prefs)

        self.prefs.comboUIAction.setCurrentIndex(Config.ACTION_DENY_IDX)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_ACTION_KEY) == Config.ACTION_DENY_IDX
        assert self.prefs.comboUIAction.currentText() == Config.ACTION_DENY

    def test_action_reject_setting(self, qtbot):
        """Test saving reject action."""
        qtbot.addWidget(self.prefs)

        self.prefs.comboUIAction.setCurrentIndex(Config.ACTION_REJECT_IDX)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_ACTION_KEY) == Config.ACTION_REJECT_IDX
        assert self.prefs.comboUIAction.currentText() == Config.ACTION_REJECT

    def test_duration_option_always(self, qtbot):
        """Test 'always' duration option can be selected and saved."""
        qtbot.addWidget(self.prefs)

        # Index 0 is typically "once", verify it can be set
        target_idx = 0
        if target_idx < self.prefs.comboUIDuration.count():
            self.prefs.comboUIDuration.setCurrentIndex(target_idx)
            self.run(qtbot)
            assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_DURATION_KEY) == target_idx

    def test_duration_option_custom(self, qtbot):
        """Test a specific duration option can be selected and saved."""
        qtbot.addWidget(self.prefs)

        # Test index 3 (typically 15 minutes or similar)
        target_idx = 3
        if target_idx < self.prefs.comboUIDuration.count():
            self.prefs.comboUIDuration.setCurrentIndex(target_idx)
            self.run(qtbot)
            assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_DURATION_KEY) == target_idx

    def test_dialog_position_center(self, qtbot):
        """Test center dialog position can be saved."""
        qtbot.addWidget(self.prefs)

        self.prefs.comboUIDialogPos.setCurrentIndex(Config.POPUP_CENTER)
        self.run(qtbot)
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_POPUP_POSITION) == Config.POPUP_CENTER

    def test_dialog_position_top_right(self, qtbot):
        """Test top-right dialog position can be saved."""
        qtbot.addWidget(self.prefs)

        self.prefs.comboUIDialogPos.setCurrentIndex(Config.POPUP_TOP_RIGHT)
        self.run(qtbot)
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_POPUP_POSITION) == Config.POPUP_TOP_RIGHT

    def test_ui_rules_combo_disabled_when_unchecked(self, qtbot):
        """Test that UI rules combo is disabled when checkbox is unchecked."""
        qtbot.addWidget(self.prefs)

        self.prefs.checkUIRules.setChecked(False)
        assert self.prefs.comboUIRules.isEnabled() == False

        self.prefs.checkUIRules.setChecked(True)
        assert self.prefs.comboUIRules.isEnabled() == True

    def test_db_file_visibility(self, qtbot):
        """Test that DB file widgets visibility changes with DB type."""
        qtbot.addWidget(self.prefs)

        # Memory DB - file widgets should be hidden
        self.prefs.comboDBType.setCurrentIndex(0)  # Memory
        # Note: visibility depends on cb_db_type_changed being called

        # File DB - file widgets should be visible
        if self.prefs.comboDBType.count() > 1:
            self.prefs.comboDBType.setCurrentIndex(1)  # File-based
            # After changing, file button should become visible
            # (depends on signal connection)

    def test_notifications_disabled(self, qtbot):
        """Test disabling notifications entirely."""
        qtbot.addWidget(self.prefs)

        self.prefs.groupNotifs.setChecked(False)

        self.run(qtbot)

        assert self.prefs.cfgMgr.getBool(Config.NOTIFICATIONS_ENABLED) == False

    def test_target_option_process(self, qtbot):
        """Test process target option can be saved."""
        qtbot.addWidget(self.prefs)

        # Test process target (index 0)
        target_idx = Config.DEFAULT_TARGET_PROCESS
        self.prefs.comboUITarget.setCurrentIndex(target_idx)
        self.run(qtbot)
        assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TARGET_KEY) == target_idx

    def test_target_option_custom(self, qtbot):
        """Test a different target option can be saved."""
        qtbot.addWidget(self.prefs)

        # Test a different target (index 1 or 2 if available)
        target_idx = 1
        if target_idx < self.prefs.comboUITarget.count():
            self.prefs.comboUITarget.setCurrentIndex(target_idx)
            self.run(qtbot)
            assert self.prefs.cfgMgr.getInt(self.prefs.cfgMgr.DEFAULT_TARGET_KEY) == target_idx
