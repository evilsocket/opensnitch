#
# pytest -v tests/dialogs/test_ruleseditor.py
#

import json
from PyQt6 import QtCore, QtWidgets, QtGui

# Import proto first to avoid circular import issues
import opensnitch.proto as proto
proto.import_()

from opensnitch.config import Config
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
from opensnitch.dialogs.ruleseditor import constants as re_constants
from opensnitch.dialogs.ruleseditor import rules as re_rules
from opensnitch.dialogs.ruleseditor import utils as re_utils
from opensnitch.dialogs.ruleseditor import nodes as re_nodes

class TestRulesEditor():

    def setup_method(self):
        white_icon = QtGui.QIcon("../res/icon-white.svg")
        self.rd = RulesEditorDialog(appicon=white_icon)
        self.rd.show()
        self.rd.ruleNameEdit.setText("xxx")
        # Add item with both text and data so itemData() returns the address
        self.rd.nodesCombo.addItem("unix:/tmp/osui.sock", "unix:/tmp/osui.sock")
        self.rd.nodesCombo.setCurrentText("unix:/tmp/osui.sock")

    def test_rule_no_fields(self, qtbot):
        """ Test that rules without fields selected cannot be created.
        """
        qtbot.addWidget(self.rd)

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()
        assert self.rd.statusLabel.text() != ""

    def test_fields_empty(self, qtbot):
        """ Test that fields cannot be empty.
        """

        self.rd.pidCheck.setChecked(True)
        self.rd.pidLine.setText("")
        result, error = self.rd.save_rule()
        assert error != None

        self.rd.pidCheck.setChecked(False)
        self.rd.uidCheck.setChecked(True)
        self.rd.uidCombo.setCurrentText("")
        result, error = self.rd.save_rule()
        assert error != None

        self.rd.uidCheck.setChecked(False)
        self.rd.procCheck.setChecked(True)
        self.rd.procLine.setText("")
        result, error = self.rd.save_rule()
        assert error != None

        self.rd.procCheck.setChecked(False)
        self.rd.cmdlineCheck.setChecked(True)
        self.rd.cmdlineLine.setText("")
        result, error = self.rd.save_rule()
        assert error != None

        self.rd.cmdlineCheck.setChecked(False)
        self.rd.dstPortCheck.setChecked(True)
        self.rd.dstPortLine.setText("")
        result, error = self.rd.save_rule()
        assert error != None

        self.rd.dstPortCheck.setChecked(False)
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("")
        result, error = self.rd.save_rule()
        assert error != None

        self.rd.dstHostCheck.setChecked(False)
        self.rd.dstListsCheck.setChecked(True)
        self.rd.dstListsLine.setText("")
        result, error = self.rd.save_rule()
        assert error != None

    def test_add_basic_rule(self, qtbot):
        """ Test adding a basic rule.
        """

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test.com")
        self.rd.durationCombo.setCurrentIndex(re_rules.load_duration(self.rd,Config.DURATION_UNTIL_RESTART))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_SIMPLE
        assert self.rd.rule.operator.operand == "dest.host"
        assert self.rd.rule.operator.data == "www.test.com"
        assert self.rd.rule.duration == Config.DURATION_UNTIL_RESTART

    def test_add_complex_rule(self, qtbot):
        """ Test add complex rule.
        """
        re_constants.WORK_MODE = re_constants.ADD_RULE
        re_utils.reset_state(self.rd)
        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-complex.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test-complex.com")
        self.rd.dstPortCheck.setChecked(True)
        self.rd.dstPortLine.setText("443")

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-complex.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-complex.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_LIST
        assert self.rd.rule.operator.operand == Config.RULE_TYPE_LIST
        json_rule = json.loads(self.rd.rule.operator.data)
        assert json_rule[0]['type'] == "simple"
        assert json_rule[0]['operand'] == "dest.port"
        assert json_rule[0]['data'] == "443"
        assert json_rule[1]['type'] == "simple"
        assert json_rule[1]['operand'] == "dest.host"
        assert json_rule[1]['data'] == "www.test-complex.com"

    def test_add_reject_rule(self, qtbot):
        """ Test adding new rule with action "reject".
        """

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-reject.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test-reject.com")
        self.rd.actionRejectRadio.setChecked(True)

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-reject.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-reject.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_SIMPLE
        assert self.rd.rule.operator.operand == "dest.host"
        assert self.rd.rule.operator.data == "www.test-reject.com"
        assert self.rd.rule.action == Config.ACTION_REJECT

    def test_add_deny_rule(self, qtbot):
        """ Test adding new rule with action "deny".
        """

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-deny.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test-deny.com")
        self.rd.actionDenyRadio.setChecked(True)

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-deny.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-deny.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_SIMPLE
        assert self.rd.rule.operator.operand == "dest.host"
        assert self.rd.rule.operator.data == "www.test-deny.com"
        assert self.rd.rule.action == Config.ACTION_DENY

    def test_add_allow_rule(self, qtbot):
        """ Test adding new rule with action "allow".
        """

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-allow.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test-allow.com")
        self.rd.actionAllowRadio.setChecked(True)

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-allow.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-allow.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_SIMPLE
        assert self.rd.rule.operator.operand == "dest.host"
        assert self.rd.rule.operator.data == "www.test-allow.com"
        assert self.rd.rule.action == Config.ACTION_ALLOW

    def test_add_rule_name_conflict(self, qtbot):
        """ Test that rules with the same name cannot be added.
        """
        assert self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText()).next() == True

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test.com")

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() != ""

    def test_load_rule(self, qtbot):
        """ Test loading a rule.
        """
        re_constants.WORK_MODE = re_constants.ADD_RULE
        re_utils.reset_state(self.rd)
        records = self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText())
        assert records.next() == True

        # Set up timer BEFORE edit_rule() since it calls exec() internally
        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)
        QtCore.QTimer.singleShot(100, handle_dialog)

        self.rd.edit_rule(records, self.rd.nodesCombo.currentText())
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.ruleNameEdit.text() == "www.test.com"
        assert self.rd.dstHostCheck.isChecked() == True
        assert self.rd.dstHostLine.text() == "www.test.com"
        assert self.rd.durationCombo.currentIndex() == re_rules.load_duration(self.rd,Config.DURATION_UNTIL_RESTART)

    def test_edit_and_rename_rule(self, qtbot):
        """ Test loading, editing and renaming a rule.
        """
        re_constants.WORK_MODE = re_constants.ADD_RULE
        re_utils.reset_state(self.rd)
        records = self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText())
        assert records.next() == True

        # Set up timer BEFORE edit_rule() since it calls exec() internally
        # Do all modifications inside the timer callback
        def handle_dialog():
            # Verify rule was loaded correctly
            assert re_constants.WORK_MODE == re_constants.EDIT_RULE
            assert self.rd.ruleNameEdit.text() == "www.test.com"
            assert self.rd.dstHostCheck.isChecked() == True
            assert self.rd.dstHostLine.text() == "www.test.com"
            # Rename the rule
            self.rd.ruleNameEdit.setText("www.test-renamed.com")
            self.rd.dstHostLine.setText("www.test-renamed.com")
            # Save and close
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.edit_rule(records, self.rd.nodesCombo.currentText())

        # Use get_node_addr() which returns itemData() - the actual node address used for DB storage
        # (edit_rule calls load_all which changes currentText format to "{node} - {hostname}")
        node_addr = re_nodes.get_node_addr(self.rd)
        records = self.rd._db.get_rule("www.test.com", node_addr)
        assert records.next() == False
        records = self.rd._db.get_rule("www.test-renamed.com", node_addr)
        assert records.next() == True

    def test_durations(self, qtbot):
        """ Test adding new rule with action "deny".
        """

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-duration.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test-duration.com")
        self.rd.actionDenyRadio.setChecked(True)
        self.rd.durationCombo.setCurrentIndex(re_rules.load_duration(self.rd,Config.DURATION_ALWAYS))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-duration.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-duration.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_SIMPLE
        assert self.rd.rule.operator.operand == "dest.host"
        assert self.rd.rule.operator.data == "www.test-duration.com"
        assert self.rd.rule.action == Config.ACTION_DENY
        assert self.rd.rule.duration == Config.DURATION_ALWAYS

    def test_rule_LANs(self, qtbot):
        """ Test rule with regexp and LAN keyword in particular.
        """
        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-rule-LAN.com")
        self.rd.dstIPCheck.setChecked(True)
        self.rd.dstIPCombo.setCurrentText(re_constants.LAN_LABEL)
        self.rd.actionDenyRadio.setChecked(True)
        self.rd.durationCombo.setCurrentIndex(re_rules.load_duration(self.rd,Config.DURATION_ALWAYS))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-rule-LAN.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-rule-LAN.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        # LAN is now handled as network type with "LAN" keyword
        assert self.rd.rule.operator.type == Config.RULE_TYPE_NETWORK
        assert self.rd.rule.operator.operand == "dest.network"
        assert self.rd.rule.operator.data == "LAN"
        assert self.rd.rule.action == Config.ACTION_DENY
        assert self.rd.rule.duration == Config.DURATION_ALWAYS

    def test_rule_networks(self, qtbot):
        """ Test rule with networks.
        """
        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-rule-networks.com")
        self.rd.dstIPCheck.setChecked(True)
        self.rd.dstIPCombo.setCurrentText("192.168.111.0/24")
        self.rd.actionDenyRadio.setChecked(True)
        self.rd.durationCombo.setCurrentIndex(re_rules.load_duration(self.rd,Config.DURATION_ALWAYS))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Save), QtCore.Qt.MouseButton.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.StandardButton.Close), QtCore.Qt.MouseButton.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-rule-networks.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-rule-networks.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert re_constants.WORK_MODE == re_constants.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_NETWORK
        assert self.rd.rule.operator.operand == "dest.network"
        assert self.rd.rule.operator.data == "192.168.111.0/24"
        assert self.rd.rule.action == Config.ACTION_DENY
        assert self.rd.rule.duration == Config.DURATION_ALWAYS
