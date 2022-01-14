#
# pytest -v tests/dialogs/test_ruleseditor.py
#

import json
from PyQt5 import QtCore, QtWidgets, QtGui

from opensnitch.config import Config
from opensnitch.dialogs.ruleseditor import RulesEditorDialog

class TestRulesEditor():

    @classmethod
    def setup_method(self):
        white_icon = QtGui.QIcon("../res/icon-white.svg")
        self.rd = RulesEditorDialog(appicon=white_icon)
        self.rd.show()
        self.rd.ruleNameEdit.setText("xxx")
        self.rd.nodesCombo.addItem("unix:/tmp/osui.sock")
        self.rd.nodesCombo.setCurrentText("unix:/tmp/osui.sock")
        self.rd._nodes._nodes["unix:/tmp/osui.sock"] = {}

    def test_rule_no_fields(self, qtbot):
        """ Test that rules without fields selected cannot be created.
        """
        qtbot.addWidget(self.rd)

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()
        assert self.rd.statusLabel.text() != ""

    def test_fields_empty(self, qtbot):
        """ Test that fields cannot be empty.
        """

        self.rd.pidCheck.setChecked(True)
        self.rd.pidLine.setText("")
        result, error = self.rd._save_rule()
        assert error != None

        self.rd.pidCheck.setChecked(False)
        self.rd.uidCheck.setChecked(True)
        self.rd.uidLine.setText("")
        result, error = self.rd._save_rule()
        assert error != None

        self.rd.uidCheck.setChecked(False)
        self.rd.procCheck.setChecked(True)
        self.rd.procLine.setText("")
        result, error = self.rd._save_rule()
        assert error != None

        self.rd.procCheck.setChecked(False)
        self.rd.cmdlineCheck.setChecked(True)
        self.rd.cmdlineLine.setText("")
        result, error = self.rd._save_rule()
        assert error != None

        self.rd.cmdlineCheck.setChecked(False)
        self.rd.dstPortCheck.setChecked(True)
        self.rd.dstPortLine.setText("")
        result, error = self.rd._save_rule()
        assert error != None

        self.rd.dstPortCheck.setChecked(False)
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("")
        result, error = self.rd._save_rule()
        assert error != None

        self.rd.dstHostCheck.setChecked(False)
        self.rd.dstListsCheck.setChecked(True)
        self.rd.dstListsLine.setText("")
        result, error = self.rd._save_rule()
        assert error != None

    def test_add_basic_rule(self, qtbot):
        """ Test adding a basic rule.
        """

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test.com")
        self.rd.durationCombo.setCurrentIndex(self.rd._load_duration(Config.DURATION_UNTIL_RESTART))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_SIMPLE
        assert self.rd.rule.operator.operand == "dest.host"
        assert self.rd.rule.operator.data == "www.test.com"
        assert self.rd.rule.duration == Config.DURATION_UNTIL_RESTART

    def test_add_complex_rule(self, qtbot):
        """ Test add complex rule.
        """
        self.rd.WORK_MODE = self.rd.ADD_RULE
        self.rd._reset_state()
        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-complex.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test-complex.com")
        self.rd.dstPortCheck.setChecked(True)
        self.rd.dstPortLine.setText("443")

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-complex.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-complex.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
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
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-reject.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-reject.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
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
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-deny.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-deny.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
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
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-allow.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-allow.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
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
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() != ""

    def test_load_rule(self, qtbot):
        """ Test loading a rule.
        """
        self.rd.WORK_MODE = self.rd.ADD_RULE
        self.rd._reset_state()
        records = self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText())
        assert records.next() == True

        self.rd.edit_rule(records, self.rd.nodesCombo.currentText())
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
        assert self.rd.ruleNameEdit.text() == "www.test.com"
        assert self.rd.dstHostCheck.isChecked() == True
        assert self.rd.dstHostLine.text() == "www.test.com"
        assert self.rd.durationCombo.currentIndex() == self.rd._load_duration(Config.DURATION_UNTIL_RESTART)

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

    def test_edit_and_rename_rule(self, qtbot):
        """ Test loading, editing and renaming a rule.
        """
        self.rd.WORK_MODE = self.rd.ADD_RULE
        self.rd._reset_state()
        records = self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText())
        assert records.next() == True

        self.rd.edit_rule(records, self.rd.nodesCombo.currentText())
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
        assert self.rd.ruleNameEdit.text() == "www.test.com"
        assert self.rd.dstHostCheck.isChecked() == True
        assert self.rd.dstHostLine.text() == "www.test.com"

        self.rd.ruleNameEdit.setText("www.test-renamed.com")
        self.rd.dstHostLine.setText("www.test-renamed.com")

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        records = self.rd._db.get_rule("www.test.com", self.rd.nodesCombo.currentText())
        assert records.next() == False
        records = self.rd._db.get_rule("www.test-renamed.com", self.rd.nodesCombo.currentText())
        assert records.next() == True

    def test_durations(self, qtbot):
        """ Test adding new rule with action "deny".
        """

        self.rd.statusLabel.setText("")
        self.rd.ruleNameEdit.setText("www.test-duration.com")
        self.rd.dstHostCheck.setChecked(True)
        self.rd.dstHostLine.setText("www.test-duration.com")
        self.rd.actionDenyRadio.setChecked(True)
        self.rd.durationCombo.setCurrentIndex(self.rd._load_duration(Config.DURATION_ALWAYS))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-duration.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-duration.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
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
        self.rd.dstIPCombo.setCurrentText(self.rd.LAN_LABEL)
        self.rd.actionDenyRadio.setChecked(True)
        self.rd.durationCombo.setCurrentIndex(self.rd._load_duration(Config.DURATION_ALWAYS))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-rule-LAN.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-rule-LAN.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_REGEXP
        assert self.rd.rule.operator.operand == "dest.ip"
        assert self.rd.rule.operator.data == self.rd.LAN_RANGES
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
        self.rd.durationCombo.setCurrentIndex(self.rd._load_duration(Config.DURATION_ALWAYS))

        def handle_dialog():
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Apply), QtCore.Qt.LeftButton)
            qtbot.mouseClick(self.rd.buttonBox.button(QtWidgets.QDialogButtonBox.Close), QtCore.Qt.LeftButton)

        QtCore.QTimer.singleShot(100, handle_dialog)
        self.rd.exec_()

        assert self.rd.statusLabel.text() == ""
        assert self.rd._db.get_rule("www.test-rule-networks.com", self.rd.nodesCombo.currentText()).next() == True
        assert self.rd._old_rule_name == "www.test-rule-networks.com"
        # after adding a rule, we enter into editing mode, to allow editing it
        # without closing the dialog.
        assert self.rd.WORK_MODE == self.rd.EDIT_RULE
        assert self.rd.rule.operator.type == Config.RULE_TYPE_NETWORK
        assert self.rd.rule.operator.operand == "dest.network"
        assert self.rd.rule.operator.data == "192.168.111.0/24"
        assert self.rd.rule.action == Config.ACTION_DENY
        assert self.rd.rule.duration == Config.DURATION_ALWAYS

