import re
import os.path
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.utils.network_aliases import NetworkAliases
from opensnitch.utils import (
    qvalidator,
    Icons
)
from . import nodes, constants

# XXX: remove?
def bool(s):
    return s == 'True'

def load_aliases_into_menu(win):
    aliases = NetworkAliases.get_alias_all()

    for alias in reversed(aliases):
        if win.dstIPCombo.findText(alias) == -1:
            win.dstIPCombo.insertItem(0, alias)

def set_rulename_validator(win):
    win.ruleNameValidator = qvalidator.RestrictChars(constants.INVALID_RULE_NAME_CHARS)
    win.ruleNameValidator.result.connect(win.cb_rule_name_validator_result)
    win.ruleNameEdit.setValidator(win.ruleNameValidator)

def configure_icons(win):
    applyIcon = Icons.new(win, "emblem-default")
    denyIcon = Icons.new(win, "emblem-important")
    rejectIcon = Icons.new(win, "window-close")
    openIcon = Icons.new(win, "document-open")
    win.actionAllowRadio.setIcon(applyIcon)
    win.actionDenyRadio.setIcon(denyIcon)
    win.actionRejectRadio.setIcon(rejectIcon)
    win.selectListButton.setIcon(openIcon)
    win.selectListRegexpButton.setIcon(openIcon)
    win.selectNetsListButton.setIcon(openIcon)
    win.selectIPsListButton.setIcon(openIcon)

def set_status_error(win, msg):
    win.statusLabel.setStyleSheet('color: red')
    win.statusLabel.setText(msg)

def set_status_message(win, msg):
    win.statusLabel.setStyleSheet('color: green')
    win.statusLabel.setText(msg)

def reset_state(win):
    win._old_rule_name = None
    win.rule = None

    win.ruleNameEdit.setText("")
    win.ruleDescEdit.setPlainText("")
    win.statusLabel.setText("")

    win.actionDenyRadio.setChecked(True)
    win.durationCombo.setCurrentIndex(0)

    win.protoCheck.setChecked(False)
    win.protoCombo.setCurrentText("")

    win.procCheck.setChecked(False)
    win.checkProcRegexp.setEnabled(False)
    win.checkProcRegexp.setChecked(False)
    win.checkProcRegexp.setVisible(False)
    win.procLine.setText("")

    win.cmdlineCheck.setChecked(False)
    win.checkCmdlineRegexp.setEnabled(False)
    win.checkCmdlineRegexp.setChecked(False)
    win.checkCmdlineRegexp.setVisible(False)
    win.cmdlineLine.setText("")

    win.uidCheck.setChecked(False)
    win.uidCombo.setCurrentText("")

    win.pidCheck.setChecked(False)
    win.pidLine.setText("")

    win.ifaceCheck.setChecked(False)
    win.ifaceCombo.setCurrentText("")

    win.dstPortCheck.setChecked(False)
    win.dstPortLine.setText("")

    win.srcPortCheck.setChecked(False)
    win.srcPortLine.setText("")

    win.srcIPCheck.setChecked(False)
    win.srcIPCombo.setCurrentText("")

    win.dstIPCheck.setChecked(False)
    win.dstIPCombo.setCurrentText("")

    win.dstHostCheck.setChecked(False)
    win.dstHostLine.setText("")

    win.selectListButton.setEnabled(False)
    win.dstListsCheck.setChecked(False)
    win.dstListsLine.setText("")

    win.selectListRegexpButton.setEnabled(False)
    win.dstListRegexpCheck.setChecked(False)
    win.dstRegexpListsLine.setText("")

    win.selectIPsListButton.setEnabled(False)
    win.dstListIPsCheck.setChecked(False)
    win.dstListIPsLine.setText("")

    win.selectNetsListButton.setEnabled(False)
    win.dstListNetsCheck.setChecked(False)
    win.dstListNetsLine.setText("")

    win.md5Check.setChecked(False)
    win.md5Line.setText("")
    win.md5Line.setEnabled(False)

    win.sensitiveCheck.setChecked(False)
    win.nologCheck.setChecked(False)
    win.enableCheck.setChecked(False)
    win.precedenceCheck.setChecked(False)
    win.nodeApplyAllCheck.setChecked(False)

def comma_to_regexp(win, text, expected_type):
    """translates items separated by comma, to regular expression
    returns True|False, regexp|error
    """
    s_parts = text.replace(" ", "").split(",")
    sp_regex = r'^('
    for p in s_parts:
        if expected_type == int:
            try:
                int(p)
            except:
                return False, QC.translate("rules", "Invalid text")
        if p == "":
            return False, QC.translate("rules", "Invalid text")

        sp_regex += '{0}|'.format(p)
    sp_regex = sp_regex.removesuffix("|")
    sp_regex += r')$'
    if not is_valid_regex(win, sp_regex):
        return False, QC.translate("rules", "regexp error (report it)")

    return True, sp_regex

def regexp_to_comma(win, text, expected_type):
    """translates a regular expression to a comma separated list
    from ^(1|2|3)$ to "1,2,3"
    """
    error = ""
    # match ^(1|2|3)$
    regexp_str = r'\^\(([\d|]+)\)\$'
    if expected_type == str:
        # match ^(www.a-b-c.org|fff.uk|ooo.tw)$
        regexp_str = r'\^\(([.\-\w|]+)\)\$'
    q = re.search(regexp_str, text)
    if not q:
        return None, error
    try:
        parts = q.group(1).split("|")
        for p in parts:
            # unlikely. The regexp should haven't match.
            if expected_type == int:
                int(p)
        return ",".join(parts), ""
    except Exception as e:
        win.logger.warning("_regexp_to_comma exception: %s", repr(e))
        error = "Error parsing regexp to comma: {0}".format(e)

    return None, error

def is_regex(win, text):
    charset="\\*{[|^?$"
    for c in charset:
        if c in text:
            return True
    return False

def is_valid_regex(win, regex):
    try:
        re.compile(regex)
        return True
    except re.error as e:
        win.statusLabel.setText(str(e))
        return False

def is_valid_list_path(win, listWidget):
    if listWidget.text() == "":
        return QC.translate("rules", "Lists field cannot be empty")
    if win._nodes.is_local(nodes.get_node_addr(win)) and \
        win.nodeApplyAllCheck.isChecked() == False and \
        os.path.isdir(listWidget.text()) == False:
        return QC.translate("rules", "Lists field must be a directory")

    return None

