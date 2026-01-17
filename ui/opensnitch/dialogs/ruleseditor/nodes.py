from PyQt6 import QtWidgets
from PyQt6.QtCore import Qt, QCoreApplication as QC

from opensnitch.database.enums import RuleFields
from opensnitch.utils import (
    Message
)

def load_all(win, addr=None):
    try:
        win.nodesCombo.blockSignals(True)
        win.nodesCombo.clear()
        win._node_list = win._nodes.get()

        if addr is not None and addr not in win._node_list:
            Message.ok(QC.translate("rules", "<b>Error loading rule</b>"),
                    QC.translate("rules", "node {0} not connected".format(addr)),
                    QtWidgets.QMessageBox.Icon.Warning)
            return False

        if len(win._node_list) < 2:
            win.nodeApplyAllCheck.setVisible(False)

        for node in win._node_list:
            hostname = win._nodes.get_node_hostname(node)
            win.nodesCombo.addItem(f"{node} - {hostname}", node)

        nIdx = win.nodesCombo.findData(addr)
        if nIdx != -1:
            win.nodesCombo.setCurrentIndex(nIdx)

        showNodes = len(win._node_list) > 1
        win.nodesCombo.setVisible(showNodes)
        win.nodeApplyAllCheck.setVisible(showNodes)

    except Exception as e:
        print(win.LOG_TAG, "exception loading nodes: ", e, addr)
        return False
    finally:
        win.nodesCombo.blockSignals(False)

    return True

def get_node_addr(win):
    nIdx = win.nodesCombo.currentIndex()
    addr = win.nodesCombo.itemData(nIdx)
    return addr

def load_rules(win, addr):
    rec = win._nodes.get_rules(addr)
    if rec is None:
        return

    rlist = []
    while rec.next() is not False:
        rlist.append(rec.value(RuleFields.Name))
    completer = QtWidgets.QCompleter(rlist)
    completer.setFilterMode(Qt.MatchFlag.MatchContains)
    win.ruleNameEdit.setCompleter(completer)
