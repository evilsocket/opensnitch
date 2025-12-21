from PyQt6 import QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from . import constants

def load_nodes(win):
    win.comboNodes.blockSignals(True)

    win.comboNodes.clear()
    win._node_list = win.nodes.get()
    win.comboNodes.addItem(QC.translate("firewall", "All"), "all")
    for addr in win._node_list:
        hostname = win.nodes.get_node_hostname(addr)
        win.comboNodes.addItem(f"{addr} - {hostname}", addr)

    if len(win._node_list) == 0:
        win.tabWidget.setDisabled(True)
    elif len(win._node_list) == 1:
        win.comboNodes.setCurrentIndex(1)

    hideNodes = len(win._node_list) > 1
    win.comboNodes.setVisible(hideNodes)
    win.labelNode.setVisible(hideNodes)

    win.comboNodes.blockSignals(False)

def reset_widgets(win, title, topWidget):
    for i in range(topWidget.count()):
        topWidget.removeItem(i)
        w = topWidget.widget(i)
        if w is not None:
            w.setParent(None)

    win.statements = {}
    win.st_num = 0

    # if we don't do this, toolbox's subwidgets are not deleted (removed
    # from the GUI, but not deleted), so sometimes after loading/closing several rules,
    # you may end up with rules mixed on the same layout/form.
    win.toolBoxSimple.setParent(None)
    win.toolBoxSimple = QtWidgets.QToolBox()
    win.tabWidget.widget(0).layout().addWidget(win.toolBoxSimple)
    #win.toolBoxSimple.currentChanged.connect(win._cb_toolbox_page_changed)

def set_status_error(win, msg):
    win.statusLabel.show()
    win.statusLabel.setStyleSheet('color: red')
    win.statusLabel.setText(msg)

def set_status_successful(win, msg):
    win.statusLabel.show()
    win.statusLabel.setStyleSheet('color: green')
    win.statusLabel.setText(msg)

def set_status_message(win, msg):
    win.statusLabel.show()
    win.statusLabel.setStyleSheet('color: darkorange')
    win.statusLabel.setText(msg)

def reset_status_message(win):
    win.statusLabel.setText("")
    win.statusLabel.hide()

def reset_fields(win):
    win.FORM_TYPE = constants.FORM_TYPE_SIMPLE
    win.setWindowTitle(QC.translate("firewall", "Firewall rule"))

    win.cmdDelete.setVisible(False)
    win.cmdSave.setVisible(False)
    win.cmdAdd.setVisible(True)

    win.checkEnable.setVisible(True)
    win.checkEnable.setEnabled(True)
    win.checkEnable.setChecked(True)
    win.frameDirection.setVisible(True)
    win.lblExcludeTip.setVisible(False)
    win.lblExcludeTip.setText("")

    reset_status_message(win)
    enable_buttons(win)
    win.tabWidget.setDisabled(False)
    win.lineDescription.setText("")
    win.comboDirection.setCurrentIndex(constants.IN)
    win.comboDirection.setEnabled(True)

    win.comboVerdict.blockSignals(True)
    win.comboVerdict.setCurrentIndex(0)
    win.comboVerdict.blockSignals(False)
    win.lineVerdictParms.setVisible(False)
    win.comboVerdictParms.setVisible(False)
    win.lineVerdictParms.setText("")

    win.uuid = ""
    win.addr = ""

def enable_save(win, enable=True):
    """Enable Save buton whenever some detail of a rule changes.
    The button may or not be hidden. If we're editing a rule it'll be shown
    but disabled/enabled.
    """
    win.cmdSave.setEnabled(enable)

def enable_buttons(win, enable=True):
    """Disable add/save buttons until a response is received from the daemon.
    """
    win.cmdSave.setEnabled(enable)
    win.cmdAdd.setEnabled(enable)
    win.cmdDelete.setEnabled(enable)

def disable_buttons(win, disabled=True):
    win.cmdSave.setDisabled(disabled)
    win.cmdAdd.setDisabled(disabled)
    win.cmdDelete.setDisabled(disabled)

def disable_controls(win):
    disable_buttons(win)
    win.tabWidget.setDisabled(True)

def is_valid_int_value(value):
    try:
        int(value)
    except:
        return False

    return True

