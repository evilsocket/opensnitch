import json
from PyQt5 import QtWidgets
from opensnitch.plugins.virustotal.virustotal import VTAnalysis, Virustotal
from opensnitch.plugins.virustotal import _utils

def build_vt_tab(plugin, parent):
    """add a new tab with a text field that will contain the result of the query in JSON format.
    """
    wdg_count = parent.tabWidget.count()
    prev_wdg = parent.tabWidget.widget(wdg_count)
    if prev_wdg != None and prev_wdg.objectName() == "vt_tab":
        return prev_wdg

    wdg = QtWidgets.QWidget()
    wdg.setObjectName("vt_tab")
    gridLayout =  QtWidgets.QGridLayout()
    textWdg = QtWidgets.QTextEdit()
    textWdg.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
    gridLayout.addWidget(textWdg, 0, 0)
    wdg.setLayout(gridLayout)

    return wdg

def add_vt_tab(vt, parent, widget):
    parent.tabWidget.addTab(widget, "Virustotal")
    parent.tabWidget.currentChanged.connect(lambda idx: _cb_proctab_changed(idx, vt, parent))

def _cb_proctab_changed(idx, vt, parent):
    cur_tab = parent.tabWidget.widget(idx)
    if cur_tab.objectName() != "vt_tab":
        return

    tmp = parent.labelChecksums.text().split(" ")
    lblChecksum = ""
    if len(tmp) > 1:
        lblChecksum = tmp[1]

    if lblChecksum == "":
        return

    url = vt.API_FILES + lblChecksum
    vt_thread = VTAnalysis(parent, vt._config, "", url, vt.API_CONNECT_TIMEOUT, vt.API_KEY, None)
    vt_thread.signals.completed.connect(vt.analysis_completed)
    vt_thread.signals.error.connect(vt.analysis_error)
    vt.threadsPool.start(vt_thread)

def update_tab(what, response, parent, config, conn):
    tabs = parent.tabWidget.count()-1
    cur_tab = parent.tabWidget.widget(tabs)
    if cur_tab.objectName() != "vt_tab":
        return
    result = json.loads(response.content)
    textWdg = cur_tab.layout().itemAtPosition(0, 0).widget()
    textWdg.clear()

    if result.get('data') == None:
        textWdg.setPlainText("checksum not found on Virustotal. Upload the binary for analysis and generate a report.")
        return
    textWdg.setHtml(_utils.report_to_html(result))
