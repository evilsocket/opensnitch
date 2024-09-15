import json
from PyQt5 import QtWidgets, QtGui, QtCore
from opensnitch.utils import Icons
from opensnitch.plugins.virustotal import _utils

def build_vt_tab(plugin, parent):
    """add a new tab with a text field that will contain the result of the query in JSON format.
    """
    backIcon = Icons.new(plugin, "go-previous")

    # FIXME: find the widget with the name 'vt_tab', there could be more
    # plugins that are tabs.
    prev_wdg = parent.stackedWidget.widget(3)
    if prev_wdg != None and prev_wdg.objectName() == "vt_tab":
        return prev_wdg

    wdg = QtWidgets.QWidget()
    gridLayout =  QtWidgets.QGridLayout()
    hor_wdg = QtWidgets.QHBoxLayout()
    cmdBack = QtWidgets.QPushButton("", objectName="plugin_virustotal")
    cmdBack.setFlat(True)
    cmdBack.setIcon(backIcon)

    # 0 details, 1 checksums, 2 main
    cmdBack.clicked.connect(lambda: parent.stackedWidget.setCurrentIndex(2))
    cmdBack.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum)
    textWdg = QtWidgets.QTextEdit()
    textWdg.setTextInteractionFlags(
        QtCore.Qt.LinksAccessibleByMouse | QtCore.Qt.TextSelectableByKeyboard | QtCore.Qt.TextSelectableByMouse
    )
    textWdg.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
    wdg.setObjectName("vt_tab")
    gridLayout.setContentsMargins(5, 3, 5, 5)
    gridLayout.setVerticalSpacing(3)

    hor_wdg.addWidget(cmdBack)
    hor_wdg.addStretch(1)
    #hor_wdg.addWidget(spacer)
    gridLayout.addLayout(hor_wdg, 0, 0)
    gridLayout.addWidget(textWdg, 1, 0)
    wdg.setLayout(gridLayout)

    return wdg

def add_vt_tab(parent, tab):
    parent.stackedWidget.addWidget(tab)

def add_vt_response(parent, response, error=None):
    tab = parent.stackedWidget.widget(3).layout()
    textWdg = tab.itemAtPosition(1, 0).widget()
    textWdg.clear()
    #textWdg.insertPlainText(str(json.dumps(response, indent=4)))
    #textWdg.insertPlainText(_utils.report_to_ascii(response, "", ""))
    if error:
        textWdg.insertPlainText("{0}\n\nBe sure that there's a rule to allow outbound connections from the GUI to www.virustotal.com".format(
            error
        ))
    else:
        textWdg.setHtml(_utils.report_to_html(response))
    textWdg.moveCursor(QtGui.QTextCursor.Start)

def add_analyzing_msg(vt, parent):
    parent.messageLabel.setText("{0}<br>{1}".format(
        vt.ANALYZING_MESSAGE,
        parent.messageLabel.text()
    ))

def reset_widgets_state(parent):
    parent.messageLabel.setStyleSheet('')
    parent.appNameLabel.setStyleSheet('')
    parent.checksumLabel.setStyleSheet('')
    parent.destIPLabel.setStyleSheet('')

def _cb_popup_link_clicked(link, parent):
    """link clicked on the popup"""
    if link == "#virustotal-warning":
        wdg_count = parent.stackedWidget.count()
        parent.stackedWidget.setCurrentIndex(3)
