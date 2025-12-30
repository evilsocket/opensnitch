from PyQt6 import QtWidgets, QtGui, QtCore
from opensnitch.utils import Icons
from opensnitch.plugins.virustotal import _utils
from opensnitch.config import Config
from opensnitch.dialogs.prompt import (
    constants,
    utils as popup_utils
)

# XXX: the tab index may vary. TODO: Find it dynamically.
VT_TAB = 3

def build_vt_tab(plugin, parent):
    """add a new tab with a text field that will contain the result of the query in JSON format.
    """
    backIcon = Icons.new(parent, "go-previous")

    # FIXME: find the widget with the name 'vt_tab', there could be more
    # plugins that are tabs.
    prev_wdg = parent.get_main_widget().widget(VT_TAB)
    if prev_wdg != None and prev_wdg.objectName() == "vt_tab":
        return prev_wdg

    wdg = QtWidgets.QWidget()
    gridLayout =  QtWidgets.QGridLayout()
    hor_wdg = QtWidgets.QHBoxLayout()
    cmdBack = QtWidgets.QPushButton("", objectName="plugin_virustotal")
    cmdBack.setFlat(True)
    cmdBack.setIcon(backIcon)

    # 0 details, 1 checksums, 2 main
    cmdBack.clicked.connect(lambda: parent.get_main_widget().setCurrentIndex(constants.PAGE_MAIN))
    cmdBack.setSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Maximum)
    textWdg = QtWidgets.QTextBrowser()
    textWdg.setTextInteractionFlags(
        QtCore.Qt.TextInteractionFlag.LinksAccessibleByMouse | QtCore.Qt.TextInteractionFlag.TextSelectableByKeyboard | QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
    )
    textWdg.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
    # https://doc.qt.io/qtforpython-6/PySide6/QtWidgets/QTextBrowser.html#PySide6.QtWidgets.QTextBrowser.openExternalLinks
    textWdg.setOpenExternalLinks(True)
    textWdg.setOpenLinks(True)
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
    parent.get_main_widget().addWidget(tab)

def add_vt_response(parent, response, conn, error=None):
    tab = parent.get_main_widget().widget(VT_TAB).layout()
    textWdg = tab.itemAtPosition(1, 0).widget()
    textWdg.clear()
    #textWdg.insertPlainText(str(json.dumps(response, indent=4)))
    #textWdg.insertPlainText(_utils.report_to_ascii(response, "", ""))
    if error:
        textWdg.insertPlainText("{0}\n\nBe sure that there's a rule to allow outbound connections from the GUI to www.virustotal.com".format(
            error
        ))
    else:
        md5 = conn.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]
        dstip = conn.dst_ip
        dsthost = conn.dst_host
        vturl = "https://www.virustotal.com/gui"
        vthash = f"{vturl}/file/{md5}"
        vtip = f"{vturl}/ip-address/{dstip}"

        links = "View on VirusTotal: "
        links += f"<a href=\"{vtip}\">IP</a>"
        if md5 != "":
            links += f" &ndash; <a href=\"{vthash}\">hash</a>"
        if dsthost != "":
            vtdomain = f"{vturl}/domain/{dsthost}"
            links += f" &ndash; <a target=\"_blank\" href=\"{vtdomain}\">domain</a>"

        textWdg.setHtml(links + "<br><br>" + _utils.report_to_html(response))
    textWdg.moveCursor(QtGui.QTextCursor.MoveOperation.Start)

def add_analyzing_msg(vt, parent):
    parent.set_message_text("{0}<br>{1}".format(
        vt.ANALYZING_MESSAGE,
        parent.get_message_text()
    ))

def reset_widgets_state(parent):
    parent.set_message_style('')
    parent.appNameLabel.setStyleSheet('')
    parent.checksumLabel.setStyleSheet('')
    parent.destIPLabel.setStyleSheet('')

def _cb_popup_link_clicked(link, parent):
    """link clicked on the popup"""
    if link == "#virustotal-warning":
        wdg_count = parent.get_main_widget().count()
        parent.get_main_widget().setCurrentIndex(VT_TAB)
