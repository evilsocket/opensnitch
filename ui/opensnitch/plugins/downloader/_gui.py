
from PyQt5 import QtWidgets

# TODO
def add_panel_items(parent, config):
    """add an entry to the Rules Tab -> left panel, to list configured urls"""
    cmdPrefs = QtWidgets.QPushButton("x", objectName="cmdPrefsDownloaders")
    cmdPrefs.setFlat(True)
    #cmdPregs.clicked.connect(_cb_prefs_lists_clicked)
    itemTop = QtWidgets.QTreeWidgetItem(parent.rulesTreePanel)
    font = itemTop.font(0)
    font.setBold(True)
    itemTop.setFont(0, font)
    itemTop.setText(0, "lists")
    for idx, cfg in enumerate(config):
        for url in cfg['urls']:
            item = QtWidgets.QTreeWidgetItem(itemTop)
            item.setText(0, url['name'])

    parent.rulesTreePanel.addTopLevelItem(itemTop)
