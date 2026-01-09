
import sys
import os

from PyQt6 import QtCore, QtGui, uic, QtWidgets

from . import (
    constants
)

DIALOG_UI_PATH = "%s/../../res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)
class EventsBase(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    def __init__(self, parent=None):
        super(EventsBase, self).__init__(parent)
        self.setupUi(self)

    def add_tab(self, widget, icon, label):
        tab = self.get_central_widget()
        tab.addTab(widget, icon, label)

    def set_current_tab(self, idx, block_events=False):
        if block_events:
            self.get_central_widget().blockSignals(True)
        self.get_central_widget().setCurrentIndex(idx)
        if block_events:
            self.get_central_widget().blockSignals(False)

    def add_toolbar_buton(self):
        #self.horizontalLayout_10
        pass

    def add_tree_items(self, level, labels, clean=True):
        """adds new items to the panel.
         - level: index under the items will be added.
         - labels: tuple with the labels of columns 0 and 1.
         - clean: if the existing items must be deleted.
        """
        item = self.rulesTreePanel.topLevelItem(level)
        if clean:
            item.takeChildren()

        for k, v in labels:
            item.addChild(
                QtWidgets.QTreeWidgetItem([k, v])
            )

    def get_tree_item(self, idx):
        try:
            return self.rulesTreePanel.topLevelItem(idx)
        except Exception:
            return None

    def find_tree_items(self, idx, data):
        item = self.rulesTreePanel.topLevelItem(idx)
        it = QtWidgets.QTreeWidgetItemIterator(item)
        items = []
        while it.value():
            x = it.value()
            if x.data(0, QtCore.Qt.ItemDataRole.UserRole) == data:
                items.append(x)
            it+=1

        return items

    def get_tree_selected_items(self, tree_idx):
        expanded = list()
        selected = None
        item = self.rulesTreePanel.topLevelItem(tree_idx)
        it = QtWidgets.QTreeWidgetItemIterator(item)
        # save tree selected rows
        try:
            while it.value():
                v = it.value()
                if v.isExpanded():
                    expanded.append(v)
                if v.isSelected():
                    selected = v
                it += 1
        except Exception:
            pass

        return selected, expanded

    def set_tree_selected_items(self, selected, expanded):
        try:
            for item in expanded:
                items = self.rulesTreePanel.findItems(item.text(0), QtCore.Qt.MatchRecursive)
                for it in items:
                    it.setExpanded(True)
                    if selected is not None and selected.text(0) == it.text(0):
                        it.setSelected(True)
        except:
            pass

    def get_current_view_idx(self):
        return self.tabWidget.currentIndex()

    def get_central_widget(self):
        return self.tabWidget

    def get_data_view(self, idx):
        return self.eventsTable

    def get_search_widget(self):
        return self.filterLine

    def get_search_text(self):
        return self.filterLine.text()

    def set_search_text(self, text):
        return self.filterLine.setText(text)
