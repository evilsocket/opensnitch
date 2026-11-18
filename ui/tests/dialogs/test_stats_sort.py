#
# pytest -v tests/dialogs/test_stats_sort.py
#
# Note: these tests save the settings of the stats dialog.
#

import os
import sys
from PyQt6 import QtCore, QtGui

# Import proto first to avoid circular import issues
import opensnitch.proto as proto
proto.import_()

# the .ui file of the stats dialog loads the custom widgets as a top level
# module
sys.path.append(os.path.join(os.path.dirname(__file__), "../../opensnitch"))

from opensnitch.config import Config
from opensnitch.database import Database
from opensnitch.dialogs.events import StatsDialog
from opensnitch.dialogs.events import constants


# the stats dialog is not meant to be destroyed (it lives as long as the GUI),
# and deleting it crashes on exit. Keep the dialogs alive.
_dialogs = []

def new_stats_dialog():
    dialog = StatsDialog(dbname="general", db=Database.instance(), appicon=QtGui.QIcon())
    dialog.show()
    _dialogs.append(dialog)
    return dialog


def get_rules_query(dialog):
    return dialog.rulesTable.model().query().lastQuery()


def reset_rules_view_settings():
    Config.get().settings.remove(Config.STATS_RULES_COL_STATE)


class TestStatsSortOrder():

    def test_rules_sort_order_restored(self, qtbot):
        """The rules view must be sorted by the saved sort column after
        reopening the dialog, not only display the sort indicator."""
        reset_rules_view_settings()
        dialog = new_stats_dialog()
        dialog.set_current_tab(constants.TAB_RULES)
        header = dialog.rulesTable.horizontalHeader()
        last_col = dialog.rulesTable.model().columnCount()-1
        header.setSortIndicator(last_col, QtCore.Qt.SortOrder.DescendingOrder)
        assert "ORDER BY %d DESC" % (last_col+1) in get_rules_query(dialog)
        dialog.close()

        dialog = new_stats_dialog()
        header = dialog.rulesTable.horizontalHeader()
        assert header.sortIndicatorSection() == last_col
        assert "ORDER BY %d DESC" % (last_col+1) in get_rules_query(dialog)
        dialog.close()

    def test_rules_default_sort_order_kept(self, qtbot):
        """If the user never sorted the view, the default order (by name)
        must be kept after reopening the dialog, and the sort indicator must
        point to the column used to sort the rows."""
        reset_rules_view_settings()
        dialog = new_stats_dialog()
        assert "ORDER BY 2 ASC" in get_rules_query(dialog)
        dialog.close()

        dialog = new_stats_dialog()
        header = dialog.rulesTable.horizontalHeader()
        assert header.sortIndicatorSection() == 1
        assert header.sortIndicatorOrder() == QtCore.Qt.SortOrder.AscendingOrder
        assert "ORDER BY 2 ASC" in get_rules_query(dialog)
        dialog.close()

    def test_rules_detail_view_order_not_restored(self, qtbot):
        """Reopening the dialog while in a detail view of the rules tab must
        not overwrite the order of the rules list."""
        reset_rules_view_settings()
        dialog = new_stats_dialog()
        dialog.set_current_tab(constants.TAB_RULES)
        dialog.set_in_detail_view(constants.TAB_RULES, True)
        dialog.TABLES[constants.TAB_RULES]['cmd'].setVisible(True)
        dialog.rulesTable.horizontalHeader().setSortIndicator(4, QtCore.Qt.SortOrder.DescendingOrder)
        order_by = dialog.TABLES[constants.TAB_RULES]['last_order_by']

        dialog.hide()
        dialog.show()

        assert dialog.TABLES[constants.TAB_RULES]['last_order_by'] == order_by
        dialog.set_in_detail_view(constants.TAB_RULES, False)
        dialog.TABLES[constants.TAB_RULES]['cmd'].setVisible(False)
        dialog.close()
