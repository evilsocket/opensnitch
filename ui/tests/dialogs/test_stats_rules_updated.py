#
# pytest -v tests/dialogs/test_stats_rules_updated.py
#
# Note: these tests save the settings of the stats dialog.
#

import os
import sys
from unittest.mock import patch
from PyQt6 import QtGui

# Import proto first to avoid circular import issues
import opensnitch.proto as proto
proto.import_()

# the .ui file of the stats dialog loads the custom widgets as a top level
# module
sys.path.append(os.path.join(os.path.dirname(__file__), "../../opensnitch"))

from opensnitch.database import Database
from opensnitch.dialogs.events import StatsDialog

# the stats dialog is not meant to be destroyed (it lives as long as the GUI),
# and deleting it crashes on exit. Keep it alive.
_dialogs = []


def test_rules_updated_refreshes_only_visible_dialog(qtbot):
    """Rules are added/deleted all the time (pop-ups, temporary rules), so
    the active view must not be queried while the dialog is hidden."""
    dialog = StatsDialog(dbname="general", db=Database.instance(), appicon=QtGui.QIcon())
    _dialogs.append(dialog)

    with patch.object(dialog, "refresh_active_table") as refresh:
        dialog._cb_app_rules_updated(None)
        assert refresh.call_count == 0

        dialog.show()
        refresh.reset_mock()
        dialog._cb_app_rules_updated(None)
        assert refresh.call_count == 1
    dialog.close()
