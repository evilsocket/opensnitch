#
# pytest -v tests/customwidgets/test_generictableview.py
#
# Regression tests for the selection tracking of GenericTableView:
# the view keeps a parallel set of selected rows (texts of the tracking
# column) which menu actions operate on, so it must always match the
# visually selected rows.
#

import pytest
from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import Qt

# opensnitch.utils must be imported before opensnitch.database to resolve
# their circular import
import opensnitch.utils  # noqa: F401
from opensnitch.database import Database
from opensnitch.customwidgets.generictableview import GenericTableModel, GenericTableView

RULES_HEADERS = ["Time", "Node", "Name", "Enabled"]
RULES_QUERY = "SELECT time, node, name, enabled FROM rules ORDER BY name ASC"
COL_NAME = 2
NUM_RULES = 6
TEST_NODE = "unix:/tmp/osui.sock"
# time enough for the deferred (QTimer.singleShot) selection sync to run
DEFERRED_SYNC_WAIT_MS = 50


def rule_name(num):
    return "rule-{0:03d}".format(num)


def insert_test_rules(db):
    db.clean("rules")
    for i in range(NUM_RULES):
        db.insert(
            "rules",
            "(time, node, name, enabled, precedence, action, duration, " \
            "operator_type, operator_sensitive, operator_operand, operator_data, " \
            "description, nolog, created)",
            (
                "2026-06-06 10:00:0{0}".format(i), TEST_NODE, rule_name(i), "True",
                "False", "allow", "always", "simple", "False", "process.path",
                "/bin/app-{0}".format(i), "", "False", "2026-06-06 10:00:0{0}".format(i)
            )
        )


@pytest.fixture
def rules_view(qtbot):
    db = Database.instance()
    insert_test_rules(db)

    container = QtWidgets.QWidget()
    layout = QtWidgets.QHBoxLayout(container)
    view = GenericTableView(container)
    scrollbar = QtWidgets.QScrollBar(container)
    layout.addWidget(view)
    layout.addWidget(scrollbar)

    model = GenericTableModel("rules", RULES_HEADERS)
    view.setVerticalScrollBar(scrollbar)
    view.setTrackingColumn(COL_NAME)
    view.setModel(model)
    model.setQuery(RULES_QUERY, db.get_db())

    qtbot.addWidget(container)
    container.resize(600, 400)
    container.show()
    qtbot.waitExposed(container)
    view.refresh()
    # yield keeps the fixture frame (and so the container) referenced for
    # the duration of the test; qtbot only holds a weak reference
    yield view


def click_row(qtbot, view, row):
    cell_rect = view.visualRect(view.model().index(row, COL_NAME))
    qtbot.mouseClick(view.viewport(), Qt.MouseButton.LeftButton, pos=cell_rect.center())


def get_current_row_name(view):
    cur_idx = view.selectionModel().currentIndex()
    if not cur_idx.isValid():
        return None
    return view.model().index(cur_idx.row(), COL_NAME).data()


def test_click_tracks_clicked_row(rules_view, qtbot):
    click_row(qtbot, rules_view, 0)
    assert rules_view._rows_selection == {rule_name(0)}
    assert get_current_row_name(rules_view) == rule_name(0)


def test_key_down_tracks_new_current_row(rules_view, qtbot):
    """Regression: the tracked selection lagged one row behind the visible
    one on keyboard navigation, so actions hit the wrong rule. Also guards
    against the NameError raised by onKeyDown."""
    click_row(qtbot, rules_view, 0)

    qtbot.keyClick(rules_view, Qt.Key.Key_Down)
    qtbot.wait(DEFERRED_SYNC_WAIT_MS)

    assert get_current_row_name(rules_view) == rule_name(1)
    assert rules_view._rows_selection == {rule_name(1)}


def test_key_up_tracks_new_current_row(rules_view, qtbot):
    click_row(qtbot, rules_view, 2)

    qtbot.keyClick(rules_view, Qt.Key.Key_Up)
    qtbot.wait(DEFERRED_SYNC_WAIT_MS)

    assert get_current_row_name(rules_view) == rule_name(1)
    assert rules_view._rows_selection == {rule_name(1)}


def test_click_empty_area_clears_tracked_selection(rules_view, qtbot):
    """Regression: clicking on the empty area below the rows cleared the
    visual selection but kept the tracked rows, so menu actions kept
    operating on rules no longer highlighted."""
    click_row(qtbot, rules_view, 0)
    assert rules_view._rows_selection == {rule_name(0)}

    empty_area_pos = QtCore.QPoint(10, rules_view.viewport().height() - 5)
    qtbot.mouseClick(rules_view.viewport(), Qt.MouseButton.LeftButton, pos=empty_area_pos)

    assert rules_view._rows_selection == set()
    assert rules_view.selectedRows() is None


def test_viewport_refresh_preserves_selection_and_current_row(rules_view, qtbot):
    """Regression: the periodic viewport refresh cleared currentIndex, so
    the focused row was lost every time the daemon pushed an event."""
    click_row(qtbot, rules_view, 2)

    rules_view.refresh()

    selected = rules_view.selectionModel().selectedRows(COL_NAME)
    assert [sel.data() for sel in selected] == [rule_name(2)]
    assert get_current_row_name(rules_view) == rule_name(2)


def test_selected_rows_returns_clicked_rule(rules_view, qtbot):
    """selectedRows() feeds the context-menu actions: it must return the
    db row matching the visually selected rule."""
    click_row(qtbot, rules_view, 1)

    selected_db_rows = rules_view.selectedRows()
    assert selected_db_rows is not None
    assert len(selected_db_rows) == 1
    assert selected_db_rows[0][COL_NAME] == rule_name(1)


def test_right_press_does_not_arm_drag_selection(rules_view, qtbot):
    """Regression: a right-button press armed the drag-selection logic
    (mousePressed), interfering with refresh skipping and row tracking."""
    cell_rect = rules_view.visualRect(rules_view.model().index(0, COL_NAME))
    qtbot.mousePress(rules_view.viewport(), Qt.MouseButton.RightButton, pos=cell_rect.center())
    assert rules_view.mousePressed is False
    qtbot.mouseRelease(rules_view.viewport(), Qt.MouseButton.RightButton, pos=cell_rect.center())
