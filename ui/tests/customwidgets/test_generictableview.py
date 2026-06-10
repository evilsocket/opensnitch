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


def insert_test_rules(db, names=None):
    if names is None:
        names = [rule_name(i) for i in range(NUM_RULES)]
    db.clean("rules")
    for i, name in enumerate(names):
        rule_time = "2026-06-06 10:{0:02d}:{1:02d}".format(i // 60, i % 60)
        db.insert(
            "rules",
            "(time, node, name, enabled, precedence, action, duration, " \
            "operator_type, operator_sensitive, operator_operand, operator_data, " \
            "description, nolog, created)",
            (
                rule_time, TEST_NODE, name, "True",
                "False", "allow", "always", "simple", "False", "process.path",
                "/bin/app-{0}".format(i), "", "False", rule_time
            )
        )


def build_rules_view(qtbot):
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
    model.setQuery(RULES_QUERY, Database.instance().get_db())

    qtbot.addWidget(container)
    container.resize(600, 400)
    container.show()
    qtbot.waitExposed(container)
    view.refresh()
    return container, view


@pytest.fixture
def rules_view(qtbot):
    insert_test_rules(Database.instance())
    container, view = build_rules_view(qtbot)
    # the fixture frame keeps the container referenced for the duration
    # of the test; qtbot only holds a weak reference
    yield view


@pytest.fixture
def mixed_rules_view(qtbot):
    """Two name groups with enough rules to scroll the view."""
    names = ["app-{0:03d}".format(i) for i in range(30)]
    names += ["term-{0:03d}".format(i) for i in range(30)]
    insert_test_rules(Database.instance(), names)
    container, view = build_rules_view(qtbot)
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


def test_query_change_refreshes_viewport_while_scrolled(mixed_rules_view, qtbot):
    """Regression: changing the query (e.g. typing a filter) while the
    scrollbar was not at the top or bottom of the view kept displaying the
    rows of the previous query, so the visible rows didn't match the data
    that selections and menu actions operated on."""
    view = mixed_rules_view
    model = view.model()

    view.vScrollBar.setValue(10)
    displayed = [row[COL_NAME] for row in model.items]
    assert len(displayed) > 0
    assert all(name.startswith("app-") for name in displayed)

    filtered_query = "SELECT time, node, name, enabled FROM rules " \
        "WHERE name LIKE 'term-%' ORDER BY name ASC"
    model.setQuery(filtered_query, Database.instance().get_db())

    displayed = [row[COL_NAME] for row in model.items]
    assert len(displayed) > 0
    assert all(name.startswith("term-") for name in displayed)


def test_right_press_does_not_arm_drag_selection(rules_view, qtbot):
    """Regression: a right-button press armed the drag-selection logic
    (mousePressed), interfering with refresh skipping and row tracking."""
    cell_rect = rules_view.visualRect(rules_view.model().index(0, COL_NAME))
    qtbot.mousePress(rules_view.viewport(), Qt.MouseButton.RightButton, pos=cell_rect.center())
    assert rules_view.mousePressed is False
    qtbot.mouseRelease(rules_view.viewport(), Qt.MouseButton.RightButton, pos=cell_rect.center())
