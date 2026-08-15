GUI unit tests.

We use pytest [0] to pytest-qt [1] to test GUI code.

To run the tests: `cd tests; pytest -v`

The tests under `cli/` cover opensnitch-cli, which runs on servers without Qt.
They don't need PyQt6 or a display, so they can be run on their own with only
grpcio, protobuf and python-slugify installed:

    cd tests; pytest -v cli/

`cli/test_no_qt.py` fails if anything in opensnitch/cli/ ends up importing Qt,
and `cli/test_operands_parity.py` checks that the terminal client builds exactly
the same rules as the pop-up does (it is skipped when PyQt6 is missing).

TODO:
 - test service class (Service.py)
 - test events window (stats.py):
   - The size of the window must be saved on close, and restored when opening it again.
   - Columns width of every view must be saved and restored properly.
   - On the Events tab, clicking on the Node, Process or Rule column must jump to the detailed view of the selected item.
   - When entering into a detail view:
     - the results limit configured must be respected (that little button on the bottom right of every tab).
     - must apply the proper SQL query for every detailed view.
   - When going back from a detail view:
     - The SQL query must be restored.
   - Test rules context menu actions.
   - Test select rows and copy them to the clipboard (ctrl+c).


0. https://docs.pytest.org/en/6.2.x/
1. https://pytest-qt.readthedocs.io/en/latest/intro.html
