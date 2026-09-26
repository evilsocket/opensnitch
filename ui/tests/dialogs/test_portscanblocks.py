#
# pytest -v tests/dialogs/test_portscanblocks.py
#
# The list of blocked scan sources exists to show every address the daemon is
# blocking, and to let the user release one. Both claims are checked here by
# driving the real widgets -- a real QTableWidget, the real notification queue,
# the real generated protobuf bindings, and the real main window -- rather than
# by inspecting their source.
#
import json
import pytest
import time
import os
import sys

from PyQt6 import QtCore, QtGui, QtWidgets

# stats.ui names its custom widgets as top-level modules ("customwidgets...");
# the application puts its package directory on the path for them (see
# service.py), and so does this test.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "opensnitch"))

# Import proto first to avoid circular import issues
import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from opensnitch.nodes import Nodes
from opensnitch.portscan import BlockedListPresenter
from opensnitch.customwidgets.portscanblocksview import PortScanBlocksView
from opensnitch.dialogs.events.tasks.portscanblocks import BlockedSources
from opensnitch.dialogs.events import StatsDialog, constants
from opensnitch.database import Database
from opensnitch.config import Config

NODE = "unix:/tmp/osui.sock"
VIEW = "opensnitch.customwidgets.portscanblocksview"
FEED = "opensnitch.dialogs.events.tasks.portscanblocks"


@pytest.fixture(autouse=True)
def render_every_push(monkeypatch):
    """The tests deliver pushes back to back and read the table at once: the
    coalescing of renders is tested on its own, in TestTheRenderCoalescing."""
    monkeypatch.setattr(PortScanBlocksView, "RENDER_INTERVAL_MS", 0)


def snapshot(blocks, total=None, omitted=0, detections=None, can_block=True):
    snap = {
        "blocks": blocks,
        "total": len(blocks) if total is None else total,
        "omitted": omitted,
    }
    if detections is not None:
        snap.update({"detections": detections, "detections_total": len(detections),
                     "can_block": can_block})
    return json.dumps(snap)


def detected(addr, status="unanswered", eligible=True, exempt=False, reason="",
             method="tcp-xmas", detail="TCP Xmas scan (equivalent to nmap -sX)"):
    d = {"addr": addr, "method": method, "method_detail": detail, "status": status,
         "first_reported": 1758640000, "last_reported": 1758644000,
         "eligible": eligible}
    if reason:
        d["reason"] = reason
    if exempt:
        d["exempt"] = True
    return d


def block(addr, reason="automatic policy", remaining=14400, expires_at=1758648000):
    return {"addr": addr, "reason": reason,
            "remaining": remaining, "expires_at": expires_at}


def queue():
    return Nodes.instance()._nodes[NODE]['notifications']


def drain():
    out = []
    q = queue()
    while not q.empty():
        out.append(q.get())
    return out


def settle(qtbot):
    """Lets the event loop run the deferred stop, if one is pending."""
    qtbot.wait(20)


class TestPortScanBlocksView():
    """One view and its feed, as the Port scan Detection tab uses them."""

    def setup_method(self):
        self.nodes = Nodes.instance()
        self.feed = BlockedSources()
        self.view = PortScanBlocksView(self.feed)

    def teardown_method(self):
        try:
            self.view.hide()
            self.feed._stop()
        except Exception:
            pass

    # ---------------------------------------------------------------- helpers

    def _open(self, qtbot):
        drain()
        qtbot.addWidget(self.view)
        self.view.show()
        return drain()

    def _deliver(self, data, code=None):
        """Feeds the view one reply, as the daemon would."""
        nid = next(iter(self.feed._sent))
        reply = ui_pb2.NotificationReply(
            id=nid,
            code=ui_pb2.OK if code is None else code,
            data=data)
        self.feed._cb_notification_callback(NODE, reply)

    def _column(self, col):
        return [self.view.table.item(i, col).text()
                for i in range(self.view.table.rowCount())]

    def _status(self):
        return self.view.lblStatus.text()

    # ------------------------------------------------------------ the stream

    def test_showing_the_view_asks_the_daemon_for_the_list(self, qtbot):
        sent = self._open(qtbot)
        assert len(sent) == 1
        assert sent[0].type == ui_pb2.TASK_START
        payload = json.loads(sent[0].data)
        assert payload["name"] == "portscan-blocks"
        assert payload["data"]["interval"] == BlockedSources.INTERVAL
        # The reply has to be routable back to the node that answers it.
        assert list(self.feed._sent.values()) == [NODE]

    def test_hiding_the_view_stops_the_task(self, qtbot):
        self._open(qtbot)
        self.view.hide()
        settle(qtbot)
        sent = drain()
        assert [n.type for n in sent] == [ui_pb2.TASK_STOP]
        assert json.loads(sent[0].data)["name"] == "portscan-blocks"
        assert not self.feed.is_running()

    def test_nothing_is_said_before_the_first_answer(self, qtbot):
        # "No address is blocked." is a statement about the host; before the
        # daemon has answered, it would be a guess.
        self._open(qtbot)
        assert self._status() != BlockedListPresenter.empty_label()

    # -------------------------------------------------------------- the table

    def test_a_snapshot_fills_the_table(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([
            block("192.0.2.66", "automatic policy", remaining=14400),
            block("2001:db8::1", "confirmed by the user", remaining=90),
        ]))
        assert self.view.table.rowCount() == 2
        assert self._column(PortScanBlocksView.COL_ADDR) == [
            "192.0.2.66", "2001:db8::1"]
        assert self._column(PortScanBlocksView.COL_STATUS) == ["blocked", "blocked"]
        assert self._column(PortScanBlocksView.COL_REASON) == [
            "automatic policy", "confirmed by the user"]
        assert self._column(PortScanBlocksView.COL_EXPIRES) == ["4h 0m", "1m 30s"]

    def test_the_view_says_where_a_block_lives(self, qtbot):
        # The question that led to this view: a block is not an OpenSnitch
        # rule, and the user could not find it. The view names the table.
        self._open(qtbot)
        intro = self.view.lblIntro.text()
        assert "inet opensnitch-portscan" in intro
        assert "portscan_sources_v4" in intro and "portscan_sources_v6" in intro

    def test_an_empty_table_says_so(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([]))
        assert self.view.table.rowCount() == 0
        assert self._status() == BlockedListPresenter.empty_label()

    def test_a_later_snapshot_replaces_the_earlier_one(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66"), block("192.0.2.67")]))
        assert self.view.table.rowCount() == 2
        # One expired on its own while the view was open.
        self._deliver(snapshot([block("192.0.2.67")]))
        assert self._column(PortScanBlocksView.COL_ADDR) == ["192.0.2.67"]

    def test_the_node_column_is_hidden_with_a_single_node(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        assert self.view.table.isColumnHidden(PortScanBlocksView.COL_NODE)

    def test_truncation_is_reported_rather_than_hidden(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")], total=900, omitted=899))
        status = self._status()
        assert "900" in status and "899" in status

    def test_the_filter_keeps_matching_rows(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66"), block("198.51.100.7", "confirmed by the user")]))
        self.view.set_filter("198.51")
        assert self._column(PortScanBlocksView.COL_ADDR) == ["198.51.100.7"]
        self.view.set_filter("CONFIRMED")
        assert self._column(PortScanBlocksView.COL_ADDR) == ["198.51.100.7"]
        self.view.set_filter("")
        assert self.view.table.rowCount() == 2

    def test_copy_puts_the_selected_rows_on_the_clipboard(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66"), block("192.0.2.67")]))
        self.view.table.selectRow(1)
        self.view.copy_selected_rows()
        copied = QtWidgets.QApplication.clipboard().text()
        assert "192.0.2.67" in copied and "192.0.2.66" not in copied

    # ------------------------------------------------- what must not be shown

    def test_detection_not_running_is_said_out_loud(self, qtbot):
        # The failure this prevents: an empty table reads as "nothing is
        # blocked", which is a claim about the host. When the daemon says it is
        # not detecting, the view must repeat that instead.
        self._open(qtbot)
        self._deliver("port scan detection is not running", code=ui_pb2.ERROR)
        assert self.view.table.rowCount() == 0
        assert "not running" in self._status()
        assert self._status() != BlockedListPresenter.empty_label()

    def test_a_reply_that_arrives_before_its_id_is_not_dropped(self, qtbot):
        # Nodes.send_notification answers a request for a node that is not
        # connected from inside the call, before returning the id the feed
        # records -- so the reply that says the node is gone carries an id the
        # feed has never seen. Dropping it left the table showing blocks
        # nobody was maintaining, with nothing on screen to say so.
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.9")]))
        assert self.view.table.rowCount() == 1
        unknown = ui_pb2.NotificationReply(
            id=0, code=ui_pb2.ERROR, data="node not connected: " + NODE)
        self.feed._cb_notification_callback(NODE, unknown)
        assert self.view.table.rowCount() == 0
        assert "not connected" in self._status()

    def test_an_unreadable_snapshot_is_not_an_empty_table(self, qtbot):
        self._open(qtbot)
        self._deliver("{not json")
        assert self.view.table.rowCount() == 0
        assert self._status() != BlockedListPresenter.empty_label()

    def test_markup_in_a_reason_never_reaches_the_table(self, qtbot):
        # These rows sit next to a button that removes a firewall rule. A field
        # that could forge a line of the program's own text is the last thing
        # that should be rendered verbatim here.
        self._open(qtbot)
        self._deliver(snapshot([
            block("192.0.2.66", "<b>trusted</b><script>x</script>"),
        ]))
        shown = self._column(PortScanBlocksView.COL_REASON)[0]
        assert "<" not in shown and ">" not in shown

    def test_a_row_that_is_not_an_address_is_dropped_and_counted(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([
            block("192.0.2.66"),
            block("not-an-address"),
        ], total=2))
        assert self._column(PortScanBlocksView.COL_ADDR) == ["192.0.2.66"]
        # Dropped, but not silently: the status line still accounts for it.
        assert "2" in self._status()

    # ------------------------------------------------------------- releasing

    def _yes(self, monkeypatch, answer=QtWidgets.QMessageBox.StandardButton.Yes):
        monkeypatch.setattr(VIEW + ".Message.yes_no", lambda *a, **k: answer)

    def test_release_sends_an_unblock_for_the_selected_address(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66"), block("192.0.2.67")]))

        self.view.table.selectRow(1)
        assert self.view.cmdRelease.isEnabled()

        self._yes(monkeypatch)
        drain()
        qtbot.mouseClick(self.view.cmdRelease, QtCore.Qt.MouseButton.LeftButton)

        sent = drain()
        assert len(sent) == 1
        assert sent[0].type == ui_pb2.PORTSCAN_UNBLOCK
        assert json.loads(sent[0].data) == {"ip": "192.0.2.67"}

    def test_the_delete_key_deletes_the_row(self, qtbot, monkeypatch):
        # As for a rule in the Rules tab: the source leaves the list, its block
        # released by the daemon first.
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")], detections=[detected("192.0.2.70")]))
        self.view.table.selectAll()
        said = []
        monkeypatch.setattr(VIEW + ".Message.yes_no",
                            lambda title, text, icon: said.append(text) or
                            QtWidgets.QMessageBox.StandardButton.Yes)
        drain()
        qtbot.keyClick(self.view.table, QtCore.Qt.Key.Key_Delete)
        sent = drain()
        assert [n.type for n in sent] == [ui_pb2.PORTSCAN_UNBLOCK] * 2
        assert sorted(json.loads(n.data)["ip"] for n in sent) == ["192.0.2.66", "192.0.2.70"]
        assert all(json.loads(n.data)["forget"] is True for n in sent)
        assert "released first" in said[0] and "detected afresh" in said[0]
        assert "remembers what the others did" in said[0]
        lines = said[0].splitlines()
        assert any(l.startswith("192.0.2.66  (") and l.endswith(", blocked") for l in lines)
        assert any(l.startswith("192.0.2.70  (") and not l.endswith(", blocked") for l in lines)

    def test_deleting_blocks_only_says_nothing_about_remembering(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        self.view.table.selectAll()
        said = []
        monkeypatch.setattr(VIEW + ".Message.yes_no",
                            lambda title, text, icon: said.append(text) or
                            QtWidgets.QMessageBox.StandardButton.Cancel)
        qtbot.keyClick(self.view.table, QtCore.Qt.Key.Key_Delete)
        assert "released first" in said[0]
        assert "remembers" not in said[0]

    def test_the_question_reads_the_stream_not_a_stale_table(self, qtbot, monkeypatch):
        # The table can be a render behind the stream: a detection it still
        # shows may already be a block, and the question must say so.
        self._open(qtbot)
        self._deliver(snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        monkeypatch.setattr(self.view, "_render", lambda: None)
        self._deliver(snapshot([block("192.0.2.70")], detections=[]))
        assert self.view._kind((NODE, "192.0.2.70")) == "detection"
        said = []
        monkeypatch.setattr(VIEW + ".Message.yes_no",
                            lambda title, text, icon: said.append(text) or
                            QtWidgets.QMessageBox.StandardButton.Cancel)
        qtbot.keyClick(self.view.table, QtCore.Qt.Key.Key_Delete)
        assert "192.0.2.70  (" in said[0] and ", blocked" in said[0]
        assert "released first" in said[0]

    def test_a_row_blocked_during_the_confirmation_is_not_deleted(self, qtbot, monkeypatch):
        # Under the policy auto, a detection can become a block while the
        # dialog is open: deleting it would lift a block nobody was told
        # about.
        self._open(qtbot)
        self._deliver(snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        told = []
        monkeypatch.setattr(VIEW + ".Message.ok", lambda *a, **k: told.append(a))

        def answer(title, text, icon):
            assert "released first" not in text
            self._deliver(snapshot([block("192.0.2.70")], detections=[]))
            return QtWidgets.QMessageBox.StandardButton.Yes
        monkeypatch.setattr(VIEW + ".Message.yes_no", answer)
        drain()
        qtbot.keyClick(self.view.table, QtCore.Qt.Key.Key_Delete)
        assert drain() == []
        assert told and "192.0.2.70" in told[0][1]

    def test_deleting_asks_first_and_declining_sends_nothing(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._deliver(snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        self._yes(monkeypatch, QtWidgets.QMessageBox.StandardButton.Cancel)
        drain()
        qtbot.keyClick(self.view.table, QtCore.Qt.Key.Key_Delete)
        assert drain() == []

    def test_the_rules_tab_view_still_releases_on_delete(self, qtbot, monkeypatch):
        rules = PortScanBlocksView(self.feed, detections=False)
        qtbot.addWidget(rules)
        rules.show()
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        rules.table.selectRow(0)
        self._yes(monkeypatch)
        drain()
        qtbot.keyClick(rules.table, QtCore.Qt.Key.Key_Delete)
        sent = drain()
        assert [n.type for n in sent] == [ui_pb2.PORTSCAN_UNBLOCK]
        assert "forget" not in json.loads(sent[0].data)
        assert rules._delete_targets() == []

    def test_another_refusal_does_not_blame_the_daemon_version(self, qtbot, monkeypatch):
        self._open(qtbot)
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a, **k: said.append(a))
        self.feed.delete(NODE, "192.0.2.70")
        nid = next(iter(self.feed._releases))
        self.nodes.reply_notification(NODE.split(":", 1)[1], ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="portscan: detection is not running"))
        assert said and "cannot delete a detection" not in said[0][1]

    def test_deleting_on_a_node_not_connected_says_delete(self, qtbot, monkeypatch):
        self._open(qtbot)
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a, **k: said.append(a))
        self.feed.delete("unix:/tmp/no-such-node.sock", "192.0.2.70")
        assert said and said[0][0] == "Could not delete 192.0.2.70"
        assert self.feed._deleting == set()

    def test_a_node_leaving_forgets_its_deletions(self, qtbot):
        self._open(qtbot)
        self.feed.delete(NODE, "192.0.2.70")
        assert self.feed._deleting
        self.feed._forget_releases(NODE)
        assert self.feed._deleting == set() and self.feed._releases == {}

    def test_hostile_block_times_still_render(self, qtbot):
        # blocked_at is read through unix_time: a node sending anything else
        # must not make the sort raise at every render.
        self._open(qtbot)
        blocks = []
        for i, value in enumerate(["x", -5, True, 10 ** 30, None, 1.5, [1]]):
            b = block("192.0.2.{0}".format(10 + i))
            b["blocked_at"] = value
            blocks.append(b)
        self._deliver(snapshot(blocks, detections=[detected("192.0.2.70")]))
        assert self.view.table.rowCount() == len(blocks) + 1

    def test_a_daemon_that_cannot_delete_says_so(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._deliver(snapshot([], detections=[detected("192.0.2.70")]))
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a, **k: said.append(a))
        self.feed.delete(NODE, "192.0.2.70")
        nid = next(iter(self.feed._releases))
        assert nid in self.feed._deleting
        self.nodes.reply_notification(NODE.split(":", 1)[1], ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="192.0.2.70 is not blocked"))
        assert said and said[0][0] == "Could not delete 192.0.2.70"
        assert "cannot delete a detection" in said[0][1]
        assert self.feed._deleting == set() and self.feed._releases == {}

    def test_release_asks_first_and_declining_sends_nothing(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        self.view.table.selectRow(0)

        self._yes(monkeypatch, QtWidgets.QMessageBox.StandardButton.Cancel)
        drain()
        qtbot.mouseClick(self.view.cmdRelease, QtCore.Qt.MouseButton.LeftButton)
        assert drain() == []

    def test_release_is_disabled_with_nothing_selected(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        self.view.table.clearSelection()
        assert not self.view.cmdRelease.isEnabled()

    def test_the_selection_survives_a_push(self, qtbot):
        # A snapshot arrives every couple of seconds. Rebuilding the table
        # under the cursor would make the Release button unusable on a host
        # that is being scanned, which is exactly when it is needed.
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66"), block("192.0.2.67")]))
        self.view.table.selectRow(1)
        assert self.view._selected_keys() == {(NODE, "192.0.2.67")}

        self._deliver(snapshot([block("192.0.2.66"), block("192.0.2.67")]))
        assert self.view._selected_keys() == {(NODE, "192.0.2.67")}

    @staticmethod
    def _made_at(addr, at):
        b = block(addr)
        b["blocked_at"] = at
        return b

    def _select_rows(self, *rows):
        flags = (QtCore.QItemSelectionModel.SelectionFlag.Select
                 | QtCore.QItemSelectionModel.SelectionFlag.Rows)
        for r in rows:
            self.view.table.selectionModel().select(
                self.view.table.model().index(r, 0), flags)

    def test_the_selection_does_not_move_to_the_row_that_takes_its_place(self, qtbot):
        # The selection model counts rows. Left alone, it would pass to the
        # row now sitting where the departed one was, and Release would act
        # on an address the user never chose.
        self._open(qtbot)
        self._deliver(snapshot([self._made_at("192.0.2.1", 3000),
                                self._made_at("192.0.2.2", 2000)]))
        self.view.table.selectRow(0)
        self._deliver(snapshot([self._made_at("192.0.2.2", 2000)]))
        assert self.view._selected_keys() == set()
        assert not self.view.cmdRelease.isEnabled()

    def test_several_selected_rows_survive_a_push(self, qtbot):
        self._open(qtbot)
        rows = [self._made_at("192.0.2.1", 3000), self._made_at("192.0.2.2", 2000),
                self._made_at("192.0.2.3", 1000)]
        self._deliver(snapshot(rows))
        self._select_rows(0, 2)
        chosen = {(NODE, "192.0.2.1"), (NODE, "192.0.2.3")}
        assert self.view._selected_keys() == chosen

        self._deliver(snapshot(rows))
        assert self.view._selected_keys() == chosen
        # Reordered: the same addresses, on other rows.
        self._deliver(snapshot([self._made_at("192.0.2.3", 4000), self._made_at("192.0.2.2", 2000),
                                self._made_at("192.0.2.1", 1000)]))
        assert self.view._selected_keys() == chosen
        assert self.view._release_targets() == sorted(chosen)

    def test_restoring_a_large_selection_signals_once(self, qtbot):
        # Each selection change re-reads the whole selection to set the
        # buttons; restored row by row, a full selection of a long list would
        # cost the square of its size on every push.
        self._open(qtbot)
        rows = [self._made_at("192.0.2.%d" % i, 1000 + i) for i in range(1, 201)]
        self._deliver(snapshot(rows))
        self.view.table.selectAll()
        changes = []
        self.view.table.itemSelectionChanged.connect(lambda: changes.append(1))
        self._deliver(snapshot(rows))
        assert len(self.view._selected_keys()) == 200
        assert len(changes) <= 2, "%d selection changes for one push" % len(changes)

    def test_the_current_row_follows_its_address(self, qtbot):
        # Shift+click and the keyboard extend the selection from the current
        # row: left at its row number, it would take in an address the user
        # never chose once a new row arrives above it.
        self._open(qtbot)
        self._deliver(snapshot([self._made_at("192.0.2.1", 3000),
                                self._made_at("192.0.2.2", 2000)]))
        self.view.table.setCurrentCell(0, self.view.COL_ADDR)
        self._deliver(snapshot([self._made_at("192.0.2.9", 4000), self._made_at("192.0.2.1", 3000),
                                self._made_at("192.0.2.2", 2000)]))
        assert self.view._key_at(self.view.table.currentRow()) == (NODE, "192.0.2.1")
        # Gone from the list: no current row, rather than its successor.
        self._deliver(snapshot([self._made_at("192.0.2.9", 4000), self._made_at("192.0.2.2", 2000)]))
        assert self.view.table.currentRow() == -1

    def test_a_push_does_not_scroll_the_list(self, qtbot):
        # Keeping the current row by key moves it when rows shift; Qt would
        # scroll to it, and a list under a distributed scan, pushed every two
        # seconds, could not be read past its first screen.
        self._open(qtbot)
        self.view.resize(600, 300)
        rows = [self._made_at("192.0.2.%d" % i, 1000 + i) for i in range(1, 151)]
        self._deliver(snapshot(rows))
        self.view.table.setCurrentCell(0, self.view.COL_ADDR)
        bar = self.view.table.verticalScrollBar()
        bar.setValue(bar.maximum())
        where = bar.value()
        assert where > 10, "the list does not scroll; the test exercises nothing"
        rows.append(self._made_at("198.51.100.1", 9999))
        self._deliver(snapshot(rows))
        assert self.view._key_at(self.view.table.currentRow()) == (NODE, "192.0.2.150")
        assert bar.value() == where

    def test_a_push_that_shortens_the_list_keeps_the_scroll(self, qtbot):
        # The current row's number past the new end of the list: Qt moves the
        # current row and scrolls to it, whatever the key says. The position
        # is put back.
        self._open(qtbot)
        self.view.resize(600, 300)
        rows = [self._made_at("192.0.2.%d" % i, 2000 - i) for i in range(1, 151)]
        self._deliver(snapshot(rows))
        bar = self.view.table.verticalScrollBar()
        self.view.table.setCurrentCell(149, self.view.COL_ADDR)
        bar.setValue(50)
        self._deliver(snapshot(rows[:140] + rows[149:]))
        assert self.view._key_at(self.view.table.currentRow()) == (NODE, "192.0.2.150")
        assert bar.value() == 50

    def test_a_push_does_not_scroll_the_list_sideways(self, qtbot):
        # Scrolling to the current row moves the view horizontally too, to the
        # current cell's column: the vertical position put back would not undo
        # that.
        self._open(qtbot)
        self.view.resize(260, 300)
        reason = "automatic policy, with a long explanation " * 4
        rows = [dict(self._made_at("2001:db8::%x" % i, 2000 - i), reason=reason)
                for i in range(1, 81)]
        self._deliver(snapshot(rows))
        self.view.table.setCurrentCell(3, self.view.COL_ADDR)
        side = self.view.table.horizontalScrollBar()
        side.setValue(side.maximum())
        where = side.value()
        assert where > 0, "the list does not scroll sideways; the test exercises nothing"
        self._deliver(snapshot([self._made_at("2001:db8::ffff", 9999)] + rows))
        assert side.value() == where

    def test_a_filter_hiding_the_selected_row_selects_nothing(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([self._made_at("192.0.2.1", 3000),
                                self._made_at("203.0.113.5", 2000)]))
        self.view.table.selectRow(0)
        self.view.set_filter("203.0.113")
        assert self.view._selected_keys() == set()
        assert not self.view.cmdRelease.isEnabled()

    def test_a_refused_release_is_reported(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        self.view.table.selectRow(0)
        self._yes(monkeypatch)
        said = []
        monkeypatch.setattr(
            FEED + ".Message.ok",
            lambda title, message, icon: said.append((title, message)))
        qtbot.mouseClick(self.view.cmdRelease, QtCore.Qt.MouseButton.LeftButton)

        nid = next(iter(self.feed._releases))
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="detection is not running"))
        assert said, "a refused release was swallowed"
        assert "192.0.2.66" in said[0][0]
        assert "not running" in said[0][1]

    def test_a_successful_release_says_nothing(self, qtbot, monkeypatch):
        # The address leaving the table is the confirmation; a modal box for
        # every release would be noise on the one workflow this view has.
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        self.view.table.selectRow(0)
        self._yes(monkeypatch)
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a, **k: said.append(a))
        qtbot.mouseClick(self.view.cmdRelease, QtCore.Qt.MouseButton.LeftButton)

        nid = next(iter(self.feed._releases))
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=""))
        assert said == []

    # ------------------------------------------------- nodes that come and go

    def test_a_disconnected_node_is_not_shown_as_blocking(self, qtbot):
        # A daemon restart is a disconnection: the daemon released every block
        # on the way down. The list must not go on showing them, counting
        # down, and must ask the returning node for its new ones.
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66"), block("198.51.100.7")]))
        assert self.view.table.rowCount() == 2
        saved = self.nodes._nodes.pop(NODE)
        try:
            self.nodes.nodesUpdated.emit(self.nodes.count())
            assert self.view.table.rowCount() == 0
            assert "disconnected" in self._status()
        finally:
            self.nodes._nodes[NODE] = saved
        drain()
        self.nodes.nodesUpdated.emit(self.nodes.count())
        sent = drain()
        assert [n.type for n in sent] == [ui_pb2.TASK_START], \
            "the returning node was not asked for its blocks"

    def test_a_node_that_never_answers_is_not_said_to_block_nothing(self, qtbot):
        # A daemon that predates port scan detection ignores TASK_START. The
        # list must not say "No address is blocked." for it. Its requests are
        # released when the views are hidden (see
        # test_hiding_leaves_nothing_waiting_in_nodes).
        self._open(qtbot)
        self.feed._asked[NODE] -= 10
        self.feed._tick()
        status = self._status()
        assert "may not support" in status
        assert status != BlockedListPresenter.empty_label()

    def test_a_slow_node_is_shown_once_it_answers(self, qtbot):
        # The request is kept when the message is shown: dropped with it, a
        # node whose first snapshot took more than STALE_AFTER -- a loaded
        # link -- would stay "may not support port scan detection" for as long
        # as the list was on screen.
        self._open(qtbot)
        self.feed._asked[NODE] -= 10
        self.feed._tick()
        assert "may not support" in self._status()
        self._deliver(snapshot([block("192.0.2.66")]))
        assert self._column(PortScanBlocksView.COL_ADDR) == ["192.0.2.66"]
        assert "may not support" not in self._status()

    def test_a_stale_snapshot_is_withdrawn(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66")]))
        self.feed._received[NODE] -= 10
        self.feed._tick()
        assert self.view.table.rowCount() == 0
        assert "no update" in self._status()

    def test_hiding_leaves_nothing_waiting_in_nodes(self, qtbot):
        self._open(qtbot)
        ids = list(self.feed._sent)
        before = set(self.nodes._notifications_sent)
        self.view.hide()
        settle(qtbot)
        assert not any(i in self.nodes._notifications_sent for i in ids)
        assert set(self.nodes._notifications_sent) <= before

    # ------------------------------------------------------- what is shown

    def test_the_countdown_runs_between_pushes(self, qtbot):
        self._open(qtbot)
        self._deliver(snapshot([block("192.0.2.66", remaining=90)]))
        assert self._column(PortScanBlocksView.COL_EXPIRES) == ["1m 30s"]
        # Within STALE_AFTER of the last push: counted down, not withdrawn.
        self.feed._received[NODE] -= 5
        self.feed._tick()
        assert self._column(PortScanBlocksView.COL_EXPIRES) == ["1m 25s"]

    def test_a_stuck_block_is_not_shown_as_expiring(self, qtbot):
        self._open(qtbot)
        stuck = block("192.0.2.66", remaining=0)
        stuck["stuck"] = True
        self._deliver(snapshot([stuck]))
        assert self._column(PortScanBlocksView.COL_EXPIRES) == [BlockedListPresenter.stuck_label()]

    def test_the_status_line_is_plain_and_bounded(self, qtbot):
        self._open(qtbot)
        self._deliver("<b>Detection is running.</b> " + "x" * 4000000, code=ui_pb2.ERROR)
        label = self.view.lblStatus
        assert label.textFormat() == QtCore.Qt.TextFormat.PlainText
        assert len(label.text()) < 1000
        assert "<b>" not in label.text()


class TestRepliesAsTheServiceDeliversThem():
    """Replies through Nodes.reply_notification, as service.Notifications does.

    The service passes the gRPC peer WITHOUT its protocol prefix ("/tmp/osui.sock"
    for the node "unix:/tmp/osui.sock"). Tests that called the feed's callback
    with the full key could not see what that did: rows filed under a node that
    does not exist, Release sent nowhere, staleness never computed.
    """

    PEER = NODE.split(":", 1)[1]

    def setup_method(self):
        self.nodes = Nodes.instance()
        self.feed = BlockedSources()
        self.view = PortScanBlocksView(self.feed)

    def teardown_method(self):
        try:
            self.view.hide()
            self.feed._stop()
        except Exception:
            pass
        self.nodes._nodes.pop("unix:/tmp/second.sock", None)

    def _open(self, qtbot):
        qtbot.addWidget(self.view)
        self.view.show()
        drain()

    def _push(self, data, code=None, node=NODE):
        nid = next(n for n, a in self.feed._sent.items() if a == node)
        self.nodes.reply_notification(node.split(":", 1)[1], ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK if code is None else code, data=data))

    def test_rows_belong_to_the_node_in_nodes(self, qtbot):
        self._open(qtbot)
        self._push(snapshot([block("192.0.2.66")]))
        assert [r["node"] for r in self.feed.rows()] == [NODE]
        assert self.view._selected_keys() == set()
        assert NODE in self.feed._received

    def test_release_reaches_the_daemon(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._push(snapshot([block("192.0.2.66")]))
        self.view.table.selectRow(0)
        monkeypatch.setattr(VIEW + ".Message.yes_no",
                            lambda *a, **k: QtWidgets.QMessageBox.StandardButton.Yes)
        qtbot.mouseClick(self.view.cmdRelease, QtCore.Qt.MouseButton.LeftButton)
        sent = drain()
        assert [n.type for n in sent] == [ui_pb2.PORTSCAN_UNBLOCK]
        assert json.loads(sent[0].data) == {"ip": "192.0.2.66"}
        # The row stays until the daemon's next snapshot says otherwise.
        assert self.view.table.rowCount() == 1

    def test_a_refusal_through_the_service_is_reported(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._push(snapshot([block("192.0.2.66")]))
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda title, msg, icon: said.append((title, msg)))
        self.feed.release(NODE, "192.0.2.66")
        nid = next(iter(self.feed._releases))
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="192.0.2.66 is not blocked"))
        assert said and "192.0.2.66" in said[0][0]
        assert self.feed._releases == {}

    def test_a_node_that_answers_is_not_said_to_be_silent(self, qtbot):
        self._open(qtbot)
        self.feed._asked[NODE] -= 10
        self._push(snapshot([block("192.0.2.66")]))
        self.feed._tick()
        assert "may not support" not in self.view.lblStatus.text()
        assert self.view.table.rowCount() == 1

    def test_a_node_that_stops_pushing_is_withdrawn(self, qtbot):
        self._open(qtbot)
        self._push(snapshot([block("192.0.2.66")]))
        self.feed._received[NODE] -= 10
        self.feed._tick()
        assert self.view.table.rowCount() == 0
        assert "no update" in self.view.lblStatus.text()

    def test_a_release_to_a_node_gone_is_reported_and_leaves_the_rows(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._push(snapshot([block("192.0.2.66")]))
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda title, msg, icon: said.append((title, msg)))
        saved = self.nodes._nodes.pop(NODE)
        try:
            # Nodes answers from inside send_notification for an unknown node.
            self.feed.release(NODE, "192.0.2.66")
        finally:
            self.nodes._nodes[NODE] = saved
        assert said and "not connected" in said[0][1]
        assert self.feed._releases == {}
        assert self.view.table.rowCount() == 1

    def test_pending_releases_of_a_departed_node_are_dropped(self, qtbot):
        self._open(qtbot)
        self._push(snapshot([block("192.0.2.66")]))
        self.feed.release(NODE, "192.0.2.66")
        nid = next(iter(self.feed._releases))
        saved = self.nodes._nodes.pop(NODE)
        try:
            self.nodes.nodesUpdated.emit(self.nodes.count())
            assert self.feed._releases == {}
            assert nid not in self.nodes._notifications_sent
        finally:
            self.nodes._nodes[NODE] = saved

    def test_a_node_not_heard_from_is_not_counted_as_blocking_nothing(self, qtbot):
        from queue import Queue
        from tests.dialogs import ClientConfig
        second = "unix:/tmp/second.sock"
        self.nodes._nodes[second] = {'data': ClientConfig, 'notifications': Queue(), 'online': True}
        self._open(qtbot)
        self._push(snapshot([]))
        status = self.view.lblStatus.text()
        assert status != BlockedListPresenter.empty_label()
        assert "loading" in status.lower()


class TestRepliesComeFromTheirOwnNode():
    """A reply counts only on the stream of the node it was asked of.

    Notification ids are timestamps, and the id of a reply is chosen by the
    daemon that sends it: trusting the id alone let one node rewrite another's
    list, or put an address of its choosing under the other's name.
    """

    OTHER = "unix:/tmp/second.sock"

    def setup_method(self):
        from queue import Queue
        from tests.dialogs import ClientConfig
        self.nodes = Nodes.instance()
        self.nodes._nodes[self.OTHER] = {'data': ClientConfig, 'notifications': Queue(), 'online': True}
        self.feed = BlockedSources()
        self.view = PortScanBlocksView(self.feed)

    def teardown_method(self):
        try:
            self.view.hide()
            self.feed._stop()
        except Exception:
            pass
        self.nodes._nodes.pop(self.OTHER, None)

    def _open(self, qtbot):
        qtbot.addWidget(self.view)
        self.view.show()
        drain()

    def _id_of(self, node):
        return next(n for n, a in self.feed._sent.items() if a == node)

    def _push(self, node, data, peer=None, code=None):
        peer = node.split(":", 1)[1] if peer is None else peer
        self.nodes.reply_notification(peer, ui_pb2.NotificationReply(
            id=self._id_of(node), code=ui_pb2.OK if code is None else code, data=data))

    def _genuine_after_forged(self, qtbot, monkeypatch, send, pending):
        # Another node answering OK first with the id consumed it in Nodes,
        # and the genuine refusal was lost.
        self._open(qtbot)
        self._push(NODE, snapshot([block("192.0.2.66")]))
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a, **k: said.append(a))
        send()
        nid = next(iter(pending()))
        self.nodes.reply_notification(self.OTHER.split(":", 1)[1], ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=""))
        self.nodes.reply_notification(NODE.split(":", 1)[1], ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="genuine refusal"))
        assert said, "the genuine refusal was not shown"
        assert nid not in pending()

    def test_a_release_refusal_survives_another_nodes_ok(self, qtbot, monkeypatch):
        self._genuine_after_forged(qtbot, monkeypatch,
                                   lambda: self.feed.release(NODE, "192.0.2.66"),
                                   lambda: self.feed._releases)

    def test_a_block_refusal_survives_another_nodes_ok(self, qtbot, monkeypatch):
        self._genuine_after_forged(qtbot, monkeypatch,
                                   lambda: self.feed.block(NODE, "192.0.2.77"),
                                   lambda: self.feed._blocks)

    def test_a_node_leaving_its_row_does_not_hand_the_selection_to_another(self, qtbot, monkeypatch):
        # Both nodes block the same address. The user picks the other node's
        # row; that node then drops it. The selection must not pass to the
        # local node's row, or Release would lift the wrong block.
        self._open(qtbot)
        other = self.nodes._nodes[self.OTHER]['notifications']
        while not other.empty():
            other.get()
        local = dict(block("198.51.100.7"), blocked_at=1000)
        remote = dict(block("198.51.100.7"), blocked_at=2000)
        self._push(NODE, snapshot([local]))
        self._push(self.OTHER, snapshot([remote]))
        self.view.table.selectRow(0)
        assert self.view._selected_keys() == {(self.OTHER, "198.51.100.7")}

        self._push(self.OTHER, snapshot([]))
        assert self.view._selected_keys() == set()
        monkeypatch.setattr(VIEW + ".Message.yes_no",
                            lambda *a, **k: QtWidgets.QMessageBox.StandardButton.Yes)
        drain()
        qtbot.mouseClick(self.view.cmdRelease, QtCore.Qt.MouseButton.LeftButton)
        assert not [n for n in drain() if n.type == ui_pb2.PORTSCAN_UNBLOCK]

    def test_a_node_cannot_rewrite_another_nodes_list(self, qtbot):
        self._open(qtbot)
        self._push(NODE, snapshot([block("192.0.2.66")]))
        # The other node answers with the first node's id, on its own stream.
        self._push(NODE, snapshot([block("203.0.113.9")]), peer=self.OTHER.split(":", 1)[1])
        rows = [(r["node"], r["ip"]) for r in self.feed.rows()]
        assert rows == [(NODE, "192.0.2.66")]

    def test_a_node_cannot_answer_a_release_sent_to_another(self, qtbot, monkeypatch):
        self._open(qtbot)
        self._push(NODE, snapshot([block("192.0.2.66")]))
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a, **k: said.append(a))
        self.feed.release(NODE, "192.0.2.66")
        nid = next(iter(self.feed._releases))
        self.nodes.reply_notification(self.OTHER.split(":", 1)[1], ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="forged refusal"))
        assert said == []
        assert nid in self.feed._releases

    def test_nothing_is_left_in_flight_after_a_release_is_sent(self, qtbot):
        self._open(qtbot)
        self.feed.release(NODE, "192.0.2.66")
        assert self.feed._inflight_release is None
        assert list(self.feed._releases.values()) == [(NODE, "192.0.2.66")]

    def test_a_count_names_the_nodes_still_loading(self, qtbot):
        self._open(qtbot)
        self._push(NODE, snapshot([block("192.0.2.66")]))
        status = self.view.lblStatus.text()
        assert "1 blocked" in status
        assert self.OTHER in status and "loading" in status

    def test_a_stray_error_creates_no_state(self, qtbot):
        self._open(qtbot)
        self.feed._cb_notification_callback("/somewhere", ui_pb2.NotificationReply(
            id=1, code=ui_pb2.ERROR, data="noise"))
        assert "/somewhere" not in self.feed._state

    def test_a_release_waiting_while_hidden_is_dropped_when_its_node_leaves(self, qtbot):
        self._open(qtbot)
        self.feed.release(self.OTHER, "192.0.2.66")
        nid = next(iter(self.feed._releases))
        self.view.hide()
        self.feed._stop_if_unwatched()
        saved = self.nodes._nodes.pop(self.OTHER)
        try:
            self.nodes.nodesUpdated.emit(self.nodes.count())
            assert self.feed._releases == {}
            assert nid not in self.nodes._notifications_sent
        finally:
            self.nodes._nodes[self.OTHER] = saved

    def test_a_node_leaving_keeps_the_releases_of_the_others(self, qtbot, monkeypatch):
        # Only the departed node's releases go: a refusal still owed by a node
        # that is connected must still be shown, since a success says nothing.
        self._open(qtbot)
        self.feed.release(NODE, "192.0.2.1")
        self.feed.release(self.OTHER, "192.0.2.2")
        kept = next(n for n, (node, _ip) in self.feed._releases.items() if node == NODE)
        saved = self.nodes._nodes.pop(self.OTHER)
        try:
            self.nodes.nodesUpdated.emit(self.nodes.count())
        finally:
            self.nodes._nodes[self.OTHER] = saved
        assert list(self.feed._releases) == [kept]
        assert kept in self.nodes._notifications_sent
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda title, msg, icon: said.append((title, msg)))
        self.nodes.reply_notification(NODE.split(":", 1)[1], ui_pb2.NotificationReply(
            id=kept, code=ui_pb2.ERROR, data="192.0.2.1 is not blocked"))
        assert len(said) == 1 and "192.0.2.1" in said[0][0]

    def test_an_address_that_prefixes_another_is_not_that_node(self, qtbot):
        # "/tmp/osui.so" is a prefix of "/tmp/osui.sock": the comparison is
        # equality, not a prefix match.
        from queue import Queue
        from tests.dialogs import ClientConfig
        prefix = "unix:/tmp/osui.so"
        self.nodes._nodes[prefix] = {'data': ClientConfig, 'notifications': Queue(), 'online': True}
        try:
            self._open(qtbot)
            self._push(NODE, snapshot([block("192.0.2.66")]))
            self._push(NODE, snapshot([block("203.0.113.9")]), peer=prefix.split(":", 1)[1])
            assert [(r["node"], r["ip"]) for r in self.feed.rows()] == [(NODE, "192.0.2.66")]
        finally:
            self.nodes._nodes.pop(prefix, None)

    def test_a_stream_reply_during_a_release_send_is_not_its_answer(self, qtbot, monkeypatch):
        # Only the answer Nodes gives itself, carrying the node's key, is the
        # answer to the release being sent; a stream reply delivered meanwhile
        # keeps its own meaning.
        self._open(qtbot)
        real_send = self.nodes.send_notification
        def send(addr, noti, cb=None):
            if noti.type == ui_pb2.PORTSCAN_UNBLOCK:
                self._push(NODE, "port scan detection is not running", code=ui_pb2.ERROR)
            return real_send(addr, noti, cb)
        monkeypatch.setattr(self.nodes, "send_notification", send)
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a, **k: said.append(a))
        self.feed.release(NODE, "192.0.2.66")
        assert said == []
        assert "not running" in self.feed._state[NODE]["error"]
        assert list(self.feed._releases.values()) == [(NODE, "192.0.2.66")]

    def test_nothing_is_in_flight_while_the_refusal_box_is_open(self, qtbot, monkeypatch):
        # A second synchronous-looking answer arriving while the box is open is
        # not taken for the release that box is about.
        self._open(qtbot)
        gone = "unix:/tmp/gone.sock"
        said = []
        def box(title, msg, icon):
            said.append((title, msg))
            self.feed._cb_notification_callback(gone, ui_pb2.NotificationReply(
                id=424242, code=ui_pb2.ERROR, data="node not connected: " + gone))
        monkeypatch.setattr(FEED + ".Message.ok", box)
        self.feed.release(gone, "192.0.2.66")
        assert len(said) == 1

    def test_a_reply_during_the_refusal_box_is_not_taken_for_it(self, qtbot, monkeypatch):
        # The refusal box runs an event loop of its own; a stream reply
        # delivered meanwhile belongs to its stream, not to the release.
        self._open(qtbot)
        gone = "unix:/tmp/gone.sock"
        said = []
        def box(title, msg, icon):
            said.append((title, msg))
            self._push(NODE, "port scan detection is not running", code=ui_pb2.ERROR)
        monkeypatch.setattr(FEED + ".Message.ok", box)
        self.feed.release(gone, "192.0.2.66")
        assert len(said) == 1 and "not connected" in said[0][1]
        assert "not running" in self.feed._state[NODE]["error"]


class TestOneStreamForTwoViews():
    """The Port scan Detection tab and the Rules tab show the same list.

    A node runs one portscan-blocks task at a time (TaskManager.AddTask refuses
    a second of the same name), so the two views must share one stream: a
    second TASK_START would be answered with an error, and a TASK_STOP sent by
    one view would cut the other off.
    """

    def setup_method(self):
        self.feed = BlockedSources()
        self.a = PortScanBlocksView(self.feed)
        self.b = PortScanBlocksView(self.feed)

    def teardown_method(self):
        for v in (self.a, self.b):
            v.hide()
        self.feed._stop()

    def _types(self):
        return [n.type for n in drain()]

    def test_two_visible_views_open_one_stream(self, qtbot):
        qtbot.addWidget(self.a)
        qtbot.addWidget(self.b)
        drain()
        self.a.show()
        self.b.show()
        assert self._types() == [ui_pb2.TASK_START]

    def test_hiding_one_of_two_views_keeps_the_stream(self, qtbot):
        qtbot.addWidget(self.a)
        qtbot.addWidget(self.b)
        self.a.show()
        self.b.show()
        drain()
        self.a.hide()
        settle(qtbot)
        assert self._types() == []
        assert self.feed.is_running()
        self.b.hide()
        settle(qtbot)
        assert self._types() == [ui_pb2.TASK_STOP]

    def test_switching_from_one_view_to_the_other_does_not_restart(self, qtbot):
        # Qt hides the page being left before it shows the one being entered.
        # Stopping at once would send TASK_STOP and TASK_START back to back,
        # and a daemon that handled them out of order would refuse the start
        # as a duplicate and then stop the task: an empty list on screen.
        qtbot.addWidget(self.a)
        qtbot.addWidget(self.b)
        self.a.show()
        drain()
        self.a.hide()
        self.b.show()
        settle(qtbot)
        assert self._types() == []
        assert self.feed.is_running()

    def test_both_views_show_the_same_rows(self, qtbot):
        qtbot.addWidget(self.a)
        qtbot.addWidget(self.b)
        self.a.show()
        self.b.show()
        nid = next(iter(self.feed._sent))
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=snapshot([block("192.0.2.66")])))
        for v in (self.a, self.b):
            assert v.table.rowCount() == 1
            assert v.table.item(0, PortScanBlocksView.COL_ADDR).text() == "192.0.2.66"


class TestMainWindow():
    """Where the list lives in the main window, and what that must not break."""

    def setup_method(self):
        self.win = StatsDialog(dbname="general", db=Database.instance(),
                               appicon=QtGui.QIcon())

    def teardown_method(self):
        try:
            self.win.close()
            self.win._portscan_blocks._stop()
        except Exception:
            pass

    def _show(self, qtbot):
        qtbot.addWidget(self.win)
        self.win.show()
        self.win.set_current_tab(constants.TAB_MAIN)
        settle(qtbot)
        drain()

    def _tree_item(self, idx):
        return self.win.rulesTreePanel.topLevelItem(idx)

    def _click_tree(self, idx):
        item = self._tree_item(idx)
        self.win.rulesTreePanel.setCurrentItem(item)
        self.win._cb_rules_tree_item_clicked(item, 0)

    def _types(self):
        return [n.type for n in drain()]

    # ------------------------------------------------------------- the tab

    def test_the_port_scan_tab_follows_netstat(self, qtbot):
        self._show(qtbot)
        tw = self.win.tabWidget
        assert tw.tabText(constants.TAB_NETSTAT) == "Netstat"
        assert tw.tabText(constants.TAB_PORTSCAN) == "Port scan Detection"
        assert tw.count() == constants.TAB_PORTSCAN + 1

    def test_every_tab_carries_its_table_key(self, qtbot):
        # The window maps tabs to self.TABLES by position, and hides or shows
        # a tab by the key stored in its object name. A tab inserted at the
        # wrong position would shift every key after it.
        self._show(qtbot)
        tw = self.win.tabWidget
        keys = list(self.win.TABLES)
        for i in range(tw.count()):
            assert tw.widget(i).objectName() == str(keys[i])
        # The views that are not tabs come after every tab.
        for k in (constants.TAB_FIREWALL, constants.TAB_ALERTS):
            assert k >= tw.count()
            assert self.win.TABLES[k]['isTab'] is False

    def test_the_tab_opens_the_stream_and_leaving_it_closes_it(self, qtbot):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_PORTSCAN)
        assert self._types() == [ui_pb2.TASK_START]
        self.win.set_current_tab(constants.TAB_MAIN)
        settle(qtbot)
        assert self._types() == [ui_pb2.TASK_STOP]

    def test_a_hidden_window_does_not_keep_the_stream(self, qtbot):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_PORTSCAN)
        drain()
        self.win.close()
        settle(qtbot)
        assert self._types() == [ui_pb2.TASK_STOP]

    def test_the_main_window_machinery_tolerates_the_tab(self, qtbot):
        # The tab has no SQL view; the code that refreshes, filters, limits or
        # cleans "the active table" must leave it alone rather than raise.
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_PORTSCAN)
        self.win.refresh_active_table()
        self.win._on_update_triggered(True, True)
        self.win._cb_limit_combo_changed(1)
        self.win._cb_clean_sql_clicked(constants.TAB_PORTSCAN)
        self.win.clear_rows_selection()
        assert not self.win.are_rows_selected()
        assert not self.win.cmdCleanSql.isVisible()
        self.win.show_columns()

    def test_the_search_line_filters_the_tab(self, qtbot):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_PORTSCAN)
        feed = self.win._portscan_blocks
        nid = next(iter(feed._sent))
        feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK,
            data=snapshot([block("192.0.2.66"), block("198.51.100.7")])))
        assert self.win.portscanView.table.rowCount() == 2
        try:
            self.win.filterLine.setText("198.51")
            assert self.win.portscanView.table.rowCount() == 1
        finally:
            # The window saves the search text on close.
            self.win.filterLine.setText("")

    def test_hiding_the_tab_through_its_menu_hides_it(self, qtbot):
        # The tab bar lets the user close tabs; the port scan tab is one of
        # them, and closing it must not stop at a missing SQL model.
        self._show(qtbot)
        try:
            self.win._cb_tab_closed(constants.TAB_PORTSCAN)
            assert not self.win.tabWidget.isTabVisible(constants.TAB_PORTSCAN)
            hidden = self.win.cfg.getSettings(Config.STATS_TAB_HIDDEN_LIST)
            assert constants.TAB_PORTSCAN in [int(i) for i in hidden]
        finally:
            # The hidden list is saved in the settings; left there, it would
            # hide the tab from every later test.
            self.win.cfg.setSettings(Config.STATS_TAB_HIDDEN_LIST, [])
            self.win.tabWidget.setTabVisible(constants.TAB_PORTSCAN, True)

    def test_csv_export_lists_only_sql_views(self, qtbot):
        self._show(qtbot)
        self.win.configure_main_btn_menu()
        names = []
        for act in self.win.actionsButton.menu().actions():
            if act.menu() is not None:
                names += [a.text() for a in act.menu().actions()]
        assert "portscan_blocks" not in names

    # --------------------------------------------------------- the Rules tab

    def test_the_rules_tree_lists_port_scan_blocks(self, qtbot):
        self._show(qtbot)
        assert self._tree_item(constants.RULES_TREE_PORTSCAN).text(0) == "Port scan blocks"
        # The existing entries keep their positions: the window finds them by
        # index.
        assert self._tree_item(constants.RULES_TREE_APPS).text(0) == "Application rules"
        assert self._tree_item(constants.RULES_TREE_ALERTS).text(0) == "Alerts"
        assert self._tree_item(constants.RULES_TREE_NODES).text(0) == "Nodes"
        assert self._tree_item(constants.RULES_TREE_FIREWALL).text(0) == "System rules"

    def test_selecting_port_scan_blocks_shows_them_in_place_of_the_rules(self, qtbot):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        drain()
        self._click_tree(constants.RULES_TREE_PORTSCAN)
        assert self.win.rulesPortscanView.isVisible()
        assert not self.win.rulesTable.isVisible()
        assert not self.win.fwTable.isVisible()
        assert not self.win.alertsTable.isVisible()
        assert self._types() == [ui_pb2.TASK_START]

        self._click_tree(constants.RULES_TREE_APPS)
        settle(qtbot)
        assert not self.win.rulesPortscanView.isVisible()
        assert self.win.rulesTable.isVisible()
        assert self._types() == [ui_pb2.TASK_STOP]

    def test_the_rules_tab_and_the_port_scan_tab_share_the_stream(self, qtbot):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        self._click_tree(constants.RULES_TREE_PORTSCAN)
        drain()
        self.win.set_current_tab(constants.TAB_PORTSCAN)
        settle(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        settle(qtbot)
        assert self._types() == []
        assert self.win._portscan_blocks.is_running()

    def test_the_rules_tab_shows_the_same_blocks(self, qtbot):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        self._click_tree(constants.RULES_TREE_PORTSCAN)
        feed = self.win._portscan_blocks
        nid = next(iter(feed._sent))
        feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=snapshot([block("192.0.2.66")],
                                                  detections=[detected("192.0.2.70")])))
        view = self.win.rulesPortscanView
        assert view.table.item(0, PortScanBlocksView.COL_ADDR).text() == "192.0.2.66"
        assert view.table.item(0, PortScanBlocksView.COL_STATUS).text() == "blocked"
        # The Rules tab lists what the firewall enforces: no detections, and
        # nothing to block from there.
        assert view.table.rowCount() == 1
        assert not view.cmdBlock.isVisible()

    def test_the_port_scan_entries_have_no_icon(self, qtbot):
        # The other tabs have none, and the other Rules entries name theme
        # icons that most themes do not provide: an icon here was the odd one
        # out.
        self._show(qtbot)
        assert self.win.tabWidget.tabIcon(constants.TAB_PORTSCAN).isNull()
        assert self._tree_item(constants.RULES_TREE_PORTSCAN).icon(0).isNull()
        combo = self.win.comboRulesFilter
        idx = combo.findData(self.win.PORTSCAN_COMBO_DATA)
        assert idx >= 0 and combo.itemIcon(idx).isNull()

    def test_the_rules_tab_opens_the_nftables_rule_of_a_block(self, qtbot, monkeypatch):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        self._click_tree(constants.RULES_TREE_PORTSCAN)
        feed = self.win._portscan_blocks
        nid = next(iter(feed._sent))
        feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=snapshot([block("192.0.2.66")])))
        drain()
        view = self.win.rulesPortscanView
        view.table.selectRow(0)
        monkeypatch.setattr(QtWidgets.QMenu, "exec", lambda menu, *_a: next(
            a for a in menu.actions() if a.text() == "Show nftables rule"))
        view._cb_context_menu(view.table.visualItemRect(view.table.item(0, 1)).center())
        sent = drain()
        assert [n.type for n in sent] == [ui_pb2.PORTSCAN_BLOCK_INFO]
        dialog = next(iter(view._dialogs))
        assert dialog.tabs.currentIndex() == PortScanBlockDialog.TAB_FIREWALL
        feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=next(iter(feed._infos)), code=ui_pb2.OK, data=info()))
        assert dialog.txtFirewall.toPlainText() == FIREWALL
        dialog.close()

    def test_the_rules_filter_combo_brings_the_rules_back(self, qtbot):
        # With the tree panel collapsed, the combo box above the table picks
        # what is listed; choosing rules there must not leave the blocks on
        # screen with the rules table hidden behind them.
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        self._click_tree(constants.RULES_TREE_PORTSCAN)
        self.win._cb_rules_filter_combo_changed(constants.RULES_COMBO_PERMANENT)
        assert not self.win.rulesPortscanView.isVisible()
        assert self.win.rulesTable.isVisible()

    def test_the_rules_filter_combo_offers_the_blocks(self, qtbot):
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        combo = self.win.comboRulesFilter
        idx = combo.findData(StatsDialog.PORTSCAN_COMBO_DATA)
        assert idx >= 0
        self.win._cb_rules_filter_combo_changed(idx)
        assert self.win.rulesPortscanView.isVisible()
        assert not self.win.rulesTable.isVisible()
        assert not self.win.fwTable.isVisible()

    def test_the_combo_does_not_stack_tables_it_did_not_show(self, qtbot):
        # From System rules or Alerts, the existing combo entries keep their
        # own behaviour: the blocks entry must not make them show the rules
        # table on top of another one.
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        for tree in (constants.RULES_TREE_FIREWALL, constants.RULES_TREE_ALERTS):
            for idx in range(self.win.comboRulesFilter.count()):
                if self.win.comboRulesFilter.itemData(idx) == StatsDialog.PORTSCAN_COMBO_DATA:
                    continue
                self._click_tree(tree)
                self.win._cb_rules_filter_combo_changed(idx)
                shown = [t for t in (self.win.rulesTable, self.win.fwTable, self.win.alertsTable)
                         if t.isVisible()]
                assert len(shown) == 1, (tree, idx, [t.objectName() for t in shown])

    def test_leaving_the_blocks_by_the_combo_shows_current_rules(self, qtbot):
        # The rules table is not refreshed while hidden behind the blocks, and
        # the combo entry used here runs no query of its own: a rule added
        # meanwhile must be there when the table comes back.
        from PyQt6.QtSql import QSqlQuery
        db = Database.instance()
        name = "rule-added-behind-the-blocks"
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        self._click_tree(constants.RULES_TREE_APPS)
        combo = self.win.comboRulesFilter
        self.win._cb_rules_filter_combo_changed(combo.findData(StatsDialog.PORTSCAN_COMBO_DATA))
        QSqlQuery(db.get_db()).exec(
            "INSERT INTO rules (time,node,name,enabled,action,duration) VALUES "
            "('2026-10-10 12:00:00','%s','%s','True','allow','always')" % (NODE, name))
        try:
            self.win._stats = ui_pb2.Statistics(daemon_version="t")
            self.win._on_update_triggered(True, True)
            self.win._cb_rules_filter_combo_changed(3)
            assert self.win.rulesTable.isVisible()
            m = self.win.rulesTable.model()
            shown = [m.index(r, constants.COL_R_NAME).data() for r in range(m.rowCount())]
            assert name in shown
        finally:
            QSqlQuery(db.get_db()).exec("DELETE FROM rules WHERE name = '%s'" % name)

    def test_no_sql_query_runs_behind_the_blocks(self, qtbot, monkeypatch):
        # The rules table is hidden while the blocks are shown; refreshing it
        # on every tick was a query for nothing.
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        self._click_tree(constants.RULES_TREE_PORTSCAN)
        calls = []
        monkeypatch.setattr(self.win.queries, "setQuery", lambda *a, **k: calls.append(a))
        self.win.refresh_active_table()
        self.win._cb_limit_combo_changed(1)
        assert calls == []

    def test_opening_a_rule_from_the_events_hides_the_blocks(self, qtbot):
        # Jumping to a rule's details shows the rules table; the blocks view
        # must not stay beside it.
        self._show(qtbot)
        self.win.set_current_tab(constants.TAB_RULES)
        self._click_tree(constants.RULES_TREE_PORTSCAN)
        model = QtGui.QStandardItemModel(1, 14)
        model.setItem(0, constants.COL_RULES, QtGui.QStandardItem("some-rule"))
        model.setItem(0, constants.COL_NODE, QtGui.QStandardItem(NODE))
        self.win.set_rules_tab_active(model.index(0, 0), constants.TAB_RULES,
                                      constants.COL_RULES, constants.COL_NODE)
        assert not self.win.rulesPortscanView.isVisible()
        assert self.win.rulesTable.isVisible()


class TestBlockedListPresenter():
    """The parsing and formatting the views depend on, without the widgets."""

    def test_remaining_never_goes_negative(self):
        rows, _, _ = BlockedListPresenter.parse(
            snapshot([block("192.0.2.66", remaining=-5)]))
        assert rows[0]["remaining"] == 0

    def test_formats(self):
        f = BlockedListPresenter.format_remaining
        assert f(0) == "expiring"
        assert f(-1) == "expiring"
        assert f(45) == "45s"
        assert f(90) == "1m 30s"
        assert f(3600) == "1h 0m"
        assert f(14400) == "4h 0m"
        assert f(90000) == "1d 1h"

    def test_a_missing_blocks_key_is_an_empty_list_not_a_crash(self):
        rows, total, omitted = BlockedListPresenter.parse(json.dumps({"total": 0}))
        assert rows == [] and total == 0 and omitted == 0

    def test_a_list_instead_of_an_object_is_refused(self):
        try:
            BlockedListPresenter.parse("[]")
        except ValueError:
            return
        raise AssertionError("a malformed snapshot was accepted")

    def test_non_numeric_counters_do_not_break_the_totals(self):
        rows, total, omitted = BlockedListPresenter.parse(json.dumps({
            "blocks": [block("192.0.2.66")],
            "total": "many", "omitted": True,
        }))
        assert rows and total == 1 and omitted == 0

    def test_more_rows_than_the_bound_are_counted_as_omitted(self):
        many = [block("192.0.2.%d" % (i % 256)) for i in range(BlockedListPresenter.MAX_ROWS + 5)]
        rows, total, omitted = BlockedListPresenter.parse(snapshot(many))
        assert len(rows) == BlockedListPresenter.MAX_ROWS
        assert omitted == 5

    def test_a_zoned_address_is_refused(self):
        # The daemon never sends one; trimming the zone let markup after the
        # "%" reach a rich-text message box with clickable links.
        # Both payloads: ipaddress itself refuses a zone containing "/", so the
        # first alone passed without the guard; the second, with no "/", is
        # accepted by ipaddress and only the guard refuses it.
        for text in ("fe80::1%<a href='https://evil.example/'>renew</a>",
                     "fe80::1%<a href=https:evil.example>renew"):
            rows, _, omitted = BlockedListPresenter.parse(snapshot([block(text)]))
            assert rows == [] and omitted == 1, text

    def test_addresses_are_canonical(self):
        rows, _, _ = BlockedListPresenter.parse(snapshot([block("2001:DB8::0001")]))
        assert rows[0]["ip"] == "2001:db8::1"


# ------------------------------------------------------------ block details

from opensnitch.customwidgets.portscanblocksview import PortScanBlockDialog
from opensnitch.portscan import BlockInfoPresenter

FIREWALL = (
    "table inet opensnitch-portscan {\n"
    "\tset portscan_sources_v4 {\n"
    "\t\ttype ipv4_addr\n"
    "\t\ttimeout 4h5m\n"
    "\t\telements = { 192.0.2.66 expires 3h59m2s10ms }\n"
    "\t}\n\n"
    "\tchain portscan-input {\n"
    "\t\ttype filter hook input priority filter - 10; policy accept;\n"
    "\t\tip saddr @portscan_sources_v4 drop\n"
    "\t}\n"
    "}\n")


def scan(**over):
    s = {"method": "tcp-syn", "method_detail": "TCP SYN scan",
         "src_mac": "02:00:00:00:00:01", "src_mac_is_source_own": True,
         "flags_summary": "fSrpauec", "distinct_ports": 300, "min_port": 1,
         "max_port": 300, "sample_ports": [21, 22, 80, 443],
         "protocols": 0, "score": 120, "interface": "eth0",
         "targets": ["192.0.2.1"], "first_seen_unixnano": 1758648000 * 10**9,
         "last_seen_unixnano": 1758648003 * 10**9,
         "anomalies": ["syn-without-tcp-options"], "has_tcp_evidence": True}
    s.update(over)
    return s


def info(addr="192.0.2.66", **over):
    i = {"addr": addr, "reason": "TCP SYN scan", "remaining": 14400,
         "expires_at": 1758648000, "scan": scan(), "firewall": FIREWALL}
    i.update(over)
    return json.dumps(i)


class TestBlockDetails():
    """Double-click and the context menu open the details of a block: the scan
    that caused it and the nftables rule applying it, asked of the node that
    holds the block, through Nodes as the service delivers replies."""

    OTHER = "unix:/tmp/second.sock"
    PEER = NODE.split(":", 1)[1]

    def setup_method(self):
        self.nodes = Nodes.instance()
        self.feed = BlockedSources()
        self.view = PortScanBlocksView(self.feed)

    def teardown_method(self):
        for d in list(self.view._dialogs):
            d.close()
        try:
            self.view.hide()
            self.feed._stop()
        except Exception:
            pass
        self.nodes._nodes.pop(self.OTHER, None)

    def _open(self, qtbot, rows=("192.0.2.66",)):
        qtbot.addWidget(self.view)
        self.view.show()
        drain()
        nid = next(iter(self.feed._sent))
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=snapshot([block(a) for a in rows])))

    def _double_click(self, row=0):
        self.view._cb_double_clicked(row, PortScanBlocksView.COL_REASON)
        sent = drain()
        dialog = next(iter(self.view._dialogs))
        return dialog, sent

    def _answer(self, data, code=None, peer=None):
        nid = next(iter(self.feed._infos))
        self.nodes.reply_notification(self.PEER if peer is None else peer, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK if code is None else code, data=data))

    @staticmethod
    def _form(dialog):
        out = {}
        for i in range(dialog.form.rowCount()):
            label = dialog.form.itemAt(i, QtWidgets.QFormLayout.ItemRole.LabelRole)
            field = dialog.form.itemAt(i, QtWidgets.QFormLayout.ItemRole.FieldRole)
            out[label.widget().text()] = field.widget().text()
        return out

    def test_double_click_asks_the_node_for_the_details(self, qtbot):
        self._open(qtbot)
        dialog, sent = self._double_click()
        assert [n.type for n in sent] == [ui_pb2.PORTSCAN_BLOCK_INFO]
        assert json.loads(sent[0].data) == {"ip": "192.0.2.66"}
        assert dialog.tabs.currentIndex() == PortScanBlockDialog.TAB_SCAN
        assert dialog.lblStatus.text() == "Loading..."

    def test_the_details_show_the_scan(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info())
        form = self._form(dialog)
        assert form["Source address"] == "192.0.2.66"
        assert form["Scan type"] == "TCP SYN scan"
        assert form["Source hardware address"] == "02:00:00:00:00:01 (the source's own)"
        assert form["Ports probed"] == "300, between 1 and 300"
        # Four of three hundred: said, so the sample is not taken for the list.
        assert form["Ports"].startswith("21, 22, 80, 443 (the first 4 of 300")
        assert form["TCP flags"] == "SYN"
        assert form["Evasion signs"] == "SYN without TCP options (raw packet generator)"
        assert form["Interface"] == "eth0"
        assert form["Local addresses probed"] == "192.0.2.1"
        assert form["Corroborating evidence"].startswith("yes")
        assert dialog.lblStatus.text() == ""
        assert self.feed._infos == {}

    def test_every_port_is_listed_when_the_daemon_has_them_all(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info(scan=scan(distinct_ports=3, min_port=22, max_port=443,
                                    sample_ports=[22, 80, 443])))
        assert self._form(dialog)["Ports"] == "22, 80, 443"

    def test_a_routers_hardware_address_is_not_the_sources(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info(scan=scan(src_mac_is_source_own=False)))
        assert self._form(dialog)["Source hardware address"] == \
            "02:00:00:00:00:01 (the last router's, not the source's)"

    def test_a_block_without_its_scan_says_so(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info(scan=None))
        form = self._form(dialog)
        assert "no details" in form["Scan"]
        assert "Scan type" not in form

    def test_the_context_menu_shows_the_nftables_rule(self, qtbot, monkeypatch):
        self._open(qtbot)
        self.view.table.selectRow(0)
        offered = []

        def pick(menu, *_a):
            offered.extend(a.text() for a in menu.actions() if a.text())
            return next(a for a in menu.actions() if a.text() == "Show nftables rule")
        monkeypatch.setattr(QtWidgets.QMenu, "exec", pick)
        pos = self.view.table.visualItemRect(self.view.table.item(0, 0)).center()
        self.view._cb_context_menu(pos)
        assert offered == ["Details", "Show nftables rule", "Release", "Delete", "Copy"]
        dialog = next(iter(self.view._dialogs))
        assert dialog.tabs.currentIndex() == PortScanBlockDialog.TAB_FIREWALL
        assert [n.type for n in drain()] == [ui_pb2.PORTSCAN_BLOCK_INFO]
        self._answer(info())
        assert dialog.txtFirewall.toPlainText() == FIREWALL

    def test_the_rule_tab_explains_why_the_kernel_expires_later(self, qtbot):
        # The rule's "expires" runs a few minutes past the countdown in the
        # list, on purpose; unexplained, a user takes one of them for wrong.
        self._open(qtbot)
        dialog, _ = self._double_click()
        dialog.tabs.setCurrentIndex(PortScanBlockDialog.TAB_FIREWALL)
        assert dialog.lblExpiry.isVisible()
        assert dialog.lblExpiry.parent() is dialog.txtFirewall.parent()
        text = dialog.lblExpiry.text()
        assert "\"expires\" is later than the end of the block" in text
        assert "only if the daemon was stopped" in text

    def test_a_firewall_that_could_not_be_read_says_why(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info(firewall="", firewall_error="portscan: the address is not in the firewall"))
        text = dialog.txtFirewall.toPlainText()
        assert "could not be shown" in text and "not in the firewall" in text
        # The rest of the details are still shown.
        assert self._form(dialog)["Scan type"] == "TCP SYN scan"

    def test_a_refusal_is_shown_in_the_dialog(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer("192.0.2.66 is not blocked", code=ui_pb2.ERROR)
        assert "not blocked" in dialog.lblStatus.text()
        assert self._form(dialog) == {}

    def test_an_answer_about_another_address_is_refused(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info(addr="198.51.100.9"))
        assert "another address" in dialog.lblStatus.text()
        assert self._form(dialog) == {}

    def test_another_node_cannot_answer(self, qtbot):
        from queue import Queue
        from tests.dialogs import ClientConfig
        self.nodes._nodes[self.OTHER] = {'data': ClientConfig, 'notifications': Queue(), 'online': True}
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info(), peer=self.OTHER.split(":", 1)[1])
        assert self._form(dialog) == {}
        assert len(self.feed._infos) == 1

    def test_a_node_gone_is_reported_at_once(self, qtbot):
        self._open(qtbot)
        saved = self.nodes._nodes.pop(NODE)
        try:
            self.view.show_details((NODE, "192.0.2.66"), PortScanBlockDialog.TAB_SCAN)
        finally:
            self.nodes._nodes[NODE] = saved
        dialog = next(iter(self.view._dialogs))
        assert "not connected" in dialog.lblStatus.text()
        assert self.feed._infos == {} and self.feed._inflight_info is None

    def test_a_node_leaving_while_asked_is_reported(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        nid = next(iter(self.feed._infos))
        saved = self.nodes._nodes.pop(NODE)
        try:
            self.nodes.nodesUpdated.emit(self.nodes.count())
        finally:
            self.nodes._nodes[NODE] = saved
        assert "disconnected" in dialog.lblStatus.text()
        assert self.feed._infos == {}
        assert nid not in self.nodes._notifications_sent

    def test_refresh_asks_again(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        self._answer(info())
        qtbot.mouseClick(dialog.cmdRefresh, QtCore.Qt.MouseButton.LeftButton)
        assert [n.type for n in drain()] == [ui_pb2.PORTSCAN_BLOCK_INFO]
        assert dialog.lblStatus.text() == "Loading..."

    def test_a_closed_dialog_stops_listening(self, qtbot):
        self._open(qtbot)
        dialog, _ = self._double_click()
        dialog.close()
        qtbot.wait(20)
        # Delivered after the close: nothing may touch the deleted dialog.
        self._answer(info())
        assert self.view._dialogs == set()

    def test_the_intro_says_how_to_reach_the_details(self, qtbot):
        intro = self.view.lblIntro.text()
        assert "Double-click" in intro and "nftables rule" in intro


class TestBlockInfoPresenter():

    def test_unreadable_answers_are_refused(self):
        for data in ("nonsense", "[]", json.dumps({"addr": "not an address"}),
                     json.dumps({"addr": "fe80::1%eth0"})):
            try:
                BlockInfoPresenter.parse(data)
            except ValueError:
                continue
            raise AssertionError("accepted: " + data)

    def test_fields_from_the_wire_are_bounded(self):
        parsed = BlockInfoPresenter.parse(info(
            scan=scan(sample_ports=[22, -1, 70000, True, "80"] + list(range(100)),
                      targets=["192.0.2.1", "<b>x</b>", "fe80::1%eth0"],
                      src_mac="<a href=x>mac</a>"),
            firewall="ok\x1b[2Jcleared\x00" + "x" * 20000))
        s = parsed["scan"]
        assert s.sample_ports[0] == 22 and -1 not in s.sample_ports and 70000 not in s.sample_ports
        assert True not in s.sample_ports[:1] and "80" not in s.sample_ports
        assert len(s.sample_ports) == BlockInfoPresenter.MAX_PORTS
        assert s.targets == ["192.0.2.1"]
        assert "\x1b" not in parsed["firewall"] and "\x00" not in parsed["firewall"]
        assert len(parsed["firewall"]) == BlockInfoPresenter.MAX_FIREWALL
        rows = dict(BlockInfoPresenter.scan_rows(s))
        assert "<" not in rows["Source hardware address"]

    def test_the_firewall_keeps_its_layout(self):
        assert BlockInfoPresenter.parse(info())["firewall"] == FIREWALL

    def test_a_protocol_scan_shows_protocols_not_ports(self):
        rows = dict(BlockInfoPresenter.scan_rows(BlockInfoPresenter.parse(info(
            scan=scan(method="ip-protocol", is_protocol_scan=True, protocols=12,
                      distinct_ports=0, sample_ports=[])))["scan"]))
        assert rows["IP protocols probed"] == "12"
        assert "Ports" not in rows and "Ports probed" not in rows


class TestTheDetectionHistory():
    """The Port scan Detection tab lists, after the blocks, the sources the
    daemon detected and does not block -- the question expired or was
    answered no, the daemon refused, a block ended -- with the means to block
    one after the fact: a scan is reconnaissance, the attempt comes later."""

    PEER = NODE.split(":", 1)[1]

    def setup_method(self):
        self.nodes = Nodes.instance()
        self.feed = BlockedSources()
        self.view = PortScanBlocksView(self.feed)

    def teardown_method(self):
        for d in list(self.view._dialogs):
            d.close()
        try:
            self.view.hide()
            self.feed._stop()
        except Exception:
            pass

    def _open(self, qtbot, data):
        drain()
        qtbot.addWidget(self.view)
        self.view.show()
        drain()
        nid = next(iter(self.feed._sent))
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=data))

    def _column(self, col):
        return [self.view.table.item(i, col).text()
                for i in range(self.view.table.rowCount())]

    def _yes(self, monkeypatch, said=None, answer=QtWidgets.QMessageBox.StandardButton.Yes):
        def ask(title, message, icon):
            if said is not None:
                said.append((title, message, icon))
            return answer
        monkeypatch.setattr(VIEW + ".Message.yes_no", ask)

    @staticmethod
    def _sent_blocks():
        return [json.loads(n.data) for n in drain() if n.type == ui_pb2.PORTSCAN_BLOCK]

    def test_the_detections_follow_the_blocks(self, qtbot):
        self._open(qtbot, snapshot([block("192.0.2.66")], detections=[
            detected("192.0.2.70", status="unanswered"),
            detected("192.0.2.71", status="refused", eligible=False,
                     reason="no corroborating evidence: nothing arrived that only a scanner sends"),
        ]))
        assert self._column(PortScanBlocksView.COL_ADDR) == ["192.0.2.66", "192.0.2.70", "192.0.2.71"]
        assert self._column(PortScanBlocksView.COL_STATUS) == [
            "blocked", "not blocked: no answer", "not blocked: refused"]
        reasons = self._column(PortScanBlocksView.COL_REASON)
        assert reasons[1] == "TCP Xmas scan (equivalent to nmap -sX)"
        assert reasons[2] == ("TCP Xmas scan (equivalent to nmap -sX); no corroborating evidence:"
                              " nothing arrived that only a scanner sends")
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(1758644000))
        assert self._column(PortScanBlocksView.COL_EXPIRES)[1] == "detected " + when
        assert self.view.lblStatus.text() == "1 blocked; 2 detected and not blocked"

    def test_blocks_and_detections_are_listed_most_recent_first(self, qtbot):
        # The user's run of real-condition-test: blocks were all listed above
        # the detections, so the latest scans showed below older blocks and
        # the list read as sorted by address.
        t = 1760350000

        def at(row, key, minutes):
            row[key] = t + minutes * 60
            return row
        self._open(qtbot, snapshot([
            at(block("10.99.0.104"), "blocked_at", 9),
            at(block("10.99.0.103"), "blocked_at", 4),
            at(block("10.99.0.102"), "blocked_at", 3),
        ], detections=[
            at(detected("10.99.0.107"), "last_reported", 19),
            at(detected("10.99.0.106"), "last_reported", 16),
            at(detected("10.99.0.105"), "last_reported", 12),
            at(detected("10.99.0.101", status="released"), "last_reported", 0),
        ]))
        assert self._column(PortScanBlocksView.COL_ADDR) == [
            "10.99.0.107", "10.99.0.106", "10.99.0.105", "10.99.0.104",
            "10.99.0.103", "10.99.0.102", "10.99.0.101"]

    def test_a_daemon_without_block_times_keeps_its_blocks_first(self, qtbot):
        self._open(qtbot, snapshot([block("192.0.2.66"), block("192.0.2.65")], detections=[
            detected("192.0.2.70"), detected("192.0.2.71")]))
        assert self._column(PortScanBlocksView.COL_ADDR) == [
            "192.0.2.66", "192.0.2.65", "192.0.2.70", "192.0.2.71"]

    def test_every_status_has_words(self, qtbot):
        statuses = ["detected", "asked", "unanswered", "ignored", "refused", "released", "ended"]
        self._open(qtbot, snapshot([], detections=[
            detected("192.0.2.{0}".format(10 + i), status=st) for i, st in enumerate(statuses)]))
        shown = self._column(PortScanBlocksView.COL_STATUS)
        assert all(label not in statuses for label in shown), shown
        assert len(set(shown)) == len(statuses)

    def test_block_is_offered_for_a_detection_and_release_for_a_block(self, qtbot):
        self._open(qtbot, snapshot([block("192.0.2.66")], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        assert self.view.cmdRelease.isEnabled() and not self.view.cmdBlock.isEnabled()
        self.view.table.selectRow(1)
        assert self.view.cmdBlock.isEnabled() and not self.view.cmdRelease.isEnabled()

    def test_block_asks_then_sends_a_block_without_force(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        said = []
        self._yes(monkeypatch, said)
        drain()
        qtbot.mouseClick(self.view.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        assert said and "192.0.2.70" in said[0][1] and "forge" not in said[0][1]
        assert self._sent_blocks() == [{"ip": "192.0.2.70", "dismiss": False}]

    def test_declining_sends_nothing(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        self._yes(monkeypatch, answer=QtWidgets.QMessageBox.StandardButton.Cancel)
        drain()
        qtbot.mouseClick(self.view.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        assert self._sent_blocks() == []

    def test_a_weak_detection_is_blocked_only_after_a_warning(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.71", status="refused", eligible=False)]))
        self.view.table.selectRow(0)
        said = []
        self._yes(monkeypatch, said)
        drain()
        qtbot.mouseClick(self.view.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        title, message, icon = said[0]
        assert "costs nothing to forge" in message and "192.0.2.71" in message
        assert icon == QtWidgets.QMessageBox.Icon.Warning
        assert self._sent_blocks() == [{"ip": "192.0.2.71", "dismiss": False, "force": True}]

    def test_an_exempt_source_cannot_be_blocked(self, qtbot):
        self._open(qtbot, snapshot([], detections=[
            detected("192.0.2.72", status="refused", exempt=True, reason="the source is on the never-block list")]))
        self.view.table.selectRow(0)
        assert not self.view.cmdBlock.isEnabled()

    def test_nothing_can_be_blocked_on_a_node_that_cannot_block(self, qtbot):
        # The policy "never": detections are listed, a block is not possible.
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.73", status="detected")],
                                   can_block=False))
        self.view.table.selectRow(0)
        assert self._column(PortScanBlocksView.COL_STATUS) == ["detected; blocking is off"]
        assert not self.view.cmdBlock.isEnabled()

    def test_a_refused_block_is_reported(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        self._yes(monkeypatch)
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda title, message, icon: said.append((title, message)))
        qtbot.mouseClick(self.view.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        nid = next(iter(self.feed._blocks))
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="portscan: 192.0.2.70 was never reported as scanning"))
        assert said and "192.0.2.70" in said[0][0] and "never reported" in said[0][1]
        assert self.feed._blocks == {}

    def test_a_block_answer_from_another_node_is_not_taken(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        self._yes(monkeypatch)
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda *a: said.append(a))
        qtbot.mouseClick(self.view.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        nid = next(iter(self.feed._blocks))
        self.feed._cb_notification_callback("/tmp/other.sock", ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="forged"))
        assert said == [] and nid in self.feed._blocks

    def test_the_context_menu_of_a_detection(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        offered = []

        def pick(menu, *_a):
            offered.extend(a.text() for a in menu.actions() if a.text())
            return None
        monkeypatch.setattr(QtWidgets.QMenu, "exec", pick)
        pos = self.view.table.visualItemRect(self.view.table.item(0, 0)).center()
        self.view._cb_context_menu(pos)
        # No nftables rule to show and nothing to release: it is not blocked.
        assert offered == ["Details", "Block", "Delete", "Copy"]

    def test_an_empty_history_is_said_as_such(self, qtbot):
        self._open(qtbot, snapshot([], detections=[]))
        assert self.view.lblStatus.text() == \
            "No address is blocked, and no scan is in the daemon's history."

    def test_a_daemon_without_history_is_not_said_to_have_seen_nothing(self, qtbot):
        # A daemon that predates the history sends no detections: nothing can
        # be said about scans it did not block.
        self._open(qtbot, snapshot([]))
        assert self.view.lblStatus.text() == BlockedListPresenter.empty_label()
        assert not self.view.cmdBlock.isEnabled()

    def test_the_search_finds_a_status_and_a_scan(self, qtbot):
        self._open(qtbot, snapshot([block("192.0.2.66")], detections=[detected("192.0.2.70")]))
        self.view.set_filter("no answer")
        assert self._column(PortScanBlocksView.COL_ADDR) == ["192.0.2.70"]
        self.view.set_filter("xmas")
        assert self._column(PortScanBlocksView.COL_ADDR) == ["192.0.2.70"]

    # ------------------------------------------------------- the details

    def _details(self, qtbot, monkeypatch, det, can_block=True):
        self._open(qtbot, snapshot([], detections=[det], can_block=can_block))
        drain()
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        sent = drain()
        assert [n.type for n in sent] == [ui_pb2.PORTSCAN_BLOCK_INFO]
        dialog = next(iter(self.view._dialogs))
        nid = next(iter(self.feed._infos))
        answer = {"addr": det["addr"], "reason": "", "remaining": 0, "expires_at": 0,
                  "scan": scan(method="tcp-xmas", method_detail="TCP Xmas scan (equivalent to nmap -sX)"),
                  "firewall_error": "not blocked: there is no firewall rule for this address",
                  "detection": det}
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=json.dumps(answer)))
        return dialog

    @staticmethod
    def _form(dialog):
        return TestBlockDetails._form(dialog)

    def test_the_details_of_a_detection(self, qtbot, monkeypatch):
        dialog = self._details(qtbot, monkeypatch, detected("192.0.2.70", status="ignored"))
        form = self._form(dialog)
        assert form["Status"] == "not blocked: ignored"
        assert form["Scan type"] == "TCP Xmas scan (equivalent to nmap -sX)"
        assert "Expires in" not in form and "Blocked because" not in form
        assert dialog.txtFirewall.toPlainText() == \
            "This address is not blocked: there is no nftables rule for it."
        assert dialog.lblExpiry.isHidden()
        assert dialog.cmdBlock.isVisibleTo(dialog)

    def test_block_from_the_details(self, qtbot, monkeypatch):
        dialog = self._details(qtbot, monkeypatch, detected("192.0.2.70"))
        self._yes(monkeypatch)
        drain()
        qtbot.mouseClick(dialog.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        sent = drain()
        assert [json.loads(n.data) for n in sent if n.type == ui_pb2.PORTSCAN_BLOCK] == \
            [{"ip": "192.0.2.70", "dismiss": False}]
        # And the details are asked again, to show the block.
        assert ui_pb2.PORTSCAN_BLOCK_INFO in [n.type for n in sent]

    def test_the_details_of_a_weak_detection_say_why_it_needs_a_warning(self, qtbot, monkeypatch):
        dialog = self._details(qtbot, monkeypatch, detected("192.0.2.71", status="refused",
                                                            eligible=False, reason="no corroborating evidence"))
        form = self._form(dialog)
        assert form["Not blocked because"] == "no corroborating evidence"
        assert "forged" in form["Blocking"]

    def test_no_block_button_for_an_exempt_source_or_a_node_that_cannot_block(self, qtbot, monkeypatch):
        dialog = self._details(qtbot, monkeypatch, detected("192.0.2.72", exempt=True))
        assert not dialog.cmdBlock.isVisibleTo(dialog)
        assert "never-block" in self._form(dialog)["Blocking"]

    def test_no_block_button_where_blocking_is_off(self, qtbot, monkeypatch):
        dialog = self._details(qtbot, monkeypatch, detected("192.0.2.73", status="detected"), can_block=False)
        assert not dialog.cmdBlock.isVisibleTo(dialog)

    def _deliver(self, data):
        nid = next(iter(self.feed._sent))
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=data))

    def test_unchanged_detections_are_kept(self, qtbot):
        # The daemon leaves the detections out of a snapshot when they are the
        # ones it sent last on the stream.
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self._deliver(json.dumps({"blocks": [block("192.0.2.66")], "total": 1, "omitted": 0,
                                  "detections_unchanged": True, "detections_total": 1,
                                  "can_block": True}))
        assert self._column(PortScanBlocksView.COL_ADDR) == ["192.0.2.66", "192.0.2.70"]

    def test_unchanged_with_nothing_kept_says_nothing_about_detections(self, qtbot):
        # A new stream starts with the full list; "unchanged" with nothing to
        # keep is not taken for an empty history.
        self._open(qtbot, json.dumps({"blocks": [], "total": 0, "omitted": 0,
                                      "detections_unchanged": True, "can_block": True}))
        assert self.view.table.rowCount() == 0
        assert self.view.lblStatus.text() == BlockedListPresenter.empty_label()


class TestHostileAndRacingInput():
    """What a node can send, and what can change while the user decides:
    out-of-range times, rows changing kind during a confirmation, details
    that never come, answers from the wrong node."""

    OTHER = "unix:/tmp/second.sock"
    PEER = NODE.split(":", 1)[1]

    def setup_method(self):
        from queue import Queue
        from tests.dialogs import ClientConfig
        self.nodes = Nodes.instance()
        self.nodes._nodes[self.OTHER] = {'data': ClientConfig, 'notifications': Queue(), 'online': True}
        self.feed = BlockedSources()
        self.view = PortScanBlocksView(self.feed)

    def teardown_method(self):
        for d in list(self.view._dialogs):
            d.close()
        try:
            self.view.hide()
            self.feed._stop()
        except Exception:
            pass
        self.nodes._nodes.pop(self.OTHER, None)

    def _open(self, qtbot, data):
        drain()
        qtbot.addWidget(self.view)
        self.view.show()
        drain()
        self._deliver(data)

    def _deliver(self, data):
        nid = next(n for n, a in self.feed._sent.items() if a == NODE)
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=data))

    def _column(self, col):
        return [self.view.table.item(i, col).text() for i in range(self.view.table.rowCount())]

    def _details(self, det, scan_over=None):
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        dialog = next(iter(self.view._dialogs))
        nid = next(iter(self.feed._infos))
        answer = {"addr": det["addr"], "scan": scan(**(scan_over or {})), "detection": det,
                  "firewall_error": "not blocked"}
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=json.dumps(answer)))
        return dialog

    # ------------------------------------------------ timestamps (MOYENNE)

    def test_a_timestamp_out_of_range_does_not_abort_the_gui(self, qtbot):
        dets = [detected("192.0.2.{0}".format(i)) for i in (1, 2, 3, 4)]
        for d, ts in zip(dets, (10**20, 1e300, -5, 0)):
            d["last_reported"] = ts
            d["first_reported"] = ts
        self._open(qtbot, snapshot([], detections=dets))
        assert self._column(PortScanBlocksView.COL_EXPIRES) == ["", "", "", ""]

    def test_a_scan_time_out_of_range_does_not_abort_the_details(self, qtbot):
        det = detected("192.0.2.70")
        self._open(qtbot, snapshot([], detections=[det]))
        dialog = self._details(det, {"first_seen_unixnano": 10**30, "last_seen_unixnano": 1e300})
        form = TestBlockDetails._form(dialog)
        assert form.get("First seen", "") == "" and form.get("Last seen", "") == ""
        assert form["Scan type"] == "TCP SYN scan"

    # --------------------------------- what is confirmed is sent (MOYENNE)

    def test_a_row_that_becomes_a_block_during_the_confirmation(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)

        def ask(title, text, icon):
            # The source is blocked elsewhere while the box is open.
            self._deliver(snapshot([block("192.0.2.70")], detections=[]))
            return QtWidgets.QMessageBox.StandardButton.Yes
        monkeypatch.setattr(VIEW + ".Message.yes_no", ask)
        drain()
        self.view._cb_block_clicked()
        sent = [json.loads(n.data) for n in drain() if n.type == ui_pb2.PORTSCAN_BLOCK]
        assert sent == [{"ip": "192.0.2.70", "dismiss": False}]

    def test_force_is_what_was_confirmed(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        shown = []

        def ask(title, text, icon):
            shown.append(text)
            # Now reported weak: the user did not see a warning for it.
            self._deliver(snapshot([], detections=[detected("192.0.2.70", eligible=False)]))
            return QtWidgets.QMessageBox.StandardButton.Yes
        monkeypatch.setattr(VIEW + ".Message.yes_no", ask)
        drain()
        self.view._cb_block_clicked()
        assert "forge" not in shown[0]
        sent = [json.loads(n.data) for n in drain() if n.type == ui_pb2.PORTSCAN_BLOCK]
        assert sent == [{"ip": "192.0.2.70", "dismiss": False}]

    def test_block_from_details_after_the_source_was_blocked_elsewhere(self, qtbot, monkeypatch):
        det = detected("192.0.2.70")
        self._open(qtbot, snapshot([], detections=[det]))
        dialog = self._details(det)
        self._deliver(snapshot([block("192.0.2.70")], detections=[]))
        said = []
        monkeypatch.setattr(VIEW + ".Message.ok", lambda title, text, icon: said.append(text))
        monkeypatch.setattr(VIEW + ".Message.yes_no", lambda *a: pytest.fail("asked to block a block"))
        drain()
        qtbot.mouseClick(dialog.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        assert said and "no longer listed" in said[0]
        assert [n for n in drain() if n.type == ui_pb2.PORTSCAN_BLOCK] == []

    # ------------------------------------- Block in the dialog (FAIBLE)

    def test_no_block_in_the_details_from_the_rules_tab(self, qtbot):
        rules = PortScanBlocksView(self.feed, detections=False)
        qtbot.addWidget(rules)
        det = detected("192.0.2.70", status="ended")
        self._open(qtbot, snapshot([block("192.0.2.70")], detections=[]))
        rules.show()
        dialog = rules.show_details((NODE, "192.0.2.70"), PortScanBlockDialog.TAB_SCAN)
        nid = next(iter(self.feed._infos))
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=json.dumps({"addr": "192.0.2.70", "scan": scan(), "detection": det})))
        assert not dialog.cmdBlock.isVisibleTo(dialog)
        dialog.close()

    def test_block_from_the_details_works_with_the_row_filtered_out(self, qtbot, monkeypatch):
        det = detected("192.0.2.70")
        self._open(qtbot, snapshot([], detections=[det]))
        dialog = self._details(det)
        self.view.set_filter("nothing matches this")
        monkeypatch.setattr(VIEW + ".Message.yes_no", lambda *a: QtWidgets.QMessageBox.StandardButton.Yes)
        drain()
        qtbot.mouseClick(dialog.cmdBlock, QtCore.Qt.MouseButton.LeftButton)
        assert [json.loads(n.data)["ip"] for n in drain() if n.type == ui_pb2.PORTSCAN_BLOCK] == ["192.0.2.70"]

    def test_details_unanswered_are_given_up(self, qtbot, monkeypatch):
        # A daemon that predates PORTSCAN_BLOCK_INFO never answers it.
        monkeypatch.setattr(BlockedSources, "INFO_TIMEOUT", 0.05)
        monkeypatch.setattr(BlockedSources, "INFO_GIVE_UP", 0.3)
        self._open(qtbot, snapshot([block("192.0.2.66")]))
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        dialog = next(iter(self.view._dialogs))
        nid = next(iter(self.feed._infos))
        qtbot.waitUntil(lambda: "no answer yet" in dialog.lblStatus.text(), timeout=2000)
        qtbot.waitUntil(lambda: self.feed._infos == {}, timeout=2000)
        assert nid not in self.nodes._notifications_sent
        assert self.feed._info_latest == {}
        # Given up is said too, with what to do.
        assert "Refresh asks again" in dialog.lblStatus.text()

    def test_a_late_answer_is_still_shown(self, qtbot, monkeypatch):
        # A busy daemon answers after INFO_TIMEOUT; until the request is given
        # up, its answer replaces "no answer yet".
        monkeypatch.setattr(BlockedSources, "INFO_TIMEOUT", 0.05)
        self._open(qtbot, snapshot([block("192.0.2.66")]))
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        dialog = next(iter(self.view._dialogs))
        nid = next(iter(self.feed._infos))
        qtbot.waitUntil(lambda: "no answer yet" in dialog.lblStatus.text(), timeout=2000)
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=info()))
        assert dialog.lblStatus.text() == ""
        assert dialog.txtFirewall.toPlainText() == FIREWALL

    def test_a_superseded_request_does_not_cover_fresh_details(self, qtbot, monkeypatch):
        monkeypatch.setattr(BlockedSources, "INFO_TIMEOUT", 0.2)
        self._open(qtbot, snapshot([block("192.0.2.66")]))
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        dialog = next(iter(self.view._dialogs))
        dialog.refresh()
        # Not max(_infos): the ids are time-based strings turned into ints,
        # and do not always increase.
        latest = self.feed._info_latest[(NODE, "192.0.2.66")]
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=latest, code=ui_pb2.OK, data=info()))
        qtbot.wait(400)
        assert "no answer" not in dialog.lblStatus.text()

    def test_block_says_why_it_skips_an_exempt_source(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.72", exempt=True)]))
        said = []
        monkeypatch.setattr(VIEW + ".Message.ok", lambda title, text, icon: said.append(text))
        monkeypatch.setattr(VIEW + ".Message.yes_no", lambda *a: pytest.fail("asked"))
        drain()
        self.view.block([(NODE, "192.0.2.72")])
        assert said and "never-block" in said[0] and "no longer listed" not in said[0]
        assert [n for n in drain() if n.type == ui_pb2.PORTSCAN_BLOCK] == []

    def test_block_says_why_it_skips_a_node_that_cannot_block(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.73")], can_block=False))
        said = []
        monkeypatch.setattr(VIEW + ".Message.ok", lambda title, text, icon: said.append(text))
        monkeypatch.setattr(VIEW + ".Message.yes_no", lambda *a: pytest.fail("asked"))
        drain()
        self.view.block([(NODE, "192.0.2.73")])
        assert said and "cannot block" in said[0]
        assert [n for n in drain() if n.type == ui_pb2.PORTSCAN_BLOCK] == []

    def test_the_kept_detections_are_dropped_with_the_stream(self, qtbot):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        assert NODE in self.feed._last_detections
        self.view.hide()
        self.feed._stop_if_unwatched()
        assert self.feed._last_detections == {}

    def test_the_status_line_after_an_unchanged_snapshot(self, qtbot):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self._deliver(json.dumps({"blocks": [], "total": 0, "omitted": 0,
                                  "detections_unchanged": True, "detections_total": 1,
                                  "can_block": True}))
        assert self.view.lblStatus.text().startswith("1 detected and not blocked")

    # ------------------------------------------------- escaping and bounds

    def test_a_refused_block_is_escaped(self, qtbot, monkeypatch):
        self._open(qtbot, snapshot([], detections=[detected("192.0.2.70")]))
        self.view.table.selectRow(0)
        monkeypatch.setattr(VIEW + ".Message.yes_no", lambda *a: QtWidgets.QMessageBox.StandardButton.Yes)
        said = []
        monkeypatch.setattr(FEED + ".Message.ok", lambda title, text, icon: said.append(title + text))
        self.view._cb_block_clicked()
        nid = next(iter(self.feed._blocks))
        self.feed._cb_notification_callback(NODE, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data='<a href="http://x">click</a>'))
        assert said and "<a" not in said[0]

    def test_a_details_error_is_bounded_and_plain(self, qtbot):
        self._open(qtbot, snapshot([block("192.0.2.66")]))
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        dialog = next(iter(self.view._dialogs))
        nid = next(iter(self.feed._infos))
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data="<b>" + "x" * 5000))
        text = dialog.lblStatus.text()
        assert "<" not in text and len(text) < 400

    def test_details_from_another_node_with_the_same_address_are_not_taken(self, qtbot):
        self._open(qtbot, snapshot([block("192.0.2.66")]))
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        dialog = next(iter(self.view._dialogs))
        self.feed.info_received.emit(self.OTHER, "192.0.2.66", {"error": "from the other node"})
        assert "other node" not in dialog.lblStatus.text()

    def test_blocks_waiting_on_a_node_that_leaves_are_dropped(self, qtbot):
        self._open(qtbot, snapshot([]))
        self.feed.block(self.OTHER, "192.0.2.70")
        nid = next(iter(self.feed._blocks))
        # Hidden first: the requests outlive the views, and a node leaving
        # while nothing is on screen must still take its own with it.
        self.view.hide()
        self.feed._stop_if_unwatched()
        saved = self.nodes._nodes.pop(self.OTHER)
        try:
            self.nodes.nodesUpdated.emit(self.nodes.count())
            assert self.feed._blocks == {}
            assert nid not in self.nodes._notifications_sent
        finally:
            self.nodes._nodes[self.OTHER] = saved

    def test_the_rules_tab_does_not_count_detections(self, qtbot):
        rules = PortScanBlocksView(self.feed, detections=False)
        qtbot.addWidget(rules)
        rules.show()
        self._open(qtbot, snapshot([block("192.0.2.66")], detections=[detected("192.0.2.70")]))
        assert "detected" not in rules.lblStatus.text()
        assert "detected" in self.view.lblStatus.text()

    def test_the_kernel_note_shows_for_a_block_only(self, qtbot):
        self._open(qtbot, snapshot([block("192.0.2.66")]))
        self.view._cb_double_clicked(0, PortScanBlocksView.COL_REASON)
        dialog = next(iter(self.view._dialogs))
        nid = next(iter(self.feed._infos))
        self.nodes.reply_notification(self.PEER, ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=info()))
        assert not dialog.lblExpiry.isHidden()

    def test_details_waiting_on_a_node_that_leaves_while_hidden_are_answered(self, qtbot):
        self._open(qtbot, snapshot([]))
        got = []
        self.feed.info_received.connect(lambda node, ip, result: got.append((node, result)))
        self.feed.request_info(self.OTHER, "192.0.2.70")
        nid = next(iter(self.feed._infos))
        self.view.hide()
        self.feed._stop_if_unwatched()
        saved = self.nodes._nodes.pop(self.OTHER)
        try:
            self.nodes.nodesUpdated.emit(self.nodes.count())
            assert self.feed._infos == {}
            assert nid not in self.nodes._notifications_sent
            assert got and got[0][0] == self.OTHER and "disconnected" in got[0][1]["error"]
        finally:
            self.nodes._nodes[self.OTHER] = saved


class TestTheRenderCoalescing():
    """A node can answer on its stream as often as it likes: a table rebuilt
    per answer froze the GUI at a few answers a second."""

    def setup_method(self):
        self.nodes = Nodes.instance()
        self.feed = BlockedSources()

    def teardown_method(self):
        self.feed._stop()

    def _push(self, data):
        nid = next(n for n, a in self.feed._sent.items() if a == NODE)
        self.nodes.reply_notification(NODE.split(":", 1)[1], ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.OK, data=data))

    def test_a_burst_of_pushes_renders_twice(self, qtbot, monkeypatch):
        monkeypatch.setattr(PortScanBlocksView, "RENDER_INTERVAL_MS", 250)
        view = PortScanBlocksView(self.feed)
        qtbot.addWidget(view)
        view.show()
        drain()
        renders = []
        real = view._render
        monkeypatch.setattr(view, "_render", lambda: (renders.append(1), real()))
        view._render_timer.timeout.disconnect()
        view._render_timer.timeout.connect(view._render)
        view._last_render = 0.0
        for i in range(30):
            self._push(snapshot([block("192.0.2.{0}".format(i + 1))]))
        assert len(renders) == 1, "the first push of a burst is shown at once"
        qtbot.waitUntil(lambda: len(renders) == 2, timeout=2000)
        qtbot.wait(400)
        assert len(renders) == 2
        assert view.table.rowCount() == 1
        assert view.table.item(0, view.COL_ADDR).text() == "192.0.2.30", \
            "the last push of the burst is the one shown"

    def test_the_view_of_an_inactive_tab_does_not_render(self, qtbot, monkeypatch):
        tabs = QtWidgets.QTabWidget()
        qtbot.addWidget(tabs)
        shown = PortScanBlocksView(self.feed)
        hidden = PortScanBlocksView(self.feed, detections=False)
        tabs.addTab(shown, "a")
        tabs.addTab(hidden, "b")
        tabs.show()
        drain()
        renders = []
        monkeypatch.setattr(hidden, "_render", lambda: renders.append(1))
        self._push(snapshot([block("192.0.2.1")]))
        assert renders == []
        assert shown.table.rowCount() == 1
