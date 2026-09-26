"""The list of port scan sources, blocked or detected, shared by the views
that show it.

The daemon pushes the list on a task stream (daemon/tasks/portscanblocks)
rather than answering a one-shot query, so it follows the daemon: a block that
expires on its own, or one installed while the list is on screen, appears
without the user refreshing anything. Between pushes the countdown is
decremented locally, which is why the daemon sends the time remaining as well
as the absolute expiry -- a GUI watching a node whose clock differs would
otherwise count down to the wrong moment.

Two views of the main window show this list: the Port scan Detection tab, and
the "Port scan blocks" entry of the Rules tab. A node runs at most one task of
a given name (TaskManager.AddTask refuses a second), so the views cannot each
open their own stream: this object opens one per node, for as long as at least
one view is visible, and both views render from it.

The daemon owns the blocks throughout. This object asks; it never touches the
firewall itself.
"""

import time
from html import escape

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.nodes import Nodes
from opensnitch.portscan import BlockedListPresenter, BlockInfoPresenter, PortScanPresenter
from opensnitch.utils import Message

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()


class BlockedSources(QtCore.QObject):
    LOG_TAG = "[portscan blocks]"

    # How often the daemon is asked to push a snapshot. The local countdown
    # ticks every second regardless, so this decides how quickly a new or
    # expired block appears, not how smooth the display looks.
    INTERVAL = "2s"
    # A node that has sent nothing for this long is no longer described by
    # what it last sent: its daemon may have restarted (releasing every block)
    # or the connection may be gone. Three intervals, so one late push is not
    # an alarm.
    STALE_AFTER = 6.0

    # The rows, or the status of a node, changed: views rebuild their table.
    changed = QtCore.pyqtSignal()
    # How long a details request waits before the dialog says it has no
    # answer yet, and how long before the request is given up. A daemon that
    # predates PORTSCAN_BLOCK_INFO never answers, and the dialog would say
    # "Loading..." for good; a busy one answers late (reading a set of the
    # largest MaxBlockedSources takes over a second, one request at a time),
    # and its answer is still shown until the request is given up.
    INFO_TIMEOUT = 10.0
    INFO_GIVE_UP = 120.0

    # A second went by: views only refresh the countdown column.
    ticked = QtCore.pyqtSignal()
    # The details of a row asked with request_info arrived: node, address,
    # and the parsed answer, or {"error": "..."}.
    info_received = QtCore.pyqtSignal(str, str, object)

    _notification_callback = QtCore.pyqtSignal(str, ui_pb2.NotificationReply)

    def __init__(self, parent=None, nodes=None):
        QtCore.QObject.__init__(self, parent)
        self._nodes = Nodes.instance() if nodes is None else nodes
        # node address -> {"rows": [...], "total": n, "omitted": n} or
        # {"error": "..."}; one entry per node heard from.
        self._state = {}
        # notification id -> node, for the snapshots this object asked for.
        self._sent = {}
        # notification id -> (node, address), for releases awaiting an answer.
        self._releases = {}
        # The ids of those releases that are deletions (forget): the source
        # leaves the list, detection included.
        self._deleting = set()
        # notification id -> (node, address), for details awaiting an answer.
        self._infos = {}
        # (node, address) -> the id of its latest details request: only that
        # one may say it has no answer yet, not one a Refresh superseded.
        self._info_latest = {}
        # notification id -> (node, address), for blocks asked from the
        # history, awaiting an answer.
        self._blocks = {}
        # node -> (detections, detections_total) last received on its stream:
        # the daemon leaves them out of a snapshot when they have not changed.
        self._last_detections = {}
        # When the last snapshot of each node arrived, so the countdown can be
        # decremented from it rather than drifting.
        self._received = {}
        # When TASK_START was sent to each node, to tell a node that never
        # answers -- a daemon that predates port scan detection -- from one
        # that is slow.
        self._asked = {}
        # The release being sent right now, for the answer Nodes may give from
        # inside send_notification; see release().
        self._inflight_release = None
        self._inflight_forget = False
        self._inflight_info = None
        self._inflight_block = None
        self._running = False
        # The views currently visible. The stream runs while this is not empty.
        self._viewers = set()

        # Stopping is deferred to the next turn of the event loop. Switching
        # from one view to the other hides the first before showing the second
        # (QStackedWidget does it in that order), and stopping at once would
        # send TASK_STOP then TASK_START for a list nobody stopped looking at.
        self._stop_pending = QtCore.QTimer(self)
        self._stop_pending.setSingleShot(True)
        self._stop_pending.setInterval(0)
        self._stop_pending.timeout.connect(self._stop_if_unwatched)

        self._notification_callback.connect(self._cb_notification_callback)
        # Nodes come and go while the list is on screen: a daemon restart is a
        # disconnection followed by a new connection. Without this the views
        # would go on showing, and counting down, blocks a restarted daemon had
        # already released, and never ask the returning node for its new ones.
        self._nodes.nodesUpdated.connect(self._cb_nodes_updated)
        self._countdown = QtCore.QTimer(self)
        self._countdown.setInterval(1000)
        self._countdown.timeout.connect(self._tick)

    # ------------------------------------------------------------ the viewers

    def attach(self, viewer):
        """A view became visible: the stream runs from now on."""
        self._viewers.add(viewer)
        self._stop_pending.stop()
        self._start()

    def detach(self, viewer):
        """A view was hidden: the stream stops once no view is left."""
        self._viewers.discard(viewer)
        if not self._viewers:
            self._stop_pending.start()

    def is_running(self):
        return self._running

    def _stop_if_unwatched(self):
        if not self._viewers:
            self._stop()

    # ------------------------------------------------------------ the stream

    def _connected_nodes(self):
        try:
            return [addr for addr in self._nodes.get_nodes()]
        except Exception as e:
            print(self.LOG_TAG, "listing nodes:", repr(e))
            return []

    def _start(self):
        if self._running:
            return
        self._running = True
        self._state = {}
        self._last_detections = {}
        self._received = {}
        self._asked = {}
        self._sent = {}
        for addr in self._connected_nodes():
            self._start_on(addr)
        self._countdown.start()
        self.changed.emit()

    def _start_on(self, addr):
        payload = BlockedListPresenter.list_request(self.INTERVAL)
        try:
            noti = ui_pb2.Notification(
                clientName="", serverName="",
                type=ui_pb2.TASK_START, data=payload, rules=[])
            self._asked[addr] = time.monotonic()
            nid = self._nodes.send_notification(
                addr, noti, self._notification_callback)
            self._sent[nid] = addr
        except Exception as e:
            print(self.LOG_TAG, "starting on", addr, repr(e))
            self._state[addr] = {"error": repr(e)}

    def _forget_requests(self, addr):
        """Drops this object's bookkeeping for a node, and Nodes' as well.

        Nodes keeps a TASK_START's callback until the stream ends, and a node
        that never answers -- a daemon that predates this feature -- never ends
        it: every time the list was shown would leave two entries behind for
        good.
        """
        for nid in [n for n, a in self._sent.items() if a == addr]:
            del self._sent[nid]
            self._nodes.forget_notification(nid)
        # A new stream starts with the full list.
        self._last_detections.pop(addr, None)

    @QtCore.pyqtSlot(int)
    def _cb_nodes_updated(self, _total):
        connected = set(self._connected_nodes())
        # Releases outlive the views: one sent just before they were hidden is
        # still waiting, and its node may leave while nothing is on screen.
        waiting = {node for node, _ip in self._releases.values()} | \
            {node for node, _ip in self._infos.values()} | \
            {node for node, _ip in self._blocks.values()}
        for addr in waiting - connected:
            self._forget_releases(addr)
        if not self._running:
            return
        for addr in set(self._sent.values()) | set(self._state):
            if addr not in connected:
                self._forget_requests(addr)
                self._forget_releases(addr)
                self._received.pop(addr, None)
                self._asked.pop(addr, None)
                self._state[addr] = {"error": QC.translate(
                    "portscan", "node disconnected; its blocks are not shown")}
        for addr in connected:
            if addr not in self._sent.values():
                self._state.pop(addr, None)
                self._start_on(addr)
        self.changed.emit()

    def _stop(self):
        if not self._running:
            return
        self._running = False
        self._countdown.stop()
        payload = BlockedListPresenter.list_request(self.INTERVAL)
        for addr in set(self._sent.values()):
            try:
                noti = ui_pb2.Notification(
                    clientName="", serverName="",
                    type=ui_pb2.TASK_STOP, data=payload, rules=[])
                nid = self._nodes.send_notification(addr, noti, None)
                # Nobody waits for this answer; an old daemon never sends one.
                self._nodes.forget_notification(nid)
            except Exception as e:
                print(self.LOG_TAG, "stopping on", addr, repr(e))
            self._forget_requests(addr)
        self._sent = {}

    def _forget_releases(self, addr):
        """Drops the releases still waiting for an answer from a node.

        A node that disconnects never answers them; kept, they would stay here
        and in Nodes for good. Nothing is said: the list already shows the
        node as disconnected, and a daemon that stops releases every block.
        """
        for pending in (self._releases, self._blocks):
            for nid in [n for n, (node, _ip) in pending.items() if node == addr]:
                del pending[nid]
                self._deleting.discard(nid)
                self._nodes.forget_notification(nid)
        # A details dialog waiting on the node is told, or it would say
        # "Loading..." for good.
        for nid in [n for n, (node, _ip) in self._infos.items() if node == addr]:
            _node, ip = self._infos.pop(nid)
            self._info_latest.pop((addr, ip), None)
            self._nodes.forget_notification(nid)
            self.info_received.emit(addr, ip, {"error": QC.translate(
                "portscan", "node disconnected")})

    def _reply_is_from(self, node, addr):
        """Reports whether a reply delivered with addr came from node.

        The id of a reply is chosen by whoever sends it, and the ids are
        timestamps, easy to guess: an id alone would let one node answer for
        another -- rewrite its list, or put an address of its choosing under
        its name, for the user to release there. A reply is accepted only on
        the stream of the node it was asked of. That stream delivers addr as
        Nodes.get_addr gives it for the node's key; Nodes.send_notification's
        own answers, for a node that is not connected, carry the key itself.
        Nodes applies the same check to the one-time requests (block,
        release, details), so that another node's reply cannot consume them.
        """
        return self._nodes.reply_is_from(node, addr)

    @QtCore.pyqtSlot(str, ui_pb2.NotificationReply)
    def _cb_notification_callback(self, addr, reply):
        # The node a reply comes from is taken from this object's own record
        # of the request it answers, and the stream it came on must be that
        # node's (see _reply_is_from). addr is not the node's key: for replies
        # on a daemon's stream it is the gRPC peer without its protocol prefix
        # ("/local" for the node "unix:/local"); rows filed under it would be
        # released towards a node that does not exist, and the staleness
        # checks, keyed on the real node, would never see them.
        target = self._infos.get(reply.id)
        if target is not None:
            if self._reply_is_from(target[0], addr):
                del self._infos[reply.id]
                if self._info_latest.get(target) == reply.id:
                    del self._info_latest[target]
                self._info_answered(target, reply)
            return
        inflight = self._inflight_info
        if inflight is not None and addr == inflight[0]:
            # The synchronous answer for a node that is not connected, as for a
            # release below.
            self._inflight_info = None
            self._info_answered(inflight, reply)
            return
        target = self._blocks.get(reply.id)
        if target is not None:
            if self._reply_is_from(target[0], addr):
                del self._blocks[reply.id]
                self._block_answered(target, reply)
            return
        inflight = self._inflight_block
        if inflight is not None and addr == inflight[0]:
            # The synchronous answer for a node that is not connected, as for a
            # release below.
            self._inflight_block = None
            self._block_answered(inflight, reply)
            return
        target = self._releases.get(reply.id)
        if target is not None:
            if self._reply_is_from(target[0], addr):
                del self._releases[reply.id]
                forget = reply.id in self._deleting
                self._deleting.discard(reply.id)
                self._release_answered(target, reply, forget)
            return
        inflight = self._inflight_release
        if inflight is not None and addr == inflight[0]:
            # Nodes.send_notification answers a release for a node that is not
            # connected by emitting the reply itself, from inside the call,
            # before it returns the id release() would record. Cleared before
            # the answer is shown: the message box runs an event loop of its
            # own, and other replies must not be taken for this one meanwhile.
            self._inflight_release = None
            self._release_answered(inflight, reply, self._inflight_forget)
            return
        node = self._sent.get(reply.id)
        if node is not None and not self._reply_is_from(node, addr):
            return
        if node is None:
            # An id this object has not recorded yet is not necessarily noise.
            # The same synchronous answer comes for a TASK_START sent to a node
            # that is not connected, and it carries the key _start_on passed,
            # already in _asked. Dropping it would lose the one answer that says
            # the node is gone, leaving the views showing a block table nobody
            # is maintaining any more. Anything else -- a late reply to a
            # request already forgotten -- is ignored.
            if reply.code == ui_pb2.ERROR and addr in self._asked:
                self._state[addr] = {"error": reply.data}
                self.changed.emit()
            return
        addr = node
        if reply.code == ui_pb2.ERROR:
            # The daemon's own words -- "port scan detection is not running"
            # is the common one, and it is the answer to the question the user
            # opened the list to ask.
            self._state[addr] = {"error": reply.data}
            self.changed.emit()
            return
        if reply.data == "":
            return
        try:
            state = BlockedListPresenter.parse_snapshot(reply.data)
        except ValueError as e:
            self._state[addr] = {"error": str(e)}
            self.changed.emit()
            return
        if state["unchanged"]:
            last = self._last_detections.get(addr)
            if last is None:
                # Nothing was received to keep: nothing is said about the
                # node's detections rather than "none".
                state["history"] = False
            else:
                state["detections"], state["detections_total"] = last
        elif state["history"]:
            self._last_detections[addr] = (state["detections"], state["detections_total"])
        self._state[addr] = state
        self._received[addr] = time.monotonic()
        self.changed.emit()

    def _info_answered(self, target, reply):
        node, ip = target
        if reply.code == ui_pb2.ERROR:
            result = {"error": BlockedListPresenter.status_text(reply.data)}
        else:
            try:
                result = BlockInfoPresenter.parse(reply.data)
            except ValueError as e:
                result = {"error": BlockedListPresenter.status_text(str(e))}
            else:
                if result["ip"] != ip:
                    # The node answered about another address than the one
                    # asked: shown under this one, it would be a forgery.
                    result = {"error": QC.translate(
                        "portscan", "the node answered about another address")}
        self.info_received.emit(node, ip, result)

    def request_info(self, node, ip):
        """Asks one node for the details of one row: a block or a detection.

        The answer comes as info_received. It is asked when the user opens the
        details, not pushed with the list: it is many times the size of a row,
        and the firewall is read for it.
        """
        try:
            noti = ui_pb2.Notification(
                clientName="", serverName="",
                type=ui_pb2.PORTSCAN_BLOCK_INFO,
                data=BlockInfoPresenter.request(ip),
                rules=[])
            self._inflight_info = (node, ip)
            try:
                nid = self._nodes.send_notification(
                    node, noti, self._notification_callback)
            finally:
                answered = self._inflight_info is None
                self._inflight_info = None
            if not answered:
                self._infos[nid] = (node, ip)
                self._info_latest[(node, ip)] = nid
                QtCore.QTimer.singleShot(int(self.INFO_TIMEOUT * 1000),
                                         lambda nid=nid: self._info_timed_out(nid))
                QtCore.QTimer.singleShot(int(self.INFO_GIVE_UP * 1000),
                                         lambda nid=nid: self._info_given_up(nid))
        except Exception as e:
            print(self.LOG_TAG, "asking", node, "about", ip, repr(e))
            self.info_received.emit(node, ip, {"error": BlockedListPresenter.status_text(str(e))})

    def _info_timed_out(self, nid):
        target = self._infos.get(nid)
        if target is None or self._info_latest.get(target) != nid:
            return
        self.info_received.emit(target[0], target[1], {"error": QC.translate(
            "portscan", "no answer yet; this node's daemon may be busy, or may not"
            " support block details")})

    def _info_given_up(self, nid):
        target = self._infos.pop(nid, None)
        if target is None:
            return
        self._nodes.forget_notification(nid)
        if self._info_latest.get(target) == nid:
            del self._info_latest[target]
            # Said, or the dialog would read "no answer yet" for good: an
            # answer arriving now is no longer taken.
            self.info_received.emit(target[0], target[1], {"error": QC.translate(
                "portscan", "no answer; this node's daemon may not support block details."
                " Refresh asks again")})

    def _release_answered(self, target, reply, forget=False):
        """Reports a refused release or deletion.

        One that succeeds needs no message: the address disappears from the
        list on the next push, which is the answer. One that fails must be
        said out loud, because the list will keep showing the row and the
        user would reasonably read that as the view being slow.
        """
        node, ip = target
        if reply.code != ui_pb2.ERROR:
            return
        title = QC.translate("portscan", "Could not delete {ip}") if forget \
            else QC.translate("portscan", "Could not release {ip}")
        # Message.ok renders rich text; everything from the node is escaped.
        text = QC.translate("portscan", "{node} refused: {error}").format(
            node=escape(node), error=BlockInfoPresenter.detail_text(reply.data))
        if forget and "is not blocked" in reply.data:
            # A daemon that predates deletion ignores "forget" and answers a
            # release of a detection with "not blocked".
            text += QC.translate(
                "portscan", "\n\nThis node's daemon cannot delete a detection; "
                "it needs the version that can.")
        Message.ok(title.format(ip=escape(ip)), text, QtWidgets.QMessageBox.Icon.Warning)

    def _tick(self):
        """Advances the countdown between pushes.

        It also notices a node that has gone quiet. A snapshot older than
        STALE_AFTER is no longer shown; a node that never answered at all is
        most likely running a daemon without port scan detection, and saying
        "No address is blocked." for it would be a claim about a host that
        nothing is watching. Its request is kept, so a node that was only slow
        is shown when it answers; hiding the views releases it.
        """
        now = time.monotonic()
        changed = False
        for addr, asked in list(self._asked.items()):
            last = self._received.get(addr)
            if last is None and now - asked > self.STALE_AFTER and "error" not in self._state.get(addr, {}):
                self._state[addr] = {"error": QC.translate(
                    "portscan", "no answer; this node's daemon may not support"
                    " port scan detection")}
                changed = True
            elif last is not None and now - last > self.STALE_AFTER and "rows" in self._state.get(addr, {}):
                self._state[addr] = {"error": QC.translate(
                    "portscan", "no update for {s} seconds; its blocks are not"
                    " shown").format(s=int(now - last))}
                changed = True
        if changed:
            self.changed.emit()
        else:
            self.ticked.emit()

    # -------------------------------------------------------------- the rows

    def multi_node(self):
        return len(self._connected_nodes()) > 1

    def rows(self, detections=False):
        """Every block from every node that answered, each tagged with its
        node, and with detections, the sources each node reported and does not
        block, most recent first: a block by when it was made, a detection by
        when it was last reported. Listed after the blocks, a scan reported
        after them would be shown below older ones.

        The tag is not decoration: a release has to go back to the node that
        installed the rule, and two nodes can legitimately be blocking the same
        address.
        """
        out = []
        kinds = ("rows", "detections") if detections else ("rows",)
        for kind in kinds:
            for addr in sorted(self._state):
                for row in self._state[addr].get(kind, []):
                    tagged = dict(row)
                    tagged["node"] = addr
                    out.append(tagged)
        # Stable: rows of the same time keep the daemon's order. A daemon that
        # does not send blocked_at has its blocks listed first.
        out.sort(key=self._recency, reverse=True)
        return out

    @staticmethod
    def _recency(row):
        if row.get("kind") == "detection":
            return row.get("last_reported") or 0
        return row.get("blocked_at") or float("inf")

    def can_block(self, node):
        """Whether node said it can install a block: not under the policy
        "never", and with a firewall backend."""
        return self._state.get(node, {}).get("can_block") is True

    def has_history(self):
        """Whether a node that answered keeps a detection history."""
        return any(st.get("history") for st in self._state.values())

    def remaining(self, row):
        """The countdown, decremented locally since the snapshot arrived."""
        since = self._received.get(row["node"])
        elapsed = 0 if since is None else int(time.monotonic() - since)
        return max(0, row["remaining"] - elapsed)

    def expires_text(self, row):
        if row.get("kind") == "detection":
            when = BlockedListPresenter.when_text(row["last_reported"])
            if not when:
                return ""
            return QC.translate("portscan", "detected {when}").format(when=when[:16])
        if row.get("stuck"):
            return BlockedListPresenter.stuck_label()
        return BlockedListPresenter.format_remaining(self.remaining(row))

    def status_text(self, shown, detections=False):
        """The line under the list: a count, or what went wrong, or both.

        shown is the number of rows the list displays; detections, whether it
        displays the detections too.
        """
        errors = [(addr, BlockedListPresenter.status_text(st["error"]))
                  for addr, st in sorted(self._state.items()) if "error" in st]
        if not self._running and not self._state:
            return ""
        if not self._connected_nodes() and not self._state:
            return QC.translate("portscan", "No node is connected.")
        if errors and not shown:
            # Nothing to show AND something went wrong: say what went wrong.
            # An empty list on its own would read as "nothing is blocked",
            # which is a claim about the host that cannot be made when the
            # host's answer could not be read.
            return "\n".join(
                QC.translate("portscan", "{node}: {error}").format(
                    node=node, error=err) for node, err in errors)
        total = sum(st.get("total", 0) for st in self._state.values())
        omitted = sum(st.get("omitted", 0) for st in self._state.values())
        detected = sum(st.get("detections_total", 0) for st in self._state.values()) \
            if detections else 0
        # Nodes asked and not answered yet. Until each has, a count or "No
        # address is blocked." is a claim about hosts that have not spoken.
        waiting = sorted(a for a in self._asked
                         if a not in self._received and "error" not in self._state.get(a, {}))
        if total == 0 and detected == 0 and not errors:
            if waiting:
                return QC.translate("portscan", "Loading...")
            if detections and self.has_history():
                return QC.translate(
                    "portscan", "No address is blocked, and no scan is in the daemon's history.")
            return BlockedListPresenter.empty_label()
        text = BlockedListPresenter.omitted_label(
            min(shown, total), total, omitted) if total or not detections else ""
        if detected:
            more = QC.translate("portscan", "{n} detected and not blocked").format(n=detected)
            text = "{0}; {1}".format(text, more) if text else more
        if errors:
            text += "\n" + "\n".join(
                QC.translate("portscan", "{node}: {error}").format(
                    node=node, error=err) for node, err in errors)
        if waiting:
            text += "\n" + "\n".join(
                QC.translate("portscan", "{node}: loading...").format(node=node)
                for node in waiting)
        return text

    # ------------------------------------------------------------- releasing

    def release(self, node, ip, forget=False):
        """Asks one node to drop one block, or with forget, to remove the
        source from the list: its detection is deleted, and its block
        released if it has one.

        The reply is not awaited: the next snapshot is the confirmation, and it
        arrives within the push interval. A refusal comes back as an ERROR
        reply and is reported by _release_answered -- for instance when
        detection was stopped between the snapshot and the click.
        """
        try:
            noti = ui_pb2.Notification(
                clientName="", serverName="",
                type=ui_pb2.PORTSCAN_UNBLOCK,
                data=PortScanPresenter.unblock_request(ip, forget=forget),
                rules=[])
            self._inflight_release = (node, ip)
            self._inflight_forget = forget
            try:
                nid = self._nodes.send_notification(
                    node, noti, self._notification_callback)
            finally:
                answered = self._inflight_release is None
                self._inflight_release = None
                self._inflight_forget = False
            if not answered:
                self._releases[nid] = (node, ip)
                if forget:
                    self._deleting.add(nid)
        except Exception as e:
            print(self.LOG_TAG, "releasing", ip, "on", node, repr(e))
            title = QC.translate("portscan", "Could not delete {ip}") if forget \
                else QC.translate("portscan", "Could not release {ip}")
            Message.ok(title.format(ip=escape(ip)), escape(str(e)),
                       QtWidgets.QMessageBox.Icon.Warning)

    def delete(self, node, ip):
        """Removes one source from one node's list; see release."""
        self.release(node, ip, forget=True)

    # ------------------------------------------------- blocking after the fact

    def block(self, node, ip, force=False):
        """Asks one node to block a source it reported, after the fact.

        As with release(), the next snapshot is the confirmation: the row
        moves from the detections to the blocks. A refusal comes back as an
        ERROR reply and is reported by _block_answered.
        """
        try:
            noti = ui_pb2.Notification(
                clientName="", serverName="",
                type=ui_pb2.PORTSCAN_BLOCK,
                data=PortScanPresenter.block_request(ip, force=force),
                rules=[])
            self._inflight_block = (node, ip)
            try:
                nid = self._nodes.send_notification(
                    node, noti, self._notification_callback)
            finally:
                answered = self._inflight_block is None
                self._inflight_block = None
            if not answered:
                self._blocks[nid] = (node, ip)
        except Exception as e:
            print(self.LOG_TAG, "blocking", ip, "on", node, repr(e))
            Message.ok(
                QC.translate("portscan", "Could not block {ip}").format(ip=escape(ip)),
                escape(str(e)), QtWidgets.QMessageBox.Icon.Warning)

    def _block_answered(self, target, reply):
        """Reports a refused block; an accepted one shows in the list."""
        node, ip = target
        if reply.code != ui_pb2.ERROR:
            return
        Message.ok(
            QC.translate("portscan", "Could not block {ip}").format(ip=escape(ip)),
            QC.translate("portscan", "{node} refused: {error}").format(
                node=escape(node), error=escape(BlockedListPresenter.status_text(reply.data))),
            QtWidgets.QMessageBox.Icon.Warning)
