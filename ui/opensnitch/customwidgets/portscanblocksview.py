"""A view of the blocked port scan sources, with the means to release one,
and of the sources detected and not blocked, with the means to block one.

The main window shows it twice: as the Port scan Detection tab, with the
detections, and in the Rules tab, under "Port scan blocks", with the blocks
only, next to the application rules and the system firewall rules. Both
instances render from the same BlockedSources object
(dialogs/events/tasks/portscanblocks.py), which holds the one stream the
daemon allows; a view only says when it is visible, so that the stream runs
while someone is looking and not otherwise.

A block is not an OpenSnitch rule. It is an element, with a timeout, of a set
in a table of its own that the daemon manages (see daemon/portscan/
blocker_nftables.go): it is not saved anywhere, it goes when it expires, and
the daemon deletes the whole table when it stops -- or, after a crash, when it
starts again. This view is where a block can be seen.
"""

import time
from html import escape

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.portscan import BlockedListPresenter, BlockInfoPresenter
from opensnitch.utils import Icons, Message


class PortScanBlocksView(QtWidgets.QWidget):

    COL_NODE = 0
    COL_ADDR = 1
    COL_STATUS = 2
    COL_REASON = 3
    COL_EXPIRES = 4

    # Where the daemon enforces a block. Checked against the daemon's
    # constants by tests/test_portscan.py, so a rename cannot leave the view
    # pointing the user at a table that does not exist.
    NFT_TABLE = "inet opensnitch-portscan"
    NFT_SET_V4 = "portscan_sources_v4"
    NFT_SET_V6 = "portscan_sources_v6"

    def __init__(self, feed, parent=None, detections=True):
        QtWidgets.QWidget.__init__(self, parent)
        self._feed = feed
        # Whether the view lists the sources detected and not blocked. The
        # Rules tab lists what the firewall enforces, so blocks only.
        self._detections = detections
        self._filter = ""
        # The rows on screen, by (node, address): the kind of a row decides
        # what can be done with it.
        self._shown = {}
        # Open details dialogs. They delete themselves on close; the reference
        # only keeps them from being collected while open.
        self._dialogs = set()
        self._build()
        # A push re-renders the table, coalesced: a node can answer on its
        # stream as often as it likes, and a table of a thousand rows rebuilt
        # per answer would freeze the GUI at a few answers a second. The first push
        # after a quiet spell is shown at once, the rest at most every
        # RENDER_INTERVAL_MS; a view not on screen renders when shown.
        self._last_render = 0.0
        self._render_timer = QtCore.QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.timeout.connect(self._render)
        self._feed.changed.connect(self._render_soon)
        self._feed.ticked.connect(self._tick)

    # ------------------------------------------------------------------ setup

    def _build(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        intro = QC.translate(
            "portscan",
            "Addresses blocked because a port scan was detected from them. All "
            "inbound traffic from them is dropped by the daemon, in the "
            "nftables table {table} (sets {v4} and {v6}). A block is not an "
            "OpenSnitch rule and is not saved: it expires on its own, and the "
            "daemon removes every block when it stops or starts. Release "
            "removes one early. Double-click a block for the scan that caused "
            "it; right-click it to see its nftables rule.").format(
                table=self.NFT_TABLE, v4=self.NFT_SET_V4, v6=self.NFT_SET_V6)
        if self._detections:
            intro += " " + QC.translate(
                "portscan",
                "With the blocks, most recent first, the sources detected and "
                "not blocked (no answer, ignored, refused, or a block that "
                "ended), which the daemon keeps for a while: a scan is often "
                "only the first step of an attack. Block blocks one now.")
        self.lblIntro = QtWidgets.QLabel(intro)
        self.lblIntro.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.lblIntro.setWordWrap(True)
        layout.addWidget(self.lblIntro)

        self.table = QtWidgets.QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels([
            QC.translate("portscan", "Node"),
            QC.translate("portscan", "Address"),
            QC.translate("portscan", "Status"),
            QC.translate("portscan", "Scan or reason") if self._detections
            else QC.translate("portscan", "Blocked because"),
            QC.translate("portscan", "Expires in / detected") if self._detections
            else QC.translate("portscan", "Expires in"),
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        # Read-only: the cells are a report, not a form. An editable table
        # would let a user retype an address and then press Release on it.
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(
            self.COL_REASON, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._cb_context_menu)
        self.table.cellDoubleClicked.connect(self._cb_double_clicked)
        self.table.installEventFilter(self)
        layout.addWidget(self.table)

        bottom = QtWidgets.QHBoxLayout()
        self.lblStatus = QtWidgets.QLabel("")
        # Plain text: the line carries the daemon's own words.
        self.lblStatus.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.lblStatus.setWordWrap(True)
        bottom.addWidget(self.lblStatus, 1)
        self.cmdRelease = QtWidgets.QPushButton(
            QC.translate("portscan", "Release"))
        self.cmdRelease.setToolTip(QC.translate(
            "portscan",
            "Remove the block on the selected addresses now, instead of "
            "waiting for it to expire."))
        self.cmdRelease.setEnabled(False)
        self.cmdRelease.clicked.connect(self._cb_release_clicked)
        try:
            self.cmdRelease.setIcon(Icons.new(self, "edit-delete"))
        except Exception:
            # An icon theme that lacks the name must not cost the button.
            pass
        bottom.addWidget(self.cmdRelease)
        self.cmdBlock = QtWidgets.QPushButton(QC.translate("portscan", "Block"))
        self.cmdBlock.setToolTip(QC.translate(
            "portscan",
            "Block the selected sources now, for the node's block duration."))
        self.cmdBlock.setEnabled(False)
        self.cmdBlock.clicked.connect(self._cb_block_clicked)
        self.cmdBlock.setVisible(self._detections)
        bottom.addWidget(self.cmdBlock)
        layout.addLayout(bottom)

    # ------------------------------------------------------------ visibility

    def showEvent(self, event):
        QtWidgets.QWidget.showEvent(self, event)
        self._feed.attach(self)
        self._render()

    def hideEvent(self, event):
        # A hidden view must not keep a node marshalling its block table every
        # two seconds.
        self._feed.detach(self)
        QtWidgets.QWidget.hideEvent(self, event)

    # -------------------------------------------------------------- filtering

    def set_filter(self, text):
        """Shows only the rows that contain text, in any column.

        Driven by the main window's search line, as the other views are.
        """
        self._filter = (text or "").strip().lower()
        self._render()

    def _matches(self, row):
        if not self._filter:
            return True
        hay = " ".join((row["node"], row["addr"], self._status_text(row),
                        self._reason_text(row))).lower()
        return self._filter in hay

    @staticmethod
    def _status_text(row):
        if row.get("kind") == "detection":
            return BlockedListPresenter.status_label(row["status"])
        return BlockedListPresenter.blocked_label()

    @staticmethod
    def _reason_text(row):
        if row.get("kind") != "detection":
            return row["reason"]
        if row["reason"]:
            return "{0}; {1}".format(row["scan_type"], row["reason"])
        return row["scan_type"]

    # -------------------------------------------------------------- the table

    RENDER_INTERVAL_MS = 250

    def _render_soon(self):
        # A view in an inactive tab of a window on screen (the Rules tab's,
        # most of the time) renders when shown.
        if self.window().isVisible() and not self.isVisible():
            return
        if self._render_timer.isActive():
            return
        wait = self._last_render + self.RENDER_INTERVAL_MS / 1000 - time.monotonic()
        if wait <= 0:
            self._render()
        else:
            self._render_timer.start(int(wait * 1000) + 1)

    def _render(self):
        self._render_timer.stop()
        self._last_render = time.monotonic()
        rows = [r for r in self._feed.rows(detections=self._detections) if self._matches(r)]
        self._shown = {(r["node"], r["ip"]): r for r in rows}
        self.table.setColumnHidden(self.COL_NODE, not self._feed.multi_node())

        # Selection is preserved across a push, because a push happens every
        # couple of seconds and rebuilding the table under the user's cursor
        # would make the Release button unusable on a busy host. It is kept
        # by key, not by row number: the selection model counts rows, and left
        # in place it would move to whatever row now sits where a departed one
        # was, for the next Release, Delete or Block to act on. The current
        # row, from which Shift+click and the keyboard extend the selection,
        # is kept by key for the same reason.
        selected = self._selected_keys()
        current = self._key_at(self.table.currentRow())
        # Where the user has scrolled to is kept too: a push every two seconds
        # must not pull a long list back to its current row.
        scroll = self.table.verticalScrollBar().value()
        self.table.clearSelection()
        self.table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            self._set_cell(i, self.COL_NODE, row["node"])
            self._set_cell(i, self.COL_ADDR, row["addr"], data=row)
            self._set_cell(i, self.COL_STATUS, self._status_text(row))
            self._set_cell(i, self.COL_REASON, self._reason_text(row))
            self._set_cell(i, self.COL_EXPIRES, self._feed.expires_text(row))
        self.table.resizeColumnToContents(self.COL_ADDR)
        self.table.resizeColumnToContents(self.COL_STATUS)
        self.table.resizeColumnToContents(self.COL_EXPIRES)
        self._restore_selection(selected, current)
        self.table.verticalScrollBar().setValue(scroll)
        self.lblStatus.setText(self._feed.status_text(len(rows), detections=self._detections))
        self._update_buttons()

    def _set_cell(self, row, col, text, data=None):
        item = QtWidgets.QTableWidgetItem(text)
        if data is not None:
            item.setData(QtCore.Qt.ItemDataRole.UserRole, (data["node"], data["ip"]))
        self.table.setItem(row, col, item)

    def _tick(self):
        """Refreshes the countdown column without rebuilding the table."""
        by_key = {(row["node"], row["ip"]): row for row in self._feed.rows()
                  if row.get("kind") != "detection"}
        for i in range(self.table.rowCount()):
            item = self.table.item(i, self.COL_ADDR)
            expires = self.table.item(i, self.COL_EXPIRES)
            if item is None or expires is None:
                continue
            key = item.data(QtCore.Qt.ItemDataRole.UserRole)
            row = None if key is None else by_key.get(tuple(key))
            if row is not None:
                expires.setText(self._feed.expires_text(row))

    def _selected_keys(self):
        keys = set()
        for item in self.table.selectedItems():
            if item.column() != self.COL_ADDR:
                continue
            key = item.data(QtCore.Qt.ItemDataRole.UserRole)
            if key is not None:
                keys.add(tuple(key))
        return keys

    def _restore_selection(self, keys, current):
        # One selection, applied once: each select() call signals a change,
        # and every change re-reads the whole selection, so row by row a
        # large selection would cost the square of its size on every push.
        selection = QtCore.QItemSelection()
        current_index = QtCore.QModelIndex()
        model = self.table.model()
        for i in range(self.table.rowCount()):
            item = self.table.item(i, self.COL_ADDR)
            if item is None:
                continue
            key = item.data(QtCore.Qt.ItemDataRole.UserRole)
            if key is None:
                continue
            key = tuple(key)
            if key in keys:
                index = model.index(i, self.COL_ADDR)
                selection.select(index, index)
            if key == current:
                current_index = model.index(i, self.COL_ADDR)
        flags = QtCore.QItemSelectionModel.SelectionFlag
        sm = self.table.selectionModel()
        # Without autoscroll: moving the current row must not move the view.
        autoscroll = self.table.hasAutoScroll()
        self.table.setAutoScroll(False)
        sm.setCurrentIndex(current_index, flags.NoUpdate)
        self.table.setAutoScroll(autoscroll)
        if not selection.isEmpty():
            sm.select(selection, flags.Select | flags.Rows)

    def _update_buttons(self):
        self.cmdRelease.setEnabled(bool(self._release_targets()))
        self.cmdBlock.setEnabled(bool(self._block_targets()))

    def _kind(self, key):
        row = self._shown.get(key)
        return None if row is None else row.get("kind", "block")

    def _release_targets(self):
        return sorted(k for k in self._selected_keys() if self._kind(k) == "block")

    def _delete_targets(self):
        """The selected rows, blocks and detections alike, where the view
        lists detections: the Rules tab lists what the firewall enforces."""
        if not self._detections:
            return []
        return sorted(k for k in self._selected_keys() if self._kind(k) is not None)

    def _block_targets(self):
        """The selected detections the node can block: not exempt, and on a
        node that can install a block at all."""
        out = []
        for key in sorted(self._selected_keys()):
            row = self._shown.get(key)
            if row is None or row.get("kind") != "detection":
                continue
            if row["exempt"] or not self._feed.can_block(key[0]):
                continue
            out.append(key)
        return out

    # ---------------------------------------------------- keys and the menu

    def eventFilter(self, source, event):
        if source is self.table and event.type() == QtCore.QEvent.Type.KeyPress:
            if event.matches(QtGui.QKeySequence.StandardKey.Copy):
                self.copy_selected_rows()
                return True
            if event.key() == QtCore.Qt.Key.Key_Delete:
                # As for a rule in the Rules tab, Delete removes the row; where
                # the view lists blocks only, it releases them, as Release does.
                if self._detections:
                    self._cb_delete_clicked()
                else:
                    self._cb_release_clicked()
                return True
        return QtWidgets.QWidget.eventFilter(self, source, event)

    def _cb_context_menu(self, pos):
        if not self._selected_keys():
            return
        menu = QtWidgets.QMenu(self)
        # The details are of the row under the cursor, one row at a time.
        key = self._key_at(self.table.rowAt(pos.y()))
        details = rule = block = release = delete = None
        if key is not None:
            details = menu.addAction(QC.translate("portscan", "Details"))
            if self._kind(key) == "block":
                # A detection not blocked has no rule to show.
                rule = menu.addAction(QC.translate("portscan", "Show nftables rule"))
            menu.addSeparator()
        if self._block_targets():
            block = menu.addAction(QC.translate("portscan", "Block"))
        if self._release_targets():
            release = menu.addAction(QC.translate("portscan", "Release"))
        if self._delete_targets():
            delete = menu.addAction(QC.translate("portscan", "Delete"))
        copy = menu.addAction(QC.translate("portscan", "Copy"))
        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action is None:
            return
        if action == details:
            self.show_details(key, PortScanBlockDialog.TAB_SCAN)
        elif action == rule:
            self.show_details(key, PortScanBlockDialog.TAB_FIREWALL)
        elif action == release:
            self._cb_release_clicked()
        elif action == delete:
            self._cb_delete_clicked()
        elif action == block:
            self._cb_block_clicked()
        elif action == copy:
            self.copy_selected_rows()

    def _key_at(self, row):
        if row < 0:
            return None
        item = self.table.item(row, self.COL_ADDR)
        key = None if item is None else item.data(QtCore.Qt.ItemDataRole.UserRole)
        return None if key is None else tuple(key)

    def _cb_double_clicked(self, row, _col):
        key = self._key_at(row)
        if key is not None:
            self.show_details(key, PortScanBlockDialog.TAB_SCAN)

    def show_details(self, key, tab):
        """Opens the details of one row, on the given tab."""
        node, ip = key
        # Block from the details only where the view lists detections: the
        # Rules tab lists what the firewall enforces.
        dialog = PortScanBlockDialog(self._feed, node, ip, tab, self,
                                     on_block=self._block_from_dialog if self._detections else None)
        self._dialogs.add(dialog)
        dialog.destroyed.connect(lambda _=None, d=dialog: self._dialogs.discard(d))
        dialog.show()
        return dialog

    def copy_selected_rows(self):
        """Copies the selected rows to the clipboard, one per line."""
        rows = sorted({i.row() for i in self.table.selectedItems()})
        cols = [c for c in range(self.table.columnCount())
                if not self.table.isColumnHidden(c)]
        lines = []
        for r in rows:
            cells = []
            for c in cols:
                item = self.table.item(r, c)
                cells.append("" if item is None else item.text())
            lines.append("\t".join(cells))
        QtWidgets.QApplication.clipboard().setText("\n".join(lines))

    # ------------------------------------------------------------- releasing

    def _cb_release_clicked(self):
        targets = self._release_targets()
        if not targets:
            return
        listed = "\n".join("{0}  ({1})".format(ip, node) for node, ip in targets)
        answer = Message.yes_no(
            QC.translate("portscan", "Release these blocks?"),
            QC.translate(
                "portscan",
                "The firewall will accept traffic from these addresses again:\n\n"
                "{list}\n\n"
                "The scan that caused the block is not undone; if it continues, "
                "the source may be blocked again.").format(list=listed),
            QtWidgets.QMessageBox.Icon.Question)
        if answer != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        for node, ip in targets:
            self._feed.release(node, ip)

    def _cb_delete_clicked(self):
        targets = self._delete_targets()
        if not targets:
            return
        # Read from the stream, not from the table, which can be a render
        # behind; read again after the answer, since a push can turn a
        # detection into a block while the dialog is open.
        kinds = self._current_kinds()
        blocked = {k for k in targets if kinds.get(k) == "block"}
        listed = "\n".join(
            "{0}  ({1}){2}".format(ip, node, QC.translate("portscan", ", blocked")
                                   if (node, ip) in blocked else "")
            for node, ip in targets)
        text = QC.translate(
            "portscan",
            "These sources will be removed from the list, with the details of "
            "their scan:\n\n{list}").format(list=listed)
        if blocked:
            text += QC.translate(
                "portscan",
                "\n\nThe blocked ones are released first, as by Release: the "
                "firewall accepts their traffic again, and one that scans again "
                "is detected afresh.")
        if len(blocked) < len(targets):
            text += QC.translate(
                "portscan",
                "\n\nThe daemon still remembers what the others did recently: "
                "one that scans again is reported when it shows something new.")
        answer = Message.yes_no(
            QC.translate("portscan", "Delete these entries?"), text,
            QtWidgets.QMessageBox.Icon.Question)
        if answer != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        kinds = self._current_kinds()
        skipped = []
        for node, ip in targets:
            if kinds.get((node, ip)) == "block" and (node, ip) not in blocked:
                # Blocked while the question was open: deleting it would lift
                # a block the user was not told about.
                skipped.append(ip)
                continue
            self._feed.delete(node, ip)
        if skipped:
            Message.ok(
                QC.translate("portscan", "Not deleted"),
                QC.translate(
                    "portscan",
                    "Blocked while you were confirming, so not deleted: "
                    "{list}").format(list=escape(", ".join(skipped))),
                QtWidgets.QMessageBox.Icon.Information)

    def _current_kinds(self):
        return {(r["node"], r["ip"]): r.get("kind")
                for r in self._feed.rows(detections=True)}


    # -------------------------------------------------------------- blocking

    def _cb_block_clicked(self):
        self.block(self._block_targets())

    def _block_from_dialog(self, key):
        self.block([key])

    def block(self, targets):
        """Asks for confirmation, then asks each node to block its sources.

        A source whose detection is not enough on its own -- nothing arrived
        that only a scanner sends -- is blocked only after a warning that
        names it: its address costs nothing to forge, and blocking a forged
        one cuts the host off from whoever really owns it.
        """
        # What is confirmed is what is sent: the targets, and whether each
        # needs force, are fixed before the question, from the feed rather
        # than from the rows on screen, which a filter may hide. Snapshots
        # keep arriving while the box is open.
        current = {(r["node"], r["ip"]): r for r in self._feed.rows(detections=True)
                   if r.get("kind") == "detection"}
        plan, skipped = [], []
        for key in targets:
            row = current.get(key)
            if row is None:
                skipped.append(QC.translate(
                    "portscan", "{ip}: no longer listed as detected and not blocked").format(ip=key[1]))
            elif row["exempt"]:
                skipped.append(QC.translate(
                    "portscan", "{ip}: on the never-block list").format(ip=key[1]))
            elif not self._feed.can_block(key[0]):
                skipped.append(QC.translate(
                    "portscan", "{ip}: {node} cannot block (policy never, or no firewall)").format(
                        ip=key[1], node=key[0]))
            else:
                plan.append((key[0], key[1], row["eligible"]))
        if not plan:
            if skipped:
                Message.ok(
                    QC.translate("portscan", "Nothing to block"),
                    # Rich text: each line escaped, joined with <br>.
                    "<br>".join(escape(line) for line in skipped),
                    QtWidgets.QMessageBox.Icon.Information)
            return
        weak = [(node, ip) for node, ip, eligible in plan if not eligible]
        listed = "\n".join("{0}  ({1})".format(ip, node) for node, ip, _e in plan)
        text = QC.translate(
            "portscan",
            "The firewall will drop all inbound traffic from these addresses, "
            "for the node's block duration:\n\n{list}").format(list=listed)
        icon = QtWidgets.QMessageBox.Icon.Question
        if weak:
            icon = QtWidgets.QMessageBox.Icon.Warning
            text += "\n\n" + QC.translate(
                "portscan",
                "Warning: nothing arrived from {weak} that only a scanner "
                "sends, and the source address of such traffic costs nothing "
                "to forge. Anyone can make an address look like a scanner, "
                "including one this host depends on (a DNS resolver, a mail or "
                "update server); blocking it would cut the host off from it. "
                "The daemon did not block it for that reason.").format(
                    weak=", ".join(ip for _node, ip in weak))
        answer = Message.yes_no(
            QC.translate("portscan", "Block these sources?"), text, icon)
        if answer != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        for node, ip, eligible in plan:
            self._feed.block(node, ip, force=not eligible)


class PortScanBlockDialog(QtWidgets.QDialog):
    """The details of one block: the scan that led to it, and the nftables
    objects that apply it. Or of one source detected and not blocked: the
    scan, what became of it, and a Block button.

    Both are asked of the node when the dialog opens (BlockedSources.
    request_info), and again on Refresh. The firewall part is read from the
    kernel by the daemon, so it shows what is in force, not what the daemon
    believes it installed.
    """

    TAB_SCAN = 0
    TAB_FIREWALL = 1

    def __init__(self, feed, node, ip, tab=TAB_SCAN, parent=None, on_block=None):
        QtWidgets.QDialog.__init__(self, parent)
        self._feed = feed
        self._node = node
        self._ip = ip
        # Called with (node, ip) when Block is pressed; the view confirms.
        self._on_block = on_block
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(QC.translate("portscan", "Port scan: {ip}").format(ip=ip))
        self.resize(640, 480)
        self._build()
        self.tabs.setCurrentIndex(tab)
        self._feed.info_received.connect(self._cb_info)
        self.refresh()

    def _build(self):
        layout = QtWidgets.QVBoxLayout(self)
        self.tabs = QtWidgets.QTabWidget(self)
        layout.addWidget(self.tabs)

        scan_page = QtWidgets.QWidget()
        scan_layout = QtWidgets.QVBoxLayout(scan_page)
        self.form = QtWidgets.QFormLayout()
        scan_layout.addLayout(self.form)
        scan_layout.addStretch(1)
        self.tabs.addTab(scan_page, QC.translate("portscan", "Scan"))

        fw_page = QtWidgets.QWidget()
        fw_layout = QtWidgets.QVBoxLayout(fw_page)
        self.lblFirewall = QtWidgets.QLabel(QC.translate(
            "portscan",
            "Read from the kernel by the daemon of {node}: what "
            "\"nft list table {table}\" shows for this address.").format(
                node=self._node, table=PortScanBlocksView.NFT_TABLE))
        self.lblFirewall.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.lblFirewall.setWordWrap(True)
        fw_layout.addWidget(self.lblFirewall)
        self.txtFirewall = QtWidgets.QPlainTextEdit()
        self.txtFirewall.setReadOnly(True)
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        font.setStyleHint(QtGui.QFont.StyleHint.Monospace)
        font.setFixedPitch(True)
        self.txtFirewall.setFont(font)
        # nft indents with tabs; at the default width they are eight spaces
        # of a proportional font, far wider than in a terminal.
        self.txtFirewall.setTabStopDistance(
            4 * QtGui.QFontMetricsF(font).horizontalAdvance(" "))
        self.txtFirewall.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        fw_layout.addWidget(self.txtFirewall)
        # The two countdowns differ, and a user comparing them would take one
        # for wrong. The margin is the daemon's to choose, so it is not stated.
        self.lblExpiry = QtWidgets.QLabel(QC.translate(
            "portscan",
            "The kernel's \"expires\" is later than the end of the block on "
            "purpose: OpenSnitch removes the address when the block ends, and "
            "the kernel's own timeout removes it only if the daemon was "
            "stopped without doing so."))
        self.lblExpiry.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.lblExpiry.setWordWrap(True)
        fw_layout.addWidget(self.lblExpiry)
        self.tabs.addTab(fw_page, QC.translate("portscan", "nftables rule"))

        bottom = QtWidgets.QHBoxLayout()
        self.lblStatus = QtWidgets.QLabel("")
        self.lblStatus.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.lblStatus.setWordWrap(True)
        bottom.addWidget(self.lblStatus, 1)
        self.cmdBlock = QtWidgets.QPushButton(QC.translate("portscan", "Block"))
        self.cmdBlock.clicked.connect(self._cb_block)
        self.cmdBlock.setVisible(False)
        bottom.addWidget(self.cmdBlock)
        self.cmdRefresh = QtWidgets.QPushButton(QC.translate("portscan", "Refresh"))
        self.cmdRefresh.clicked.connect(self.refresh)
        bottom.addWidget(self.cmdRefresh)
        self.cmdClose = QtWidgets.QPushButton(QC.translate("portscan", "Close"))
        self.cmdClose.clicked.connect(self.close)
        bottom.addWidget(self.cmdClose)
        layout.addLayout(bottom)

    def refresh(self):
        self.lblStatus.setText(QC.translate("portscan", "Loading..."))
        self._feed.request_info(self._node, self._ip)

    def _clear_form(self):
        while self.form.rowCount():
            self.form.removeRow(0)

    def _add_row(self, label, value):
        text = QtWidgets.QLabel(value)
        # Plain text: every value came from the node.
        text.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        text.setWordWrap(True)
        text.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
        name = QtWidgets.QLabel(label)
        name.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.form.addRow(name, text)

    @QtCore.pyqtSlot(str, str, object)
    def _cb_info(self, node, ip, result):
        if node != self._node or ip != self._ip:
            return
        if "error" in result:
            self.lblStatus.setText(QC.translate("portscan", "{node}: {error}").format(
                node=node, error=result["error"]))
            return
        self.lblStatus.setText("")
        self._clear_form()
        self._add_row(QC.translate("portscan", "Node"), node)
        self._add_row(QC.translate("portscan", "Source address"), result["addr"])
        det = result.get("detection")
        if det is not None:
            self._add_row(QC.translate("portscan", "Status"),
                          BlockedListPresenter.status_label(det["status"]))
            if det["reason"]:
                self._add_row(QC.translate("portscan", "Not blocked because"), det["reason"])
            if det["exempt"]:
                self._add_row(QC.translate("portscan", "Blocking"), QC.translate(
                    "portscan", "not possible: the address is on the never-block list"))
            elif not det["eligible"]:
                self._add_row(QC.translate("portscan", "Blocking"), QC.translate(
                    "portscan", "possible after a warning: nothing arrived that only a "
                    "scanner sends, so the source address may be forged"))
        else:
            self._add_row(QC.translate("portscan", "Blocked because"), result["reason"])
            if result["stuck"]:
                expires = BlockedListPresenter.stuck_label()
            else:
                expires = BlockedListPresenter.format_remaining(result["remaining"])
            self._add_row(QC.translate("portscan", "Expires in"), expires)
        self.cmdBlock.setVisible(
            det is not None and not det["exempt"] and self._on_block is not None
            and self._feed.can_block(node))
        self.lblExpiry.setVisible(det is None)
        if result["scan"] is None:
            self._add_row(QC.translate("portscan", "Scan"), QC.translate(
                "portscan", "the daemon has no details of the scan behind this block"))
        else:
            for label, value in BlockInfoPresenter.scan_rows(result["scan"]):
                self._add_row(label, value)
        if result["firewall"]:
            self.txtFirewall.setPlainText(result["firewall"])
        elif det is not None:
            self.txtFirewall.setPlainText(QC.translate(
                "portscan", "This address is not blocked: there is no nftables rule for it."))
        else:
            self.txtFirewall.setPlainText(QC.translate(
                "portscan", "The firewall rule could not be shown: {error}").format(
                    error=result["firewall_error"] or QC.translate("portscan", "no answer")))

    def _cb_block(self):
        if self._on_block is not None:
            self._on_block((self._node, self._ip))
        self.refresh()

    def closeEvent(self, event):
        try:
            self._feed.info_received.disconnect(self._cb_info)
        except (TypeError, RuntimeError):
            pass
        QtWidgets.QDialog.closeEvent(self, event)
