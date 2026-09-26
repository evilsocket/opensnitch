#
# pytest -v tests/test_portscan.py
#
# The presenter is the last hop: whatever the daemon reports, this module is
# what the user actually reads. Its label tables are keyed by identifiers the
# daemon defines, in another language, in another directory -- so nothing in
# Python fails when one of them is misspelled or a new one is added. The
# failure is silent by construction: an identifier with no label falls through
# to the raw string, which still renders, still looks deliberate, and is simply
# wrong.
#
# That is not hypothetical. Two labels were added for anomalies under invented
# names ("vlan-depth", "frame-trailer") while the daemon emits
# "vlan-stack-too-deep" and "trailing-bytes-after-payload". The labels existed,
# the commit said the gap was closed, and the user still saw the raw
# identifier. The tables are therefore checked against the daemon's own source
# rather than against a list restated here, which would have been copied with
# the same mistake.
#
import re
from pathlib import Path

import pytest

# Import proto first to avoid circular import issues
import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

import json

from opensnitch.portscan import BlockedListPresenter, BlockInfoPresenter, PortScanPresenter

DAEMON = Path(__file__).resolve().parents[2] / "daemon" / "portscan"
DAEMON_ROOT = DAEMON.parent


def _read(name):
    path = DAEMON / name
    # Deliberately not a skip. A test that quietly does nothing when it cannot
    # find its subject is the same silent failure it exists to catch.
    assert path.is_file(), "cannot find {0}; run the tests from the checkout".format(path)
    return path.read_text(encoding="utf-8")


def daemon_methods():
    """Every value ScanMethod.String() can return, read from the daemon."""
    source = _read("method.go")
    start = source.index("func (m ScanMethod) String() string")
    end = source.index("\n}", start)
    names = set(re.findall(r'return "([a-z0-9-]+)"', source[start:end]))
    # "unknown" is the default arm, not a technique: it is what the daemon
    # reports when it has no name, and the presenter's own fallback covers it.
    names.discard("unknown")
    assert names, "no method identifiers found; did method.go change shape?"
    return names


def daemon_descriptions():
    """ScanMethod.Description() of every method, keyed by its String()."""
    source = _read("method.go")

    def arms(signature):
        start = source.index(signature)
        body = source[start:source.index("\n}", start)]
        return dict(re.findall(r'case (Method[A-Za-z]+):\s*return "([^"]+)"', body))

    names = arms("func (m ScanMethod) String() string")
    texts = arms("func (m ScanMethod) Description() string")
    assert names and set(names) == set(texts), "method.go changed shape"
    return {names[m]: texts[m] for m in names}


def daemon_anomalies():
    """Every identifier AnomalyStrings can return, read from the daemon."""
    source = _read("protocol.go")
    start = source.index("var anomalyNames = []struct")
    end = source.index("\n}", source.index("{", source.index("}{", start)))
    names = set(re.findall(r'\{Anomaly[A-Za-z]+, "([a-z0-9-]+)"\}', source[start:end]))
    assert names, "no anomaly identifiers found; did protocol.go change shape?"
    return names


def go_json_tags(path, struct):
    """The json tags of one Go struct, read from its source."""
    p = DAEMON_ROOT / path
    assert p.is_file(), "cannot find {0}".format(p)
    source = p.read_text(encoding="utf-8")
    start = source.index("type {0} struct {{".format(struct))
    end = source.index("\n}", start)
    tags = re.findall(r'json:"([a-z_]+)', source[start:end])
    assert tags, "no json tags in {0}; did it change shape?".format(struct)
    return tags


class TestTheWireMatchesTheDaemon():
    """Names the GUI and the daemon exchange, checked against the Go source.

    Copied into a test as literals, they agree with the GUI whatever the daemon
    says: renaming the task in Go, or the "ip" key in Python, left both suites
    green while the list of blocks stopped receiving anything and the Block
    button -- the only way to a block under the default policy -- sent a
    payload the daemon refused.
    """

    def test_the_nftables_names_the_view_shows(self):
        # The view tells the user where a block lives, so that it can be found
        # with nft. A name copied wrong would send them looking for a table
        # that does not exist.
        from opensnitch.customwidgets.portscanblocksview import PortScanBlocksView
        source = (DAEMON_ROOT / "portscan" / "blocker_nftables.go").read_text(encoding="utf-8")
        const = dict(re.findall(r'^\s*(nft\w+Name)\s*=\s*"([^"]+)"', source, re.M))
        assert PortScanBlocksView.NFT_TABLE == "inet " + const["nftTableName"]
        assert PortScanBlocksView.NFT_SET_V4 == const["nftSetV4Name"]
        assert PortScanBlocksView.NFT_SET_V6 == const["nftSetV6Name"]
        # And the table is created in the inet family the label names.
        assert "TableFamilyINet" in source

    def test_the_task_name(self):
        source = (DAEMON_ROOT / "tasks" / "portscanblocks" / "main.go").read_text(encoding="utf-8")
        name = re.search(r'const Name = "([^"]+)"', source).group(1)
        assert json.loads(BlockedListPresenter.list_request())["name"] == name

    def test_the_block_and_unblock_keys(self):
        tags = set(go_json_tags("ui/notifications.go", "portScanRequest"))
        for payload in (PortScanPresenter.block_request("192.0.2.1"),
                        PortScanPresenter.block_request("192.0.2.1", dismiss=True),
                        PortScanPresenter.block_request("192.0.2.1", force=True),
                        PortScanPresenter.unblock_request("192.0.2.1")):
            keys = set(json.loads(payload))
            assert keys <= tags, "keys the daemon does not read: {0}".format(keys - tags)
            assert "192.0.2.1" in json.loads(payload).values()

    def test_the_snapshot_keys(self):
        # Every key the presenter reads must be one the daemon writes.
        written = set(go_json_tags("tasks/portscanblocks/main.go", "Blocked"))
        written |= set(go_json_tags("tasks/portscanblocks/main.go", "Snapshot"))
        written |= set(go_json_tags("tasks/portscanblocks/main.go", "Detected"))
        source = (Path(__file__).resolve().parents[1] / "opensnitch" / "portscan.py").read_text(encoding="utf-8")
        start = source.index("class BlockedListPresenter")
        read = set(re.findall(r'(?:snapshot|entry|det)\.get\("([a-z_]+)"', source[start:]))
        assert read, "no keys found in BlockedListPresenter.parse"
        assert read <= written, "keys the daemon never writes: {0}".format(read - written)


class TestLabelTablesMatchTheDaemon():

    def test_every_method_the_daemon_emits_has_a_label(self):
        missing = daemon_methods() - set(PortScanPresenter.METHOD_LABELS)
        assert not missing, (
            "daemon/portscan emits these methods with no label in "
            "METHOD_LABELS, so the raw identifier is shown: "
            + ", ".join(sorted(missing)))

    def test_every_anomaly_the_daemon_emits_has_a_label(self):
        missing = daemon_anomalies() - set(PortScanPresenter.ANOMALY_LABELS)
        assert not missing, (
            "daemon/portscan emits these anomalies with no label in "
            "ANOMALY_LABELS, so the raw identifier is shown: "
            + ", ".join(sorted(missing)))

    def test_no_label_is_keyed_by_something_the_daemon_never_emits(self):
        # The half that catches a misspelling. A missing label and a label
        # under the wrong key look identical to the user -- both show the raw
        # identifier -- but only this direction names the dead entry, which is
        # the one a reader of the table would otherwise trust.
        stale = set(PortScanPresenter.METHOD_LABELS) - daemon_methods()
        assert not stale, (
            "METHOD_LABELS has entries no daemon identifier matches: "
            + ", ".join(sorted(stale)))
        stale = set(PortScanPresenter.ANOMALY_LABELS) - daemon_anomalies()
        assert not stale, (
            "ANOMALY_LABELS has entries no daemon identifier matches: "
            + ", ".join(sorted(stale)))

    def test_the_block_details_show_each_description_whole_on_one_line(self):
        # The details of a block once read "TCP Xmas scan ?nmap -sX?": the
        # alert's allowlist had replaced the parentheses. Each description
        # must reach the dialog unchanged, and start with the method's label
        # so that it is shown once, as the scan type, rather than twice.
        described = daemon_descriptions()
        assert set(described) == daemon_methods()
        for name, description in sorted(described.items()):
            scan = BlockInfoPresenter._scan({"method": name, "method_detail": description})
            rows = BlockInfoPresenter.scan_rows(scan)
            assert rows[0] == ("Scan type", description), name
            assert "Detail" not in [label for label, _ in rows], name


class Scan():
    """A PortScan message with the fields the presenter reads.

    Hand-built rather than a real protobuf so that a test can state one case in
    one line. The fields are exactly those PortScanPresenter touches; a new one
    added to the presenter without being added here fails with AttributeError,
    which is the right outcome.
    """

    def __init__(self, **kw):
        self.method = kw.get("method", "tcp-syn")
        self.src_ip = kw.get("src_ip", "192.0.2.10")
        self.src_mac = kw.get("src_mac", "")
        self.src_mac_is_source_own = kw.get("src_mac_is_source_own", False)
        self.is_protocol_scan = kw.get("is_protocol_scan", False)
        self.protocols = kw.get("protocols", 0)
        self.distinct_ports = kw.get("distinct_ports", 0)
        self.min_port = kw.get("min_port", 0)
        self.max_port = kw.get("max_port", 0)
        self.sample_ports = kw.get("sample_ports", [])
        self.flags_summary = kw.get("flags_summary", "")
        self.anomalies = kw.get("anomalies", [])
        self.interface = kw.get("interface", "")
        self.suppressed_since = kw.get("suppressed_since", 0)
        self.has_tcp_evidence = kw.get("has_tcp_evidence", True)
        self.block_duration_seconds = kw.get("block_duration_seconds", 14400)


class TestTheAlertAUserReads():

    def test_an_icmp_sweep_is_named_and_does_not_claim_ports(self):
        # Three errors in five lines, all in this one case: the raw
        # "icmp-sweep" identifier, a "0 ports probed" measurement of a
        # technique that has no ports, and a missing-evidence line.
        body = PortScanPresenter.body(Scan(method="icmp-sweep"))
        assert "icmp-sweep" not in body
        assert "ICMP" in body
        assert "0 ports" not in body

    def test_an_anomaly_is_named_rather_than_shown_raw(self):
        body = PortScanPresenter.body(
            Scan(anomalies=["vlan-stack-too-deep", "trailing-bytes-after-payload"]))
        assert "vlan-stack-too-deep" not in body
        assert "trailing-bytes-after-payload" not in body

    def test_an_unknown_identifier_is_still_shown(self):
        # Hiding a technique this client does not know about would under-report
        # a real scan, so the fallback is to show it -- bounded and escaped.
        body = PortScanPresenter.body(Scan(method="tcp-invented-tomorrow"))
        assert "tcp-invented-tomorrow" in body

    def test_markup_in_a_field_never_reaches_the_body(self):
        body = PortScanPresenter.body(
            Scan(src_ip="<b>x</b>", flags_summary="<img src=x onerror=1>"))
        assert "<b>" not in body
        assert "<img" not in body

    @pytest.mark.parametrize("ports,expect", [
        (1, False),
        (9, True),
    ])
    def test_a_range_is_given_only_when_there_is_one(self, ports, expect):
        body = PortScanPresenter.body(
            Scan(distinct_ports=ports, min_port=53, max_port=3389))
        assert ("between" in body) == expect


class TestTheBlockAnswer():
    """The daemon's answer to a click on "Block" must reach the user.

    The answer was sent with no callback, so a refusal -- after a
    configuration reload or a restart, once the source's state expired, or
    on an nftables error -- was dropped, and the user believed the source
    blocked.
    """

    def _prompt(self, shown):
        import types
        from opensnitch.nodes import Nodes
        from opensnitch import service
        from opensnitch.notifications import DesktopNotifications
        nodes = Nodes.instance()
        captured = {}

        class FakeNtf:
            def __init__(self, *a):
                self.actions = {}
            def set_urgency(self, u):
                pass
            def set_category(self, c):
                pass
            def add_action(self, aid, label, cb):
                self.actions[aid] = cb
            def show(self):
                captured['ntf'] = self

        fake = types.SimpleNamespace(
            _nodes=nodes,
            _desktop_notifications=types.SimpleNamespace(
                ntf2=types.SimpleNamespace(Notification=FakeNtf)),
            logger=types.SimpleNamespace(warning=lambda *a: None),
            _show_message_trigger=types.SimpleNamespace(
                emit=lambda *a: shown.append(a)),
        )
        fake._port_scan_answer = types.SimpleNamespace(
            emit=lambda addr, reply: service.UIService._on_port_scan_answer(fake, addr, reply))
        scan = ui_pb2.PortScan(src_ip="203.0.113.7", block_eligible=True, distinct_ports=100)
        node = "unix:/tmp/osui.sock"
        service.UIService._show_port_scan_prompt(fake, node, scan, "t", "b")
        return nodes, node, captured['ntf'], DesktopNotifications

    @staticmethod
    def _stream(node):
        """The address a daemon's reply comes with on its stream: the node's
        key without its protocol. A reply under the full key would only take
        the shortcut kept for a node that is not connected."""
        return node.split(":", 1)[1]

    def _click(self, nodes, node, ntf, action):
        before = set(nodes._notifications_sent)
        ntf.actions[action](None, action)
        new = set(nodes._notifications_sent) - before
        assert len(new) == 1
        nodes._nodes[node]['notifications'].get_nowait()
        return new.pop()

    def test_a_refused_block_is_shown(self, qapp):
        shown = []
        nodes, node, ntf, dn = self._prompt(shown)
        nid = self._click(nodes, node, ntf, dn.ACTION_ID_DROP)
        nodes.reply_notification(self._stream(node), ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR,
            data="portscan: 203.0.113.7 was never reported as scanning; refusing"))
        assert len(shown) == 1
        assert "203.0.113.7" in shown[0][0] + shown[0][1]
        assert "never reported" in shown[0][1]

    def test_an_applied_block_says_nothing_more(self, qapp):
        shown = []
        nodes, node, ntf, dn = self._prompt(shown)
        nid = self._click(nodes, node, ntf, dn.ACTION_ID_DROP)
        nodes.reply_notification(self._stream(node), ui_pb2.NotificationReply(id=nid, code=ui_pb2.OK))
        assert shown == []

    def test_the_whole_reason_is_shown(self, qapp):
        # The alert's 64 characters cut the daemon's sentence, and an IPv6
        # address with it.
        shown = []
        nodes, node, ntf, dn = self._prompt(shown)
        nid = self._click(nodes, node, ntf, dn.ACTION_ID_DROP)
        reason = ("portscan: refusing to block an exempt address: "
                  "2001:db8:1234:5678:9abc:def0:1234:5678")
        nodes.reply_notification(self._stream(node), ui_pb2.NotificationReply(
            id=nid, code=ui_pb2.ERROR, data=reason + " <b>x</b>"))
        assert reason in shown[0][1]
        assert "<" not in shown[0][1]

    def test_another_node_cannot_answer_for_the_node_asked(self, qapp):
        # The id is a timestamp: another node answering OK first consumed it,
        # and the real refusal was never shown.
        from queue import Queue
        from tests.dialogs import ClientConfig
        shown = []
        nodes, node, ntf, dn = self._prompt(shown)
        other = "unix:/tmp/second.sock"
        nodes._nodes[other] = {'data': ClientConfig, 'notifications': Queue(), 'online': True}
        try:
            nid = self._click(nodes, node, ntf, dn.ACTION_ID_DROP)
            nodes.reply_notification(other.split(":", 1)[1], ui_pb2.NotificationReply(
                id=nid, code=ui_pb2.OK))
            nodes.reply_notification(self._stream(node), ui_pb2.NotificationReply(
                id=nid, code=ui_pb2.ERROR, data="genuine refusal"))
            assert len(shown) == 1 and "genuine refusal" in shown[0][1]
        finally:
            nodes._nodes.pop(other, None)


class TestTheDetections():
    """The detections of a snapshot came off a socket like the blocks: what
    cannot be read is dropped, not shown as something it is not."""

    def test_a_snapshot_without_detections_is_a_daemon_without_history(self):
        snap = BlockedListPresenter.parse_snapshot(json.dumps({"blocks": [], "total": 0, "omitted": 0}))
        assert snap["history"] is False and snap["detections"] == [] and snap["can_block"] is False

    def test_what_cannot_be_read_is_dropped(self):
        snap = BlockedListPresenter.parse_snapshot(json.dumps({
            "blocks": [], "total": 0, "omitted": 0, "can_block": 1,
            "detections": [
                "nonsense",
                {"addr": "fe80::1%<a href=x>"},
                {"addr": "192.0.2.5", "method": 7, "status": ["x"], "eligible": "yes",
                 "exempt": 1, "last_reported": True, "reason": "<b>bold</b>"},
            ]}))
        assert snap["history"] is True and snap["can_block"] is False
        [d] = snap["detections"]
        assert d["ip"] == "192.0.2.5"
        assert d["eligible"] is False and d["exempt"] is False
        assert d["last_reported"] == 0 and d["status"] == ""
        assert "<" not in d["reason"] and ">" not in d["reason"]

    def test_the_scan_type_keeps_its_parentheses(self):
        snap = BlockedListPresenter.parse_snapshot(json.dumps({"blocks": [
            {"addr": "192.0.2.6", "reason": "TCP Xmas scan (equivalent to nmap -sX)", "remaining": 1}],
            "detections": [{"addr": "192.0.2.7", "method": "tcp-ack",
                            "method_detail": "TCP ACK/Window scan (equivalent to nmap -sA or -sW, which are identical on the wire)"}]}))
        assert snap["rows"][0]["reason"] == "TCP Xmas scan (equivalent to nmap -sX)"
        assert snap["detections"][0]["scan_type"].endswith("identical on the wire)")

    def test_a_description_that_does_not_match_the_method_is_not_shown_as_its_type(self):
        # A node that sends a description under another method's name: the
        # type shown is the method's own label.
        [d] = BlockedListPresenter.parse_snapshot(json.dumps({"blocks": [], "detections": [
            {"addr": "192.0.2.8", "method": "tcp-syn", "method_detail": "Nothing to worry about"}]}))["detections"]
        assert d["scan_type"] == "TCP SYN scan"

    def test_every_status_the_daemon_sends_has_a_label(self):
        source = (DAEMON / "history.go").read_text(encoding="utf-8")
        start = source.index("func (s DetectionStatus) String() string")
        sent = set(re.findall(r'return "([a-z]+)"', source[start:source.index("\n}", start)]))
        sent.discard("unknown")
        # "ended" is the user interface conversion of a block that ended.
        sent.add("ended")
        assert sent - {"blocked"} == set(BlockedListPresenter.STATUS_LABELS), (
            "statuses without a label, or labels without a status")


class TestTheDetectionBounds():
    """Bounds a hostile node runs into."""

    def test_the_detail_is_bounded(self):
        assert len(BlockInfoPresenter.detail_text("x" * 1000)) == BlockInfoPresenter.MAX_DETAIL

    def test_an_unknown_status_is_cleaned(self):
        label = BlockedListPresenter.status_label("<b>owned</b>")
        assert "<" not in label and ">" not in label

    def test_the_detections_are_bounded_and_counted(self):
        dets = [{"addr": "10.0.{0}.{1}".format(i // 256, i % 256)} for i in range(600)]
        snap = BlockedListPresenter.parse_snapshot(json.dumps(
            {"blocks": [], "detections": dets, "detections_total": 3}))
        assert len(snap["detections"]) == BlockedListPresenter.MAX_ROWS
        assert snap["detections_total"] >= len(snap["detections"])

    def test_times_out_of_range_are_dropped(self):
        for bad in (-5, 10**20, 1e300, True, "2026"):
            [d] = BlockedListPresenter.parse_snapshot(json.dumps(
                {"blocks": [], "detections": [{"addr": "192.0.2.1", "last_reported": bad}]}))["detections"]
            assert d["last_reported"] == 0, bad


class TestTheFlags():
    """The compact flags_summary of the daemon, read for the user: "??r?a?ec"
    after an -sS then an -sX was reported as unreadable."""

    def test_a_constant_combination_is_named(self):
        assert PortScanPresenter.flags_text("fSrpauec") == "SYN"
        assert PortScanPresenter.flags_text("FsrPaUec") == "FIN, PSH, URG"
        assert PortScanPresenter.flags_text("fsrpauec") == "none (NULL)"

    def test_varying_flags_are_said_to_vary(self):
        assert PortScanPresenter.flags_text("??r?a?ec") == (
            "FIN, SYN, PSH, URG, varying from probe to probe")
        assert PortScanPresenter.flags_text("??rpAuec") == (
            "ACK on every probe; FIN, SYN, varying from probe to probe")

    def test_another_form_is_shown_cleaned(self):
        assert PortScanPresenter.flags_text("******S*") == "******S*".replace("*", "?")
        assert "<" not in PortScanPresenter.flags_text("<img src=x>")
        assert PortScanPresenter.flags_text(None) == ""

    def test_the_alert_and_the_details_read_them(self):
        scan = Scan(flags_summary="??r?a?ec", distinct_ports=3, min_port=1, max_port=3)
        assert "TCP flags: FIN, SYN, PSH, URG, varying" in PortScanPresenter.body(scan)
        details = BlockInfoPresenter._scan({"method": "tcp-mixed-flags", "flags_summary": "??r?a?ec"})
        rows = dict(BlockInfoPresenter.scan_rows(details))
        assert rows["TCP flags"].startswith("FIN, SYN, PSH, URG, varying")

    def test_a_custom_combination_keeps_its_bars(self):
        assert BlockInfoPresenter.detail_text("TCP scan with flags SYN|ACK (0x12)") == (
            "TCP scan with flags SYN|ACK (0x12)")
