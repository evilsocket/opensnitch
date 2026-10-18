#!/usr/bin/env python3
#
# Checks that a generated ui_pb2.py really carries the port scan additions and
# agrees with the others on the wire.
#
# There are three implementations of this message in the tree -- the Go
# bindings the daemon serialises with, and the two Python generations the GUI
# picks between at import time -- and a mismatch between any two of them shows
# up as a GUI that starts, connects, and silently never displays a scan.
#
# Usage:
#   check_portscan_bindings.py <path-to-ui_pb2.py>            self-check
#   check_portscan_bindings.py <path-to-ui_pb2.py> --write F  emit a fixture
#   check_portscan_bindings.py <path-to-ui_pb2.py> --read F   parse a fixture
#
# The fixture forms are what make this a cross-check: write with one
# implementation, read with another. The daemon can produce one too; see
# run_binding_check.sh.
#
# The module is loaded from an explicit path rather than imported by name, so
# the same script can check either generation without the package's import-time
# version selection getting in the way.

import importlib.util
import sys

# The values the daemon and the GUI must agree on. They are part of the wire
# contract: never repurposed, only added to.
EXPECTED_PORT_SCAN_ALERT = 7
EXPECTED_PORTSCAN_BLOCK = 15
EXPECTED_PORTSCAN_UNBLOCK = 16
EXPECTED_PORTSCAN_BLOCK_INFO = 17


def load(path):
    spec = importlib.util.spec_from_file_location("ui_pb2", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample(ui_pb2):
    """An alert exercising every field the feature added."""
    scan = ui_pb2.PortScan(
        src_ip="2001:db8::66",
        src_mac="02:11:22:33:44:55",
        src_mac_is_source_own=False,
        method="tcp-xmas",
        method_detail="TCP Xmas scan (nmap -sX)",
        flags_summary="**u*p**f",
        distinct_ports=42,
        min_port=1,
        max_port=65535,
        sample_ports=[1, 2, 3, 4, 5],
        protocols=3,
        is_protocol_scan=False,
        score=200,
        interface="eth0",
        targets=["2001:db8::1"],
        anomalies=["ip-fragment"],
        has_tcp_evidence=True,
        block_eligible=True,
        suppressed_since=99,
        block_duration_seconds=14400,
        first_seen_unixnano=1700000000000000000,
        last_seen_unixnano=1700000002000000000,
    )
    return ui_pb2.Alert(what=ui_pb2.Alert.PORT_SCAN, portscan=scan)


def check(ui_pb2, alert):
    """Assert that alert carries what it was built with."""
    assert alert.what == ui_pb2.Alert.PORT_SCAN, alert.what
    p = alert.portscan
    assert p.src_ip == "2001:db8::66", p.src_ip
    assert p.src_mac == "02:11:22:33:44:55", p.src_mac
    # False is the load-bearing value here: the MAC belongs to the last router,
    # not to the source, and a client must be able to tell.
    assert p.src_mac_is_source_own is False, p.src_mac_is_source_own
    assert p.method == "tcp-xmas", p.method
    assert p.method_detail == "TCP Xmas scan (nmap -sX)", p.method_detail
    assert p.flags_summary == "**u*p**f", p.flags_summary
    assert p.distinct_ports == 42, p.distinct_ports
    assert p.min_port == 1, p.min_port
    assert p.max_port == 65535, p.max_port
    assert p.protocols == 3, p.protocols
    assert p.is_protocol_scan is False, p.is_protocol_scan
    assert p.score == 200, p.score
    assert p.interface == "eth0", p.interface
    assert list(p.sample_ports) == [1, 2, 3, 4, 5], list(p.sample_ports)
    assert list(p.targets) == ["2001:db8::1"], list(p.targets)
    assert list(p.anomalies) == ["ip-fragment"], list(p.anomalies)
    assert p.has_tcp_evidence is True
    assert p.block_eligible is True
    assert p.suppressed_since == 99, p.suppressed_since
    assert p.block_duration_seconds == 14400, p.block_duration_seconds
    assert p.first_seen_unixnano == 1700000000000000000
    assert p.last_seen_unixnano == 1700000002000000000, p.last_seen_unixnano


def main(argv):
    if len(argv) < 2:
        print(__doc__ or "usage: check_portscan_bindings.py <ui_pb2.py>", file=sys.stderr)
        return 2

    path = argv[1]
    ui_pb2 = load(path)

    # The enum values are checked before anything else: a mismatch here means
    # the daemon and the GUI disagree about what an alert even is.
    for name, want in (
        ("Alert.PORT_SCAN", EXPECTED_PORT_SCAN_ALERT),
        ("PORTSCAN_BLOCK", EXPECTED_PORTSCAN_BLOCK),
        ("PORTSCAN_UNBLOCK", EXPECTED_PORTSCAN_UNBLOCK),
        ("PORTSCAN_BLOCK_INFO", EXPECTED_PORTSCAN_BLOCK_INFO),
    ):
        got = ui_pb2.Alert.PORT_SCAN if name.startswith("Alert.") else getattr(ui_pb2, name)
        if got != want:
            print("FAIL: %s = %s, want %s" % (name, got, want), file=sys.stderr)
            return 1

    if len(argv) >= 4 and argv[2] == "--write":
        with open(argv[3], "wb") as fh:
            fh.write(sample(ui_pb2).SerializeToString())
        print("wrote %s" % argv[3])
        return 0

    if len(argv) >= 4 and argv[2] == "--read":
        alert = ui_pb2.Alert()
        with open(argv[3], "rb") as fh:
            alert.ParseFromString(fh.read())
        check(ui_pb2, alert)
        print("parsed %s with %s" % (argv[3], path))
        return 0

    raw = sample(ui_pb2).SerializeToString()
    alert = ui_pb2.Alert()
    alert.ParseFromString(raw)
    check(ui_pb2, alert)

    import google.protobuf

    print(
        "port scan bindings OK: %s, protobuf runtime %s, %d bytes on the wire"
        % (path, google.protobuf.__version__, len(raw))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
