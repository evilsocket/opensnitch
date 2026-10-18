"""Presentation of inbound port scan alerts.

The daemon does the detecting and owns the firewall; this module only decides
how a scan is shown to the user and turns their answer into a notification
back to the daemon.

Two presentation rules are load-bearing rather than cosmetic, and both exist
because getting them wrong would state something the packets do not support:

  * the source address is never called "the attacker". With nmap -D (decoys),
    nmap -S (spoofing), an idle scan or an FTP bounce, that address belongs to
    an uninvolved third party. It is "the address the packets carried";
  * the MAC address is only presented as the source's own when the daemon says
    it is. Otherwise it belongs to the last router the packets crossed and
    identifies nobody.
"""

import ipaddress
import json
import re
import time
from types import SimpleNamespace
from html import escape

from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.notifications import DesktopNotifications


class PortScanPresenter:
    """Formats port scan alerts and builds the reply the daemon expects."""

    # Bounds on anything taken from the message rather than from a table here.
    #
    # The daemon fills these fields from safe Go types, so a local daemon
    # cannot produce anything hostile. The interface can also be reached over
    # TCP in multi-node mode, and it renders interface names chosen by whoever
    # is root on the reporting host -- so the presentation must not depend on
    # the sender being well behaved.
    #
    # Two things are bounded here. Length: body() concatenates without limit,
    # and a 2 MB alert would produce a 1.4 MB notification body that also goes
    # into the alerts table on disk, once per alert. And markup: the notification
    # body is rendered as markup -- the project documents this itself, and uses
    # <b> in its own connection alerts -- so an unescaped value can forge a line
    # that looks like one the program wrote, in the very window where the user
    # decides whether to block.
    MAX_FIELD = 64
    MAX_ANOMALIES = 8
    MAX_TARGETS = 4
    MAX_BODY = 4096

    # Legitimate values use nothing else. Anything outside this is replaced
    # rather than escaped, so no markup reaches the renderer at all.
    _SAFE = re.compile(r"[^\w .:+/\[\]-]")

    @classmethod
    def _clean(cls, value):
        """Bound and neutralise a value that came from the message."""
        if not value:
            return ""
        text = cls._SAFE.sub("?", str(value))[:cls.MAX_FIELD]
        return escape(text)

    # Values of PortScan.method, as emitted by daemon/portscan. Unknown values
    # are shown verbatim rather than dropped: a client that silently hid a
    # technique it did not recognise would under-report a real scan. Every
    # method the daemon emits needs a label here, or the raw identifier
    # reaches the user.
    METHOD_LABELS = {
        "tcp-syn": QC.translate("portscan", "TCP SYN scan"),
        "tcp-fin": QC.translate("portscan", "TCP FIN scan"),
        "tcp-null": QC.translate("portscan", "TCP NULL scan"),
        "tcp-xmas": QC.translate("portscan", "TCP Xmas scan"),
        "tcp-maimon": QC.translate("portscan", "TCP Maimon scan"),
        "tcp-ack": QC.translate("portscan", "TCP ACK/Window scan"),
        "tcp-syn-fin": QC.translate("portscan", "TCP SYN+FIN scan"),
        "tcp-full-xmas": QC.translate("portscan", "TCP all-flags scan"),
        "tcp-os-fingerprint": QC.translate("portscan", "OS fingerprinting probe"),
        "tcp-custom-flags": QC.translate("portscan", "TCP scan, custom flags"),
        "tcp-mixed-flags": QC.translate("portscan", "TCP scan, several flag combinations"),
        "tcp-fragmented": QC.translate("portscan", "Fragmented TCP scan"),
        "ipv6-extension-evasion": QC.translate(
            "portscan", "Scan hidden behind IPv6 extension headers"),
        "udp": QC.translate("portscan", "UDP scan"),
        "ip-protocol": QC.translate("portscan", "IP protocol scan"),
        "icmp-sweep": QC.translate("portscan", "ICMP host sweep"),
        "mixed": QC.translate("portscan", "Several scan techniques"),
    }

    ANOMALY_LABELS = {
        "ip-fragment": QC.translate("portscan", "IP fragmentation"),
        "ipv6-extension-header-chain": QC.translate(
            "portscan", "over-long IPv6 extension header chain"),
        "truncated-header": QC.translate("portscan", "truncated headers"),
        "syn-without-tcp-options": QC.translate(
            "portscan", "SYN without TCP options (raw packet generator)"),
        # ip-first-fragment is what nmap -f produces, one of the techniques
        # this feature names.
        "ip-first-fragment": QC.translate("portscan", "split across IP fragments"),
        "vlan-stack-too-deep": QC.translate("portscan", "deeply stacked VLAN tags"),
        "trailing-bytes-after-payload": QC.translate(
            "portscan", "extra bytes after the payload"),
    }

    @classmethod
    def method_label(cls, scan):
        known = cls.METHOD_LABELS.get(scan.method)
        if known:
            return known
        # An unknown method is still shown -- hiding a technique this client
        # does not know about would be worse -- but bounded and neutralised.
        return cls._clean(scan.method) or "unknown"

    # The order of daemon/portscan FlagsString: FIN, SYN, RST, PSH, ACK, URG,
    # ECE, CWR, the bit order of the TCP header.
    FLAG_NAMES = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")

    @classmethod
    def flags_text(cls, summary):
        """Reads the daemon's compact flags_summary, one character per bit
        as scanlogd prints them (uppercase: set on every probe, lowercase:
        never set, '?': varied), as a sentence, so that a summary such as
        "??r?a?ec" reads as flags rather than as noise. Anything not in that
        form is shown cleaned, as is."""
        if not isinstance(summary, str):
            return ""
        if len(summary) != len(cls.FLAG_NAMES) or any(
                c not in (n[0].lower(), n[0], "?")
                for c, n in zip(summary, cls.FLAG_NAMES)):
            return cls._clean(summary)
        always = [n for c, n in zip(summary, cls.FLAG_NAMES) if c == n[0]]
        varied = [n for c, n in zip(summary, cls.FLAG_NAMES) if c == "?"]
        if not varied:
            if not always:
                return QC.translate("portscan", "none (NULL)")
            return ", ".join(always)
        text = QC.translate("portscan", "{flags}, varying from probe to probe").format(
            flags=", ".join(varied))
        if always:
            text = QC.translate("portscan", "{flags} on every probe; {rest}").format(
                flags=", ".join(always), rest=text)
        return text

    @classmethod
    def title(cls, scan):
        return QC.translate("portscan", "Port scan detected")

    @classmethod
    def body(cls, scan):
        """Builds the notification body."""
        lines = []
        lines.append(QC.translate("portscan", "{method} from {ip}").format(
            method=cls.method_label(scan), ip=cls._clean(scan.src_ip)))

        if scan.src_mac:
            if scan.src_mac_is_source_own:
                lines.append(QC.translate("portscan", "Hardware address: {mac}").format(
                    mac=cls._clean(scan.src_mac)))
            else:
                # Saying whose address it is matters. Presenting a router's MAC
                # as the scanner's would be an attribution the packets do not
                # support.
                lines.append(QC.translate(
                    "portscan", "Last hop hardware address: {mac} (not the source's own)").format(
                        mac=cls._clean(scan.src_mac)))

        if scan.is_protocol_scan:
            lines.append(QC.translate("portscan", "{n} distinct IP protocols probed").format(
                n=scan.protocols))
        elif not scan.distinct_ports:
            # An ICMP sweep has no ports at all, and saying "0 ports probed"
            # would tell the user nothing while looking like a measurement.
            pass
        else:
            detail = QC.translate("portscan", "{n} ports probed").format(n=scan.distinct_ports)
            if scan.distinct_ports > 1:
                detail += QC.translate("portscan", " between {lo} and {hi}").format(
                    lo=scan.min_port, hi=scan.max_port)
            lines.append(detail)
            if scan.sample_ports:
                sample = ", ".join(str(p) for p in scan.sample_ports[:8])
                if len(scan.sample_ports) < scan.distinct_ports:
                    sample += ", ..."
                lines.append(QC.translate("portscan", "For example: {ports}").format(ports=sample))

        if scan.flags_summary:
            # Cleaned like every other field taken from the wire, and rendered
            # inside the body of the prompt where the user decides whether to
            # block. The daemon builds this string from observed TCP flag
            # bits, so on a single host it cannot contain markup -- but the
            # alert travels to a user interface that may be watching several
            # daemons, and a field is either escaped or it is trusted. This
            # one is not trusted.
            lines.append(QC.translate("portscan", "TCP flags: {flags}").format(
                flags=cls.flags_text(scan.flags_summary)))

        if scan.anomalies:
            labels = [cls.ANOMALY_LABELS.get(a) or cls._clean(a)
                      for a in scan.anomalies[:cls.MAX_ANOMALIES]]
            lines.append(QC.translate("portscan", "Evasion signs: {list}").format(
                list=", ".join(labels)))

        if scan.interface:
            lines.append(QC.translate("portscan", "Interface: {iface}").format(
                iface=cls._clean(scan.interface)))

        if scan.suppressed_since:
            # Without this line the user would believe a single host is
            # scanning them, when a decoy or spoofed-source scan is under way.
            lines.append(QC.translate(
                "portscan",
                "{n} further scan alerts were suppressed to avoid flooding.").format(
                    n=scan.suppressed_since))

        if not scan.has_tcp_evidence:
            # Says what is missing, not what usually causes it: it is shown
            # for a UDP scan, but also for an ACK scan, a Window scan, a
            # Maimon scan, a protocol scan and an ICMP sweep, none of which
            # carry a single UDP datagram.
            lines.append(QC.translate(
                "portscan",
                "No corroborating evidence: nothing arrived that only a scanner "
                "sends, and this kind of source address costs nothing to forge."))

        # One last bound on the whole thing: this string goes to a notification
        # server and into the alerts table, and neither imposes a limit of its
        # own.
        return "\n".join(lines)[:cls.MAX_BODY]

    @staticmethod
    def block_label(scan):
        hours = scan.block_duration_seconds // 3600
        if hours > 0:
            return QC.translate("portscan", "Block {h}h").format(h=hours)
        minutes = max(1, scan.block_duration_seconds // 60)
        return QC.translate("portscan", "Block {m}min").format(m=minutes)

    @staticmethod
    def block_request(ip, dismiss=False, force=False):
        """Builds the JSON payload of a PORTSCAN_BLOCK notification.

        force blocks a source whose detection is not enough on its own; it is
        sent only after the user was warned that the address may be forged.
        """
        request = {"ip": ip, "dismiss": bool(dismiss)}
        if force:
            request["force"] = True
        return json.dumps(request)

    @staticmethod
    def unblock_request(ip, forget=False):
        """Builds the JSON payload of a PORTSCAN_UNBLOCK notification. forget
        also removes the source from the list: its detection is deleted, and
        its block released if it has one."""
        request = {"ip": ip}
        if forget:
            request["forget"] = True
        return json.dumps(request)

    @classmethod
    def urgency(cls, scan, needs_answer):
        """Maps a scan to a notification urgency.

        Only a scan awaiting a decision is critical. Marking every detection
        critical would train the user to dismiss them, which is how a real one
        gets missed.
        """
        if needs_answer:
            return DesktopNotifications.URGENCY_CRITICAL
        return DesktopNotifications.URGENCY_NORMAL

    @staticmethod
    def notifications_enabled():
        return Config.init().getBool(Config.NOTIFICATIONS_ENABLED, True)


class BlockedListPresenter:
    """Turns the daemon's block table into rows a table view can show.

    The daemon pushes this list on a task stream (daemon/tasks/portscanblocks),
    once every couple of seconds, for as long as a view of it is on screen.
    Everything in it came off a socket, so the same two rules that govern the
    alert apply here, for the same reasons:

      * every string is bounded and neutralised before it is displayed. These
        rows are rendered next to a button that removes a firewall rule, which
        is the last place a forged line should be able to appear;
      * the address is validated as an address here, not only by the daemon.
        The daemon re-validates whatever comes back and would refuse a bad one,
        but a row the user cannot act on should never be offered in the first
        place.
    """

    # The daemon already bounds a snapshot (portscanblocks.MaxEntries), so this
    # is the second half of the same bound rather than the only one: a GUI can
    # be pointed at a node it does not control.
    MAX_ROWS = 512

    @staticmethod
    def _address(text):
        """Returns text as a canonical IP address, or None.

        A scope identifier is refused rather than trimmed. The daemon removes
        zones before it blocks anything, so a zoned address has no legitimate
        source; trimming it would validate "fe80::1%<a href=...>" as fe80::1
        and carry the rest, verbatim, into a rich-text message box with
        clickable links. The canonical form is what is displayed and what a
        release sends back.
        """
        if not isinstance(text, str) or "%" in text:
            return None
        try:
            return str(ipaddress.ip_address(text))
        except Exception:
            return None

    # What became of a source the daemon reported and does not block, as
    # daemon/portscan.DetectionStatus names it ("ended" is a block that
    # ended on its own). An unknown status is shown cleaned, as an unknown
    # method is.
    STATUS_LABELS = {
        "detected": QC.translate("portscan", "detected; blocking is off"),
        "asked": QC.translate("portscan", "awaiting your answer"),
        "unanswered": QC.translate("portscan", "not blocked: no answer"),
        "ignored": QC.translate("portscan", "not blocked: ignored"),
        "refused": QC.translate("portscan", "not blocked: refused"),
        "released": QC.translate("portscan", "block released"),
        "ended": QC.translate("portscan", "block ended"),
    }

    @staticmethod
    def blocked_label():
        return QC.translate("portscan", "blocked")

    @classmethod
    def status_label(cls, status):
        return cls.STATUS_LABELS.get(status) or cls._clean(status) or "unknown"

    @classmethod
    def parse_snapshot(cls, data):
        """Decodes one snapshot: the blocks, and the detections not blocked.

        Returns a dict with:
          rows        the blocks, as parse returns them
          total, omitted
          detections  the reported sources not blocked right now, dicts with
                      kind "detection", ip, addr, method, scan_type (the
                      method's description, cleaned), status, reason,
                      first_reported, last_reported, eligible, exempt
          detections_total
          history     False for a daemon that sends no detections: one that
                      predates the history, of which nothing can be said
          unchanged   True when the daemon left the detections out because
                      they are those it sent last on this stream: the caller
                      keeps the previous ones
          can_block   whether the node can install a block at all

        Raises ValueError as parse does.
        """
        snapshot = cls._decode(data)
        rows, total, omitted = cls._blocks(snapshot)
        found = snapshot.get("detections")
        unchanged = found is None and snapshot.get("detections_unchanged") is True
        history = isinstance(found, list) or unchanged
        detections = []
        for det in (found if isinstance(found, list) else [])[:cls.MAX_ROWS]:
            row = cls.detection(det)
            if row is not None:
                detections.append(row)
        return {
            "rows": rows, "total": total, "omitted": omitted,
            "detections": detections,
            "detections_total": max(len(detections), cls._as_int(snapshot.get("detections_total"), len(detections))),
            "history": history,
            "unchanged": unchanged,
            "can_block": snapshot.get("can_block") is True,
        }

    @classmethod
    def detection(cls, det):
        """One detection of the snapshot, or of a details answer, as a row;
        None when it cannot be read."""
        if not isinstance(det, dict):
            return None
        ip = cls._address(det.get("addr"))
        if ip is None:
            return None
        scan = SimpleNamespace(method=det.get("method") if isinstance(det.get("method"), str) else "")
        detail = BlockInfoPresenter.detail_text(det.get("method_detail"))
        label = PortScanPresenter.method_label(scan)
        return {
            "kind": "detection",
            "ip": ip,
            "addr": cls._clean(ip),
            "method": label,
            "scan_type": detail if detail.startswith(label) else label,
            "status": det.get("status") if isinstance(det.get("status"), str) else "",
            "reason": BlockInfoPresenter.detail_text(det.get("reason")),
            "first_reported": cls.unix_time(det.get("first_reported")),
            "last_reported": cls.unix_time(det.get("last_reported")),
            "eligible": det.get("eligible") is True,
            "exempt": det.get("exempt") is True,
        }

    @classmethod
    def parse(cls, data):
        """Decodes the blocks of one snapshot.

        Returns (rows, total, omitted). rows is a list of dicts with:
          ip         the address, verbatim, for the release request
          addr       the address, cleaned, for display
          reason     the daemon's words for why it is blocked, cleaned
          remaining  seconds left as the daemon counted them, an int >= 0
          expires_at Unix seconds, or 0 when the daemon sent none
          stuck      True when the firewall refused to release it

        A malformed snapshot raises ValueError rather than producing an empty
        table: "nothing is blocked" is a statement about the host, and the
        list must not make it on the strength of a message it could not read.
        """
        return cls._blocks(cls._decode(data))

    @staticmethod
    def _decode(data):
        try:
            snapshot = json.loads(data)
        except Exception as e:
            raise ValueError("unreadable block list: {0}".format(e))
        if not isinstance(snapshot, dict):
            raise ValueError("unreadable block list: expected an object")
        return snapshot

    @classmethod
    def _blocks(cls, snapshot):
        blocks = snapshot.get("blocks")
        if blocks is None:
            blocks = []
        if not isinstance(blocks, list):
            raise ValueError("unreadable block list: \"blocks\" is not a list")

        total = cls._as_int(snapshot.get("total"), len(blocks))
        omitted = cls._as_int(snapshot.get("omitted"), 0)

        rows = []
        for entry in blocks[:cls.MAX_ROWS]:
            if not isinstance(entry, dict):
                continue
            ip = cls._address(entry.get("addr"))
            if ip is None:
                # Dropped, and counted as omitted, so the list's own totals
                # stay honest about what it is not showing.
                omitted += 1
                continue
            rows.append({
                "kind": "block",
                "ip": ip,
                "addr": cls._clean(ip),
                # The daemon's reason is often the method's description, a
                # sentence with parentheses: cleaned as the details are.
                "reason": BlockInfoPresenter.detail_text(entry.get("reason")),
                "remaining": max(0, cls._as_int(entry.get("remaining"), 0)),
                "expires_at": cls._as_int(entry.get("expires_at"), 0),
                # When the block was made, to list blocks and detections
                # together; 0 from a daemon that does not send it.
                "blocked_at": cls.unix_time(entry.get("blocked_at")),
                # A block the firewall refused to release: past its expiry
                # and still installed, so not "expiring".
                "stuck": entry.get("stuck") is True,
            })
        if len(blocks) > cls.MAX_ROWS:
            omitted += len(blocks) - cls.MAX_ROWS
        return rows, total, omitted

    # The last second time.localtime can render everywhere (9999-12-31). A
    # node can send any number, and one time_t cannot hold raises
    # OverflowError in a slot, which aborts the whole GUI.
    MAX_UNIX = 253402300799

    @classmethod
    def unix_time(cls, value):
        """Unix seconds from a node, or 0 when absent or out of range."""
        t = cls._as_int(value, 0)
        return t if 0 < t <= cls.MAX_UNIX else 0

    @staticmethod
    def when_text(unix):
        """Local time of Unix seconds, or "" for 0 or what cannot be shown."""
        if not unix:
            return ""
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unix))
        except (OverflowError, OSError, ValueError):
            return ""

    @staticmethod
    def _as_int(value, default):
        # bool is an int in Python, and True would silently become 1.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return default
        try:
            return int(value)
        except Exception:
            return default

    @classmethod
    def _clean(cls, value):
        return PortScanPresenter._clean(value)

    @staticmethod
    def format_remaining(seconds):
        """Renders a countdown.

        Coarse on purpose. The daemon pushes a snapshot every couple of
        seconds and the view counts down locally in between, so a display to
        the second would be precise about a number that is not.
        """
        seconds = int(seconds)
        if seconds <= 0:
            return QC.translate("portscan", "expiring")
        if seconds < 60:
            return QC.translate("portscan", "{s}s").format(s=seconds)
        minutes, secs = divmod(seconds, 60)
        if minutes < 60:
            return QC.translate("portscan", "{m}m {s}s").format(m=minutes, s=secs)
        hours, minutes = divmod(minutes, 60)
        if hours < 24:
            return QC.translate("portscan", "{h}h {m}m").format(h=hours, m=minutes)
        days, hours = divmod(hours, 24)
        return QC.translate("portscan", "{d}d {h}h").format(d=days, h=hours)

    @staticmethod
    def stuck_label():
        return QC.translate("portscan", "release failed, still blocked")

    # The status line shows the daemon's own words. They are shown as plain
    # text and bounded: a node could otherwise put rich text, or megabytes,
    # into it.
    MAX_STATUS = 300

    @classmethod
    def status_text(cls, value):
        """Bounds and strips a node's message for a plain-text label."""
        if not value:
            return ""
        return PortScanPresenter._SAFE.sub("?", str(value))[:cls.MAX_STATUS]

    @staticmethod
    def empty_label():
        return QC.translate("portscan", "No address is blocked.")

    @staticmethod
    def omitted_label(shown, total, omitted):
        if omitted <= 0:
            return QC.translate("portscan", "{n} blocked").format(n=total)
        return QC.translate(
            "portscan", "{shown} of {total} blocked; {omitted} not shown").format(
                shown=shown, total=total, omitted=omitted)

    @staticmethod
    def list_request(interval="2s"):
        """Builds the JSON payload of the TASK_START that opens the list."""
        return json.dumps({
            "name": "portscan-blocks",
            "data": {"interval": interval},
        })


class BlockInfoPresenter:
    """Turns the daemon's answer to PORTSCAN_BLOCK_INFO into what the details
    dialog shows: the block, the scan that led to it, and the nftables objects
    applying it.

    The answer came off a socket, like the list, and is treated the same way:
    every field is checked and bounded here, and the dialog renders plain text
    only.
    """

    # The nftables excerpt is a few hundred bytes; this bounds what a node it
    # does not control can put in the dialog.
    MAX_FIREWALL = 8192
    MAX_PORTS = 64
    # Control characters other than the newline and the tab would let a node
    # rewrite the text around them in some renderers.
    _CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
    # The daemon's description of a technique is a sentence: "TCP Xmas scan
    # (equivalent to nmap -sX)", "... -sW, which are identical on the
    # wire)", "TCP scan with flags SYN|ACK (0x12)". The alert's allowlist
    # would turn its punctuation into "?" and its 64 characters cut the
    # longest in half; the dialog renders plain text, so the punctuation is
    # harmless there.
    MAX_DETAIL = 256
    _DETAIL_UNSAFE = re.compile(r"[^\w .:+/\[\]()',;|-]")

    @classmethod
    def detail_text(cls, value):
        """Bounds and cleans a sentence of the daemon's for a plain-text
        cell or label."""
        if not isinstance(value, str):
            return ""
        return cls._DETAIL_UNSAFE.sub("?", value)[:cls.MAX_DETAIL]

    @staticmethod
    def request(ip):
        """Builds the JSON payload of a PORTSCAN_BLOCK_INFO notification."""
        return json.dumps({"ip": ip})

    @classmethod
    def parse(cls, data):
        """Decodes the answer. Raises ValueError when it cannot be read.

        Returns a dict with ip, addr, reason, remaining and stuck as in
        BlockedListPresenter.parse, plus:
          scan            a namespace with the PortScan field names, or None
          firewall        the nftables excerpt, plain text, or ""
          firewall_error  why there is none, cleaned, or ""
          detection       for a source the daemon reported and does not
                          block, the row BlockedListPresenter.detection
                          makes of it; None for a block
        """
        try:
            info = json.loads(data)
        except Exception as e:
            raise ValueError("unreadable block details: {0}".format(e))
        if not isinstance(info, dict):
            raise ValueError("unreadable block details: expected an object")
        ip = BlockedListPresenter._address(info.get("addr"))
        if ip is None:
            raise ValueError("unreadable block details: no valid address")
        as_int = BlockedListPresenter._as_int
        firewall = info.get("firewall")
        firewall = cls._CONTROL.sub("?", firewall)[:cls.MAX_FIREWALL] \
            if isinstance(firewall, str) else ""
        return {
            "ip": ip,
            "addr": PortScanPresenter._clean(ip),
            "reason": PortScanPresenter._clean(info.get("reason")),
            "remaining": max(0, as_int(info.get("remaining"), 0)),
            "stuck": info.get("stuck") is True,
            "scan": cls._scan(info.get("scan")),
            "firewall": firewall,
            "firewall_error": BlockedListPresenter.status_text(info.get("firewall_error")),
            "detection": BlockedListPresenter.detection(info.get("detection")),
        }

    @classmethod
    def _scan(cls, raw):
        if not isinstance(raw, dict):
            return None
        as_int = BlockedListPresenter._as_int

        def text(name):
            v = raw.get(name)
            return v if isinstance(v, str) else ""

        def strings(name, limit):
            v = raw.get(name)
            if not isinstance(v, list):
                return []
            return [s for s in v if isinstance(s, str)][:limit]

        ports = raw.get("sample_ports")
        ports = [p for p in ports if isinstance(p, int) and not isinstance(p, bool)
                 and 0 <= p <= 65535][:cls.MAX_PORTS] if isinstance(ports, list) else []
        targets = [t for t in (BlockedListPresenter._address(t)
                               for t in strings("targets", PortScanPresenter.MAX_TARGETS))
                   if t is not None]
        return SimpleNamespace(
            method=text("method"),
            method_detail=text("method_detail"),
            src_mac=text("src_mac"),
            src_mac_is_source_own=raw.get("src_mac_is_source_own") is True,
            flags_summary=text("flags_summary"),
            distinct_ports=max(0, as_int(raw.get("distinct_ports"), 0)),
            min_port=max(0, as_int(raw.get("min_port"), 0)),
            max_port=max(0, as_int(raw.get("max_port"), 0)),
            sample_ports=ports,
            protocols=max(0, as_int(raw.get("protocols"), 0)),
            is_protocol_scan=raw.get("is_protocol_scan") is True,
            interface=text("interface"),
            targets=targets,
            first_seen_unixnano=cls._unixnano(raw.get("first_seen_unixnano")),
            last_seen_unixnano=cls._unixnano(raw.get("last_seen_unixnano")),
            anomalies=strings("anomalies", PortScanPresenter.MAX_ANOMALIES),
            has_tcp_evidence=raw.get("has_tcp_evidence") is True,
        )

    @staticmethod
    def _unixnano(value):
        t = BlockedListPresenter._as_int(value, 0)
        return t if 0 < t <= BlockedListPresenter.MAX_UNIX * 10**9 else 0

    @staticmethod
    def _when(unixnano):
        if not unixnano:
            return ""
        return BlockedListPresenter.when_text(unixnano // 10**9)

    @classmethod
    def scan_rows(cls, scan):
        """The scan as (label, value) pairs, in the order the dialog shows
        them. Values are plain text, cleaned."""
        clean = PortScanPresenter._clean
        rows = []
        label = PortScanPresenter.method_label(scan)
        detail = cls.detail_text(scan.method_detail)
        # The description usually starts with the label and adds the matching
        # nmap options: shown once, in full, rather than twice.
        if detail.startswith(label):
            rows.append((QC.translate("portscan", "Scan type"), detail))
        else:
            rows.append((QC.translate("portscan", "Scan type"), label))
            if detail:
                rows.append((QC.translate("portscan", "Detail"), detail))

        if scan.src_mac:
            if scan.src_mac_is_source_own:
                mac = QC.translate("portscan", "{mac} (the source's own)")
            else:
                # The address of the last router the packets crossed: it
                # identifies nobody, and must not be shown as the scanner's.
                mac = QC.translate("portscan", "{mac} (the last router's, not the source's)")
            rows.append((QC.translate("portscan", "Source hardware address"),
                         mac.format(mac=clean(scan.src_mac))))
        else:
            rows.append((QC.translate("portscan", "Source hardware address"),
                         QC.translate("portscan", "not observed")))

        if scan.is_protocol_scan:
            rows.append((QC.translate("portscan", "IP protocols probed"), str(scan.protocols)))
        elif scan.distinct_ports:
            n = scan.distinct_ports
            probed = str(n)
            if n > 1:
                probed = QC.translate("portscan", "{n}, between {lo} and {hi}").format(
                    n=n, lo=scan.min_port, hi=scan.max_port)
            rows.append((QC.translate("portscan", "Ports probed"), probed))
            if scan.sample_ports:
                listed = ", ".join(str(p) for p in scan.sample_ports)
                if len(scan.sample_ports) < n:
                    # The daemon keeps a bounded sample per source, never the
                    # full list: saying so stops the user taking it for all of
                    # them.
                    listed = QC.translate(
                        "portscan",
                        "{ports} (the first {k} of {n}: the daemon records only "
                        "the first ports a source probes)").format(
                            ports=listed, k=len(scan.sample_ports), n=n)
                rows.append((QC.translate("portscan", "Ports"), listed))

        if scan.flags_summary:
            rows.append((QC.translate("portscan", "TCP flags"),
                         PortScanPresenter.flags_text(scan.flags_summary)))
        if scan.anomalies:
            rows.append((QC.translate("portscan", "Evasion signs"), ", ".join(
                PortScanPresenter.ANOMALY_LABELS.get(a) or clean(a) for a in scan.anomalies)))
        if scan.interface:
            rows.append((QC.translate("portscan", "Interface"), clean(scan.interface)))
        if scan.targets:
            rows.append((QC.translate("portscan", "Local addresses probed"),
                         ", ".join(clean(t) for t in scan.targets)))
        if scan.first_seen_unixnano:
            rows.append((QC.translate("portscan", "First seen"),
                         cls._when(scan.first_seen_unixnano)))
        if scan.last_seen_unixnano:
            rows.append((QC.translate("portscan", "Last seen"),
                         cls._when(scan.last_seen_unixnano)))
        if scan.has_tcp_evidence:
            evidence = QC.translate(
                "portscan", "yes: probes that only a scanner sends arrived")
        else:
            evidence = QC.translate(
                "portscan", "no: nothing arrived that only a scanner sends, and this "
                "kind of source address costs nothing to forge")
        rows.append((QC.translate("portscan", "Corroborating evidence"), evidence))
        return rows
