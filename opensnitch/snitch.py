# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
from concurrent.futures import Future, TimeoutError
from netfilterqueue import NetfilterQueue
from threading import Lock
from scapy.all import IP
import threading
import logging
import weakref

from opensnitch.connection import Connection
from opensnitch.dns import DNSCollector
from opensnitch.rule import RuleVerdict, Rules
from opensnitch.procmon import ProcMon
from opensnitch.iptables import IPTCRules
from opensnitch.dbus_service import OpensnitchService


MARK_PACKET_DROP = 101285
PACKET_TIMEOUT = 30  # 30 seconds is a good value?
IPTABLES_RULES = (
    # Get DNS responses
    "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass",
    # Get connection packets
    "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass",  # noqa
    # Reject packets marked by OpenSnitch
    "OUTPUT --protocol tcp -m mark --mark 101285 -j REJECT")


def drop_packet(pkt, conn):
    logging.info('Dropping %s from "%s %s"',
                 conn, conn.app.path, conn.app.cmdline)
    pkt.set_mark(MARK_PACKET_DROP)
    pkt.drop()


class NetfilterQueueWrapper(threading.Thread):

    def __init__(self, snitch):
        super().__init__()
        self.snitch = snitch

        self.handlers = weakref.WeakValueDictionary()
        self.latest_packet_id = 0

        self._q = None

        self.start()

    def stop(self):
        if self._q is not None:
            self._q.unbind()

    def pkt_callback(self, pkt):
        try:
            data = pkt.get_payload()

            if self.snitch.dns.add_response(IP(data)):
                pkt.accept()
                return

            self.latest_packet_id += 1
            conn = Connection(self.snitch.procmon, self.snitch.dns,
                              self.latest_packet_id, data)
            if conn.proto is None:
                logging.debug("Could not detect protocol for packet.")
                return

            elif conn.app.pid is None and conn.proto != 'icmp':
                logging.debug("Could not detect process for connection.")
                return

            # Get verdict, if verdict cannot be found prompt user in thread
            verd = self.snitch.rules.get_verdict(conn)
            if verd is None:
                handler = PacketHandler(conn, pkt, self.snitch.rules)
                self.handlers[conn.id] = handler
                self.snitch.dbus_service.prompt(
                    conn.id,
                    conn.hostname,
                    conn.dst_port,
                    conn.dst_addr,
                    conn.proto,
                    conn.app.pid or 0,
                    conn.app.path or '',
                    conn.app.cmdline or '')

            elif RuleVerdict(verd) == RuleVerdict.DROP:
                drop_packet(pkt, conn)

            elif RuleVerdict(verd) == RuleVerdict.ACCEPT:
                pkt.accept()

            else:
                raise RuntimeError("Unhandled state")

        except Exception as e:
            logging.exception("Exception on packet callback:")
            logging.exception(e)

    def run(self):
        try:
            self._q = q = NetfilterQueue()
            q.bind(0, self.pkt_callback, 1024 * 2)
            q.run()

        finally:
            if q is not None:
                q.unbind()


class PacketHandler(threading.Thread):
    """Handle a packet asynchronously in a thread"""

    def __init__(self, connection, pkt, rules):
        super().__init__()
        self.future = Future()
        self.future.set_running_or_notify_cancel()
        self.conn = connection
        self.pkt = pkt
        self.rules = rules
        self.start()

    def run(self):
        try:
            (save_option,
             verdict,
             apply_for_all) = self.future.result(PACKET_TIMEOUT)

        except TimeoutError:
            # What to do on timeouts?
            # Should we even have timeouts?
            self.pkt.accept()

        else:
            if RuleVerdict(verdict) == RuleVerdict.DROP:
                drop_packet(self.pkt, self.conn)

            else:
                self.pkt.accept()


class Snitch:

    # TODO: Support IPv6!
    def __init__(self, database):
        self.lock = Lock()
        self.rules = Rules(database)
        self.dns = DNSCollector()
        self.q = NetfilterQueueWrapper(self)
        self.procmon = ProcMon()
        self.iptcrules = None

        self.dbus_service = OpensnitchService(
            self.q.handlers, self.rules)

    def start(self):
        if ProcMon.is_ftrace_available():
            self.procmon.enable()
            self.procmon.start()

        self.iptcrules = IPTCRules()
        self.dbus_service.run()

    def stop(self):
        self.procmon.disable()
        self.q.stop()

        if self.iptcrules is not None:
            self.iptcrules.remove()
