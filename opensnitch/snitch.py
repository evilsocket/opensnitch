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
import os

from opensnitch.ui import QtApp
from opensnitch.connection import Connection
from opensnitch.dns import DNSCollector
from opensnitch.rule import Rule, Rules
from opensnitch.procmon import ProcMon
from opensnitch.app import LinuxDesktopParser


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
    logging.info(
        "Dropping %s from %s" % (conn, conn.get_app_name()))
    pkt.set_mark(MARK_PACKET_DROP)
    pkt.drop()


class NetfilterQueueWrapper(threading.Thread):

    def __init__(self, snitch):
        super().__init__()
        self.snitch = snitch
        self.start()

    def run(self):
        q = None
        try:
            for r in IPTABLES_RULES:
                logging.debug("Applying iptables rule '%s'", r)
                os.system("iptables -I %s" % r)

            q = NetfilterQueue()
            q.bind(0, self.snitch.pkt_callback, 1024 * 2)
            q.run()

        finally:
            for r in IPTABLES_RULES:
                logging.debug("Deleting iptables rule '%s'", r)
                os.system("iptables -D %s" % r)

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
            if verdict == Rule.DROP:
                drop_packet(self.pkt, self.conn)

            else:
                self.pkt.accept()


class Snitch:

    # TODO: Support IPv6!
    def __init__(self, database):
        self.desktop_parser = LinuxDesktopParser()
        self.lock    = Lock()
        self.rules   = Rules(database)
        self.dns     = DNSCollector()
        self.q       = NetfilterQueueWrapper(self)
        self.procmon = ProcMon()
        self.connection_futures = weakref.WeakValueDictionary()
        self.qt_app  = QtApp(self.connection_futures, self.rules)
        self.latest_packet_id = 0

    def pkt_callback(self, pkt):
        try:
            data = pkt.get_payload()

            if self.dns.add_response(IP(data)):
                pkt.accept()
                return

            self.latest_packet_id += 1
            conn = Connection(self.latest_packet_id, self.procmon,
                              self.desktop_parser, data)
            if conn.proto is None:
                logging.debug("Could not detect protocol for packet.")
                return

            elif conn.pid is None and conn.proto != 'icmp':
                logging.debug("Could not detect process for connection.")
                return

            # Get verdict, if verdict cannot be found prompt user in thread
            verd = self.rules.get_verdict(conn)
            if verd == Rule.DROP:
                drop_packet(pkt, conn)

            elif verd == Rule.ACCEPT:
                pkt.accept()

            elif verd is None:
                conn.hostname = self.dns.get_hostname(conn.dst_addr)
                handler = PacketHandler(conn, pkt, self.rules)
                self.connection_futures[conn.id] = handler.future
                self.qt_app.prompt_user(conn)

            else:
                raise RuntimeError("Unhandled state")

        except Exception as e:
            logging.exception("Exception on packet callback:")
            logging.exception(e)

    def start(self):
        if ProcMon.is_ftrace_available():
            self.procmon.enable()
            self.procmon.start()

        self.qt_app.run()

    def stop(self):
        self.procmon.disable()
