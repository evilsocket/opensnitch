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
import logging
from netfilterqueue import NetfilterQueue
from threading import Lock
from scapy.all import *
import iptc

from opensnitch.ui import QtApp
from opensnitch.connection import Connection
from opensnitch.dns import DNSCollector
from opensnitch.rule import Rule, Rules
from opensnitch.procmon import ProcMon


class IPTCRules:

    def __init__(self):
        self.tables = {
            iptc.Table.FILTER: iptc.Table(iptc.Table.FILTER),
            iptc.Table.MANGLE: iptc.Table(iptc.Table.MANGLE),
        }
        for t in self.tables.values():
            t.autocommit = False

        self.chains = {
            c: r for c, r in (
                self.insert_dns_rule(),
                self.insert_connection_packet_rules(),
                self.insert_reject_rule())
        }

        self.commit()

    def commit(self):
        for t in self.tables.values():
            t.commit()
            t.refresh()

    def remove(self):
        for c, r in self.chains.items():
            c.delete_rule(r)

        self.commit()

    def insert_dns_rule(self):
        """Get DNS responses"""
        chain = iptc.Chain(self.tables[iptc.Table.FILTER], 'INPUT')
        rule = iptc.Rule()
        rule.protocol = 'udp'
        m = rule.create_match('udp')
        m.sport = '53'

        t = rule.create_target('NFQUEUE')
        t.set_parameter('queue-num', str(0))
        t.set_parameter('queue-bypass')

        chain.insert_rule(rule)
        return (chain, rule)

    def insert_connection_packet_rules(self):
        chain = iptc.Chain(self.tables[iptc.Table.MANGLE], 'OUTPUT')
        rule = iptc.Rule()

        t = rule.create_target('NFQUEUE')
        t.set_parameter('queue-num', str(0))
        t.set_parameter('queue-bypass')

        m = rule.create_match('conntrack')
        m.set_parameter('ctstate', 'NEW')

        chain.insert_rule(rule)
        return (chain, rule)

    def insert_reject_rule(self):
        chain = iptc.Chain(self.tables[iptc.Table.FILTER], 'OUTPUT')
        rule = iptc.Rule()
        rule.protol = 'tcp'

        rule.create_target('REJECT')

        m = rule.create_match('mark')
        m.mark = '0x18ba5'

        chain.insert_rule(rule)
        return (chain, rule)


class Snitch:

    # TODO: Support IPv6!
    def __init__( self ):
        self.iptcrules = None
        self.lock    = Lock()
        self.rules   = Rules()
        self.dns     = DNSCollector()
        self.q       = NetfilterQueue()
        self.procmon = ProcMon()
        self.qt_app  = QtApp()

        self.q.bind( 0, self.pkt_callback, 1024 * 2 )

    def get_verdict(self,c):
        verdict = self.rules.get_verdict(c)

        if verdict is None:
            with self.lock:
                c.hostname = self.dns.get_hostname(c.dst_addr)
                ( save_option, verdict, apply_for_all ) = self.qt_app.prompt_user(c)
                if save_option != Rule.ONCE:
                    self.rules.add_rule( c, verdict, apply_for_all, save_option )

        return verdict

    def pkt_callback(self,pkt):
        verd = Rule.ACCEPT

        try:
            data = pkt.get_payload()
            packet = IP(data)

            if self.dns.is_dns_response(packet):
                self.dns.add_response(packet)

            else:
                conn = Connection( self.procmon, data )
                if conn.proto is None:
                    logging.debug( "Could not detect protocol for packet." )

                elif conn.pid is None:
                    logging.debug( "Could not detect process for connection." )

                else:
                    verd = self.get_verdict( conn )

        except Exception as e:
            logging.exception( "Exception on packet callback:" )

        if verd == Rule.DROP:
            logging.info( "Dropping %s from %s" % ( conn, conn.get_app_name() ) )
            # mark this packet so iptables will drop it
            pkt.set_mark(101285)
            pkt.drop()
        else:
            pkt.accept()

    def start(self):
        self.iptcrules = IPTCRules()

        if ProcMon.is_ftrace_available():
            self.procmon.enable()
            self.procmon.start()

        self.qt_app.run()
        self.q.run()

    def stop(self):
        if self.iptcrules is not None:
            self.iptcrules.remove()

        self.procmon.disable()
        self.q.unbind()
