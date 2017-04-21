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
import os
import logging
from netfilterqueue import NetfilterQueue
from socket import AF_INET, AF_INET6, inet_ntoa
from threading import Lock
from scapy.all import *

from opensnitch.ui import QtApp
from opensnitch.connection import Connection
from opensnitch.dns import DNSCollector
from opensnitch.rule import Rule, Rules

class Snitch:
    IPTABLES_RULES = ( # Get DNS responses
                       "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass",
                       # Get connection packets
                       "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass",
                       # Reject packets marked by OpenSnitch
                       "OUTPUT --protocol tcp -m mark --mark 1 -j REJECT" )

    # TODO: Support IPv6!
    def __init__( self ):
        self.lock  = Lock()
        self.rules = Rules()
        self.dns   = DNSCollector()
        self.q     = NetfilterQueue()
        self.qt_app   = QtApp()

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
                conn = Connection(data)
                if conn.proto is None:
                    logging.debug( "Could not detect protocol for packet." )

                elif conn.pid is None:
                    logging.debug( "Could not detect process for connection." )

                else:
                    verd = self.get_verdict( conn )

        except Exception, e:
            logging.exception( "Exception on packet callback:" )

        if verd == Rule.DROP:
            logging.info( "Dropping %s from %s" % ( conn, conn.get_app_name() ) )
            # mark this packet so iptables will drop it
            pkt.set_mark(1)
            pkt.drop()
        else:
            pkt.accept()

    def start(self):
        for r in Snitch.IPTABLES_RULES:
            logging.debug( "Applying iptables rule '%s'" % r )
            os.system( "iptables -I %s" % r )

        self.qt_app.run()
        self.q.run()

    def stop(self):
        for r in Snitch.IPTABLES_RULES:
            logging.debug( "Deleting iptables rule '%s'" % r )
            os.system( "iptables -D %s" % r )

        self.q.unbind()
