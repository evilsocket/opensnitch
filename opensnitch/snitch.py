import os
import logging
import nfqueue
from socket import AF_INET, AF_INET6, inet_ntoa
from threading import Lock
from scapy.all import *

from opensnitch.ui import UI
from opensnitch.connection import Connection
from opensnitch.dns import DNSCollector
from opensnitch.rule import Rules

class Snitch:
    IPTABLES_RULES = ( "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass", )

    # TODO: Support IPv6!
    def __init__( self ):
        self.lock  = Lock()
        self.rules = Rules()
        self.dns   = DNSCollector()
        self.q     = nfqueue.queue()

        self.q.set_callback( self.pkt_callback )
        self.q.fast_open(0, AF_INET)
        self.q.set_queue_maxlen(2*1024)

    def get_verdict(self,c):
        verdict = self.rules.get_verdict(c)

        if verdict is None:
            with self.lock: 
                c.hostname = self.dns.get_hostname(c.dst_addr) 
                ( verdict, apply_for_all ) = UI.prompt_user(c)
                self.rules.add_rule( c, verdict, apply_for_all )

        return verdict

    def pkt_callback(self,pkt):
        verd = nfqueue.NF_ACCEPT

        try:
            data = pkt.get_data()
            packet = IP(data)

            if self.dns.is_dns_response(packet):
                self.dns.add_response(packet)

            else:
                conn = Connection(data)
                if conn.proto is not None:
                    verd = self.get_verdict( conn )
        except Exception as e:
            print e

        pkt.set_verdict(verd)
        return 1

    def start(self):
        for r in Snitch.IPTABLES_RULES:
            logging.debug( "Applying iptables rule '%s'" % r )
            os.system( "iptables -I %s" % r )

        self.q.try_run()

    def stop(self):
        for r in Snitch.IPTABLES_RULES:
            logging.debug( "Deleting iptables rule '%s'" % r )
            os.system( "iptables -D %s" % r )

        self.q.unbind(AF_INET)
        self.q.close()
