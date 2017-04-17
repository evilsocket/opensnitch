import os
import nfqueue
from socket import AF_INET, AF_INET6, inet_ntoa
from threading import Lock

from opensnitch.ui import UI
from opensnitch.connection import Connection
from opensnitch.rule import Rules

class PacketQueue:
    lock = Lock()
    rules = Rules()
    fw_rules = ( "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass",
                 "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass" )

    @staticmethod
    def get_verdict( c ):
        verdict = PacketQueue.rules.get_verdict(c)

        if verdict is None:
            with PacketQueue.lock: 
                ( verdict, apply_for_all ) = UI.prompt_user( c.app.name, 
                                                             c.app_path, 
                                                             None, 
                                                             c.dst_addr, 
                                                             c.dst_port, 
                                                             c.proto )
                PacketQueue.rules.add_rule( c, verdict, apply_for_all )

        return verdict

    @staticmethod
    def pkt_callback(pkt):
        conn = Connection(pkt)
        verd = nfqueue.NF_ACCEPT

        if conn.proto is not None:
            verd = PacketQueue.get_verdict( conn )

        pkt.set_verdict(verd)
        return 1

    # TODO: Support IPv6!
    def __init__( self ):
        self.q = nfqueue.queue()
        self.q.set_callback( PacketQueue.pkt_callback )
        self.q.fast_open(0, AF_INET)
        self.q.set_queue_maxlen(2*1024)

    def start(self):
        for r in PacketQueue.fw_rules:
            os.system( "iptables -I %s" % r )
        self.q.try_run()

    def stop(self):
        for r in PacketQueue.fw_rules:
            os.system( "iptables -D %s" % r )
        self.q.unbind(AF_INET)
        self.q.close()
