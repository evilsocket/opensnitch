import os
import nfqueue
from socket import AF_INET, AF_INET6, inet_ntoa
from threading import Lock
from opensnitch.connection import Connection

class PacketQueue:
    verdict_lock = Lock()
    verdicts     = {}
    
    @staticmethod
    def get_verdict( c ):
        PacketQueue.verdict_lock.acquire()

        try:
            ckey = c.cache_key()
            if ckey in PacketQueue.verdicts:
                verd = PacketQueue.verdicts[ckey]

            elif c.app_path in PacketQueue.verdicts:
                verd = PacketQueue.verdicts[c.app_path]
            
            else:
                choice = None
                while choice is None:
                    choice = raw_input("%s is trying to connect to %s on %s port %s, allow? [y/n/a(lways)] " % \
                                ( c.get_app_name(), c.dst_addr, c.proto, c.dst_port ) ).lower()
                    if choice == 'y':
                        verd = nfqueue.NF_ACCEPT
                        key  = ckey
                    elif choice == 'n':
                        verd = nfqueue.NF_DROP
                        key  = ckey

                    elif choice == 'a':
                        verd = nfqueue.NF_ACCEPT
                        key  = c.app_path
                    else:
                        choice = None

                PacketQueue.verdicts[key] = verd
        finally:
            PacketQueue.verdict_lock.release()

        return verd

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
        self.q.set_queue_maxlen(50000)

    def start(self):
        os.system( "iptables -I OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass" )
        self.q.try_run()

    def stop(self):
        os.system( "iptables -D OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass" )
        self.q.unbind(AF_INET)
        self.q.close()
