#!/usr/bin/python

import struct
import sys
import time
import nfqueue
import re
import os
import glob

from threading import Lock

from dpkt import ip
from socket import AF_INET, AF_INET6, inet_ntoa

def hex2address(address):
    hex_addr, hex_port = address.split(':')

    octects = [ hex_addr[i:i+2] for i in range(0, len(hex_addr), 2 ) ]
    octects.reverse()

    addr = ".".join(map(lambda x: str(int(x, 16)), octects))
    port = int(hex_port, 16)

    return (addr, port)

def get_pid_of_inode(inode):
    expr = r'.+[^\d]%s[^\d]*' % inode
    for item in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            link = os.readlink(item)
            if re.search(expr,link):
                return item.split('/')[2]
        except:
            pass
    return None

def get_process( src_addr, src_p, dst_addr, dst_p, proto = 'tcp' ):
    filename = "/proc/net/%s" % proto
    with open( filename, 'rt' ) as fd:
        header = False
        for line in fd:
            if header is False:
                header = True
                continue

            parts = line.split()
            src   = parts[1]
            dst   = parts[2]
            uid   = parts[6]
            inode = parts[9]

            src_ip, src_port = hex2address( src )
            dst_ip, dst_port = hex2address( dst )

            if src_ip == src_addr and src_port == src_p and dst_ip == dst_addr and dst_port == dst_p:
                pid = get_pid_of_inode(inode)
                return ( pid, os.readlink( "/proc/%s/exe" % pid ) )

    return ( 0, '?' )

class ConnectionPacket:
    def __init__( self, payload ):
        self.data     = payload.get_data()
        self.pkt      = ip.IP( self.data )
        self.src_addr = inet_ntoa( self.pkt.src )
        self.dst_addr = inet_ntoa( self.pkt.dst )
        self.src_port = None
        self.dst_port = None
        self.proto    = None

        if self.pkt.p == ip.IP_PROTO_TCP:
            self.proto    = 'tcp'
            self.src_port = self.pkt.tcp.sport
            self.dst_port = self.pkt.tcp.dport
        elif self.pkt.p == ip.IP_PROTO_UDP:
            self.proto    = 'udp'
            self.src_port = self.pkt.udp.sport
            self.dst_port = self.pkt.udp.dport

        if None not in ( self.proto, self.src_addr, self.src_port, self.dst_addr, self.dst_port ):
            self.pid, self.app_name = get_process( self.src_addr, 
                                                   self.src_port,
                                                   self.dst_addr, 
                                                   self.dst_port, self.proto )
    
    def __repr__(self):
        return "[%s] %s (%s) -> %s:%s" % ( self.pid, self.app_name, self.proto, self.dst_addr, self.dst_port )

    def cache_key(self):
        return "%s:%s:%s:%s" % ( self.app_name, self.proto, self.dst_addr, self.dst_port)

lock = Lock()
rules = {}

def get_verdict( c ):
    global lock, rules

    lock.acquire()

    try:
        ckey = c.cache_key()
        if ckey in rules:
            verd = rules[ckey]

        elif c.app_name in rules:
            verd = rules[c.app_name]
        
        else:
            choice = None
            while choice is None:
                choice = raw_input("%s is trying to connect to %s on %s port %s, allow? [y/n/a(lways)] " % \
                            ( c.app_name, c.dst_addr, c.proto, c.dst_port ) ).lower()
                if choice == 'y':
                    verd = nfqueue.NF_ACCEPT
                    key  = ckey
                elif choice == 'n':
                    verd = nfqueue.NF_DROP
                    key  = ckey

                elif choice == 'a':
                    verd = nfqueue.NF_ACCEPT
                    key  = c.app_name
                else:
                    choice = None

            rules[key] = verd
    finally:
        lock.release()

    return verd


def cb(i, payload):
    conn = ConnectionPacket(payload)
    verd = nfqueue.NF_ACCEPT

    if conn.proto is not None:
        verd = get_verdict( conn )

    payload.set_verdict(verd)
    return 1

print "Installing iptables rule ..."

os.system( "iptables -I OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass" )

q = nfqueue.queue()

q.set_callback(cb)
q.fast_open(0, AF_INET)
q.set_queue_maxlen(50000)

print "Running ..."

try:
    q.try_run()
except KeyboardInterrupt, e:
    pass

print "\n\nStopping ..."

q.unbind(AF_INET)
q.close()

os.system( "iptables -D OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass" )

