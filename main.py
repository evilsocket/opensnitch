#!/usr/bin/python

import struct
import sys
import time
import nfqueue
import re
import os
import glob
from dpkt import ip

from socket import AF_INET, AF_INET6, inet_ntoa

def split_every_n(data, n):
    return [data[i:i+n] for i in range(0, len(data), n)]

def convert_linux_netaddr(address):
    hex_addr, hex_port = address.split(':')

    addr_list = split_every_n(hex_addr, 2)
    addr_list.reverse()

    addr = ".".join(map(lambda x: str(int(x, 16)), addr_list))
    port = int(hex_port, 16)

    return (addr, port)

def get_pid_of_inode(inode):
    for item in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            if re.search(inode,os.readlink(item)):
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
            src = parts[1]
            dst = parts[2]
            uid = parts[6]
            inode = parts[9]

            src_ip, src_port = convert_linux_netaddr( src )
            dst_ip, dst_port = convert_linux_netaddr( dst )

            if src_ip == src_addr and src_port == src_p and dst_ip == dst_addr and dst_port == dst_p:
                pid = get_pid_of_inode(inode)
                return ( pid, os.readlink( "/proc/%s/exe" % pid ) )

class ConnectionPacket:
    def __init__( self, payload ):
        self.data = payload.get_data()
        self.pkt  = ip.IP( self.data )
        self.src_addr = inet_ntoa( self.pkt.src )
        self.dst_addr = inet_ntoa( self.pkt.dst )
        self.proto = None

        if self.pkt.p == ip.IP_PROTO_TCP:
            self.proto = 'tcp'
            self.src_port = self.pkt.tcp.sport
            self.dst_port = self.pkt.tcp.dport
        elif self.pkt.p == ip.IP_PROTO_UDP:
            self.proto = 'udp'
            self.src_port = self.pkt.udp.sport
            self.dst_port = self.pkt.udp.dport

        if self.proto is not None:
            self.pid, self.app_name = get_process( self.src_addr, \
                                                   self.src_port, \
                                                   self.dst_addr, \
                                                   self.dst_port, \
                                                   self.proto )
    
    def __repr__(self):
        return "[%s] %s (%s) -> %s:%s" % ( self.pid, self.app_name, self.proto, self.dst_addr, self.dst_port )

def cb(i, payload):
    conn = ConnectionPacket(payload)
    
    if conn.proto is not None:
        print conn

    payload.set_verdict(nfqueue.NF_ACCEPT)
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

print "Stopping ..."

q.unbind(AF_INET)
q.close()

os.system( "iptables -D OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass" )

