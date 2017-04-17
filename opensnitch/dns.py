import logging
from threading import Lock
from scapy.all import *

class DNSCollector:
    def __init__(self):
        self.lock = Lock()
        self.hosts = { '127.0.0.1': 'localhost' }

    def is_dns_response(self, packet):
        if DNSRR in packet and packet.qd is not None and packet.an is not None:
            return True
        else:
            return False

    def add_response( self, packet ):
        with self.lock:
            hostname = packet.qd.qname
            address  = packet.an.rdata
            if hostname.endswith('.'):
                hostname = hostname[:-1]

            logging.debug( "DNS[%s] = %s" % ( address, hostname ) )
            self.hosts[address] = hostname

    def get_hostname( self, address ):
        with self.lock:
            if address in self.hosts:
                return self.hosts[address]
            else:
                logging.debug( "No hostname found for address %s" % address )
                return address
