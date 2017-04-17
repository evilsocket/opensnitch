import logging
from threading import Lock
from scapy.all import *

class DNSCollector:
    def __init__(self):
        self.lock = Lock()
        self.hosts = { '127.0.0.1': 'localhost' }

    def is_dns_response(self, packet):
        if packet.haslayer(DNSRR):
            return True
        else:
            return False

    def add_response( self, packet ):
        with self.lock:
            a_count = packet[DNS].ancount
            i = a_count + 4
            while i > 4:
                hostname = packet[0][i].rrname
                address  = packet[0][i].rdata
                i -= 1

                if hostname == '.':
                    continue

                elif hostname.endswith('.'):
                    hostname = hostname[:-1]

                logging.debug( "Adding DNS response: %s => %s" % ( address, hostname ) )
                self.hosts[address] = hostname

    def get_hostname( self, address ):
        with self.lock:
            if address in self.hosts:
                return self.hosts[address]
            else:
                logging.debug( "No hostname found for address %s" % address )
                return address
