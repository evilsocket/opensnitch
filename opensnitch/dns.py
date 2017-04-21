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
        if packet.haslayer(DNS) and packet.haslayer(DNSRR):
            with self.lock:
                try:
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

                        # for CNAME records
                        if address.endswith('.'):
                            address = address[:-1]

                        logging.debug( "Adding DNS response: %s => %s" % ( address, hostname ) )
                        self.hosts[address] = hostname
                except Exception, e:
                    logging.debug("Error while parsing DNS response: %s" % e)

    def get_hostname( self, address ):
        with self.lock:
            if address in self.hosts:
                return self.hosts[address]
            else:
                logging.debug( "No hostname found for address %s" % address )
                return address
