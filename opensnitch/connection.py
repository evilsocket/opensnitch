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
from opensnitch.proc import get_pid_by_connection
from opensnitch.app import Application 
from dpkt import ip
from socket import inet_ntoa, getservbyport

class Connection:
    def __init__( self, procmon, payload ):
        self.data     = payload
        self.pkt      = ip.IP( self.data )
        self.src_addr = inet_ntoa( self.pkt.src )
        self.dst_addr = inet_ntoa( self.pkt.dst )
        self.hostname = None
        self.src_port = None
        self.dst_port = None
        self.proto    = None
        self.app      = None

        if self.pkt.p == ip.IP_PROTO_TCP:
            self.proto    = 'tcp'
            self.src_port = self.pkt.tcp.sport
            self.dst_port = self.pkt.tcp.dport
        elif self.pkt.p == ip.IP_PROTO_UDP:
            self.proto    = 'udp'
            self.src_port = self.pkt.udp.sport
            self.dst_port = self.pkt.udp.dport

        if None not in ( self.proto, self.src_addr, self.src_port, self.dst_addr, self.dst_port ):
            try:
                self.service = getservbyport( int(self.dst_port), self.proto )
            except:
                self.service = None
            
            self.pid, self.app_path = get_pid_by_connection( procmon,
                                                             self.src_addr,
                                                             self.src_port,
                                                             self.dst_addr,
                                                             self.dst_port,
                                                             self.proto )
            self.app = Application( procmon, self.pid, self.app_path )
            self.app_path = self.app.path
                        
    def get_app_name(self):
        if self.app_path == 'Unknown':
            return self.app_path

        elif self.app_path == self.app.name:
            return self.app_path

        else:
            return "'%s' ( %s )" % ( self.app.name, self.app_path )

    def get_app_name_and_cmdline(self):
        if self.app.cmdline is not None:
            if self.app.cmdline.startswith( self.app.path ):
                return self.app.cmdline
            else:
                return "%s %s" % ( self.app.path, self.app.cmdline )
        else:
            return self.app.path

    def __repr__(self):
        return "[%s] %s (%s) -> %s:%s" % ( self.pid, self.app_path, self.proto, self.dst_addr, self.dst_port )

