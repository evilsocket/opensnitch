from opensnitch.proc import get_process_name_by_connection 
from opensnitch.app import Application 
from dpkt import ip
from socket import inet_ntoa

class Connection:
    def __init__( self, payload ):
        self.data     = payload.get_data()
        self.pkt      = ip.IP( self.data )
        self.src_addr = inet_ntoa( self.pkt.src )
        self.dst_addr = inet_ntoa( self.pkt.dst )
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
            self.pid, self.app_path = get_process_name_by_connection( self.src_addr, 
                                                                      self.src_port,
                                                                      self.dst_addr, 
                                                                      self.dst_port, 
                                                                      self.proto )
            self.app = Application( self.pid, self.app_path )
                        
    def get_app_name(self):
        if self.app_path == 'Unknown':
            return self.app_path

        elif self.app_path == self.app.name:
            return self.app_path

        else:
            return "'%s' ( %s )" % ( self.app.name, self.app_path )

    def __repr__(self):
        return "[%s] %s (%s) -> %s:%s" % ( self.pid, self.app_path, self.proto, self.dst_addr, self.dst_port )

    def cache_key(self):
        return "%s:%s:%s:%s" % ( self.app_path, self.proto, self.dst_addr, self.dst_port)

