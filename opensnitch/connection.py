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
from collections import namedtuple
from socket import inet_ntoa
from opensnitch import proc
from dpkt import ip


Application = namedtuple('Application', ('pid', 'path', 'cmdline'))
_Connection = namedtuple('Connection', (
    'id',
    'data',
    'pkt',
    'src_addr',
    'dst_addr',
    'hostname',
    'src_port',
    'dst_port',
    'proto',
    'app'))


def Connection(procmon, dns, packet_id, payload):
    data = payload
    pkt = ip.IP(data)
    src_addr = inet_ntoa(pkt.src)
    dst_addr = inet_ntoa(pkt.dst)
    hostname = dns.get_hostname(dst_addr)
    src_port = None
    dst_port = None
    proto = None
    app = None

    if pkt.p == ip.IP_PROTO_TCP:
        proto = 'tcp'
        src_port = pkt.tcp.sport
        dst_port = pkt.tcp.dport
    elif pkt.p == ip.IP_PROTO_UDP:
        proto = 'udp'
        src_port = pkt.udp.sport
        dst_port = pkt.udp.dport
    elif pkt.p == ip.IP_PROTO_ICMP:
        proto = 'icmp'
        src_port = None
        dst_port = None

    if proto == 'icmp':
        app = Application(None, None, None)

    elif None not in (proto, src_addr, dst_addr):
        pid = proc.get_pid_by_connection(src_addr,
                                         src_port,
                                         dst_addr,
                                         dst_port,
                                         proto)
        app = Application(
            pid, *proc._get_app_path_and_cmdline(procmon, pid))

    return _Connection(
        packet_id,
        data,
        pkt,
        src_addr,
        dst_addr,
        hostname,
        src_port,
        dst_port,
        proto,
        app)
