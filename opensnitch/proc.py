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
import re
import glob
import os
import logging

def hex2address(address):
    hex_addr, hex_port = address.split(':')

    octects = [ hex_addr[i:i+2] for i in range(0, len(hex_addr), 2 ) ]
    octects.reverse()

    addr = ".".join(map(lambda x: str(int(x, 16)), octects))
    port = int(hex_port, 16)

    return (addr, port)

def get_pid_of_inode(inode):
    inode = int(inode)
    sname = 'socket:[%d]' % inode
    for fd_file in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            link = os.readlink(fd_file)
            if sname == link:
                return fd_file.split('/')[2]
        except:
            pass

    logging.error( "Could not find pid of inode %d" % inode )

    return None

def get_process_name_by_connection( src_addr, src_p, dst_addr, dst_p, proto = 'tcp' ):
    filename = "/proc/net/%s" % proto
    with open( filename, 'rt' ) as fd:
        for line in fd:
            line = line.strip()
            if line.startswith('sl'):
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

    logging.error( "Could not find process for %s connection %s:%s -> %s:%s inside %s" % (
                   proto,
                   src_addr,
                   src_p,
                   dst_addr,
                   dst_p,
                   filename ) )


    return ( 0, "Unknown" )
