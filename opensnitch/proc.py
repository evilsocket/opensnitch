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
import os
import logging
import psutil

def get_pid_by_connection( procmon, src_addr, src_p, dst_addr, dst_p, proto = 'tcp' ):
    connections_list = [connection for connection in psutil.net_connections(kind=proto) if connection.laddr==(src_addr, src_p) and connection.raddr==(dst_addr, dst_p)]

    # We always take the first element as we assume it contains only one, because
    # it should not be possible to keep two connections which are exactly the same.
    if connections_list:
        pid = connections_list[0][-1]
        try:
            appname = None
            if procmon.running:
                appname = procmon.get_app_name(pid)

            if appname is None:
                appname = os.readlink( "/proc/%s/exe" % pid )
                if procmon.running:
                    logging.debug( "Could not find pid %s with ProcMon, faiiling back to /proc/%s/exe -> %s" % ( pid, pid, appname ) )
            else:
                logging.debug( "ProcMon(%s) = %s" % ( pid, appname ) )

            return ( pid, appname )
        except OSError:
            return (None, "Unknown")
    else:
        logging.warning( "Could not find process for %s connection %s:%s -> %s:%s" % (
                         proto,
                         src_addr,
                         src_p,
                         dst_addr,
                         dst_p) )

        return ( None, "Unknown" )
