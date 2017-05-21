# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# https://www.evilsocket.net
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
import psutil
import os


def get_pid_by_connection(procmon, src_addr, src_p, dst_addr,
                          dst_p, proto='tcp'):
    pids = (connection.pid for connection in psutil.net_connections(kind=proto)
            if connection.laddr == (src_addr, int(src_p)) and
            connection.raddr == (dst_addr, int(dst_p)))

    # We always take the first element as we assume it contains only one
    # It should not be possible to keep two connections which are the same.
    for pid in pids:
        try:
            appname = None
            if procmon.running:
                appname = procmon.get_app_name(pid)

            if appname is None:
                appname = os.readlink("/proc/%s/exe" % pid)
                if procmon.running:
                    logging.debug("Could not find pid %s with ProcMon, falling back to /proc/%s/exe -> %s", pid, pid, appname)  # noqa
            else:
                logging.debug("ProcMon(%s) = %s", pid, appname)

            return (pid, appname)
        except OSError:
            return (None, "Unknown")

    logging.warning("Could not find process for %s connection %s:%s -> %s:%s",
                    proto,
                    src_addr,
                    src_p,
                    dst_addr,
                    dst_p)

    return (None, "Unknown")
