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
from socket import getservbyport


def get_service(conn):
    dst_port = conn.dst_port
    proto = conn.proto
    try:
        return ' ({}) '.format(getservbyport(int(dst_port), proto))
    except:
        return ''


def get_app_name_and_cmdline(conn):
    if conn.proto == 'icmp':
        return 'Unknown'

    if conn.app_cmdline is not None:
        # TODO: Figure out why we get mixed types here
        cmdline = conn.app_cmdline if isinstance(conn.app_cmdline, str) else conn.app_cmdline.decode()  # noqa
        path = conn.app_path if isinstance(conn.app_path, str) else conn.app.path_decode()  # noqa

        if cmdline.startswith(conn.app_path):
            return cmdline
        else:
            return "%s %s" % (path, cmdline)
    else:
        return conn.app_path
