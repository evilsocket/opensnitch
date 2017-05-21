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


class Application:
    def __init__(self, procmon, pid, path):
        self.pid = pid
        self.path = path

        try:

            self.cmdline = None

            if self.pid is not None:
                if procmon.running:
                    self.cmdline = procmon.get_cmdline(pid)
                    if self.cmdline is None:
                        logging.debug(
                            "Could not find pid %s command line with ProcMon", pid)  # noqa

                if self.cmdline is None:
                    with open("/proc/%s/cmdline" % pid) as cmd_fd:
                        self.cmdline = cmd_fd.read().replace('\0', ' ').strip()

        except Exception as e:
            logging.exception(e)
