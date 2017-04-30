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
import glob
import re
import os
from threading import Lock
import logging

class LinuxDesktopParser:
    lock = Lock()
    apps = None

    @staticmethod
    def get_info_by_path( path ):
        path = os.path.basename(path)
        name = path
        icon = None

        LinuxDesktopParser.lock.acquire()

        try:
            if LinuxDesktopParser.apps is None:
                LinuxDesktopParser.apps = {}
                for item in glob.glob('/usr/share/applications/*.desktop'):
                    name = None
                    icon = None
                    cmd  = None

                    with open( item, 'rt' ) as fp:
                        in_section = False
                        for line in fp:
                            line = line.strip()
                            if '[Desktop Entry]' in line:
                                in_section = True
                                continue
                            elif len(line) > 0 and line[0] == '[':
                                in_section = False
                                continue

                            if in_section and line.startswith('Exec='):
                                cmd = os.path.basename( line[5:].split(' ')[0] )

                            elif in_section and line.startswith('Icon='):
                                icon = line[5:]

                            elif in_section and line.startswith('Name='):
                                name = line[5:]
                    
                    if cmd is not None:
                        LinuxDesktopParser.apps[cmd] = ( name, icon )

            if path in LinuxDesktopParser.apps:
                name, icon = LinuxDesktopParser.apps[path]

        finally:
            LinuxDesktopParser.lock.release()

        return ( name, icon )

class Application:
    def __init__( self, procmon, pid, path ):
        self.pid = pid
        self.path = path
        self.name, self.icon = LinuxDesktopParser.get_info_by_path(self.path)

        try:

            self.cmdline = None

            if self.pid is not None:
                if procmon.running:
                    self.cmdline = procmon.get_cmdline( pid )
                    if self.cmdline is None:
                        logging.debug( "Could not find pid %s command line with ProcMon" % pid )

                if self.cmdline is None:
                    with open( "/proc/%s/cmdline" % pid ) as cmd_fd:
                        self.cmdline = cmd_fd.read().replace( '\0', ' ').strip()

        except Exception as e:
            logging.exception(e)
