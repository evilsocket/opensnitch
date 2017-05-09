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
from threading import Lock
import configparser
import pyinotify
import threading
import logging
import glob
import os


DESKTOP_PATHS = [
    os.path.join(d, 'applications')
    for d in os.getenv('XDG_DATA_DIRS', '/usr/share/').split(':')
]


class LinuxDesktopParser(threading.Thread):

    def __init__(self):
        super().__init__()
        self.lock = Lock()
        self.daemon = True
        self.running = False

        self.apps = {}
        for desktop_path in DESKTOP_PATHS:
            if not os.path.exists(desktop_path):
                continue

            for desktop_file in glob.glob(os.path.join(desktop_path,
                                                       '*.desktop')):
                self.populate_app(desktop_file)

        self.start()

    def populate_app(self, desktop_path):
        parser = configparser.ConfigParser(
            strict=False)  # Allow duplicate config entries
        parser.read(desktop_path, 'utf8')
        cmd = parser.get('Desktop Entry', 'exec', raw=True,
                         fallback=' ').split(' ')[0] or None
        if cmd is None:
            return

        icon = parser.get('Desktop Entry', 'icon',
                          raw=True, fallback=None)
        name = parser.get('Desktop Entry', 'name',
                          raw=True, fallback=None)

        with self.lock:
            self.apps[cmd] = (name, icon, desktop_path)

    def get_info_by_path(self, path):
        path = os.path.basename(path)
        with self.lock:
            return self.apps.get(path, (path, None))[:2]

    def run(self):
        self.running = True
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm)

        def inotify_callback(event):
            if event.mask == pyinotify.IN_CLOSE_WRITE:
                self.populate_app(event.pathname)

            elif event.mask == pyinotify.IN_DELETE:
                with self.lock:
                    for cmd, data in self.apps.items():
                        if data[2] == event.pathname:
                            del self.apps[cmd]
                            break

        for p in DESKTOP_PATHS:
            if os.path.exists(p):
                wm.add_watch(p,
                             pyinotify.IN_CLOSE_WRITE | pyinotify.IN_DELETE,
                             inotify_callback)
        notifier.loop()


class Application:
    def __init__(self, procmon, desktop_parser, pid, path):
        self.pid = pid
        self.path = path
        self.name, self.icon = desktop_parser.get_info_by_path(path)

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
