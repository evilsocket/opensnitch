import glob
import re
import os
from threading import Lock

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
    def __init__( self, pid, path ):
        self.pid = pid
        self.path = path
        self.name, self.icon = LinuxDesktopParser.get_info_by_path(path)
