import glob
import re
import os
from threading import Lock

class Application:
    lock = Lock()
    apps = None

    def __init__( self, pid, path ):
        self.pid = pid
        self.path = path
        self.name, self.icon = Application.get_name_and_icon( os.path.basename(self.path) )

    @staticmethod
    def get_name_and_icon( path ):
        name = path
        icon = None

        Application.lock.acquire()

        try:
            if Application.apps is None:
                Application.apps = {}
                for item in glob.glob('/usr/share/applications/*.desktop'):
                    name = None
                    icon = None
                    cmd  = None

                    with open( item, 'rt' ) as fp:
                        in_section = False
                        for line in fp:
                            if '[Desktop Entry]' in line:
                                in_section = True
                                continue
                            elif len(line.strip()) > 0 and line[0] == '[':
                                in_section = False
                                continue

                            if in_section and line.startswith('Exec='):
                                cmd = os.path.basename( line[5:].split(' ')[0].strip() )

                            elif in_section and line.startswith('Icon='):
                                icon = line[5:].strip()

                            elif in_section and line.startswith('Name='):
                                name = line[5:].strip()
                    
                    if cmd is not None:
                        print cmd
                        Application.apps[cmd] = ( name, icon )

            if path in Application.apps:
                name, icon = Application.apps[path]

        finally:
            Application.lock.release()

        return ( name, icon )
