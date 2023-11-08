from threading import Lock
import configparser
import pyinotify
import threading
import glob
import os
import re
import locale

DESKTOP_PATHS = tuple([
    os.path.join(d, 'applications')
    for d in os.getenv('XDG_DATA_DIRS', '/usr/share/').split(':')
])

class LinuxDesktopParser(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.lock = Lock()
        self.daemon = True
        self.running = False
        self.apps = {}
        self.apps_by_name = {}
        self.get_locale()
        # some things are just weird
        # (not really, i don't want to keep track of parent pids
        # just because of icons though, this hack is way easier)
        self.fixes = {
            '/opt/google/chrome/chrome': '/opt/google/chrome/google-chrome',
            '/usr/lib/firefox/firefox': '/usr/lib/firefox/firefox.sh',
            '/usr/bin/pidgin.orig': '/usr/bin/pidgin'
        }

        for desktop_path in DESKTOP_PATHS:
            if not os.path.exists(desktop_path):
                continue
            for desktop_file in glob.glob(os.path.join(desktop_path, '*.desktop')):
                self._parse_desktop_file(desktop_file)

        self.start()

    def get_locale(self):
        try:
            self.locale = locale.getlocale()[0]
            self.locale_country = self.locale.split("_")[0]
        except Exception:
            self.locale = ""
            self.locale_country = ""

    def _parse_exec(self, cmd):
        try:
            is_flatpak = re.search(r'^/usr/[s]*bin/flatpak.*--command=([a-zA-Z0-9-_\/\.\+]+)', cmd)
            if is_flatpak:
                return is_flatpak.group(1)

            # remove stuff like %U
            cmd = re.sub( r'%[a-zA-Z]+', '', cmd)
            # remove 'env .... command'
            cmd = re.sub( r'^env\s+[^\s]+\s', '', cmd)
            # split && trim
            cmd = cmd.split(' ')[0].strip()
            # remove quotes
            cmd = re.sub( r'["\']+', '', cmd)

            # check if we need to resolve the path
            if len(cmd) > 0 and cmd[0] != '/':
                for path in os.environ["PATH"].split(os.pathsep):
                    filename = os.path.join(path, cmd)
                    if os.path.exists(filename):
                        cmd = filename
                        break

        except Exception as e:
            print("desktop_parser._parse_exec() exception:", e)

        return cmd

    def get_app_description(self, parser):
        try:
            desc = parser.get('Desktop Entry', 'Comment[%s]' % self.locale_country, raw=True, fallback=None)
            if desc == None:
                desc = parser.get('Desktop Entry', 'Comment[%s]' % self.locale, raw=True, fallback=None)

            if desc == None:
                desc = parser.get('Desktop Entry', 'Comment', raw=True, fallback=None)

            return desc
        except:
            return None

    @staticmethod
    def discover_app_icon(app_name):
        # more hacks
        # normally qt will find icons if the system if configured properly.
        # if it's not, qt won't be able to find the icon by using QIcon().fromTheme(""),
        # so we fallback to try to determine if the icon exist in some well known system paths.
        icon_dirs = (
            "/usr/share/icons/hicolor/scalable/apps/",
            "/usr/share/icons/gnome/48x48/apps/",
            "/usr/share/pixmaps/",
            "/usr/share/icons/hicolor/48x48/apps/",
            "/usr/share/icons/HighContrast/scalable/apps/",
            "/usr/share/icons/HighContrast/48x48/apps/"
        )
        icon_exts = (".svg", ".png", ".svg")
        for idir in icon_dirs:
            for iext in icon_exts:
                iconPath = idir + app_name
                if iext not in app_name:
                    iconPath = idir + app_name + iext

                if os.path.exists(iconPath):
                    return iconPath

    def _parse_desktop_file(self, desktop_path):
        parser = configparser.ConfigParser(strict=False)  # Allow duplicate config entries
        try:
            basename = os.path.basename(desktop_path)[:-8]
            parser.read(desktop_path, 'utf8')

            cmdline = parser.get('Desktop Entry', 'exec', raw=True, fallback=None)
            if cmdline == None:
                cmdline = parser.get('Desktop Entry', 'Exec', raw=True, fallback=None)
            if cmdline is None:
                return

            cmd  = self._parse_exec(cmdline)
            icon = parser.get('Desktop Entry', 'Icon', raw=True, fallback=None)
            name = parser.get('Desktop Entry', 'Name', raw=True, fallback=None)
            desc = self.get_app_description(parser)

            if name == "flatpak":
                return

            if icon == None:
                # Some .desktop files doesn't have the Icon entry
                # FIXME: even if we return an icon, if the DE is not properly configured,
                # it won't be loaded/displayed.
                icon = LinuxDesktopParser.discover_app_icon(basename)

            with self.lock:
                # The Exec entry may have an absolute path to a binary or just the binary with parameters.
                # /path/binary or binary, so save both
                self.apps[cmd] = (name, icon, desc, desktop_path)
                self.apps[basename] = (name, icon, desc, desktop_path)
                # if the command is a symlink, add the real binary too
                if os.path.islink(cmd):
                    link_to = os.path.realpath(cmd)
                    self.apps[link_to] = (name, icon, desc, desktop_path)
        except:
            print("Exception parsing .desktop file ", desktop_path)

    def get_info_by_path(self, path, default_icon):
        def_name = os.path.basename(path)
        # apply fixes
        for orig, to in self.fixes.items():
            if path == orig:
                path = to
                break

        app_name = self.apps.get(path)
        if app_name != None:
            return self.apps.get(path, (def_name, default_icon, "", None))

        app_name = self.apps.get(def_name)
        if app_name != None:
            return self.apps.get(def_name, (def_name, default_icon, "", None))

        # last try to get a default terminal icon
        for def_icon in ("terminal", "utilities-terminal", "xterm", "gnome-terminal", "openterm", "xfce-terminal", "terminator"):
            test = self.apps.get(def_name, (def_name, def_icon, "", None))
            if test != None:
                return test

        return self.apps.get(def_name, (def_name, default_icon, "", None))

    def get_info_by_binname(self, name, default_icon):
        def_name = os.path.basename(name)
        return self.apps.get(def_name, (def_name, default_icon, None))

    def run(self):
        self.running = True
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm)

        def inotify_callback(event):
            if event.mask == pyinotify.IN_CLOSE_WRITE:
                self._parse_desktop_file(event.pathname)

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
