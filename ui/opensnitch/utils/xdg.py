
import os
import shutil
import xdg.BaseDirectory
import xdg.DesktopEntry

xdg_config_home = xdg.BaseDirectory.xdg_config_home
xdg_runtime_dir = xdg.BaseDirectory.get_runtime_dir(False)
xdg_current_desktop = os.environ.get('XDG_CURRENT_DESKTOP')

class Autostart():
    def __init__(self):
        desktopFile = 'opensnitch_ui.desktop'
        self.systemDesktop = os.path.join('/usr/share/applications', desktopFile)
        self.systemAutostart = os.path.join('/etc/xdg/autostart', desktopFile)
        if not os.path.isfile(self.systemAutostart) and os.path.isfile('/usr' + self.systemAutostart):
            self.systemAutostart = '/usr' + self.systemAutostart
        self.userAutostart = os.path.join(xdg_config_home, 'autostart', desktopFile)

    def createUserDir(self):
        if not os.path.isdir(xdg_config_home):
            os.makedirs(xdg_config_home, 0o700)
        if not os.path.isdir(os.path.dirname(self.userAutostart)):
            os.makedirs(os.path.dirname(self.userAutostart), 0o755)

    def isEnabled(self):
        if os.path.isfile(self.userAutostart):
            entry = xdg.DesktopEntry.DesktopEntry(self.userAutostart)
            if not entry.getHidden():
                return True
        elif os.path.isfile(self.systemAutostart):
            return True
        return False

    def enable(self, mode=True):
        self.createUserDir()
        if mode == True:
            if os.path.isfile(self.systemAutostart) and os.path.isfile(self.userAutostart):
                os.remove(self.userAutostart)
            elif os.path.isfile(self.systemDesktop):
                shutil.copyfile(self.systemDesktop, self.userAutostart)
        else:
            if os.path.isfile(self.systemAutostart):
                shutil.copyfile(self.systemAutostart, self.userAutostart)
                with open(self.userAutostart, 'a') as f:
                    f.write('Hidden=true\n')
            elif os.path.isfile(self.userAutostart):
                os.remove(self.userAutostart)

    def disable(self):
        self.enable(False)
