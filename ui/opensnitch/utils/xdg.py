
import os
import re
import shutil
import stat

# https://github.com/takluyver/pyxdg/blob/1d23e483ae869ee9532aca43b133cc43f63626a3/xdg/BaseDirectory.py
def get_runtime_dir(strict=True):
    try:
        return os.environ['XDG_RUNTIME_DIR']
    except KeyError:
        if strict:
            raise

        import getpass
        fallback = '/tmp/opensnitch-' + getpass.getuser()
        create = False

        try:
            # This must be a real directory, not a symlink, so attackers can't
            # point it elsewhere. So we use lstat to check it.
            st = os.lstat(fallback)
        except OSError as e:
            import errno
            if e.errno == errno.ENOENT:
                create = True
            else:
                raise
        else:
            # The fallback must be a directory
            if not stat.S_ISDIR(st.st_mode):
                os.unlink(fallback)
                create = True
            # Must be owned by the user and not accessible by anyone else
            elif (st.st_uid != os.getuid()) \
              or (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                os.rmdir(fallback)
                create = True

        if create:
            os.mkdir(fallback, 0o700)

        return fallback

def get_run_opensnitch_dir():
    rdir = get_runtime_dir(False)
    if 'opensnitch' not in rdir:
        rdir = os.path.join(rdir, 'opensnitch')
        try:
            os.makedirs(rdir, 0o700)
        except:
            pass

    return rdir


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
        ret = False
        if os.path.isfile(self.userAutostart):
             ret = True
             lines = open(self.userAutostart, 'r').readlines()
             for line in lines:
                 if re.search("^Hidden=true", line, re.IGNORECASE):
                     ret = False
                     break
        elif os.path.isfile(self.systemAutostart):
            ret = True
        return ret

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


_home = os.path.expanduser('~')
xdg_config_home = os.environ.get('XDG_CONFIG_HOME') or os.path.join(_home, '.config')
xdg_runtime_dir = get_runtime_dir(False)
xdg_current_desktop = os.environ.get('XDG_CURRENT_DESKTOP')
xdg_current_session = os.environ.get('XDG_SESSION_TYPE')

xdg_opensnitch_dir = get_run_opensnitch_dir()
