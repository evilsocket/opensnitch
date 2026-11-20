import os.path
import sys, glob
from PyQt6 import QtCore, QtGui

from opensnitch.config import Config

# WA for #1373
qtm_home = "{0}/.qt_material/theme/".format(QtCore.QDir.homePath())
if qtm_home not in QtCore.QDir.searchPaths("icon"):
    QtCore.QDir.addSearchPath("icon", qtm_home)

class Themes():
    """Change GUI's appearance using qt-material lib or built-in themes."""
    THEMES_PATH = [
        os.path.expanduser("~/.config/opensnitch/"),
        os.path.dirname(sys.modules[__name__].__file__) + "/../.."
    ]
    __instance = None

    AVAILABLE = False
    IS_DARK = False
    BUILTIN_DARK = "builtin:dark"
    BUILTIN_THEMES = {
        BUILTIN_DARK: "Dark (Built-in)"
    }

    try:
        from qt_material import apply_stylesheet as qtmaterial_apply_stylesheet
        from qt_material import list_themes as qtmaterial_themes
        AVAILABLE = True
    except Exception:
        pass

    @staticmethod
    def instance():
        if Themes.__instance == None:
            Themes.__instance = Themes()
        return Themes.__instance

    def __init__(self):
        self._cfg = Config.get()
        theme = self._cfg.getInt(self._cfg.DEFAULT_THEME, 0)

    def available(self):
        return True

    def _get_builtin_qss_path(self, theme_key):
        res_dir = os.path.dirname(sys.modules[__name__].__file__) + "/../../res"
        if theme_key == self.BUILTIN_DARK:
            return os.path.join(res_dir, "themes", "dark", "dark.qss")
        return ""

    def _get_builtin_icons_path(self, theme_key):
        res_dir = os.path.dirname(sys.modules[__name__].__file__) + "/../../res"
        if theme_key == self.BUILTIN_DARK:
            return os.path.join(res_dir, "themes", "dark", "icons")
        return ""

    def _apply_builtin_theme(self, widget, theme_key):
        qss_path = self._get_builtin_qss_path(theme_key)
        if not os.path.isfile(qss_path):
            print("Built-in theme QSS not found:", qss_path)
            return False

        try:
            with open(qss_path, 'r') as f:
                qss = f.read()
            widget.setStyleSheet(qss)

            icons_path = self._get_builtin_icons_path(theme_key)
            if os.path.isdir(icons_path):
                icon_theme_name = "opensnitch-dark"
                QtGui.QIcon.setThemeSearchPaths(
                    QtGui.QIcon.themeSearchPaths() + [os.path.dirname(icons_path)]
                )

            Themes.IS_DARK = True
            return True
        except Exception as e:
            print("Error applying built-in theme:", e)
            return False

    def get_saved_theme(self):
        theme = self._cfg.getSettings(self._cfg.DEFAULT_THEME)
        theme_density = self._cfg.getSettings(self._cfg.DEFAULT_THEME_DENSITY_SCALE)
        if theme_density == "" or theme_density == None:
            theme_density = '0'

        if theme == "" or theme == None:
            return 0, "", theme_density

        if theme in self.BUILTIN_THEMES:
            themes_list = self.list_themes()
            for idx, tml in enumerate(themes_list):
                if theme == tml or theme in tml:
                    return idx + 1, theme, theme_density
            return 0, "", theme_density

        if not Themes.AVAILABLE:
            return 0, "", theme_density

        try:
            if theme != "" and theme != None:
                themes_list = self.list_themes()
                for idx, tml in enumerate(themes_list):
                    if theme in tml:
                        # 0 == System
                        return idx+1, theme, theme_density
        except Exception as e:
            print("Themes.get_saved_theme() error:", e)
        return 0, "", theme_density

    def save_theme(self, theme_idx, theme, density_scale):
        self._cfg.setSettings(self._cfg.DEFAULT_THEME_DENSITY_SCALE, density_scale)
        if theme_idx == 0:
            self._cfg.setSettings(self._cfg.DEFAULT_THEME, "")
        else:
            self._cfg.setSettings(self._cfg.DEFAULT_THEME, theme)

    def load_theme(self, app):
        try:
            theme_idx, theme_name, theme_density = self.get_saved_theme()

            if theme_name == "" or theme_name is None:
                # default to built-in dark
                theme_name = self.BUILTIN_DARK

            if theme_name in self.BUILTIN_THEMES:
                print("Using built-in theme:", theme_name)
                self._apply_builtin_theme(app, theme_name)
                return

            if not Themes.AVAILABLE:
                print("Using built-in dark theme (qt-material not available)")
                self._apply_builtin_theme(app, self.BUILTIN_DARK)
                return

            if theme_name != "":
                invert = "light" in theme_name
                fname = os.path.basename(theme_name)
                Themes.IS_DARK = fname.startswith("dark")

                print("Using theme:", theme_idx, theme_name, "inverted:", invert, "dark:", Themes.IS_DARK)
                extra_opts = {
                    'density_scale': theme_density
                }
                Themes.qtmaterial_apply_stylesheet(app, theme=theme_name,  invert_secondary=invert, extra=extra_opts)
        except Exception as e:
            print("Themes.load_theme() exception:", e)

    def change_theme(self, window, theme_name, extra={}):
        try:
            if theme_name in self.BUILTIN_THEMES:
                self._apply_builtin_theme(window, theme_name)
                return

            if theme_name == "System":
                window.setStyleSheet("")
                Themes.IS_DARK = False
                return

            if not Themes.AVAILABLE:
                return

            invert = "light" in theme_name
            fname = os.path.basename(theme_name)
            Themes.IS_DARK = fname.startswith("dark")

            Themes.qtmaterial_apply_stylesheet(window, theme=theme_name,  invert_secondary=invert, extra=extra)
        except Exception as e:
            print("Themes.change_theme() exception:", e, " - ", window, theme_name)

    def list_local_themes(self):
        themes = []
        try:
            for tdir in self.THEMES_PATH:
                if not os.path.isdir(tdir):
                    continue
                themes += glob.glob(tdir + "/themes/*.xml")
        except Exception:
            pass
        return themes

    def list_themes(self):
        themes = list(self.BUILTIN_THEMES.keys())
        themes += self.list_local_themes()
        if Themes.AVAILABLE:
            themes += Themes.qtmaterial_themes()
        return themes
