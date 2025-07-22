import os.path
import sys, glob
from PyQt5 import QtCore

from opensnitch.config import Config

# WA for #1373
qtm_home = "{0}/.qt_material/theme/".format(QtCore.QDir.homePath())
if qtm_home not in QtCore.QDir.searchPaths("icon"):
    QtCore.QDir.addSearchPath("icon", qtm_home)

class Themes():
    """Change GUI's appearance using qt-material lib.
    https://github.com/dunderlab/qt-material
    """
    THEMES_PATH = [
        os.path.expanduser("~/.config/opensnitch/"),
        os.path.dirname(sys.modules[__name__].__file__)
    ]
    __instance = None

    AVAILABLE = False
    IS_DARK = False
    try:
        from qt_material import apply_stylesheet as qtmaterial_apply_stylesheet
        from qt_material import list_themes as qtmaterial_themes
        AVAILABLE = True
    except Exception:
        print("Themes not available. Install qt-material if you want to change GUI's appearance: pip3 install qt-material.")

    @staticmethod
    def instance():
        if Themes.__instance == None:
            Themes.__instance = Themes()
        return Themes.__instance

    def __init__(self):
        self._cfg = Config.get()
        theme = self._cfg.getInt(self._cfg.DEFAULT_THEME, 0)

    def available(self):
        return Themes.AVAILABLE

    def get_saved_theme(self):
        theme = self._cfg.getSettings(self._cfg.DEFAULT_THEME)
        theme_density = self._cfg.getSettings(self._cfg.DEFAULT_THEME_DENSITY_SCALE)
        if theme_density == "" or theme_density == None:
            theme_density = '0'

        if not Themes.AVAILABLE:
            return 0, "", theme_density

        try:
            if theme != "" and theme != None:
                # 0 == System
                return self.list_themes().index(theme)+1, theme, theme_density
        except Exception as e:
            print("Themes.get_saved_theme() error:", e)
        return 0, "", theme_density

    def save_theme(self, theme_idx, theme, density_scale):
        if not Themes.AVAILABLE:
            return

        self._cfg.setSettings(self._cfg.DEFAULT_THEME_DENSITY_SCALE, density_scale)
        if theme_idx == 0:
            self._cfg.setSettings(self._cfg.DEFAULT_THEME, "")
        else:
            self._cfg.setSettings(self._cfg.DEFAULT_THEME, theme)

    def load_theme(self, app):
        if not Themes.AVAILABLE:
            return

        try:
            theme_idx, theme_name, theme_density = self.get_saved_theme()
            if theme_name != "":
                invert = "light" in theme_name
                fname = os.path.basename(theme_name)
                Themes.IS_DARK = fname.startswith("dark")

                print("Using theme:", theme_idx, theme_name, "inverted:", invert, "dark:", Themes.IS_DARK)
                # TODO: load {theme}.xml.extra and .xml.css for further
                # customizations.
                extra_opts = {
                    'density_scale': theme_density
                }
                Themes.qtmaterial_apply_stylesheet(app, theme=theme_name,  invert_secondary=invert, extra=extra_opts)
        except Exception as e:
            print("Themes.load_theme() exception:", e)

    def change_theme(self, window, theme_name, extra={}):
        try:
            invert = "light" in theme_name
            fname = os.path.basename(theme_name)
            Themes.IS_DARK = fname.startswith("dark")

            Themes.qtmaterial_apply_stylesheet(window, theme=theme_name,  invert_secondary=invert, extra=extra)
        except Exception as e:
            print("Themes.change_theme() exception:", e, " - ", window, theme_name)

    def list_local_themes(self):
        themes = []
        if not Themes.AVAILABLE:
            return themes

        try:
            for tdir in self.THEMES_PATH:
                themes += glob.glob(tdir + "/themes/*.xml")
        except Exception:
            pass
        finally:
            return themes

    def list_themes(self):
        themes = self.list_local_themes()
        if not Themes.AVAILABLE:
            return themes

        themes += Themes.qtmaterial_themes()
        return themes
