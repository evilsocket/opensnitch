from PyQt6 import QtCore
import os

from opensnitch.config import Config

DEFAULT_LANG = "en"
DEFAULT_LANGNAME = "English"

def __get_i18n_path():
    return os.path.dirname(os.path.realpath(__file__)) + "/../i18n"

def init(saved_lang):
    locale = QtCore.QLocale.system()
    lang = locale.name()
    if saved_lang:
        lang = saved_lang
    i18n_path = __get_i18n_path()
    print("Loading translations:", i18n_path, "locale:", lang)
    translator = QtCore.QTranslator()
    translator.load(i18n_path + "/" + lang + "/opensnitch-" + lang + ".qm")

    return translator

def save(cfg, lang):
    q = QtCore.QLocale(lang)
    langname = q.nativeLanguageName().capitalize()
    if lang == DEFAULT_LANG:
        langname = DEFAULT_LANGNAME
    cfg.setSettings(Config.DEFAULT_LANGUAGE, lang)
    cfg.setSettings(Config.DEFAULT_LANGNAME, langname)

def get_all():
    langs = [DEFAULT_LANG]
    names = [DEFAULT_LANGNAME]
    i18n_path = __get_i18n_path()
    lang_dirs = os.listdir(i18n_path)
    lang_dirs.sort()
    for lang in lang_dirs:
        q = QtCore.QLocale(lang)
        langs.append(lang)
        names.append(q.nativeLanguageName())
    return langs, names
