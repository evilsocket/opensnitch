from PyQt5 import QtCore
import os

from opensnitch.config import Config

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
    cfg.setSettings(Config.DEFAULT_LANGUAGE, lang)
    cfg.setSettings(Config.DEFAULT_LANGNAME, q.nativeLanguageName().capitalize())

def get_all():
    langs = []
    names = []
    i18n_path = __get_i18n_path()
    lang_dirs = os.listdir(i18n_path)
    lang_dirs.sort()
    for lang in lang_dirs:
        q = QtCore.QLocale(lang)
        langs.append(lang)
        names.append(q.nativeLanguageName())
    return langs, names
