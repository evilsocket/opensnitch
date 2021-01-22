import os
from PyQt5 import QtCore

class Config:
    __instance = None

    HELP_URL = "https://github.com/gustavo-iniguez-goya/opensnitch/wiki/Configurations"

    RulesTypes = ("list", "simple", "regexp", "network")

    # don't translate
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    DURATION_UNTIL_RESTART = "until restart"
    DURATION_ALWAYS = "always"
    DURATION_ONCE = "once"
    # don't translate

    @staticmethod
    def init():
        Config.__instance = Config()
        return Config.__instance

    @staticmethod
    def get():
        if Config.__instance == None:
            Config._instance = Config()
        return Config.__instance

    def __init__(self):
        self.settings = QtCore.QSettings("opensnitch", "settings")

        if self.settings.value("global/default_timeout") == None:
            self.setSettings("global/default_timeout", 15)
        if self.settings.value("global/default_action") == None:
            self.setSettings("global/default_action", "allow")
        if self.settings.value("global/default_duration") == None:
            self.setSettings("global/default_duration", "until restart")
        if self.settings.value("global/default_target") == None:
            self.setSettings("global/default_target", 0)

    def reload(self):
        self.settings = QtCore.QSettings("opensnitch", "settings")

    def hasKey(self, key):
        return self.settings.contains(key)

    def setSettings(self, path, value):
        self.settings.setValue(path, value)
        self.settings.sync()

    def getSettings(self, path):
        return self.settings.value(path)

    def getBool(self, path):
        return self.settings.value(path, False, type=bool)

    def getInt(self, path):
        try:
            return self.settings.value(path, False, type=int)
        except Exception:
            return 0
