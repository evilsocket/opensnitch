import os
from PyQt5 import QtCore

class Config:
    __instance = None

    HELP_URL = "https://github.com/gustavo-iniguez-goya/opensnitch/wiki/Configurations"

    RulesTypes = ("list", "simple", "regexp", "network")

    DEFAULT_DURATION_IDX = 6 # until restart
    DEFAULT_TARGET_PROCESS = 0
    # don't translate
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    DURATION_UNTIL_RESTART = "until restart"
    DURATION_ALWAYS = "always"
    DURATION_ONCE = "once"

    DEFAULT_TIMEOUT_KEY  = "global/default_timeout"
    DEFAULT_ACTION_KEY   = "global/default_action"
    DEFAULT_DURATION_KEY = "global/default_duration"
    DEFAULT_TARGET_KEY   = "global/default_target"
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

        if self.settings.value(self.DEFAULT_TIMEOUT_KEY) == None:
            self.setSettings(self.DEFAULT_TIMEOUT_KEY, 15)
        if self.settings.value(self.DEFAULT_ACTION_KEY) == None:
            self.setSettings(self.DEFAULT_ACTION_KEY, self.ACTION_ALLOW)
        if self.settings.value(self.DEFAULT_DURATION_KEY) == None:
            self.setSettings(self.DEFAULT_DURATION_KEY, self.DEFAULT_DURATION_IDX)
        if self.settings.value(self.DEFAULT_TARGET_KEY) == None:
            self.setSettings(self.DEFAULT_TARGET_KEY, self.DEFAULT_TARGET_PROCESS)

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
