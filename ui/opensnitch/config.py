import os
from PyQt5 import QtCore
from opensnitch.database import Database

class Config:
    __instance = None

    HELP_URL = "https://github.com/evilsocket/opensnitch/wiki/Configurations"

    RulesTypes = ("list", "lists", "simple", "regexp", "network")

    DEFAULT_DURATION_IDX = 6 # until restart
    DEFAULT_TARGET_PROCESS = 0
    # don't translate
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    DURATION_UNTIL_RESTART = "until restart"
    DURATION_ALWAYS = "always"
    DURATION_ONCE = "once"
    DURATION_1h = "1h"
    DURATION_30m = "30m"
    DURATION_15m = "15m"
    DURATION_5m = "5m"

    POPUP_CENTER = 0
    POPUP_TOP_RIGHT = 1
    POPUP_BOTTOM_RIGHT = 2
    POPUP_TOP_LEFT = 3
    POPUP_BOTTOM_LEFT = 4

    DEFAULT_DISABLE_POPUPS = "global/disable_popups"
    DEFAULT_TIMEOUT_KEY  = "global/default_timeout"
    DEFAULT_ACTION_KEY   = "global/default_action"
    DEFAULT_DURATION_KEY = "global/default_duration"
    DEFAULT_TARGET_KEY   = "global/default_target"
    DEFAULT_POPUP_POSITION = "global/default_popup_position"
    DEFAULT_POPUP_ADVANCED = "global/default_popup_advanced"
    DEFAULT_POPUP_ADVANCED_DSTIP = "global/default_popup_advanced_dstip"
    DEFAULT_POPUP_ADVANCED_DSTPORT = "global/default_popup_advanced_dstport"
    DEFAULT_POPUP_ADVANCED_UID = "global/default_popup_advanced_uid"
    DEFAULT_DB_TYPE_KEY  = "database/type"
    DEFAULT_DB_FILE_KEY  = "database/file"
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
        if self.settings.value(self.DEFAULT_DB_TYPE_KEY) == None:
            self.setSettings(self.DEFAULT_DB_TYPE_KEY, Database.DB_TYPE_MEMORY)
            self.setSettings(self.DEFAULT_DB_FILE_KEY, Database.DB_IN_MEMORY)

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
