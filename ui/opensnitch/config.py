import os
from PyQt5 import QtCore

class Config:
    __instance = None

    @staticmethod
    def init():
        Config.__instance = Config()
        return Config.__instance

    @staticmethod
    def get():
        return Config.__instance

    def __init__(self):
        self.settings = QtCore.QSettings("opensnitch", "settings")

        if self.settings.value("global/default_timeout") == None:
            self.setSettings("global/default_timeout", 15)
            self.setSettings("global/default_action", "allow")
            self.setSettings("global/default_duration", "until restart")

    def setSettings(self, path, value):
        self.settings.setValue(path, value)

    def getSettings(self, path):
        return self.settings.value(path)
