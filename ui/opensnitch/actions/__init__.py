from PyQt5.QtCore import QObject

import json
import os
import glob
import sys

from opensnitch.utils.xdg import xdg_config_home
from opensnitch.actions import highlight
from opensnitch.actions.default_configs import commonDelegateConfig, rulesDelegateConfig, fwDelegateConfig

class Actions(QObject):
    """List of actions to perform on the data that is displayed on the GUI.
    Whenever an item matches a condition an action is applied, for example:
        - if the text of a cell matches a condition for the given columns,
        then the properties of the cell/row and the text are customized.

    There's only 1 action supported right now:
        - highlight: for customizing rows and cells appearance.

    There're 3 actions by default of type Highlight:
        - rules: applied to the rules to colorize the columns Enabled and
        Action
        - firewall: applied to the fw rules to colorize the columns Action and
        Target.
        - common: applied to the rest of the views to colorize the column
        Action.

    Users can modify the default actions, by adding more patterns to colorize.
    At the same time they can also create new actions to be applied on certain views.

    The format of the actions is JSON:
        {
        "created": "....",
        "name": "...",
        "actions": {
            "highlight": {
                "cells": [
                        {
                            "text": ["allow", "True", "online"],
                            "cols": [3,5,6],
                            "color": "green",
                        },
                        {
                            "text": ["deny", "False", "offline"],
                            "cols": [3,5,6],
                            "color": "red",
                        }
                    ],
                "rows": []
            }
        }

    """
    __instance = None

    # list of loaded actions
    _actions = None


    KEY_ACTIONS = "actions"
    KEY_NAME = "name"
    KEY_TYPE = "type"

    # TODO: emit a signal when the actions are (re)loaded
    # reloaded_signal = pyQtSignal()

    # default paths to look for actions
    _paths = [
        os.path.dirname(sys.modules[__name__].__file__) + "/data/",
        "{0}/{1}".format(xdg_config_home, "/opensnitch/actions/")
    ]

    @staticmethod
    def instance():
        if Actions.__instance == None:
            Actions.__instance = Actions()
        return Actions.__instance

    def __init__(self, parent=None):
        QObject.__init__(self)
        self._actions_list = {}
        try:
            base_dir = "{0}/{1}".format(xdg_config_home, "/opensnitch/actions/")
            os.makedirs(base_dir, 0o700)
        except:
            pass

    def _load_default_configs(self):
        self._actions_list[commonDelegateConfig[Actions.KEY_NAME]] = self.compile(commonDelegateConfig)
        self._actions_list[rulesDelegateConfig[Actions.KEY_NAME]] = self.compile(rulesDelegateConfig)
        self._actions_list[fwDelegateConfig[Actions.KEY_NAME]] = self.compile(fwDelegateConfig)

    def loadAll(self):
        """look for actions firstly on default system path, secondly on
        user's home.
        If a user customizes existing configurations, they'll be saved under
        the user's home directory.

        Action files are .json files.
        """
        self._load_default_configs()

        for path in self._paths:
            for jfile in glob.glob(os.path.join(path, '*.json')):
                self.load(jfile)

    def load(self, action_file):
        """read a json file from disk and create the action."""
        with open(action_file, 'r') as fd:
            data=fd.read()
            obj = json.loads(data)
            self._actions_list[obj[Actions.KEY_NAME]] = self.compile(obj)

    def compile(self, obj):
        try:
            if Actions.KEY_NAME not in obj or obj[Actions.KEY_NAME] == "":
                return None
            if obj.get(Actions.KEY_ACTIONS) == None:
                return None

            for action in obj[Actions.KEY_ACTIONS]:
                if action == highlight.Highlight.NAME:
                    h = highlight.Highlight(obj[Actions.KEY_ACTIONS][action])
                    h.compile()
                    obj[Actions.KEY_ACTIONS][action]= h
                else:
                    print("Actions exception: Action '{0}' not supported yet".format(obj[Actions.KEY_NAME]))

            return obj
        except Exception as e:
            print("Actions.compile() exception:", e)
            return None



    def getAll(self):
        return self._actions_list

    def deleteAll(self):
        self._actions_list = {}

    def get(self, name):
        try:
            return self._actions_list[name]
        except Exception as e:
            print("get() exception:", e)
            return None

    def delete(self, name):
        try:
            del self._actions_list[name]
            # TODO:
            # self.reloaded_signal.emit()
        except:
            pass

    def isValid(self):
        pass
