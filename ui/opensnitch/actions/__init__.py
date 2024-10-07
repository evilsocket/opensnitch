import json
import os
import glob
import sys

from PyQt5.QtCore import QObject

from opensnitch.utils.xdg import xdg_config_home
from opensnitch.actions.default_configs import (
    commonDelegateConfig,
    rulesDelegateConfig,
    fwDelegateConfig,
    netstatDelegateConfig
)

from opensnitch.plugins import PluginsList
from opensnitch.plugins import PluginsManager

class Actions(QObject):
    """List of actions to perform on the data that is displayed on the GUI,
    defined in JSON files.

    Whenever an item (popup, cell, etc) matches a condition, an action
    (config/plugin) is applied. For example:
        - if the text of a cell matches a condition for the given columns,
        then the properties of the cell/row and the text are colorized.
        - if the result of an analysis of a domain is malicious, colorize
        popups' text labels in red + add a tab with the result of the analysis.

    The actions are defined in JSON format:
        {
        "created": "....",
        "name": "...",
        "type": ["views"],
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

        "type" field is the area of the GUI where the actions will be applied:

             "global" -> global actions, like background tasks.
             "views"  -> applies to Views (lists of items), QItemDelegate
             "popups" -> applies to popups.
             "main-dialog" -> applies to the main window.
             "proc-dialog" -> applies to the Process dialog.
             "procs-list" -> applies to the Procs view. (TODO)
             "domains-list" -> applies to the Domains view. (TODO)
             "ips-list" -> applies to the IPs view. (TODO)
             "db" -> applies to the DB. Modify items before inserting, react to
              data being added, etc. (TODO)

        "actions" is the list of actions to execute:

            - the name of the action defines the python plugin to load:
                "highligh" -> plugins/highligh/highlight.py
                "downloader" -> plugins/downloader/downloader.py, etc.
            - every action has its own plugin (*.py file) which is in charge
            of parse and compile to configuration if needed.
              For example for "highlight" action, "color": "red" is compiled
              to QtColor("red")

    There're 3 hardcoded actions by default of type Highlight:
        - rules: applied to the rules to colorize the columns Enabled and
        Action
        - firewall: applied to the fw rules to colorize the columns Action and
        Target.
        - common: applied to the rest of the views to colorize the column
        Action.

    Users can modify the default actions, by adding more patterns to colorize,
    and saving them to $XDG_CONFIG_HOME/opensnitch/actions/myaction.json

    At the same time they can also create new actions in that directory
    to be applied on certain views.

    """
    __instance = None

    # list of loaded actions
    _actions_list = {}
    _plugins = []


    KEY_ACTIONS = "actions"
    KEY_NAME = "name"
    KEY_TYPE = "type"

    # TODO: emit a signal when the actions are (re)loaded
    # reloaded_signal = pyQtSignal()

    # default paths to look for actions
    _paths = [
        #os.path.dirname(sys.modules[__name__].__file__) + "/data/",
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
        self._plugin_mgr = PluginsManager.instance()
        try:
            base_dir = "{0}/{1}".format(xdg_config_home, "/opensnitch/actions/")
            os.makedirs(base_dir, 0o700)
        except Exception as e:
            print("actions.__init__ exception:", e)
        #print("ActionsLists:", PluginsList.actions)

    def _load_default_configs(self):
        # may be overwritten by user choice
        self._actions_list[commonDelegateConfig[Actions.KEY_NAME]] = self.compile(commonDelegateConfig)
        self._actions_list[rulesDelegateConfig[Actions.KEY_NAME]] = self.compile(rulesDelegateConfig)
        self._actions_list[fwDelegateConfig[Actions.KEY_NAME]] = self.compile(fwDelegateConfig)
        self._actions_list[netstatDelegateConfig[Actions.KEY_NAME]] = self.compile(netstatDelegateConfig)

    def load(self, action_file):
        """read a json file from disk and create the action."""
        try:
            with open(action_file, 'r') as fd:
                data=fd.read()
                obj = json.loads(data)
                action = self.compile(obj)
                return obj, action
        except:
            pass

        return None, None

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
                #print("Actions.loadconf()", jfile)
                obj, action = self.load(jfile)
                if obj and action:
                    self._actions_list[obj[Actions.KEY_NAME]] = action

    def compile(self, json_obj):
        """translates json definitions to python objects"""
        try:
            if Actions.KEY_NAME not in json_obj or json_obj[Actions.KEY_NAME] == "":
                return None
            if json_obj.get(Actions.KEY_ACTIONS) == None:
                return None

            # "actions": { "highlight": ..., "virustotal": ..., }
            #print("plugins >>", PluginsList.names)
            for action_name in json_obj[Actions.KEY_ACTIONS]:
                action_obj = json_obj[Actions.KEY_ACTIONS][action_name]
                if action_obj == None or action_obj.get('enabled') == None or action_obj.get('enabled') == False:
                    print("actions.compile() skipping disabled action '{0}'".format(action_name))
                    # FIXME: if one of the action is not enabled, we're
                    # invalidating all the configured actions.
                    return None

                # see if the plugin is loaded, if it's not, try to load it.
                if PluginsList.names.get(action_name.capitalize()) == None:
                    if self._plugin_mgr.load_plugin_byname(action_name, force=True) == False:
                        print("actions.compile() unable to load plugin name '{0}'".format(action_name))
                        return None

                # allow to use "Plugin" or "plugin" to name actions in json
                # files.
                # python class will be always capitalized.
                _p = PluginsList.names.get(action_name.capitalize())
                plug = _p(action_obj)

                # compile the plugin, preparing/configuring the plugin
                # before it's used.
                plug.compile()

                # save the "compiled" action to the action list
                json_obj[Actions.KEY_ACTIONS][action_name]= plug

            return json_obj
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
            print("actions.get() exception:", e, "name:", name)
            return None

    def getByType(self, acttype):
        try:
            actlist = {}
            for name in self._actions_list:
                act = self._actions_list[name]
                if act == None:
                    print("actions.getByType() none:", name)
                    continue
                types = act.get('type')
                if types == None:
                    continue
                if acttype in types:
                    actlist[name] = self._actions_list[name]
            return actlist
        except Exception as e:
            print("actions.getByType() ({0}) exception: {1}".format(acttype, e))
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
