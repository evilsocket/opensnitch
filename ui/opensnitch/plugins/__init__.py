from PyQt5 import QtCore
from abc import ABC, abstractmethod
from importlib import util
import os
import gc
import weakref

from opensnitch.config import Config

class PluginSignal(QtCore.QObject):
    signal = QtCore.pyqtSignal(dict)

    # actions to send to the plugins
    DISABLE = 0
    ENABLE = 1
    CONFIG_UPDATE = 2
    ERROR = 3
    STOP = 4

    def __init__(self):
        QtCore.QObject.__init__(self)

    def emit(self, args):
        self.signal.emit(args)

    def connect(self, callback):
        self.signal.connect(callback)

    def disconnect(self, callback):
        self.signal.disconnect(callback)

    #@QtCore.pyqtSlot(dict)
    def cb_signal(self, args):
        self.signal.disconnect(callback)

class PluginsList():
    """plugins store. Whenever a plugin is instantiated, it's added to the
    plugin list automatically
    """
    actions = []
    names = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.name != 'PluginBase' and cls.name not in PluginsList.names:
            cls.actions.append(cls)
            cls.names[cls.name] = cls

class PluginBase(PluginsList, ABC):
    """Base class for every plugin.
    A plugin may be applied on different areas of the GUI:
        - globally
          * Background tasks.
          * periodic downloaders.
          * DB.
        - popups
        - views (generic connections lists)
        - view-details
        - procs-list (processes listed on the Proc tab)
        - domains-list (domains listed on the Host tab)
        - proc-dialog

    It may have support for one or multiple types.

    Every plugin can connect to the signal 'updated', to receive events, like:
        - enable/disable
        - configuration update/reload.

    As of v1.7.0 plugins are not called directly. They're defined in "actions",
    compiled when loading, and configured when called from every view, dialog,
    etc.

    When calling compile(), every plugin must create the python objects needed,
    so they can be reused later when run() is called.

    When calling configure(), every plugin is responsable to modify the GUI
    as needed, adding new buttons, modifying existing widgets, behaviour, ...
    """
    name = "PluginBase"
    version = 0
    author = "opensnitch"
    created = ""
    modified = ""
    description = "<empty description>"
    #enabled = False

    TYPE = []
    # allowed types that every plugin must declare
    TYPE_GLOBAL = "global"
    TYPE_POPUPS = "popups"
    TYPE_MAIN_DIALOG = "main-dialog"
    TYPE_PROC_DIALOG = "proc-dialog"
    TYPE_PROCS_LIST = "procs-list"
    TYPE_DOMAINS_LIST = "domains-list"
    TYPE_IPS_LIST = "ips-list"
    TYPE_VIEWS = "views"
    TYPE_VIEW_DETAILS = "view-details"

    # Generic signal to send data to all plugins' instances.
    # A plugin may have been instanstiated on many configurations,
    # this way we can enable/update/etc all the instances of a particular
    # plugin.

    # signals sent to the plugin
    signal_in = PluginSignal()

    # signals emitted by the plugin
    signal_out = PluginSignal()

    def __init__(self):
        pass

    def get_name(self):
        return self.name

    def is_enabled(self):
        return self.enabled

    def set_enabled(self, enable):
        self.enabled = enable

    def get_description(self):
        return self.description

    @abstractmethod
    def configure(self):
        raise NotImplementedError("Needs to be implemented")

    @abstractmethod
    def compile(self):
        raise NotImplementedError("Needs to be implemented")

    @abstractmethod
    def run(self, args):
        raise NotImplementedError("Needs to be implemented")

class PluginsManager():
    __instance = None

    @staticmethod
    def instance():
        if PluginsManager.__instance == None:
            PluginsManager.__instance = PluginsManager()
        return PluginsManager.__instance

    def __init__(self):
        path = os.path.abspath(__file__)
        # TODO: allow to load plugins from a different location
        self._plugins_loaded = weakref.WeakValueDictionary()
        self._plugins_path = os.path.dirname(path)

        self._cfg = Config.get()
        self.enabled_plugins = self._cfg.getSettings(Config.PLUGINS)
        # FIXME: don't hardcode this plugin here.
        # For now, load Highlight plugin by default.
        if self.enabled_plugins == None:
            self.enabled_plugins = ['highlight']
        # if there's only 1 plugin enabled, the type will be str instead of
        # list
        if type(self.enabled_plugins) == str:
            self.enabled_plugins = [self.enabled_plugins]
        if 'highlight' not in self.enabled_plugins:
            self.enabled_plugins.append('highlight')
        #print("enabled plugins >>", self.enabled_plugins)

    def load_plugins(self):
        #print("PluginsManager.load_plugins()", self._plugins_path)
        for dname in os.listdir(self._plugins_path):
            self.load_plugin_byname(dname)

        #print("PluginsManager:", PluginsList.actions)
        for plug in PluginsList.actions:
            p = plug()
            p.signal_in.emit({"plugin": p.get_name(), "signal": PluginSignal.ENABLE})
            #print("plugin ->", p.get_name())

    def load_plugin_byname(self, name, force=False):
        path = os.path.join(self._plugins_path, name)
        if os.path.isdir(path) == False:
            return False
        # the loading of the plugin is based on the file name
        pname = os.path.join(path, name + ".py")
        #print("load_plugin_byname.plugin path:", pname)
        if os.path.exists(pname) == False:
            return False

        return self.load_plugin(pname, force)

    def load_plugin(self, path, force=False):
        """loads the .py file, the name of the file is used to load the plugin
        """
        #print("loading plugin:", path)
        name = os.path.split(path)[-1]
        if self.enabled_plugins == None and not force:
            #print("skipping not enabled plugin:", name)
            return False
        if name[:-3] not in self.enabled_plugins and force == False:
            #print("PluginsManager: plugin disabled:", name[:-3])
            return False

        # Whenever a plugin is loaded, it's automatically added to the
        # PluginsList class.
        spec = util.spec_from_file_location(name, path)
        module = util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self._plugins_loaded[module] = spec

        return True

    def unload_all(self):
        for mod in self._plugins_loaded:
            #print("PluginsManager.unload_all()", mod)
            del mod
        gc.collect()
