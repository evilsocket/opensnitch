from PyQt5 import QtCore
from opensnitch.database import Database

class Config:
    __instance = None

    HELP_URL = "https://github.com/evilsocket/opensnitch/wiki/"
    HELP_RULES_URL = "https://github.com/evilsocket/opensnitch/wiki/Rules"
    HELP_CONFIG_URL = "https://github.com/evilsocket/opensnitch/wiki/Configurations"

    RULE_TYPE_LIST = "list"
    RULE_TYPE_LISTS = "lists"
    RULE_TYPE_SIMPLE = "simple"
    RULE_TYPE_REGEXP = "regexp"
    RULE_TYPE_NETWORK = "network"
    RulesTypes = (RULE_TYPE_LIST, RULE_TYPE_LISTS, RULE_TYPE_SIMPLE, RULE_TYPE_REGEXP, RULE_TYPE_NETWORK)

    RULES_DURATION_FILTER = ()

    DEFAULT_DURATION_IDX = 6 # until restart
    DEFAULT_TARGET_PROCESS = 0
    ACTION_DENY_IDX = 0
    ACTION_ALLOW_IDX = 1

    # don't translate
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    ACTION_REJECT = "reject"
    DURATION_UNTIL_RESTART = "until restart"
    DURATION_ALWAYS = "always"
    DURATION_ONCE = "once"
    DURATION_1h = "1h"
    DURATION_30m = "30m"
    DURATION_15m = "15m"
    DURATION_5m = "5m"
    DURATION_30s = "30s"

    POPUP_CENTER = 0
    POPUP_TOP_RIGHT = 1
    POPUP_BOTTOM_RIGHT = 2
    POPUP_TOP_LEFT = 3
    POPUP_BOTTOM_LEFT = 4

    DEFAULT_THEME = "global/theme"
    DEFAULT_DISABLE_POPUPS = "global/disable_popups"
    DEFAULT_TIMEOUT_KEY  = "global/default_timeout"
    DEFAULT_ACTION_KEY   = "global/default_action"
    DEFAULT_DURATION_KEY = "global/default_duration"
    DEFAULT_TARGET_KEY   = "global/default_target"
    DEFAULT_IGNORE_RULES = "global/default_ignore_rules"
    DEFAULT_IGNORE_TEMPORARY_RULES = "global/default_ignore_temporary_rules"
    DEFAULT_POPUP_POSITION = "global/default_popup_position"
    DEFAULT_POPUP_ADVANCED = "global/default_popup_advanced"
    DEFAULT_POPUP_ADVANCED_DSTIP = "global/default_popup_advanced_dstip"
    DEFAULT_POPUP_ADVANCED_DSTPORT = "global/default_popup_advanced_dstport"
    DEFAULT_POPUP_ADVANCED_UID = "global/default_popup_advanced_uid"
    DEFAULT_SERVER_ADDR  = "global/server_address"
    DEFAULT_DB_TYPE_KEY  = "database/type"
    DEFAULT_DB_FILE_KEY  = "database/file"
    DEFAULT_DB_PURGE_OLDEST  = "database/purge_oldest"
    DEFAULT_DB_MAX_DAYS  = "database/max_days"
    DEFAULT_DB_PURGE_INTERVAL  = "database/purge_interval"

    NOTIFICATIONS_ENABLED = "notifications/enabled"
    NOTIFICATIONS_TYPE = "notifications/type"
    NOTIFICATION_TYPE_SYSTEM = 0
    NOTIFICATION_TYPE_QT = 1

    STATS_GEOMETRY = "statsDialog/geometry"
    STATS_LAST_TAB = "statsDialog/last_tab"
    STATS_FILTER_TEXT = "statsDialog/general_filter_text"
    STATS_FILTER_ACTION = "statsDialog/general_filter_action"
    STATS_LIMIT_RESULTS = "statsDialog/general_limit_results"
    STATS_SHOW_COLUMNS = "statsDialog/show_columns"
    STATS_NODES_COL_STATE = "statsDialog/nodes_columns_state"
    STATS_GENERAL_COL_STATE = "statsDialog/general_columns_state"
    STATS_GENERAL_FILTER_TEXT = "statsDialog/"
    STATS_GENERAL_FILTER_ACTION = "statsDialog/"
    STATS_RULES_COL_STATE = "statsDialog/rules_columns_state"
    STATS_RULES_TREE_EXPANDED_0 = "statsDialog/rules_tree_0_expanded"
    STATS_RULES_TREE_EXPANDED_1 = "statsDialog/rules_tree_1_expanded"
    STATS_RULES_SPLITTER_POS = "statsDialog/rules_splitter_pos"
    STATS_VIEW_COL_STATE =  "statsDialog/view_columns_state"
    STATS_VIEW_DETAILS_COL_STATE =  "statsDialog/view_details_columns_state"
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

        self.setRulesDurationFilter(
            self.getBool(self.DEFAULT_IGNORE_RULES),
            self.getInt(self.DEFAULT_IGNORE_TEMPORARY_RULES)
        )

    def reload(self):
        self.settings = QtCore.QSettings("opensnitch", "settings")

    def hasKey(self, key):
        return self.settings.contains(key)

    def setSettings(self, path, value):
        self.settings.setValue(path, value)
        self.settings.sync()

    def getSettings(self, path):
        return self.settings.value(path)

    def getBool(self, path, default_value=False):
        return self.settings.value(path, type=bool, defaultValue=default_value)

    def getInt(self, path, default_value=0):
        try:
            return self.settings.value(path, type=int, defaultValue=default_value)
        except Exception:
            return default_value

    def getDefaultAction(self):
        _default_action = self.getInt(self.DEFAULT_ACTION_KEY)
        if _default_action == self.ACTION_ALLOW_IDX:
            return self.ACTION_ALLOW
        else:
            return self.ACTION_DENY

    def setRulesDurationFilter(self, ignore_temporary_rules=False, temp_rules=1):
        if ignore_temporary_rules:
            if temp_rules  == 1:
                Config.RULES_DURATION_FILTER = (Config.DURATION_ONCE)
            elif temp_rules == 0:
                Config.RULES_DURATION_FILTER = (
                    Config.DURATION_ONCE, Config.DURATION_30s, Config.DURATION_5m,
                    Config.DURATION_15m, Config.DURATION_30m, Config.DURATION_1h,
                    Config.DURATION_UNTIL_RESTART)
        else:
            Config.RULES_DURATION_FILTER = ()
