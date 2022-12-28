from PyQt5.QtCore import QObject, pyqtSignal

from opensnitch import ui_pb2
from opensnitch.database import Database
from opensnitch.config import Config

from datetime import datetime

class Rules(QObject):
    __instance = None
    nodesUpdated = pyqtSignal(int)

    LOG_TAG = "[Rules]: "

    @staticmethod
    def instance():
        if Rules.__instance == None:
            Rules.__instance = Rules()
        return Rules.__instance

    def __init__(self):
        QObject.__init__(self)
        self._db = Database.instance()

    def add(self, time, node, name, description, enabled, precedence, nolog, action, duration, op_type, op_sensitive, op_operand, op_data):
        # don't add rule if the user has selected to exclude temporary
        # rules
        if duration in Config.RULES_DURATION_FILTER:
            return

        self._db.insert("rules",
                  "(time, node, name, description, enabled, precedence, nolog, action, duration, operator_type, operator_sensitive, operator_operand, operator_data)",
                  (time, node, name, description, enabled, precedence, nolog, action, duration, op_type, op_sensitive, op_operand, op_data),
                        action_on_conflict="REPLACE")

    def add_rules(self, addr, rules):
        try:
            for _,r in enumerate(rules):
                self.add(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                              addr,
                              r.name, r.description, str(r.enabled),
                              str(r.precedence), str(r.nolog), r.action, r.duration,
                              r.operator.type,
                              str(r.operator.sensitive),
                              r.operator.operand, r.operator.data)
        except Exception as e:
            print(self.LOG_TAG + " exception adding node rules to db: ", e)

    def delete(self, name, addr, callback):
        rule = ui_pb2.Rule(name=name)
        rule.enabled = False
        rule.action = ""
        rule.duration = ""
        rule.operator.type = ""
        rule.operator.operand = ""
        rule.operator.data = ""

        if not self._db.delete_rule(rule.name, addr):
            return None

        return rule

    def update_time(self, time, name, addr):
        self._db.update("rules",
                        "time=?",
                        (time, name, addr),
                        "name=? AND node=?",
                        action_on_conflict="OR REPLACE"
                        )
