from PyQt5.QtCore import QObject, pyqtSignal

from opensnitch import ui_pb2
from opensnitch.database import Database
from opensnitch.config import Config

import os
import json
from datetime import datetime
from google.protobuf.json_format import MessageToJson, Parse

class Rule():
    def __init__(self):
        pass

    @staticmethod
    def to_bool(s):
        return s == 'True'

    @staticmethod
    def new_empty():
        pass

    @staticmethod
    def new_from_records(records):
        """Creates a new protobuf Rule from DB records.
        Fields of the record are in the order defined on the DB.
        """
        rule = ui_pb2.Rule(name=records.value(2))
        rule.enabled = Rule.to_bool(records.value(3))
        rule.precedence = Rule.to_bool(records.value(4))
        rule.action = records.value(5)
        rule.duration = records.value(6)
        rule.operator.type = records.value(7)
        rule.operator.sensitive = Rule.to_bool(records.value(8))
        rule.operator.operand = records.value(9)
        rule.operator.data = "" if records.value(10) == None else str(records.value(10))
        rule.description = records.value(11)
        rule.nolog = Rule.to_bool(records.value(12))

        return rule


class Rules(QObject):
    __instance = None
    updated = pyqtSignal(int)

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

            return True
        except Exception as e:
            print(self.LOG_TAG + " exception adding node rules to db: ", e)
            return False

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
        """Updates the time of a rule, whenever a new connection matched a
        rule.
        """
        self._db.update("rules",
                        "time=?",
                        (time, name, addr),
                        "name=? AND node=?",
                        action_on_conflict="OR REPLACE"
                        )

    def export_rules(self, node, outdir):
        """Gets the the rules from the DB and writes them out to a directory.
        A new directory per node will be created.
        """
        records = self._db.get_rules(node)
        if records == None:
            return False

        try:
            while records.next() != False:
                rule = Rule.new_from_records(records)

                rulesdir = outdir + "/" + node
                try:
                    os.makedirs(rulesdir, 0o700)
                except:
                    pass
                rulename = rule.name
                if ".json" not in rulename:
                    rulename = rulename + ".json"
                with open(rulesdir  + "/" + rulename, 'w') as jsfile:
                    actual_json_text = MessageToJson(rule)
                    jsfile.write( actual_json_text )

        except Exception as e:
            print(self.LOG_TAG, "export_rules(", node, outdir, ") exception:", e)
            return False

        return True

    def import_rules(self, rulesdir):
        """Read a directory with rules in json format, and parse them out to protobuf
        Returns a list of rules on success, or None on error.
        """
        try:
            rules = []
            for rulename in os.listdir(rulesdir):
                with open(rulesdir  + "/" + rulename, 'r') as f:
                    jsrule = f.read()
                    pb_rule = Parse(text=jsrule, message=ui_pb2.Rule(), ignore_unknown_fields=True)
                    rules.append(pb_rule)

            return rules
        except Exception as e:
            print(self.LOG_TAG, "import_rules() exception:", e)

        return None
