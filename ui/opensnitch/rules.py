from PyQt5.QtCore import QObject, pyqtSignal

from opensnitch import ui_pb2
from opensnitch.database import Database
from opensnitch.database.enums import RuleFields
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
        rule = ui_pb2.Rule(name=records.value(RuleFields.Name))
        rule.enabled = Rule.to_bool(records.value(RuleFields.Enabled))
        rule.precedence = Rule.to_bool(records.value(RuleFields.Precedence))
        rule.action = records.value(RuleFields.Action)
        rule.duration = records.value(RuleFields.Duration)
        rule.operator.type = records.value(RuleFields.OpType)
        rule.operator.sensitive = Rule.to_bool(records.value(RuleFields.OpSensitive))
        rule.operator.operand = records.value(RuleFields.OpOperand)
        rule.operator.data = "" if records.value(RuleFields.OpData) == None else str(records.value(RuleFields.OpData))
        rule.description = records.value(RuleFields.Description)
        rule.nolog = Rule.to_bool(records.value(RuleFields.NoLog))
        created = int(datetime.now().timestamp())
        if records.value(RuleFields.Created) != "":
            created = int(datetime.strptime(
                records.value(RuleFields.Created), "%Y-%m-%d %H:%M:%S"
            ).timestamp())
        rule.created = created

        try:
            # Operator list is always saved as json string to the db,
            # so we need to load the json string.
            if rule.operator.type == Config.RULE_TYPE_LIST:
                operators = json.loads(rule.operator.data)
                for op in operators:
                    rule.operator.list.extend([
                        ui_pb2.Operator(
                            type=op['type'],
                            operand=op['operand'],
                            sensitive=False if op.get('sensitive') == None else op['sensitive'],
                            data="" if op.get('data') == None else op['data']
                        )
                    ])
                rule.operator.data = ""
        except Exception as e:
            print("new_from_records exception parsing operartor list:", e)


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

    def add(self, time, node, name, description, enabled, precedence, nolog, action, duration, op_type, op_sensitive, op_operand, op_data, created):
        # don't add rule if the user has selected to exclude temporary
        # rules
        if duration in Config.RULES_DURATION_FILTER:
            return

        self._db.insert("rules",
                  "(time, node, name, description, enabled, precedence, nolog, action, duration, operator_type, operator_sensitive, operator_operand, operator_data, created)",
                  (time, node, name, description, enabled, precedence, nolog, action, duration, op_type, op_sensitive, op_operand, op_data, created),
                        action_on_conflict="REPLACE")

    def add_rules(self, addr, rules):
        try:
            for _,r in enumerate(rules):
                # Operator list is always saved as json string to the db.
                rjson = json.loads(MessageToJson(r))
                if r.operator.type == Config.RULE_TYPE_LIST and rjson.get('operator') != None and rjson.get('operator').get('list') != None:
                    r.operator.data = json.dumps(rjson.get('operator').get('list'))

                self.add(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         addr,
                         r.name, r.description, str(r.enabled),
                         str(r.precedence), str(r.nolog), r.action, r.duration,
                         r.operator.type,
                         str(r.operator.sensitive),
                         r.operator.operand, r.operator.data,
                         str(datetime.fromtimestamp(r.created).strftime("%Y-%m-%d %H:%M:%S")))

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

    def delete_by_field(self, field, values):
        return self._db.delete_rules_by_field(field, values)

    def get_by_name(self, node, name):
        return self._db.get_rule(name, node)

    def get_by_field(self, node, field, value):
        return self._db.get_rule_by_field(node, field, value)

    def exists(self, rule, node_addr):
        return self._db.rule_exists(rule, node_addr)

    def new_unique_name(self, rule_name, node_addr, prefix):
        """generate a new name, if the supplied one already exists
        """
        if self._db.get_rule(rule_name, node_addr).next() == False:
            return rule_name

        for idx in range(0, 100):
            new_rule_name = "{0}-{1}".format(rule_name, idx)
            if self._db.get_rule(new_rule_name, node_addr).next() == False:
                return new_rule_name

        return rule_name

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

    def rule_to_json(self, node, rule_name):
        try:
            records = self._db.get_rule(rule_name, node)
            if records == None or records == -1:
                return None
            if not records.next():
                return None
            rule = Rule.new_from_records(records)
            # exclude this field when exporting to json
            tempRule = MessageToJson(rule)
            jRule = json.loads(tempRule)
            jRule['created'] = str(datetime.fromtimestamp(
                rule.created).strftime("%Y-%m-%d %H:%M:%S")
            )
            return json.dumps(jRule, indent="    ")
        except Exception as e:
            print("rule_to_json() exception:", e)
            return None

    def export_rule(self, node, rule_name, outdir):
        """Gets the the rule from the DB and writes it out to a directory.
        A new directory per node will be created.
        """
        try:
            records = self._db.get_rule(rule_name, node)
            if records.next() == False:
                print("export_rule() get_error 2:", records)
                return False

            rule = Rule.new_from_records(records)
            rulesdir = outdir + "/" + node
            try:
                os.makedirs(rulesdir, 0o700)
            except Exception as e:
                print("exception creating dirs:", e)
            rulename = rule.name
            if ".json" not in rulename:
                rulename = rulename + ".json"
            with open(rulesdir  + "/" + rulename, 'w') as jsfile:
                actual_json_text = MessageToJson(rule)
                jsfile.write( actual_json_text )

            return True
        except Exception as e:
            print(self.LOG_TAG, "export_rules(", node, outdir, ") exception:", e)

        return False

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
