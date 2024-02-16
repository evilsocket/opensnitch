from PyQt5.QtCore import QCoreApplication as QC
from opensnitch.config import Config
from opensnitch.rules import Rule

def verify(con, rule):
    """return true if the checksum of a rule matches the one of the process
    opening a connection.
    """
    if rule.operator.type != Config.RULE_TYPE_LIST:
        return True, ""

    if con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5] == "":
        return True, ""

    for ro in rule.operator.list:
        if ro.type == Config.RULE_TYPE_SIMPLE and ro.operand == Config.OPERAND_PROCESS_HASH_MD5:
            if ro.data != con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]:
                return False, ro.data

    return True, ""

def update_rule(node, rules, rule_name, con):
    """try to obtain the rule from the DB by name.
    return the rule on success, or None + error message on error.
    """

    # get rule from the db
    records = rules.get_by_name(node, rule_name)
    if records == None or records.first() == False:
        return None, QC.translate("popups", "Rule not updated, not found by name")

    # transform it to proto rule
    rule_obj = Rule.new_from_records(records)
    if rule_obj.operator.type != Config.RULE_TYPE_LIST:
        if rule_obj.operator.operand == Config.OPERAND_PROCESS_HASH_MD5:
            rule_obj.operator.data = con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]
    else:
        for op in rule_obj.operator.list:
            if op.operand == Config.OPERAND_PROCESS_HASH_MD5:
                op.data = con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]
                break
    # add it back again to the db
    added = rules.add_rules(node, [rule_obj])
    if not added:
        return None, QC.translate("popups", "Rule not updated.")

    return rule_obj, ""
