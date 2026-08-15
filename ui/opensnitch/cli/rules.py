#   Copyright (C) 2026 The OpenSnitch Authors
#
#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.

"""Building and checking the rules we send to the daemon.

The daemon rejects a rule it can't compile by answering the notification with
an error, which is easy to miss. Everything here exists so that we find out
before sending instead of afterwards. The checks mirror
daemon/rule/operator.go Compile() and daemon/rule/rule.go Deserialize().
"""

import time

from slugify import slugify

from opensnitch import operands
from opensnitch.rule_consts import RuleConsts
from opensnitch.cli import durations

# rule.Deserialize() refuses a rule without an operator, and the daemon then
# falls back to its default action.
LIST_TYPE = RuleConsts.RULE_TYPE_LIST


def new_operator(op_type, operand, data, sensitive=False):
    from opensnitch.cli.proto import ui_pb2

    return ui_pb2.Operator(type=op_type, operand=operand, data=data, sensitive=sensitive)


def build_rule(name, action, duration, ops, precedence=False, description="", enabled=True,
               nolog=False):
    """assembles a rule out of one or more operators.

    With more than one operator the daemon expects a rule of type "list", whose
    own data is empty and whose operands live in operator.list. That's what the
    pop-up does in dialogs/prompt/dialog.py when more than one field is ticked.
    """
    from opensnitch.cli.proto import ui_pb2

    rule = ui_pb2.Rule(name=name)
    rule.enabled = enabled
    rule.precedence = precedence
    rule.nolog = nolog
    rule.action = action
    rule.duration = duration
    rule.description = description
    rule.created = int(time.time())

    if len(ops) == 1:
        rule.operator.type = ops[0].type
        rule.operator.operand = ops[0].operand
        rule.operator.data = ops[0].data
        rule.operator.sensitive = ops[0].sensitive
    else:
        rule.operator.type = LIST_TYPE
        rule.operator.operand = LIST_TYPE
        # the daemon clears this field for list rules anyway (rule.go
        # Deserialize), the operands are read from operator.list
        rule.operator.data = ""
        for op in ops:
            rule.operator.list.append(op)

    return rule


def rule_name(action, duration, is_list, data, extra=()):
    """same naming the pop-up uses, see dialogs/prompt/utils.py get_rule_name.

    Every condition of a list rule goes into the name, as the pop-up does
    (dialogs/prompt/dialog.py _send_rule). Rules are replaced by name on the
    daemon, so two rules for the same program that differ only in the host
    they allow must not end up called the same thing.
    """
    name = slugify("%s %s" % (action, duration))
    name = "%s-%s" % (name, "list" if is_list else "simple")
    name = slugify("%s %s" % (name, data))
    for value in extra:
        name = slugify("%s %s" % (name, value))
    return name[:128]


def unique_name(name, taken):
    """avoids a name the node already uses.

    The daemon would otherwise rename our rule itself (loader.go setUniqueName),
    and we'd no longer be able to delete it by name.
    """
    if name not in taken:
        return name
    idx = 2
    while "%s-%d" % (name, idx) in taken:
        idx += 1
    return "%s-%d" % (name, idx)


def validate_operator(op):
    """returns an error string, or None when the daemon will accept it."""
    if op.type not in RuleConsts.RulesTypes:
        return "unknown rule type '{0}', expected one of {1}".format(
            op.type, ", ".join(RuleConsts.RulesTypes))

    # Only simple, regexp and list operators are allowed to carry no data:
    # matching an empty string is meaningful for them. See operator.go Compile()
    if op.data == "" and op.type not in (RuleConsts.RULE_TYPE_SIMPLE,
                                         RuleConsts.RULE_TYPE_REGEXP,
                                         RuleConsts.RULE_TYPE_LIST):
        return "an operand of type '{0}' cannot have empty data".format(op.type)

    if op.type == RuleConsts.RULE_TYPE_NETWORK and op.operand != RuleConsts.OPERAND_DEST_NETWORK:
        return "type '{0}' is only allowed with the operand '{1}', not '{2}'".format(
            RuleConsts.RULE_TYPE_NETWORK, RuleConsts.OPERAND_DEST_NETWORK, op.operand)

    if op.type == RuleConsts.RULE_TYPE_REGEXP:
        err = operands.check_regexp(op.data)
        if err is not None:
            return err

    return None


def validate_rule(rule):
    """returns an error string, or None when the daemon will accept it."""
    if rule.name == "":
        return "the rule needs a name"

    if rule.action not in (RuleConsts.ACTION_ALLOW, RuleConsts.ACTION_DENY,
                           RuleConsts.ACTION_REJECT):
        return "unknown action '{0}', expected allow, deny or reject".format(rule.action)

    err = durations.validate(rule.duration)
    if err is not None:
        return err
    # The daemon only skips storing "once" rules on the ask path. One that
    # arrives over the notifications channel is stored and never scheduled for
    # removal (loader.go isTemporary), so it would live until the daemon exits.
    if rule.duration == RuleConsts.DURATION_ONCE:
        return ("'{0}' cannot be used here: a rule sent to the daemon with this duration "
                "is kept until the daemon restarts. Use 'until restart' if that's what "
                "you meant".format(RuleConsts.DURATION_ONCE))

    if rule.operator.type == LIST_TYPE:
        if len(rule.operator.list) == 0:
            return "a list rule needs at least one operand"
        for op in rule.operator.list:
            err = validate_operator(op)
            if err is not None:
                return err
        return None

    return validate_operator(rule.operator)


def case_warning(op):
    """warns about a regexp that can never match.

    The daemon lowercases the pattern of a non case sensitive regexp before
    compiling it (operator.go Compile), so an upper case letter in the pattern
    silently stops it from ever matching.
    """
    if op.type != RuleConsts.RULE_TYPE_REGEXP or op.sensitive:
        return None
    if op.data.lower() == op.data:
        return None
    return ("the pattern contains upper case letters but the operand is not case "
            "sensitive: the daemon lowercases it, so it would never match. Make it "
            "case sensitive or write it in lower case")


def describe_operator(op):
    """one line description of an operand, for the review screens."""
    if op.type == RuleConsts.RULE_TYPE_SIMPLE:
        return "%s is %s" % (op.operand, op.data)
    if op.type == RuleConsts.RULE_TYPE_REGEXP:
        return "%s matches %s" % (op.operand, op.data)
    if op.type == RuleConsts.RULE_TYPE_NETWORK:
        return "%s in %s" % (op.operand, op.data)
    return "%s %s %s" % (op.type, op.operand, op.data)


def describe_rule(rule):
    """multi line description of a rule, for the review screens."""
    lines = ["%s %s" % (rule.action, rule.duration)]
    if rule.operator.type == LIST_TYPE:
        for op in rule.operator.list:
            lines.append("  %s" % describe_operator(op))
    else:
        lines.append("  %s" % describe_operator(rule.operator))
    return "\n".join(lines)
