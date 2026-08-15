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

"""Going through the review queue, one connection at a time.

Reading and writing go through the read/write arguments rather than input() and
print() directly, so that the whole loop can be driven by a test.
"""

import json
import os
import time

from opensnitch import operands
from opensnitch.rule_consts import RuleConsts
from opensnitch.cli import durations, match, rules

SEPARATOR = "─" * 62

HELP = """
  y   apply the rule as shown
  n   same match, but deny instead
  r   same match, but reject (deny silently drops, reject answers)
  e   edit the rule before applying it
  s   skip, leave it in the queue
  d   drop it from the queue, without creating a rule
  i   show everything known about the connection
  q   quit
"""


def _args_of(entry):
    try:
        return json.loads(entry["process_args"] or "[]")
    except ValueError:
        return []


def entry_connection(entry):
    """rebuilds the Connection we were asked about, out of its queue row."""
    from opensnitch.cli.proto import ui_pb2

    con = ui_pb2.Connection()
    con.protocol = entry["protocol"] or ""
    con.dst_ip = entry["dst_ip"] or ""
    con.dst_host = entry["dst_host"] or ""
    con.dst_port = entry["dst_port"] or 0
    con.user_id = entry["user_id"] if entry["user_id"] is not None else 0
    con.process_id = entry["process_id"] if entry["process_id"] is not None else 0
    con.process_path = entry["process_path"] or ""
    con.process_cwd = entry["process_cwd"] or ""
    for arg in _args_of(entry):
        con.process_args.append(arg)
    try:
        for key, value in json.loads(entry["process_checksums"] or "{}").items():
            con.process_checksums[key] = value
    except ValueError:
        pass
    return con


class Decision:
    """the rule about to be created for a queue entry."""

    def __init__(self, entry, con, default_action, default_duration, taken_names):
        self.entry = entry
        self.con = con
        self.action = default_action
        self.duration = default_duration
        self.precedence = False
        self.description = ""
        self._taken = taken_names
        self._custom_name = None

        self.candidates = operands.candidates(con)
        # the executable is the sensible default, same as the pop-up's
        self.selected = self.candidates[0] if len(self.candidates) > 0 else None
        self.extra = []

    def untrusted_command(self):
        """whether matching on the command line alone could be fooled.

        A program chooses its own argv[0], so a command line that doesn't start
        with an absolute path, or that starts under /proc (/proc/self/fd/...),
        says nothing about which binary is really running. The pop-up pins the
        executable as well in that case, and so do we.
        """
        if self.selected is None:
            return False
        if self.selected["operand"] != RuleConsts.OPERAND_PROCESS_COMMAND:
            return False
        argv = " ".join(self.con.process_args).split(" ")
        if len(argv) == 0 or argv[0] == "":
            return True
        return not os.path.isabs(argv[0]) or argv[0].startswith("/proc")

    def operators(self):
        ops = []
        if self.selected is not None:
            ops.append(rules.new_operator(self.selected["type"], self.selected["operand"],
                                          self.selected["data"]))
        for cand in self.extra:
            # the match can be changed to a candidate that was already added as
            # a condition; don't require the same thing twice
            if cand is self.selected:
                continue
            ops.append(rules.new_operator(cand["type"], cand["operand"], cand["data"]))

        if self.untrusted_command() and self.con.process_path != "":
            already = [o for o in ops if o.operand == RuleConsts.OPERAND_PROCESS_PATH]
            if len(already) == 0:
                ops.append(rules.new_operator(RuleConsts.RULE_TYPE_SIMPLE,
                                              RuleConsts.OPERAND_PROCESS_PATH,
                                              self.con.process_path))
        return ops

    @property
    def name(self):
        if self._custom_name is not None:
            return self._custom_name
        ops = self.operators()
        if len(ops) == 0:
            return ""
        return rules.unique_name(
            rules.rule_name(self.action, self.duration, len(ops) > 1, ops[0].data,
                            [op.data for op in ops[1:]]),
            self._taken)

    @name.setter
    def name(self, value):
        self._custom_name = value

    def name_is_taken(self, value):
        """whether a name the user typed would replace a rule that exists.

        Generated names avoid this by themselves; a typed one has to be
        checked, because the daemon replaces rules by name without a word.
        """
        return value in self._taken

    def build(self):
        ops = self.operators()
        if len(ops) == 0:
            return None
        return rules.build_rule(self.name, self.action, self.duration, ops,
                                precedence=self.precedence, description=self.description)

    def validate(self):
        rule = self.build()
        if rule is None:
            return "no match selected"
        return rules.validate_rule(rule)

    def warnings(self):
        found = []
        if self.untrusted_command():
            found.append("a program picks its own command line, so the executable is "
                         "matched as well, otherwise this rule could be fooled")
        for op in self.operators():
            warning = rules.case_warning(op)
            if warning is not None:
                found.append(warning)
            if op.type == RuleConsts.RULE_TYPE_REGEXP and op.data in (".*", "^.*$"):
                found.append("'%s' matches everything" % op.data)
        return found


def render_entry(entry, con, index, total, write):
    write(SEPARATOR)
    write("[%d/%d]  %s   seen %sx   first %s   last %s" % (
        index, total, entry["node"], entry["hits"],
        durations.format_time(entry["first_seen"]),
        durations.format_time(entry["last_seen"])))

    process = entry["process_path"] or "(unknown process)"
    write("  %s   pid %s  uid %s" % (process, entry["process_id"], entry["user_id"]))
    args = _args_of(entry)
    if len(args) > 1:
        write("  %s" % " ".join(args))

    destination = entry["dst_host"] or entry["dst_ip"] or "?"
    if entry["dst_host"] and entry["dst_ip"]:
        destination = "%s (%s)" % (entry["dst_host"], entry["dst_ip"])
    write("  -> %s  %s  port %s" % (entry["protocol"] or "?", destination, entry["dst_port"]))

    if entry["provisional_name"]:
        remaining = ""
        if entry["provisional_expires"]:
            left = int(entry["provisional_expires"] - time.time())
            remaining = ", %s left" % ("%dm%ds" % (left // 60, left % 60) if left > 0
                                       else "expired")
        write("  currently %s for %s%s (temporary rule %s)" % (
            entry["provisional_action"], entry["provisional_duration"], remaining,
            entry["provisional_name"]))
    write("")


def render_decision(decision, write):
    rule = decision.build()
    if rule is None:
        write("  no match selected, use 'e' to pick one")
        return
    write("  proposed rule: %s" % rule.name)
    for line in rules.describe_rule(rule).split("\n"):
        write("    %s" % line)
    for warning in decision.warnings():
        write("  ! %s" % warning)
    error = decision.validate()
    if error is not None:
        write("  ! the daemon would refuse this rule: %s" % error)
    write("")


def render_details(entry, con, write):
    write("  node          %s" % entry["node"])
    write("  signature     %s" % entry["signature"])
    write("  executable    %s" % (entry["process_path"] or "?"))
    write("  command line  %s" % " ".join(_args_of(entry)))
    write("  working dir   %s" % (entry["process_cwd"] or "?"))
    write("  pid / uid     %s / %s" % (entry["process_id"], entry["user_id"]))
    write("  destination   %s %s:%s" % (entry["protocol"], entry["dst_host"] or entry["dst_ip"],
                                        entry["dst_port"]))
    if entry["dst_host"] and entry["dst_ip"]:
        write("  address       %s" % entry["dst_ip"])
    try:
        checksums = json.loads(entry["process_checksums"] or "{}")
    except ValueError:
        checksums = {}
    for key, value in checksums.items():
        write("  %-13s %s" % (key, value))
    write("")


def edit_menu(decision, read, write):
    """changes the rule before it's applied. Returns True to apply it."""
    while True:
        ops = decision.operators()
        match = rules.describe_operator(ops[0]) if len(ops) > 0 else "(none)"
        write("")
        write("  1) match on     %s" % match)
        write("  2) action       %s" % decision.action)
        write("  3) duration     %s" % decision.duration)
        write("  4) name         %s" % decision.name)
        write("  5) also require %s" % (
            ", ".join([rules.describe_operator(o) for o in ops[1:]]) if len(ops) > 1 else "(nothing)"))
        write("  6) precedence   %s" % ("yes" if decision.precedence else "no"))
        write("  a) apply    c) cancel")
        choice = read("  edit [1-6,a,c]: ").strip().lower()

        if choice == "a":
            error = decision.validate()
            if error is not None:
                write("  cannot apply: %s" % error)
                continue
            return True
        if choice in ("c", "q", ""):
            return False
        if choice == "1":
            _choose_match(decision, read, write)
        elif choice == "2":
            _choose_action(decision, read, write)
        elif choice == "3":
            _choose_duration(decision, read, write)
        elif choice == "4":
            value = read("  rule name: ").strip()
            if value == "":
                pass
            elif decision.name_is_taken(value):
                write("  a rule named '%s' already exists on this node and would be "
                      "replaced; pick another name, or delete it first with "
                      "'opensnitch-cli rule delete %s'" % (value, value))
            else:
                decision.name = value
        elif choice == "5":
            _choose_extra(decision, read, write)
        elif choice == "6":
            decision.precedence = not decision.precedence
        else:
            write("  ?")


def _queue_provisional_delete(db, entry):
    """withdraws the temporary rule an entry was answered with."""
    from google.protobuf import json_format
    from opensnitch.cli.proto import ui_pb2

    if not entry["provisional_name"]:
        return
    stale = ui_pb2.Rule(name=entry["provisional_name"])
    # the daemon only reads the name of the rule to delete, but it refuses a
    # rule without an operator, so give it one
    stale.operator.type = RuleConsts.RULE_TYPE_SIMPLE
    stale.operator.operand = "true"
    stale.operator.data = ""
    db.queue_notification(entry["node"], ui_pb2.DELETE_RULE,
                          json_format.MessageToJson(stale), pending_id=entry["id"])


def apply_decision(db, entry, rule):
    """queues the rule for the service to send, and closes the queue entry.

    Two notifications: the temporary rule we answered with is removed first, so
    that it doesn't keep allowing the connection until it expires, then the real
    rule is installed. Deleting a rule the daemon no longer has does nothing, so
    it's safe even after the temporary rule expired on its own.
    """
    from google.protobuf import json_format
    from opensnitch.cli.proto import ui_pb2
    from opensnitch.cli import db as dbmod

    _queue_provisional_delete(db, entry)
    db.queue_notification(entry["node"], ui_pb2.CHANGE_RULE,
                          json_format.MessageToJson(rule), pending_id=entry["id"])
    db.set_pending_state(entry["id"], dbmod.STATE_DECIDED,
                         json_format.MessageToJson(rule))


# a decision that outlives the queue can settle other entries; a temporary one
# leaves them pending, the daemon will ask about them again anyway
DURABLE_DURATIONS = (RuleConsts.DURATION_ALWAYS, RuleConsts.DURATION_UNTIL_RESTART)


def resolve_covered(db, node, rule, entries):
    """closes the queue entries an approved rule already covers.

    Whoever approves 'allow always process.path is X' has answered every queued
    connection of X, so prompting again for each destination is noise. And
    worse than noise: every entry keeps its own temporary deny rule alive on
    the daemon, and the daemon lets any matching deny beat an allow
    (daemon/rule/loader.go FindFirstMatch), so the connections the new rule was
    meant to allow would stay blocked until those expire. Withdraw them and
    mark the entries decided by this rule.

    Returns the entries that were closed.
    """
    from google.protobuf import json_format
    from opensnitch.cli import db as dbmod

    if rule.duration not in DURABLE_DURATIONS:
        return []

    rule_json = json_format.MessageToJson(rule)
    covered = []
    for entry in entries:
        if entry["node"] != node:
            continue
        if match.rule_matches(rule, entry_connection(entry)) is not True:
            continue
        _queue_provisional_delete(db, entry)
        db.set_pending_state(entry["id"], dbmod.STATE_DECIDED, rule_json)
        covered.append(entry)
    return covered


def review_loop(db, entries, config, read=input, write=print):
    """walks the queue. Returns the number of rules queued for the daemon."""
    default_duration = RuleConsts.DURATION_ALWAYS
    applied = 0
    total = len(entries)
    resolved_ids = set()
    # per node: the names already in use, plus everything named this session.
    # Rule names are how rules are replaced and deleted, so a name may not be
    # handed out twice even when db.rule_names can't know about it yet.
    taken_by_node = {}

    for index, entry in enumerate(entries, start=1):
        if entry["id"] in resolved_ids:
            continue
        con = entry_connection(entry)
        taken = taken_by_node.get(entry["node"])
        if taken is None:
            taken = db.rule_names(entry["node"])
            taken_by_node[entry["node"]] = taken
        decision = Decision(entry, con, RuleConsts.ACTION_ALLOW, default_duration, taken)

        render_entry(entry, con, index, total, write)
        render_decision(decision, write)

        while True:
            choice = read("  [y]es [n]o [r]eject [e]dit [s]kip [d]rop [i]nfo [q]uit ? ").strip().lower()

            if choice == "y":
                pass
            elif choice == "n":
                decision.action = RuleConsts.ACTION_DENY
            elif choice == "r":
                decision.action = RuleConsts.ACTION_REJECT
            elif choice == "e":
                if not edit_menu(decision, read, write):
                    render_decision(decision, write)
                    continue
            elif choice == "s":
                break
            elif choice == "d":
                db.set_pending_state(entry["id"], "dropped")
                write("  dropped, no rule created")
                break
            elif choice == "i":
                render_details(entry, con, write)
                continue
            elif choice == "q":
                return applied
            elif choice in ("?", "h"):
                write(HELP)
                continue
            else:
                # like git add -p, an empty answer does nothing
                continue

            error = decision.validate()
            if error is not None:
                write("  the daemon would refuse this rule: %s" % error)
                continue

            # the rule may have been edited since it was last shown, so say what
            # is actually being sent, warnings included
            for warning in decision.warnings():
                write("  ! %s" % warning)

            rule = decision.build()
            apply_decision(db, entry, rule)
            applied += 1
            taken.add(rule.name)
            write("  queued: %s %s as '%s'" % (rule.action, rule.duration, rule.name))
            for line in rules.describe_rule(rule).split("\n")[1:]:
                write("  %s" % line)

            covered = resolve_covered(db, entry["node"], rule, entries[index:])
            if len(covered) > 0:
                write("  this rule also settles %d more queued connection(s), "
                      "their temporary rules are withdrawn:" % len(covered))
            for other in covered:
                resolved_ids.add(other["id"])
                destination = other["dst_host"] or other["dst_ip"] or "?"
                write("    %s -> %s:%s" % (other["process_path"] or "(unknown process)",
                                           destination, other["dst_port"]))
            break

    return applied


def _choose_match(decision, read, write):
    write("")
    for i, cand in enumerate(decision.candidates, start=1):
        write("   %2d) %-40s %s %s" % (i, cand["data"], cand["type"], cand["operand"]))
    write("    c) something else, typed by hand")
    choice = read("  match on [1-%d,c]: " % len(decision.candidates)).strip().lower()

    if choice == "c":
        custom = _custom_operand(read, write)
        if custom is not None:
            decision.selected = custom
        return
    try:
        index = int(choice) - 1
    except ValueError:
        return
    if 0 <= index < len(decision.candidates):
        decision.selected = decision.candidates[index]


def _custom_operand(read, write):
    op_type = read("  type [%s]: " % "/".join(RuleConsts.RulesTypes)).strip()
    if op_type not in RuleConsts.RulesTypes:
        write("  unknown type")
        return None
    operand = read("  operand (for example dest.host, process.path): ").strip()
    if operand == "":
        write("  an operand is required")
        return None
    data = read("  value: ").strip()

    candidate = {"label": "custom", "type": op_type, "operand": operand, "data": data}
    error = rules.validate_operator(
        rules.new_operator(op_type, operand, data))
    if error is not None:
        write("  the daemon would refuse this: %s" % error)
        return None
    return candidate


def _choose_action(decision, read, write):
    write("   1) allow    2) deny    3) reject")
    choice = read("  action [1-3]: ").strip()
    decision.action = {"1": RuleConsts.ACTION_ALLOW,
                       "2": RuleConsts.ACTION_DENY,
                       "3": RuleConsts.ACTION_REJECT}.get(choice, decision.action)


def _choose_duration(decision, read, write):
    for i, duration in enumerate(durations.COMMON, start=1):
        write("   %2d) %s" % (i, duration))
    write("    c) something else")
    choice = read("  duration [1-%d,c]: " % len(durations.COMMON)).strip().lower()
    if choice == "c":
        value = read("  duration (30s, 5m, 1h30m, always, until restart): ").strip()
        error = durations.validate(value)
        if error is not None:
            write("  %s" % error)
            return
        decision.duration = value
        return
    try:
        decision.duration = durations.COMMON[int(choice) - 1]
    except (ValueError, IndexError):
        pass


def _choose_extra(decision, read, write):
    available = [c for c in decision.candidates if c is not decision.selected]
    write("")
    for i, cand in enumerate(available, start=1):
        mark = "*" if cand in decision.extra else " "
        write("   %s %2d) %-38s %s %s" % (mark, i, cand["data"], cand["type"], cand["operand"]))
    write("    (a starred entry is already required; picking it again removes it)")
    choice = read("  toggle [1-%d, empty to go back]: " % len(available)).strip()
    try:
        cand = available[int(choice) - 1]
    except (ValueError, IndexError):
        return
    if cand in decision.extra:
        decision.extra.remove(cand)
    else:
        decision.extra.append(cand)
