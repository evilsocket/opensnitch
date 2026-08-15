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

"""Command line of opensnitch-cli.

grpc is only imported by the commands that need it, so that reviewing the queue
works on a machine where the service half isn't installed.
"""

import argparse
import json
import logging
import sys
import time

from opensnitch.version import version
from opensnitch.rule_consts import RuleConsts
from opensnitch.cli import durations
from opensnitch.cli.config import Config, ConfigError

LOG_FORMAT = '%(asctime)s - [%(levelname)s][%(filename)s:%(lineno)d] %(message)s'


def setup_logging(config, level=None):
    level = level or config.get("log", "level")
    handlers = []
    log_file = config.get("log", "file")
    if log_file != "":
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(level=getattr(logging, level.upper()), format=LOG_FORMAT,
                        handlers=handlers, force=True)


def open_db(config):
    from opensnitch.cli import db as dbmod

    return dbmod.Database(config.db_path())


def cmd_serve(args, config):
    from opensnitch.cli.server import Server

    if args.socket is not None:
        config.set("server", "address", args.socket)

    server = Server(config)
    try:
        server.serve_forever()
    except RuntimeError as e:
        print("opensnitch-cli: %s" % e, file=sys.stderr)
        return 1
    return 0


def _entry_summary(entry):
    destination = entry["dst_host"] or entry["dst_ip"] or "?"
    return "%-5s %-28s %-38s %s" % (
        entry["id"],
        (entry["process_path"] or "?")[-28:],
        "%s:%s" % (destination, entry["dst_port"]),
        "%sx" % entry["hits"])


def _decision_summary(entry):
    """what was decided for an entry: 'allow always as NAME'."""
    try:
        rule = json.loads(entry["decided_rule"] or "{}")
    except ValueError:
        rule = {}
    if not rule:
        return "?"
    return "%s %s as %s" % (rule.get("action", "?"), rule.get("duration", "?"),
                            rule.get("name", "?"))


def cmd_pending(args, config):
    from opensnitch.cli import db as dbmod

    db = open_db(config)
    state = dbmod.STATE_DECIDED if args.decided else dbmod.STATE_PENDING
    entries = db.pending(node=args.node, limit=args.limit, state=state)

    if args.json:
        print(json.dumps([dict(e) for e in entries], indent=2))
        return 0

    if len(entries) == 0:
        print("nothing has been decided yet" if args.decided else "nothing waiting to be reviewed")
        return 0

    if args.decided:
        print("%-5s %-28s %-38s %s" % ("ID", "PROCESS", "DESTINATION", "DECISION"))
        for entry in entries:
            destination = entry["dst_host"] or entry["dst_ip"] or "?"
            print("%-5s %-28s %-38s %s" % (
                entry["id"], (entry["process_path"] or "?")[-28:],
                "%s:%s" % (destination, entry["dst_port"]), _decision_summary(entry)))
        return 0

    print("%-5s %-28s %-38s %s" % ("ID", "PROCESS", "DESTINATION", "SEEN"))
    for entry in entries:
        print(_entry_summary(entry))
    return 0


def cmd_undo(args, config):
    """takes back a decision: withdraws its rule, reopens what it decided.

    Given a queue id (what pending --decided shows) or a rule name (what
    rules shows): people look for the thing to reverse in both places.
    """
    from google.protobuf import json_format
    from opensnitch.cli.proto import ui_pb2
    from opensnitch.cli import db as dbmod

    db = open_db(config)

    entry = db.get_pending(int(args.what)) if args.what.isdigit() else None
    if entry is not None:
        if entry["state"] != dbmod.STATE_DECIDED:
            print("opensnitch-cli: entry %s is %s, there is no decision to undo" % (
                args.what, entry["state"]), file=sys.stderr)
            return 1
        try:
            rule_name = json.loads(entry["decided_rule"] or "{}").get("name")
        except ValueError:
            rule_name = None
        if not rule_name:
            print("opensnitch-cli: entry %s does not say which rule decided it" % args.what,
                  file=sys.stderr)
            return 1
        node = entry["node"]
    else:
        known = db.decided_rule_names()
        for n in db.nodes():
            known |= db.rule_names(n["addr"])
        try:
            rule_name = resolve_rule_name(args.what, known)
        except CommandError as e:
            print("opensnitch-cli: %s" % e, file=sys.stderr)
            return 1
        # a rule name is only unique on one node; the entries it decided say
        # which, otherwise --node has to
        nodes = sorted(set(e["node"] for e in db.decided_by(None, rule_name)))
        if len(nodes) == 1 and (args.node is None or args.node == nodes[0]):
            node = nodes[0]
        else:
            try:
                node = resolve_node(db, args.node)
            except CommandError as e:
                print("opensnitch-cli: %s" % e, file=sys.stderr)
                return 1

    # the same rule may have settled several queued connections; they all come
    # back, since the rule that answered them is going away
    covered = db.decided_by(node, rule_name)
    stale = ui_pb2.Rule(name=rule_name)
    stale.operator.type = RuleConsts.RULE_TYPE_SIMPLE
    stale.operator.operand = "true"
    db.queue_notification(node, ui_pb2.DELETE_RULE, json_format.MessageToJson(stale),
                          pending_id=covered[0]["id"] if covered else None)
    db.reopen([e["id"] for e in covered])

    if covered:
        print("queued: delete rule '%s' on %s; %d connection(s) back in the review queue" % (
            rule_name, node, len(covered)))
        for other in covered:
            destination = other["dst_host"] or other["dst_ip"] or "?"
            print("  %s  %s -> %s:%s" % (other["id"], other["process_path"] or "(unknown process)",
                                         destination, other["dst_port"]))
    else:
        print("queued: delete rule '%s' on %s. No queued connection recorded that rule, so "
              "nothing to re-queue: the daemon will ask again the next time the program "
              "connects" % (rule_name, node))
    return 0


def cmd_review(args, config):
    from opensnitch.cli import review

    db = open_db(config)
    entries = db.pending(node=args.node, limit=args.limit)
    if len(entries) == 0:
        print("nothing waiting to be reviewed")
        return 0

    try:
        applied = review.review_loop(db, entries, config)
    except (KeyboardInterrupt, EOFError):
        print("")
        applied = 0

    if applied:
        if len(served_nodes(db)) > 0:
            print("\n%d rule(s) queued. The service applies them within a second; "
                  "run 'opensnitch-cli status' to check." % applied)
        else:
            print("\n%d rule(s) queued, but no daemon is connected right now — is "
                  "'opensnitch-cli serve' running? The decisions are kept, and are "
                  "applied as soon as the service and the daemon are back." % applied)
    return 0


# While a node is connected its last_seen is refreshed every 30 seconds
# (server.py LAST_SEEN_INTERVAL); older than a few of those means nobody is
# serving it, whatever its online flag says.
SERVED_MAX_AGE = 90


def is_served(node, now=None):
    """whether the serve service is talking to this node right now.

    The online flag alone can lie: a serve process that dies never marks its
    nodes offline, so it is only believed while last_seen is fresh.
    """
    now = time.time() if now is None else now
    return bool(node["online"] and node["last_seen"]
                and now - node["last_seen"] < SERVED_MAX_AGE)


def served_nodes(db):
    now = time.time()
    return [n for n in db.nodes() if is_served(n, now)]


class CommandError(Exception):
    """a command cannot do what was asked; the message is for the user."""


def resolve_node(db, requested):
    """the node a rule command applies to.

    With one node known there is nothing to choose; with several, --node has
    to say which, because a rule name only means something on one daemon.
    """
    known = [n["addr"] for n in db.nodes()]
    if requested is not None:
        if requested not in known:
            raise CommandError("no node called '%s' has connected. Known: %s" % (
                requested, ", ".join(known) or "none"))
        return requested
    if len(known) == 1:
        return known[0]
    if len(known) == 0:
        raise CommandError("no node has connected yet, so there is no daemon to send this to")
    raise CommandError("several nodes have connected, say which with --node: %s" %
                       ", ".join(known))


def cmd_decide(args, config):
    """allow / deny / reject without the interactive loop."""
    from opensnitch.cli import review

    db = open_db(config)
    entry = db.get_pending(args.id)
    if entry is None:
        print("opensnitch-cli: no queue entry with id %s" % args.id, file=sys.stderr)
        return 1

    con = review.entry_connection(entry)
    decision = review.Decision(entry, con, args.action, args.duration,
                               db.rule_names(entry["node"]))

    if args.match is not None:
        matched = [c for c in decision.candidates if c["operand"] == args.match]
        if len(matched) == 0:
            print("opensnitch-cli: '%s' is not something this connection can be matched "
                  "on. Available: %s" % (
                      args.match, ", ".join(sorted(set(c["operand"] for c in decision.candidates)))),
                  file=sys.stderr)
            return 1
        decision.selected = matched[0]
    if args.name is not None:
        if decision.name_is_taken(args.name):
            print("opensnitch-cli: a rule named '%s' already exists on this node and would "
                  "be replaced. Pick another name, or delete it first with "
                  "'opensnitch-cli rule delete %s'" % (args.name, args.name), file=sys.stderr)
            return 1
        decision.name = args.name

    error = decision.validate()
    if error is not None:
        print("opensnitch-cli: %s" % error, file=sys.stderr)
        return 1

    rule = decision.build()
    review.apply_decision(db, entry, rule)
    print("queued: %s %s as '%s'" % (rule.action, rule.duration, rule.name))
    return 0


def cmd_drop(args, config):
    db = open_db(config)
    entry = db.get_pending(args.id)
    if entry is None:
        print("opensnitch-cli: no queue entry with id %s" % args.id, file=sys.stderr)
        return 1
    db.set_pending_state(args.id, "dropped")
    print("dropped entry %s, no rule created" % args.id)
    return 0


def _rule_match_summary(row):
    """one short column describing what a stored rule matches on."""
    if row["op_type"] == RuleConsts.RULE_TYPE_LIST and row["rule_json"]:
        try:
            ops = json.loads(row["rule_json"]).get("operator", {}).get("list", [])
        except ValueError:
            ops = []
        return " and ".join("%s %s" % (o.get("operand"), o.get("data")) for o in ops) or "list"
    return "%s %s %s" % (row["op_operand"], "is" if row["op_type"] == "simple" else
                         row["op_type"], row["op_data"])


def cmd_rules(args, config):
    db = open_db(config)
    entries = db.rules(node=args.node)
    if args.json:
        out = []
        for e in entries:
            row = dict(e)
            try:
                row["rule"] = json.loads(row.pop("rule_json") or "null")
            except ValueError:
                row["rule"] = None
            out.append(row)
        print(json.dumps(out, indent=2))
        return 0
    if len(entries) == 0:
        print("no rules known. They are read from each node when it connects.")
        return 0
    # the name is how a rule is deleted or undone, so it is never cut short:
    # the column is as wide as the longest one
    width = max([len(rule["name"]) for rule in entries] + [4])
    print("%-8s %-*s %-7s %-14s %s" % ("ENABLED", width, "NAME", "ACTION", "DURATION", "MATCH"))
    for rule in entries:
        print("%-8s %-*s %-7s %-14s %s" % (
            "yes" if rule["enabled"] else "no", width, rule["name"], rule["action"],
            rule["duration"], _rule_match_summary(rule)))
    return 0


def resolve_rule_name(given, known):
    """the rule meant by a name typed on the command line.

    An exact name wins. Otherwise a prefix that fits exactly one known rule
    is enough — the generated names are long, and cutting one short is what
    people naturally do. A prefix that fits several is refused, listing them.
    """
    if given in known:
        return given
    matches = sorted(n for n in known if n.startswith(given))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise CommandError("'%s' could be any of: %s" % (given, ", ".join(matches)))
    return given


def cmd_rule(args, config):
    """delete / enable / disable a rule on the daemon, by name."""
    from google.protobuf import json_format
    from opensnitch.cli.proto import ui_pb2
    from opensnitch.cli import rules

    db = open_db(config)
    try:
        node = resolve_node(db, args.node)
        args.name = resolve_rule_name(args.name, db.rule_names(node))
    except CommandError as e:
        print("opensnitch-cli: %s" % e, file=sys.stderr)
        return 1

    row = db.get_rule(node, args.name)

    if args.verb == "delete":
        # the daemon only reads the name, but refuses a rule with no operator
        rule = ui_pb2.Rule(name=args.name)
        rule.operator.type = RuleConsts.RULE_TYPE_SIMPLE
        rule.operator.operand = "true"
        if row is None:
            print("note: '%s' is not among the rules this node reported; deleting a rule "
                  "the daemon does not have does nothing" % args.name, file=sys.stderr)
        db.queue_notification(node, ui_pb2.DELETE_RULE, json_format.MessageToJson(rule))
        print("queued: delete rule '%s' on %s" % (args.name, node))
        return 0

    # enable / disable send the whole rule back, because the daemon replaces
    # what it has with what it receives (daemon/ui/notifications.go
    # handleActionEnableRule): a name alone would leave it with an empty rule.
    if row is None:
        print("opensnitch-cli: no rule called '%s' is known on %s. 'opensnitch-cli rules' "
              "lists them" % (args.name, node), file=sys.stderr)
        return 1
    if not row["rule_json"]:
        print("opensnitch-cli: the whole of '%s' is not known yet, only its name; it will "
              "be once the daemon reconnects" % args.name, file=sys.stderr)
        return 1

    rule = ui_pb2.Rule()
    json_format.Parse(row["rule_json"], rule)
    enable = args.verb == "enable"
    if bool(rule.enabled) == enable:
        print("rule '%s' is already %sd" % (args.name, args.verb))
        return 0
    rule.enabled = enable
    error = rules.validate_rule(rule)
    if error is not None:
        print("opensnitch-cli: the daemon would refuse this rule: %s" % error, file=sys.stderr)
        return 1
    db.queue_notification(node, ui_pb2.ENABLE_RULE if enable else ui_pb2.DISABLE_RULE,
                          json_format.MessageToJson(rule))
    print("queued: %s rule '%s' on %s" % (args.verb, args.name, node))
    return 0


def cmd_nodes(args, config):
    db = open_db(config)
    nodes = db.nodes()
    now = time.time()
    if args.json:
        out = []
        for n in nodes:
            row = dict(n)
            row["online"] = is_served(n, now)
            out.append(row)
        print(json.dumps(out, indent=2))
        return 0
    if len(nodes) == 0:
        print("no node has connected yet")
        return 0
    print("%-24s %-18s %-9s %-7s %s" % ("ADDRESS", "HOSTNAME", "DAEMON", "ONLINE", "LAST SEEN"))
    for node in nodes:
        print("%-24s %-18s %-9s %-7s %s" % (node["addr"], node["hostname"] or "?",
                                            node["version"] or "?",
                                            "yes" if is_served(node, now) else "no",
                                            durations.format_time(node["last_seen"])))
    return 0


def cmd_status(args, config):
    db = open_db(config)

    if args.retry:
        print("re-sending %d rejected notification(s)" % db.retry_errors())
    elif args.clear:
        print("dropped %d rejected notification(s); their connections are back in "
              "the review queue" % db.clear_errors())

    nodes = db.nodes()
    online = len(served_nodes(db))
    errors = db.outbox_errors()
    queued = db.queued_count()

    status = {
        "pending": db.pending_count(),
        "nodes": len(nodes),
        "nodes_online": online,
        "notifications_queued": queued,
        "notifications_failed": len(errors),
        "unreviewed_action": config.get("policy", "unreviewed_action"),
        "unreviewed_duration": config.get("policy", "unreviewed_duration"),
        "database": config.db_path(),
    }

    if args.json:
        print(json.dumps(status, indent=2))
    else:
        for key, value in status.items():
            print("%-22s %s" % (key.replace("_", " "), value))
        for row in errors:
            print("\nrejected by the daemon: %s" % row["last_error"])
            print("  %s" % row["rule_json"].replace("\n", " "))

    # so that a monitoring system notices rules that never made it
    return 1 if len(errors) > 0 else 0


def _add_common_options(parser, default):
    """--config, --db and --log-level.

    Added to the main parser and to every subcommand, so that both
    'opensnitch-cli --log-level debug serve' and 'opensnitch-cli serve
    --log-level debug' work. On the subcommands the default is SUPPRESS: a
    subparser's default would otherwise overwrite a value given before the
    subcommand.
    """
    parser.add_argument("--config", default=default, help="path to cli.conf")
    parser.add_argument("--db", default=default,
                        help="path to the queue database, overrides the config file")
    parser.add_argument("--log-level", default=default,
                        choices=("debug", "info", "warning", "error"))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="opensnitch-cli",
        description="Review and answer OpenSnitch connection prompts from a terminal.")
    parser.add_argument("--version", action="version", version="opensnitch-cli %s" % version)
    _add_common_options(parser, default=None)

    subparsers = parser.add_subparsers(dest="command")

    def add_command(name, **kwargs):
        sub = subparsers.add_parser(name, **kwargs)
        _add_common_options(sub, default=argparse.SUPPRESS)
        return sub

    serve = add_command("serve", help="answer the daemon and record connections")
    serve.add_argument("--socket", help="address to listen on, overrides the config file")
    serve.set_defaults(func=cmd_serve)

    pending = add_command("pending", help="list connections waiting to be reviewed")
    pending.add_argument("--node")
    pending.add_argument("--limit", type=int)
    pending.add_argument("--json", action="store_true")
    pending.add_argument("--decided", action="store_true",
                         help="list what has been decided instead, with the rule each got")
    pending.set_defaults(func=cmd_pending)

    undo = add_command("undo", help="take a decision back: withdraw its rule, re-queue "
                                    "the connection")
    undo.add_argument("what", metavar="ID|NAME",
                      help="a queue id from 'pending --decided', or a rule name from 'rules'")
    undo.add_argument("--node", help="which daemon, when the name alone does not say")
    undo.set_defaults(func=cmd_undo)

    review_cmd = add_command("review", help="go through the queue one by one")
    review_cmd.add_argument("--node")
    review_cmd.add_argument("--limit", type=int)
    review_cmd.set_defaults(func=cmd_review)

    for action in (RuleConsts.ACTION_ALLOW, RuleConsts.ACTION_DENY, RuleConsts.ACTION_REJECT):
        decide = add_command(action, help="%s a queue entry without prompting" % action)
        decide.add_argument("id", type=int)
        decide.add_argument("--match", help="operand to match on, for example dest.host")
        decide.add_argument("--duration", default=RuleConsts.DURATION_ALWAYS)
        decide.add_argument("--name")
        decide.set_defaults(func=cmd_decide, action=action)

    drop = add_command("drop", help="remove a queue entry without creating a rule")
    drop.add_argument("id", type=int)
    drop.set_defaults(func=cmd_drop)

    rules_cmd = add_command("rules", help="the rules each daemon has")
    rules_cmd.add_argument("--node")
    rules_cmd.add_argument("--json", action="store_true")
    rules_cmd.set_defaults(func=cmd_rules)

    rule_cmd = add_command("rule", help="delete, enable or disable a rule by name")
    rule_cmd.add_argument("verb", choices=("delete", "enable", "disable"))
    rule_cmd.add_argument("name")
    rule_cmd.add_argument("--node", help="which daemon, when more than one has connected")
    rule_cmd.set_defaults(func=cmd_rule)

    nodes = add_command("nodes", help="daemons that have connected")
    nodes.add_argument("--json", action="store_true")
    nodes.set_defaults(func=cmd_nodes)

    status = add_command("status", help="queue depth, nodes and failed rules")
    status.add_argument("--json", action="store_true")
    failed = status.add_mutually_exclusive_group()
    failed.add_argument("--retry", action="store_true",
                        help="send the rules the daemon rejected once more")
    failed.add_argument("--clear", action="store_true",
                        help="forget the rules the daemon rejected and put their "
                             "connections back in the review queue")
    status.set_defaults(func=cmd_status)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "func", None) is None:
        parser.print_help()
        return 2

    try:
        config = Config(path=args.config)
    except ConfigError as e:
        print("opensnitch-cli: %s" % e, file=sys.stderr)
        return 2

    if args.db is not None:
        config.set("db", "path", args.db)

    setup_logging(config, args.log_level)

    try:
        return args.func(args, config)
    except PermissionError as e:
        print("opensnitch-cli: %s\nThe queue is only readable by root, try with sudo." % e,
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
