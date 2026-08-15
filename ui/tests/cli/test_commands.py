#
# pytest -v cli/test_commands.py
#
# The commands of opensnitch-cli that act on the database without a daemon:
# rule delete/enable/disable, nodes, status. Each is driven the way main()
# drives it, through the parser and the cmd_* function.
#

import json
import time

from google.protobuf import json_format

from opensnitch.cli import db as dbmod, main
from opensnitch.cli.proto import ui_pb2


def run(argv, config):
    args = main.build_parser().parse_args(argv)
    return args.func(args, config)


def a_rule(name, enabled=True):
    rule = ui_pb2.Rule(name=name, enabled=enabled, action="allow", duration="always")
    rule.operator.type = "simple"
    rule.operator.operand = "process.path"
    rule.operator.data = "/usr/bin/curl"
    return rule


def queued(db):
    return [(row["ntf_type"], json.loads(row["rule_json"]))
            for row in db.queued_notifications()]


class TestParser:

    def test_common_options_work_on_either_side_of_the_command(self):
        """'serve --log-level debug' is what people type; it must not be an
        error just because --log-level is defined on the main parser."""
        parser = main.build_parser()
        assert parser.parse_args(["--log-level", "debug", "serve"]).log_level == "debug"
        assert parser.parse_args(["serve", "--log-level", "debug"]).log_level == "debug"

    def test_a_value_given_before_the_command_survives(self):
        """a subparser's default must not overwrite the main parser's value."""
        parser = main.build_parser()
        args = parser.parse_args(["--db", "/tmp/x.db", "status", "--json"])
        assert args.db == "/tmp/x.db"
        assert args.log_level is None


class TestRule:

    def test_delete_queues_a_delete_for_the_daemon(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r")])

        assert run(["rule", "delete", "r"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DELETE_RULE
        assert rule["name"] == "r"
        # the daemon refuses a rule without an operator, even to delete it
        assert rule["operator"]["operand"] == "true"

    def test_a_unique_prefix_of_the_name_is_enough(self, db, config):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("allow-always-simple-usr-bin-curl")])

        assert run(["rule", "delete", "allow-always-simple-usr"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DELETE_RULE
        assert rule["name"] == "allow-always-simple-usr-bin-curl"

    def test_the_full_name_is_shown_however_long(self, db, config, capsys):
        """the name is how a rule is deleted; a cut-short one cannot be pasted."""
        name = "allow-always-list-usr-lib-x86-64-linux-gnu-some-very-long-binary-name-" \
               "api-example-com-443"
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule(name)])

        assert run(["rules"], config) == 0
        assert name in capsys.readouterr().out

    def test_disable_sends_the_whole_rule_back(self, db, config):
        """a name alone would make the daemon replace the rule with an empty
        one (notifications.go handleActionEnableRule): the real rule has to
        travel with the request."""
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r")])

        assert run(["rule", "disable", "r"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DISABLE_RULE
        # protobuf's JSON leaves out fields at their default, so a missing
        # "enabled" is false
        assert rule.get("enabled", False) is False
        assert rule["operator"]["data"] == "/usr/bin/curl"
        assert rule["action"] == "allow"

    def test_enable_after_disable(self, db, config):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r", enabled=False)])

        assert run(["rule", "enable", "r"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.ENABLE_RULE
        assert rule["enabled"] is True

    def test_enabling_an_enabled_rule_sends_nothing(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r")])

        assert run(["rule", "enable", "r"], config) == 0
        assert queued(db) == []
        assert "already enabled" in capsys.readouterr().out

    def test_enable_needs_a_rule_it_knows(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")

        assert run(["rule", "enable", "nope"], config) == 1
        assert queued(db) == []
        assert "no rule called 'nope'" in capsys.readouterr().err

    def test_delete_of_an_unknown_rule_is_sent_with_a_note(self, db, config, capsys):
        """the list can be stale; deleting a rule the daemon lacks is harmless."""
        db.node_seen("unix:/local", "h", "1.9.0")

        assert run(["rule", "delete", "nope"], config) == 0
        assert len(queued(db)) == 1
        assert "not among the rules" in capsys.readouterr().err

    def test_with_several_nodes_the_node_must_be_named(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.node_seen("ipv4:10.0.0.2", "h2", "1.9.0")
        db.replace_rules("ipv4:10.0.0.2", [a_rule("r")])

        assert run(["rule", "delete", "r"], config) == 1
        assert "--node" in capsys.readouterr().err

        assert run(["rule", "delete", "r", "--node", "ipv4:10.0.0.2"], config) == 0
        [row] = db.queued_notifications()
        assert row["node"] == "ipv4:10.0.0.2"

    def test_an_unknown_node_is_refused(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        assert run(["rule", "delete", "r", "--node", "ipv4:9.9.9.9"], config) == 1
        assert "no node called" in capsys.readouterr().err

    def test_nothing_to_send_to_without_a_node(self, db, config, capsys):
        assert run(["rule", "delete", "r"], config) == 1
        assert "no node has connected" in capsys.readouterr().err


class TestUndo:

    def _decide(self, db, connection, node="unix:/local", sig="sig", rule_name="deny-always-simple-usr-bin-curl"):
        entry_id, _ = db.record_pending(node, sig, connection, {})
        db.set_pending_state(entry_id, dbmod.STATE_DECIDED,
                             json.dumps({"name": rule_name, "action": "deny",
                                         "duration": "always"}))
        return entry_id

    def test_a_denied_connection_comes_back_and_its_rule_is_withdrawn(self, db, config,
                                                                      connection, capsys):
        entry_id = self._decide(db, connection)

        assert run(["undo", str(entry_id)], config) == 0

        entry = db.get_pending(entry_id)
        assert entry["state"] == dbmod.STATE_PENDING
        assert entry["decided_rule"] is None
        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DELETE_RULE
        assert rule["name"] == "deny-always-simple-usr-bin-curl"
        assert "1 connection(s) back" in capsys.readouterr().out

    def test_every_connection_the_rule_settled_comes_back(self, db, config, connection, capsys):
        """one approval can settle several entries; undoing it reopens them all,
        since the rule that answered them is going away."""
        first = self._decide(db, connection, sig="a")
        second = self._decide(db, connection, sig="b")
        other_rule = self._decide(db, connection, sig="c", rule_name="allow-always-simple-x")

        assert run(["undo", str(first)], config) == 0

        assert db.get_pending(first)["state"] == dbmod.STATE_PENDING
        assert db.get_pending(second)["state"] == dbmod.STATE_PENDING
        assert db.get_pending(other_rule)["state"] == dbmod.STATE_DECIDED
        assert len(queued(db)) == 1, "one rule, one delete"
        assert "2 connection(s) back" in capsys.readouterr().out

    def test_a_rule_name_works_too(self, db, config, connection, capsys):
        """`rules` shows names, not ids, and that is where people look."""
        entry_id = self._decide(db, connection)

        assert run(["undo", "deny-always-simple-usr-bin-curl"], config) == 0

        assert db.get_pending(entry_id)["state"] == dbmod.STATE_PENDING
        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DELETE_RULE
        assert rule["name"] == "deny-always-simple-usr-bin-curl"

    def test_a_unique_prefix_of_the_name_is_enough(self, db, config, connection):
        entry_id = self._decide(db, connection)

        assert run(["undo", "deny-always-simple-usr"], config) == 0

        assert db.get_pending(entry_id)["state"] == dbmod.STATE_PENDING
        [(_, rule)] = queued(db)
        assert rule["name"] == "deny-always-simple-usr-bin-curl"

    def test_an_ambiguous_prefix_is_refused_with_the_choices(self, db, config, connection, capsys):
        self._decide(db, connection, sig="a", rule_name="deny-always-simple-usr-bin-curl")
        self._decide(db, connection, sig="b", rule_name="deny-always-simple-usr-bin-wget")

        assert run(["undo", "deny-always-simple-usr"], config) == 1
        err = capsys.readouterr().err
        assert "could be any of" in err
        assert "usr-bin-curl" in err and "usr-bin-wget" in err
        assert queued(db) == []

    def test_a_name_no_entry_recorded_still_withdraws_the_rule(self, db, config, capsys):
        """the daemon asks again next time, so nothing to re-queue by hand."""
        db.node_seen("unix:/local", "h", "1.9.0")

        assert run(["undo", "allow-always-simple-usr-bin-wget"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DELETE_RULE
        assert rule["name"] == "allow-always-simple-usr-bin-wget"
        assert "nothing to re-queue" in capsys.readouterr().out

    def test_a_name_needs_a_node_when_it_cannot_be_inferred(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.node_seen("ipv4:10.0.0.2", "h2", "1.9.0")

        assert run(["undo", "allow-always-simple-x"], config) == 1
        assert "--node" in capsys.readouterr().err
        assert run(["undo", "allow-always-simple-x", "--node", "ipv4:10.0.0.2"], config) == 0
        assert db.queued_notifications()[0]["node"] == "ipv4:10.0.0.2"

    def test_only_a_decided_entry_can_be_undone(self, db, config, connection, capsys):
        entry_id, _ = db.record_pending("unix:/local", "sig", connection, {})
        assert run(["undo", str(entry_id)], config) == 1
        assert "no decision to undo" in capsys.readouterr().err
        assert run(["undo", "999"], config) == 1

    def test_pending_decided_lists_what_was_decided(self, db, config, connection, capsys):
        entry_id = self._decide(db, connection)
        assert run(["pending", "--decided"], config) == 0
        out = capsys.readouterr().out
        assert "DECISION" in out
        assert "deny always as deny-always-simple-usr-bin-curl" in out

        assert run(["pending"], config) == 0
        assert "nothing waiting" in capsys.readouterr().out


class TestNodes:

    def test_online_means_heard_from_recently(self, db, config, capsys):
        """a serve process that dies never marks its nodes offline, so the flag
        alone is not believed."""
        db.node_seen("unix:/local", "fresh", "1.9.0", online=True)
        db.node_seen("ipv4:10.0.0.2", "stale", "1.9.0", online=True)
        db._db.execute("UPDATE nodes SET last_seen=? WHERE addr='ipv4:10.0.0.2'",
                       (int(time.time()) - 600,))

        assert run(["nodes", "--json"], config) == 0
        rows = {n["addr"]: n for n in json.loads(capsys.readouterr().out)}
        assert rows["unix:/local"]["online"] is True
        assert rows["ipv4:10.0.0.2"]["online"] is False

    def test_the_daemon_version_is_shown(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        assert run(["nodes"], config) == 0
        out = capsys.readouterr().out
        assert "DAEMON" in out
        assert "1.9.0" in out
        assert "1786" not in out, "last seen should be a date, not an epoch"


class TestStatus:

    def test_nodes_online_agrees_with_nodes(self, db, config, capsys):
        db.node_seen("unix:/local", "stale", "1.9.0", online=True)
        db._db.execute("UPDATE nodes SET last_seen=?", (int(time.time()) - 600,))

        assert run(["status", "--json"], config) == 0
        status = json.loads(capsys.readouterr().out)
        assert status["nodes"] == 1
        assert status["nodes_online"] == 0


class TestDecideName:

    def test_a_name_in_use_is_refused(self, db, config, connection, capsys):
        """the daemon replaces rules by name without a word."""
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("mine")])
        entry_id, _ = db.record_pending("unix:/local", "sig", connection, {})

        assert run(["allow", str(entry_id), "--name", "mine"], config) == 1
        assert "already exists" in capsys.readouterr().err
        assert db.get_pending(entry_id)["state"] == dbmod.STATE_PENDING

        assert run(["allow", str(entry_id), "--name", "mine-2"], config) == 0
