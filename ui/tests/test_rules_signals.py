#
# pytest -v tests/test_rules_signals.py
#
# Regression tests for the Rules.updated signal: rule changes written to
# the db from any source (pop-up answers, temporary rules expiration,
# rules received on node connection) must notify the views, so they
# refresh what they display.
#

from datetime import datetime

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

# opensnitch.utils must be imported before opensnitch.database to resolve
# their circular import
import opensnitch.utils  # noqa: F401
from opensnitch.rules import Rules

TEST_NODE = "unix:/tmp/osui.sock"
RULE_TIME = "2026-06-10 10:00:00"


def new_proto_rule(name):
    rule = ui_pb2.Rule(name=name)
    rule.enabled = True
    rule.action = "allow"
    rule.duration = "always"
    rule.created = int(datetime.now().timestamp())
    rule.operator.type = "simple"
    rule.operator.operand = "process.path"
    rule.operator.data = "/bin/test-app"
    return rule


def add_test_rule(rules, name):
    rules.add(
        RULE_TIME, TEST_NODE, name, "", "True", "False", "False",
        "allow", "always", "simple", "False", "process.path",
        "/bin/test-app", RULE_TIME
    )


def count_emits(rules, operation):
    emitted = []

    def _on_updated(what):
        emitted.append(what)

    rules.updated.connect(_on_updated)
    try:
        operation()
    finally:
        rules.updated.disconnect(_on_updated)
    return len(emitted)


def test_add_emits_updated(qtbot):
    rules = Rules.instance()
    assert count_emits(rules, lambda: add_test_rule(rules, "sig-add")) == 1


def test_add_rules_emits_once_per_batch(qtbot):
    """A node sends all its rules on connection: one refresh per batch,
    not one per rule."""
    rules = Rules.instance()
    batch = [new_proto_rule("sig-batch-0"), new_proto_rule("sig-batch-1")]
    results = []
    emits = count_emits(rules, lambda: results.append(rules.add_rules(TEST_NODE, batch)))
    assert results == [True]
    assert emits == 1


def test_delete_emits_updated(qtbot):
    rules = Rules.instance()
    add_test_rule(rules, "sig-delete")
    assert count_emits(rules, lambda: rules.delete("sig-delete", TEST_NODE, None)) == 1


def test_disable_emits_updated(qtbot):
    """Temporary rules are marked as disabled in the db when they expire."""
    rules = Rules.instance()
    add_test_rule(rules, "sig-disable")
    assert count_emits(rules, lambda: rules.disable(TEST_NODE, "sig-disable")) == 1


def test_update_time_does_not_emit(qtbot):
    """update_time() runs for every connection matching a rule; emitting
    here would refresh the views non-stop."""
    rules = Rules.instance()
    add_test_rule(rules, "sig-time")
    assert count_emits(rules, lambda: rules.update_time(RULE_TIME, "sig-time", TEST_NODE)) == 0
