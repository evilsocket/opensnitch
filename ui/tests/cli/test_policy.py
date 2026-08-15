#
# pytest -v cli/test_policy.py
#

from opensnitch.cli import policy, rules
from opensnitch.cli.proto import ui_pb2
from opensnitch.rule_consts import RuleConsts


def make_connection(**kwargs):
    fields = dict(protocol="tcp", dst_ip="140.82.121.6", dst_host="api.github.com",
                  dst_port=443, user_id=1000, process_id=41233,
                  process_path="/usr/bin/curl", process_args=["/usr/bin/curl"])
    fields.update(kwargs)
    return ui_pb2.Connection(**fields)


class TestSignature:

    def test_same_connection_same_signature(self):
        assert policy.signature("n", make_connection()) == \
            policy.signature("n", make_connection())

    def test_ignores_pid(self):
        """the pid changes on every run, it must not create a new queue entry."""
        assert policy.signature("n", make_connection(process_id=1)) == \
            policy.signature("n", make_connection(process_id=99999))

    def test_ignores_address_when_the_host_is_known(self):
        """a CDN answers with a different address every time."""
        assert policy.signature("n", make_connection(dst_ip="1.1.1.1")) == \
            policy.signature("n", make_connection(dst_ip="2.2.2.2"))

    def test_destination_matters(self):
        assert policy.signature("n", make_connection(dst_host="a.com")) != \
            policy.signature("n", make_connection(dst_host="b.com"))

    def test_process_matters(self):
        assert policy.signature("n", make_connection(process_path="/bin/a")) != \
            policy.signature("n", make_connection(process_path="/bin/b"))

    def test_node_matters(self):
        assert policy.signature("a", make_connection()) != \
            policy.signature("b", make_connection())


class TestProvisionalRule:

    def test_scoped_to_process_and_destination(self):
        con = make_connection()
        rule = policy.build_provisional(con, "abcdef123456", "allow", "1h")

        assert rule.action == "allow"
        assert rule.duration == "1h"
        assert rule.name.startswith(policy.PROVISIONAL_PREFIX)
        assert rule.operator.type == RuleConsts.RULE_TYPE_LIST

        got = [(o.operand, o.data) for o in rule.operator.list]
        assert (RuleConsts.OPERAND_PROCESS_PATH, "/usr/bin/curl") in got
        assert (RuleConsts.OPERAND_DEST_HOST, "api.github.com") in got
        assert (RuleConsts.OPERAND_DEST_PORT, "443") in got

    def test_uses_the_address_when_there_is_no_host(self):
        con = make_connection(dst_host="")
        rule = policy.build_provisional(con, "abcdef123456", "allow", "1h")
        got = [(o.operand, o.data) for o in rule.operator.list]
        assert (RuleConsts.OPERAND_DEST_IP, "140.82.121.6") in got

    def test_the_daemon_would_accept_it(self):
        rule = policy.build_provisional(make_connection(), "abcdef123456", "allow", "1h")
        assert rules.validate_rule(rule) is None

    def test_nothing_to_match_on(self):
        """rather than a rule that matches everything, let the daemon decide."""
        con = ui_pb2.Connection(protocol="tcp", dst_port=0)
        assert policy.build_provisional(con, "sig", "allow", "1h") is None


class TestPolicy:

    def test_answers_and_queues(self, db, config, connection):
        p = policy.Policy(db, config)
        rule = p.on_ask("unix:/local", connection)

        assert rule is not None
        assert db.pending_count() == 1

    def test_unreviewed_connections_are_denied_by_default(self, db, config, connection):
        """nothing gets out until it has been approved.

        This is the setting that decides whether the machine is fail-closed, so
        pin the default rather than leaving it to the configuration file.
        """
        assert config.get("policy", "unreviewed_action") == "deny"

        p = policy.Policy(db, config)
        assert p.on_ask("unix:/local", connection).action == "deny"

    def test_can_be_made_fail_open(self, db, config, connection):
        config.set("policy", "unreviewed_action", "allow")
        p = policy.Policy(db, config)

        rule = p.on_ask("unix:/local", connection)
        assert rule.action == "allow"
        # still queued: allowing it for now is not the same as approving it
        assert db.pending_count() == 1

    def test_repeats_count_instead_of_duplicating(self, db, config, connection):
        p = policy.Policy(db, config)
        p.on_ask("unix:/local", connection)
        p.on_ask("unix:/local", connection)

        assert db.pending_count() == 1
        assert db.pending()[0]["hits"] == 2

    def test_records_the_provisional_rule(self, db, config, connection):
        p = policy.Policy(db, config)
        rule = p.on_ask("unix:/local", connection)
        entry = db.pending()[0]

        assert entry["provisional_name"] == rule.name
        assert entry["provisional_expires"] is not None

    def test_full_queue_still_answers(self, db, config, connection):
        config.set("policy", "queue_max", "1")
        p = policy.Policy(db, config)
        p.on_ask("unix:/local", connection)

        other = ui_pb2.Connection(protocol="tcp", dst_ip="1.2.3.4", dst_port=80,
                                  process_path="/bin/wget", process_args=["/bin/wget"])
        rule = p.on_ask("unix:/local", other)

        # the packet is waiting, answering matters more than recording
        assert rule is not None
        assert db.pending_count() == 1
        assert p.dropped == 1

    def test_never_raises(self, db, config):
        p = policy.Policy(db, config)
        assert p.on_ask("unix:/local", object()) is None


class TestUndeliveredDecisions:
    """a decision taken while the daemon was away is applied when it asks again.

    Until the outbox has delivered a decision, answering with a fresh temporary
    deny would put it in front of an approved allow — and the daemon lets any
    matching deny beat an allow (daemon/rule/loader.go FindFirstMatch).
    """

    def _decide(self, db, config, connection, action="allow", duration="always"):
        from opensnitch.cli import review

        p = policy.Policy(db, config)
        p.on_ask("unix:/local", connection)
        entry = db.pending()[0]
        con = review.entry_connection(entry)
        decision = review.Decision(entry, con, action, duration, set())
        review.apply_decision(db, entry, decision.build())
        return p

    def _deliver_everything(self, db):
        for row in db.queued_notifications():
            db.mark_sent(row["id"], row["id"])
            db.mark_result(row["id"], True)

    def test_asking_again_gets_the_decision_not_a_new_provisional(self, db, config,
                                                                  connection):
        p = self._decide(db, config, connection)

        rule = p.on_ask("unix:/local", connection)

        assert rule.action == "allow"
        assert rule.duration == "always"
        # the decision stands, the entry is not reopened
        assert db.pending_count() == 0

    def test_the_attempt_still_counts(self, db, config, connection):
        p = self._decide(db, config, connection)
        p.on_ask("unix:/local", connection)

        entry = db.pending(state="decided")[0]
        assert entry["hits"] == 2

    def test_a_broad_decision_covers_a_new_destination(self, db, config, connection):
        """allow-always on the executable answers its other destinations too."""
        p = self._decide(db, config, connection)

        other = make_connection(dst_host="pypi.org", dst_ip="151.101.0.223")
        rule = p.on_ask("unix:/local", other)

        assert rule.action == "allow"
        # covered, not queued: reviewing it again would be the duplicate-prompt
        # problem all over
        assert db.pending_count() == 0

    def test_an_undelivered_deny_beats_an_undelivered_allow(self, db, config,
                                                            connection):
        from google.protobuf import json_format
        p = self._decide(db, config, connection)
        deny = rules.build_rule(
            "deny-curl", "deny", "always",
            [rules.new_operator("simple", "process.path", "/usr/bin/curl")])
        db.queue_notification("unix:/local", ui_pb2.CHANGE_RULE,
                              json_format.MessageToJson(deny))

        assert p.on_ask("unix:/local", connection).action == "deny"

    def test_a_delivered_decision_is_the_daemons_business_again(self, db, config,
                                                                connection):
        """once the daemon confirmed the rule and still asks, it expired or was
        removed over there: back to the provisional flow and the queue."""
        p = self._decide(db, config, connection, duration="1h")
        self._deliver_everything(db)

        rule = p.on_ask("unix:/local", connection)

        assert rule.action == "deny"
        assert rule.name.startswith(policy.PROVISIONAL_PREFIX)
        assert db.pending_count() == 1

    def test_another_nodes_decision_does_not_leak(self, db, config, connection):
        self._decide(db, config, connection)

        p2 = policy.Policy(db, config)
        rule = p2.on_ask("tcp:10.0.0.7:12345", connection)

        assert rule.name.startswith(policy.PROVISIONAL_PREFIX)
