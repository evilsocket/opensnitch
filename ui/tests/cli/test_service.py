#
# pytest -v cli/test_service.py
#

import json
import threading
import time

from opensnitch.cli import policy
from opensnitch.cli.proto import ui_pb2
from opensnitch.cli.service import Service, CLOSE_STREAM


class FakeContext:
    """the parts of a grpc context the service uses."""

    def __init__(self, peer="unix:"):
        self._peer = peer
        self.callbacks = []

    def peer(self):
        return self._peer

    def add_callback(self, callback):
        self.callbacks.append(callback)

    def cancel(self):
        for callback in self.callbacks:
            callback()


def make_service(db, config):
    return Service(db, policy.Policy(db, config), config)


def client_config(default_action="deny"):
    return ui_pb2.ClientConfig(
        id=1, name="testnode", version="6.0",
        config=json.dumps({"DefaultAction": default_action, "InterceptUnknown": False}),
        rules=[])


class TestPing:

    def test_echoes_the_id(self, db, config):
        """the daemon drops the answer if the id doesn't come back."""
        service = make_service(db, config)
        reply = service.Ping(ui_pb2.PingRequest(id=987654), FakeContext())
        assert reply.id == 987654


class TestPeerAddress:

    def test_unix_socket_has_no_address(self, db, config):
        service = make_service(db, config)
        assert service.peer_addr("unix:") == "unix:/local"

    def test_tcp_drops_the_ephemeral_port(self, db, config):
        """the daemon dials from a new source port on every reconnect; if it
        were part of the key, decisions queued while it was down would be
        addressed to a node that never returns."""
        service = make_service(db, config)
        assert service.peer_addr("ipv4:192.168.1.5:12345") == "ipv4:192.168.1.5"
        assert service.peer_addr("ipv4:192.168.1.5:12345") == \
            service.peer_addr("ipv4:192.168.1.5:54321")

    def test_ipv6(self, db, config):
        service = make_service(db, config)
        assert service.peer_addr("ipv6:[::1]:59680") == "ipv6:[::1]"
        assert service.peer_addr("ipv6:[fe80::1%eth0]:1") == "ipv6:[fe80::1%eth0]"


class TestVersionWarning:
    """an old daemon does not reject what we send, it misreads it."""

    def test_a_daemon_from_before_the_renumbering_is_flagged(self):
        from opensnitch.cli.service import version_warning
        assert "older than 1.6.0" in version_warning("1.5.8")
        assert "older than 1.6.0" in version_warning("1.5.8.1")

    def test_a_different_but_compatible_version_is_only_mentioned(self):
        from opensnitch.cli.service import version_warning
        warning = version_warning("1.6.5")
        assert warning is not None
        assert "older than" not in warning

    def test_the_same_version_says_nothing(self):
        from opensnitch.cli.service import version_warning
        from opensnitch.version import version
        assert version_warning(version) is None

    def test_garbage_says_nothing(self):
        from opensnitch.cli.service import version_warning
        assert version_warning("") is None
        assert version_warning("git-abc123") is None


class TestSubscribe:

    def test_registers_the_node_before_returning(self, db, config):
        """Notifications is refused for a node that isn't registered yet."""
        service = make_service(db, config)
        service.Subscribe(client_config(), FakeContext())

        assert service.get_node("unix:/local") is not None
        assert len(db.nodes()) == 1

    def test_overrides_the_default_action(self, db, config):
        """what the daemon does while we're busy answering another connection.

        Denying by default here matters as much as denying an unreviewed
        connection: without it a burst of new connections partly gets through
        while we're answering the first one.
        """
        service = make_service(db, config)
        reply = service.Subscribe(client_config(default_action="allow"), FakeContext())

        assert json.loads(reply.config)["DefaultAction"] == "deny"

    def test_the_default_action_follows_the_configuration(self, db, config):
        config.set("policy", "default_action", "allow")
        service = make_service(db, config)
        reply = service.Subscribe(client_config(default_action="deny"), FakeContext())

        assert json.loads(reply.config)["DefaultAction"] == "allow"

    def test_leaves_a_config_it_cannot_read_alone(self, db, config):
        service = make_service(db, config)
        broken = ui_pb2.ClientConfig(id=1, name="n", version="6.0", config="not json")
        assert service.Subscribe(broken, FakeContext()).config == "not json"

    def test_stores_the_rules_of_the_node(self, db, config):
        service = make_service(db, config)
        node_config = client_config()
        rule = node_config.rules.add()
        rule.name = "000-allow-localhost"
        rule.action = "allow"
        rule.duration = "always"
        rule.enabled = True
        service.Subscribe(node_config, FakeContext())

        assert "000-allow-localhost" in db.rule_names("unix:/local")


class TestAskRule:

    def test_answers_and_queues(self, db, config, connection):
        service = make_service(db, config)
        service.Subscribe(client_config(), FakeContext())

        rule = service.AskRule(connection, FakeContext())

        assert rule is not None
        assert rule.action == "deny"
        assert db.pending_count() == 1

    def test_answers_quickly(self, db, config, connection):
        """the daemon is holding the packet, and gives up after two minutes."""
        service = make_service(db, config)
        service.Subscribe(client_config(), FakeContext())

        start = time.time()
        service.AskRule(connection, FakeContext())
        assert time.time() - start < 1.0

    def test_allow_policy(self, db, config, connection):
        config.set("policy", "unreviewed_action", "allow")
        service = make_service(db, config)
        assert service.AskRule(connection, FakeContext()).action == "allow"


def open_replies(stop):
    """a reply stream that stays open, the way a connected daemon's does.

    An iterator that is already exhausted means the daemon hung up, and the
    service closes the notification stream when that happens.
    """
    def generator():
        while not stop.wait(0.01):
            pass
        return
        yield  # pragma: no cover
    return generator()


class TestNotifications:

    def test_refuses_an_unknown_node(self, db, config):
        service = make_service(db, config)
        assert list(service.Notifications(iter([]), FakeContext())) == []

    def test_delivers_what_the_outbox_puts_on_the_queue(self, db, config):
        service = make_service(db, config)
        service.Subscribe(client_config(), FakeContext())
        node = service.get_node("unix:/local")

        node.queue.put(ui_pb2.Notification(id=1, type=ui_pb2.CHANGE_RULE))
        node.queue.put(ui_pb2.Notification(id=0, type=CLOSE_STREAM))

        stop = threading.Event()
        got = list(service.Notifications(open_replies(stop), FakeContext()))
        stop.set()

        assert len(got) == 1
        assert got[0].id == 1

    def test_stops_when_the_daemon_hangs_up(self, db, config):
        service = make_service(db, config)
        service.Subscribe(client_config(), FakeContext())
        assert list(service.Notifications(iter([]), FakeContext())) == []

    def test_marks_the_node_offline_when_it_disconnects(self, db, config):
        service = make_service(db, config)
        service.Subscribe(client_config(), FakeContext())
        context = FakeContext()

        stream = service.Notifications(iter([]), context)
        node = service.get_node("unix:/local")
        node.queue.put(ui_pb2.Notification(id=0, type=CLOSE_STREAM))
        list(stream)
        context.cancel()

        assert db.nodes()[0]["online"] == 0

    def test_records_what_the_daemon_answered(self, db, config):
        service = make_service(db, config)
        service.Subscribe(client_config(), FakeContext())

        outbox_id = db.queue_notification("unix:/local", ui_pb2.CHANGE_RULE, "{}")
        db.mark_sent(outbox_id, 42)

        replies = [ui_pb2.NotificationReply(id=0, code=ui_pb2.OK),
                   ui_pb2.NotificationReply(id=42, code=ui_pb2.ERROR, data="bad regexp")]
        service._read_replies(service.get_node("unix:/local"), iter(replies))

        row = db.get_outbox(outbox_id)
        assert row["state"] == "error"
        assert row["last_error"] == "bad regexp"


class TestPostAlert:

    def test_always_answers(self, db, config):
        service = make_service(db, config)
        alert = ui_pb2.Alert(id=1)
        assert service.PostAlert(alert, FakeContext()).id == 0
