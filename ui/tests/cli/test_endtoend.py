#
# pytest -v cli/test_endtoend.py
#
# The other tests drive the service directly with a fake context. This one runs
# the real gRPC server on a real unix socket and talks to it with a real client,
# doing what opensnitchd does: subscribe, open the notifications stream, ping,
# ask about a connection, and answer the notifications it is sent.
#
# It is the closest thing to a live daemon that doesn't need root or netfilter,
# so it's also the quickest way to check the client works on a new machine.

import json
import os
import queue
import threading
import time

import grpc
import pytest
from google.protobuf import json_format

from opensnitch.cli import db as dbmod, rules
from opensnitch.cli.config import Config
from opensnitch.cli.proto import ui_pb2, ui_pb2_grpc
from opensnitch.cli.server import Server

TIMEOUT = 10


class FakeDaemon:
    """acts like opensnitchd: dials the client and answers its notifications."""

    def __init__(self, address):
        self.channel = grpc.insecure_channel(address)
        self.stub = ui_pb2_grpc.UIStub(self.channel)
        self.outgoing = queue.Queue()
        self.received = []
        self._stream = None
        self._reader = None

    def subscribe(self, default_action="deny"):
        config = json.dumps({"DefaultAction": default_action, "InterceptUnknown": False})
        return self.stub.Subscribe(
            ui_pb2.ClientConfig(id=1, name="testnode", version="6.0", config=config),
            timeout=TIMEOUT)

    def open_notifications(self):
        # the daemon says hello before anything is sent to it
        self.outgoing.put(ui_pb2.NotificationReply(id=0, code=ui_pb2.OK))

        def replies():
            while True:
                item = self.outgoing.get()
                if item is None:
                    return
                yield item

        self._stream = self.stub.Notifications(replies())

        def read():
            try:
                for notification in self._stream:
                    self.received.append(notification)
                    # answer it the way the daemon does
                    self.outgoing.put(ui_pb2.NotificationReply(
                        id=notification.id, code=ui_pb2.OK))
            except grpc.RpcError:
                pass

        self._reader = threading.Thread(target=read, daemon=True)
        self._reader.start()

    def wait_for(self, count):
        deadline = time.time() + TIMEOUT
        while len(self.received) < count and time.time() < deadline:
            time.sleep(0.05)
        return list(self.received)

    def close(self):
        self.outgoing.put(None)
        self.channel.close()


@pytest.fixture
def running(tmp_path):
    """a client listening on a unix socket, and a daemon connected to it."""
    socket = "unix://%s" % (tmp_path / "osui.sock")
    conf = tmp_path / "cli.conf"
    conf.write_text(
        "[server]\naddress = %s\n"
        "[policy]\nunreviewed_action = deny\nunreviewed_duration = 30s\n"
        "[db]\npath = %s\n" % (socket, tmp_path / "cli.db"))

    server = Server(Config(path=str(conf)))
    server.start()
    daemon = FakeDaemon(socket)
    try:
        yield server, daemon
    finally:
        daemon.close()
        server.stop(grace=1)


def a_connection(host="api.github.com"):
    return ui_pb2.Connection(
        protocol="tcp", dst_ip="140.82.121.6", dst_host=host, dst_port=443,
        user_id=1000, process_id=41233, process_path="/usr/bin/curl",
        process_args=["/usr/bin/curl", "-sSL", "https://%s" % host])


class TestOverARealSocket:

    def test_the_socket_is_not_world_readable(self, running, tmp_path):
        """it decides what the machine may connect to; other users can't have it."""
        mode = os.stat(str(tmp_path / "osui.sock")).st_mode & 0o777
        assert mode == 0o640

    def test_subscribe_answers_with_our_default_action(self, running):
        server, daemon = running
        reply = daemon.subscribe(default_action="allow")

        assert json.loads(reply.config)["DefaultAction"] == "deny"
        assert len(server.db.nodes()) == 1

    def test_ping_echoes_the_id(self, running):
        server, daemon = running
        daemon.subscribe()
        assert daemon.stub.Ping(ui_pb2.PingRequest(id=987654), timeout=TIMEOUT).id == 987654

    def test_a_connection_is_answered_and_queued(self, running):
        server, daemon = running
        daemon.subscribe()

        started = time.time()
        rule = daemon.stub.AskRule(a_connection(), timeout=TIMEOUT)
        elapsed = time.time() - started

        # the daemon is holding the packet and gives up after 120s
        assert elapsed < 5
        assert rule.action == "deny"
        assert rule.duration == "30s"
        assert server.db.pending_count() == 1

    def test_asking_again_counts_instead_of_duplicating(self, running):
        server, daemon = running
        daemon.subscribe()
        daemon.stub.AskRule(a_connection(), timeout=TIMEOUT)
        daemon.stub.AskRule(a_connection(), timeout=TIMEOUT)

        assert server.db.pending_count() == 1
        assert server.db.pending()[0]["hits"] == 2

    def test_different_destinations_are_separate_entries(self, running):
        server, daemon = running
        daemon.subscribe()
        daemon.stub.AskRule(a_connection("api.github.com"), timeout=TIMEOUT)
        daemon.stub.AskRule(a_connection("pypi.org"), timeout=TIMEOUT)

        assert server.db.pending_count() == 2

    def test_a_decision_reaches_the_daemon_in_order(self, running):
        """the temporary rule is withdrawn first, then the real one installed."""
        server, daemon = running
        daemon.subscribe()
        daemon.open_notifications()
        daemon.stub.AskRule(a_connection(), timeout=TIMEOUT)

        entry = server.db.pending()[0]
        final = rules.build_rule(
            "allow-always-simple-github", "allow", "always",
            [rules.new_operator("regexp", "dest.host", r"^(|.*\.)github\.com$")])

        stale = ui_pb2.Rule(name=entry["provisional_name"])
        stale.operator.type = "simple"
        stale.operator.operand = "true"
        server.db.queue_notification(entry["node"], ui_pb2.DELETE_RULE,
                                     json_format.MessageToJson(stale))
        server.db.queue_notification(entry["node"], ui_pb2.CHANGE_RULE,
                                     json_format.MessageToJson(final))
        server.drain_outbox()

        got = daemon.wait_for(2)
        assert [n.type for n in got] == [ui_pb2.DELETE_RULE, ui_pb2.CHANGE_RULE]
        assert got[0].rules[0].name == entry["provisional_name"]
        assert got[1].rules[0].name == "allow-always-simple-github"
        assert got[1].rules[0].operator.data == r"^(|.*\.)github\.com$"

    def test_a_disconnected_nodes_backlog_does_not_starve_the_others(self, running):
        """decisions for a node that is down stay queued; they must not stop
        the decisions for a node that is up from going out."""
        server, daemon = running
        daemon.subscribe()
        daemon.open_notifications()

        for i in range(60):
            server.db.queue_notification(
                "ipv4:10.0.0.9", ui_pb2.CHANGE_RULE,
                json_format.MessageToJson(ui_pb2.Rule(name="down-%d" % i)))
        server.db.queue_notification(
            "unix:/local", ui_pb2.CHANGE_RULE,
            json_format.MessageToJson(ui_pb2.Rule(name="up")))

        assert server.drain_outbox() == 1
        got = daemon.wait_for(1)
        assert [n.rules[0].name for n in got] == ["up"]
        assert server.db.queued_count() == 60

    def test_the_daemons_answer_is_recorded(self, running):
        server, daemon = running
        daemon.subscribe()
        daemon.open_notifications()

        outbox_id = server.db.queue_notification(
            "unix:/local", ui_pb2.CHANGE_RULE,
            json_format.MessageToJson(ui_pb2.Rule(name="r")))
        server.drain_outbox()
        daemon.wait_for(1)

        deadline = time.time() + TIMEOUT
        while server.db.get_outbox(outbox_id)["state"] != dbmod.OUT_DONE:
            if time.time() > deadline:
                break
            time.sleep(0.05)
        assert server.db.get_outbox(outbox_id)["state"] == dbmod.OUT_DONE

    def test_a_restarted_daemon_can_come_back(self, running, tmp_path):
        """the daemon reconnects with the same peer string over a unix socket.

        The first version of the service kept the old session's state and its
        already-fired stop event, so after one daemon restart the notifications
        stream ended the moment it opened and no decision could ever be
        delivered again. Three lifetimes over the same socket, to be sure.
        """
        server, daemon = running
        daemon.subscribe()
        daemon.open_notifications()
        daemon.close()
        time.sleep(0.3)

        second = FakeDaemon("unix://%s" % (tmp_path / "osui.sock"))
        try:
            second.subscribe()
            second.open_notifications()

            server.db.queue_notification("unix:/local", ui_pb2.CHANGE_RULE,
                                         json_format.MessageToJson(ui_pb2.Rule(name="after")))
            server.drain_outbox()

            got = second.wait_for(1)
            assert len(got) == 1, "the reconnected daemon never got the notification"
            assert got[0].rules[0].name == "after"
        finally:
            second.close()

    def test_a_decision_the_daemon_never_answered_is_sent_again(self, running, tmp_path):
        """the stream can drop between sending and the daemon's reply.

        The row was stuck in 'sent' until the service restarted; now it goes
        back in the queue when the stream closes, and the next session gets it.
        """
        server, daemon = running
        daemon.subscribe()
        # no notifications stream answering: send, then let the daemon vanish
        outbox_id = server.db.queue_notification(
            "unix:/local", ui_pb2.CHANGE_RULE,
            json_format.MessageToJson(ui_pb2.Rule(name="unanswered")))

        stream = daemon.stub.Notifications(iter([ui_pb2.NotificationReply(id=0, code=ui_pb2.OK)]))
        # sending an already-exhausted request stream makes the service's reader
        # finish at once, like a daemon that died mid-conversation
        server.drain_outbox()
        try:
            list(stream)
        except grpc.RpcError:
            pass
        time.sleep(0.3)

        row = server.db.get_outbox(outbox_id)
        assert row["state"] == dbmod.OUT_QUEUED, \
            "an unanswered notification must not stay in 'sent': %s" % row["state"]

        second = FakeDaemon("unix://%s" % (tmp_path / "osui.sock"))
        try:
            second.subscribe()
            second.open_notifications()
            server.drain_outbox()
            got = second.wait_for(1)
            assert [n.rules[0].name for n in got] == ["unanswered"]
        finally:
            second.close()

    def test_a_second_client_cannot_take_the_socket(self, running, tmp_path):
        """opensnitch-ui and opensnitch-cli serve cannot both own one daemon."""
        server, _ = running
        conf = tmp_path / "second.conf"
        conf.write_text("[server]\naddress = unix://%s\n[db]\npath = %s\n"
                        % (tmp_path / "osui.sock", tmp_path / "second.db"))

        with pytest.raises(RuntimeError, match="already being served"):
            Server(Config(path=str(conf))).start()
