#
# pytest -v tests/test_nodes.py
#

import json
from PyQt6 import QtCore
import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()
from opensnitch.config import Config
from opensnitch.nodes import Nodes
from tests.dialogs import ClientConfig


class NotifTest(QtCore.QObject):
    """Subclass QObject to use signals and slots."""
    signal = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def callback(self, reply):
        assert reply is not None
        assert reply.code == ui_pb2.OK and reply.type == ui_pb2.ENABLE_FIREWALL and reply.data == "test"


class TestNodes():

    def setup_method(self):
        self.nid = None
        self.daemon_config = ClientConfig
        self.nodes = Nodes.instance()
        # Insert with full addr format "proto:addr" to match how update() queries
        self.nodes._db.insert("nodes",
                              "(addr, status, hostname, daemon_version, daemon_uptime, " \
                              "daemon_rules, cons, cons_dropped, version, last_connection)",
                              (
                                  "peer:1.2.3.4", Nodes.ONLINE, "xxx", "v1.2.3", str(0),
                                  "", "0", "0", "",
                                  "2022-01-03 11:22:48.101624"
                              )
                              )

    def test_add(self, qtbot):
        node = self.nodes.add("peer:1.2.3.4", self.daemon_config)
        assert node is not None

    def test_get_node(self, qtbot):
        node = self.nodes.get_node("peer:1.2.3.4")
        assert node is not None

    def test_get_addr(self, qtbot):
        proto, addr = self.nodes.get_addr("peer:1.2.3.4")
        assert proto == "peer" and addr == "1.2.3.4"

    def test_get_nodes(self, qtbot):
        nodes = self.nodes.get_nodes()
        assert nodes.get("peer:1.2.3.4") is not None

    def test_add_rule(self, qtbot):
        # add_rule signature: (time, node, name, description, enabled, precedence, nolog, action, duration, op_type, op_sensitive, op_operand, op_data, created)
        self.nodes.add_rule(
            "2022-01-03 11:22:48.101624",  # time
            "peer:1.2.3.4",                 # node
            "test",                         # name
            "test rule description",        # description
            True,                           # enabled
            False,                          # precedence
            False,                          # nolog
            Config.ACTION_ALLOW,            # action
            Config.DURATION_30s,            # duration
            Config.RULE_TYPE_SIMPLE,        # op_type
            False,                          # op_sensitive
            "dest.host",                    # op_operand
            "",                             # op_data
            "2022-01-03 11:22:48.101624"    # created
        )

        query = self.nodes._db.get_rule("test", "peer:1.2.3.4")

        assert query.first() == True
        assert query.record().value(2) == "test"  # name

    def test_update_rule_time(self, qtbot):
        query = self.nodes._db.get_rule("test", "peer:1.2.3.4")
        assert query.first() == True
        assert query.record().value(0) == "2022-01-03 11:22:48.101624"

        self.nodes.update_rule_time("2022-01-03 21:22:48.101624", "test", "peer:1.2.3.4")
        query = self.nodes._db.get_rule("test", "peer:1.2.3.4")
        assert query.first() == True
        assert query.record().value(0) == "2022-01-03 21:22:48.101624"

    def test_delete_rule(self, qtbot):
        query = self.nodes._db.get_rule("test", "peer:1.2.3.4")
        assert query.first() == True

        self.nodes.delete_rule("test", "peer:1.2.3.4", None)
        query = self.nodes._db.get_rule("test", "peer:1.2.3.4")
        assert query.first() == False

    def test_update_node_status(self, qtbot):
        # Note: update() constructs addr as "proto:addr", so we query with full address
        query = self.nodes._db.select("SELECT status FROM nodes WHERE addr = '{0}'".format("peer:1.2.3.4"))
        assert query is not None and query.exec() == True and query.first() == True
        assert query.record().value(0) == Nodes.ONLINE

        # update() signature: (peer, status=ONLINE)
        self.nodes.update("peer:1.2.3.4", Nodes.OFFLINE)
        query = self.nodes._db.select("SELECT status FROM nodes WHERE addr = '{0}'".format("peer:1.2.3.4"))
        assert query is not None and query.exec() == True and query.first() == True
        assert query.record().value(0) == Nodes.OFFLINE

    def test_send_notification(self, qtbot):
        notifs = NotifTest()
        notifs.signal.connect(notifs.callback)

        test_notif = ui_pb2.Notification(
            clientName="",
            serverName="",
            type=ui_pb2.ENABLE_FIREWALL,
            data="test",
            rules=[])

        self.nid = self.nodes.send_notification("peer:1.2.3.4", test_notif, notifs.signal)
        assert self.nodes._notifications_sent[self.nid] is not None
        assert self.nodes._notifications_sent[self.nid]['type'] == ui_pb2.ENABLE_FIREWALL

    def test_reply_notification(self, qtbot):
        reply_notif = ui_pb2.Notification(
            id=self.nid,
            clientName="",
            serverName="",
            type=ui_pb2.ENABLE_FIREWALL,
            data="test",
            rules=[])
        # just after process the reply, the notification is deleted (except if
        # is of type MONITOR_PROCESS
        self.nodes.reply_notification("peer:1.2.3.4", reply_notif)
        assert self.nid not in self.nodes._notifications_sent

    def test_delete(self, qtbot):
        self.nodes.delete("peer:1.2.3.4")
        node = self.nodes.get_node("peer:1.2.3.4")
        nodes = self.nodes.get_nodes()

        assert node is None
        assert nodes.get("peer:1.2.3.4") is None
