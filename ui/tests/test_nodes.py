#
# pytest -v tests/nodes.py
#

import json
from PyQt5 import QtCore
from opensnitch import ui_pb2
from opensnitch.config import Config
from opensnitch.nodes import Nodes
from tests.dialogs import ClientConfig

class NotifTest(QtCore.QObject):
    """We need to subclass from QObject in order to be able to user signals and slots.
    """
    signal = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def callback(self, reply):
        assert reply != None
        assert reply.code == ui_pb2.OK and reply.type == ui_pb2.LOAD_FIREWALL and reply.data == "test"


class TestNodes():

    @classmethod
    def setup_method(self):
        self.nid = None
        self.daemon_config = ClientConfig
        self.nodes = Nodes.instance()
        self.nodes._db.insert("nodes",
                              "(addr, status, hostname, daemon_version, daemon_uptime, " \
                              "daemon_rules, cons, cons_dropped, version, last_connection)",
                              (
                                  "1.2.3.4", Nodes.ONLINE, "xxx", "v1.2.3", str(0),
                                  "", "0", "0", "",
                                  "2022-01-03 11:22:48.101624"
                              )
                              )


    def test_add(self, qtbot):
        node = self.nodes.add("peer:1.2.3.4", self.daemon_config)

        assert node != None

    def test_get_node(self, qtbot):
        node = self.nodes.get_node("peer:1.2.3.4")

        assert node != None

    def test_get_addr(self, qtbot):
        proto, addr = self.nodes.get_addr("peer:1.2.3.4")

        assert proto == "peer" and addr == "1.2.3.4"

    def test_get_nodes(self, qtbot):
        nodes = self.nodes.get_nodes()
        print(nodes)

        assert nodes.get("peer:1.2.3.4") != None

    def test_add_rule(self, qtbot):
        self.nodes.add_rule(
            "2022-01-03 11:22:48.101624",
            "peer:1.2.3.4",
            "test",
            True,
            False,
            Config.ACTION_ALLOW, Config.DURATION_30s,
            Config.RULE_TYPE_SIMPLE, False, "dest.host", ""
        )

        query = self.nodes._db.get_rule("test", "peer:1.2.3.4")

        assert query.first() == True
        assert query.record().value(0) == "2022-01-03 11:22:48.101624"
        assert query.record().value(1) == "peer:1.2.3.4"
        assert query.record().value(2) == "test"
        assert query.record().value(3) == "1"
        assert query.record().value(4) == "0"
        assert query.record().value(5) == Config.ACTION_ALLOW
        assert query.record().value(6) == Config.DURATION_30s
        assert query.record().value(7) == Config.RULE_TYPE_SIMPLE
        assert query.record().value(8) == "0"
        assert query.record().value(9) == "dest.host"

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
        query = self.nodes._db.select("SELECT status FROM nodes WHERE addr = '{0}'".format("1.2.3.4"))
        assert query != None and query.exec_() == True and query.first() == True
        assert query.record().value(0) == Nodes.ONLINE

        self.nodes.update("peer", "1.2.3.4", Nodes.OFFLINE)
        query = self.nodes._db.select("SELECT status FROM nodes WHERE addr = '{0}'".format("1.2.3.4"))
        assert query != None and query.exec_() == True and query.first() == True
        assert query.record().value(0) == Nodes.OFFLINE

    def test_send_notification(self, qtbot):
        notifs = NotifTest()
        notifs.signal.connect(notifs.callback)

        test_notif = ui_pb2.Notification(
            clientName="",
            serverName="",
            type=ui_pb2.LOAD_FIREWALL,
            data="test",
            rules=[])

        self.nid = self.nodes.send_notification("peer:1.2.3.4", test_notif, notifs.signal)
        assert self.nodes._notifications_sent[self.nid] != None
        assert self.nodes._notifications_sent[self.nid]['type'] == ui_pb2.LOAD_FIREWALL

    def test_reply_notification(self, qtbot):
        reply_notif = ui_pb2.Notification(
            id = self.nid,
            clientName="",
            serverName="",
            type=ui_pb2.LOAD_FIREWALL,
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

        assert node == None
        assert nodes.get("peer:1.2.3.4") == None
