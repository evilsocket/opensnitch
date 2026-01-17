import json
import datetime

from PyQt6 import QtCore, QtGui, uic, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from .. import (
    constants
)

TASK_NAME = "sockets-monitor"

class Netstat:
    def __init__(self, win, cfg, db):
        self.win = win
        self.db = db
        self.cfg = cfg

        self.configure()

        self.win.comboNetstatInterval.currentIndexChanged.connect(lambda index: self.cb_combo_netstat_changed(0, index))
        self.win.comboNetstatNodes.activated.connect(lambda index: self.cb_combo_netstat_changed(1, index))
        self.win.comboNetstatProto.currentIndexChanged.connect(lambda index: self.cb_combo_netstat_changed(2, index))
        self.win.comboNetstatFamily.currentIndexChanged.connect(lambda index: self.cb_combo_netstat_changed(3, index))
        self.win.comboNetstatStates.currentIndexChanged.connect(lambda index: self.cb_combo_netstat_changed(4, index))

    def cb_combo_netstat_changed(self, combo, idx):
        refreshIndex = self.win.comboNetstatInterval.currentIndex()
        self.unmonitor_node(self.win.LAST_NETSTAT_NODE)
        if refreshIndex > 0:
            self.monitor_node()

        if combo == 2:
            self.cfg.setSettings(Config.STATS_NETSTAT_FILTER_PROTO, self.win.comboNetstatProto.currentIndex())
        elif combo == 3:
            self.cfg.setSettings(Config.STATS_NETSTAT_FILTER_FAMILY, self.win.comboNetstatFamily.currentIndex())
        elif combo == 4:
            self.cfg.setSettings(Config.STATS_NETSTAT_FILTER_STATE, self.win.comboNetstatStates.currentIndex())

        #nIdx = self.win.comboNetstatNodes.currentIndex()
        #self.win.LAST_NETSTAT_NODE = self.comboNetstatNodes.itemData(nIdx)

    def configure(self):
        self.win.comboNetstatProto.clear()
        self.win.comboNetstatProto.addItem(QC.translate("stats", "ALL"), 0)
        self.win.comboNetstatProto.addItem("TCP", 6)
        self.win.comboNetstatProto.addItem("UDP", 17)
        self.win.comboNetstatProto.addItem("SCTP", 132)
        self.win.comboNetstatProto.addItem("DCCP", 33)
        self.win.comboNetstatProto.addItem("ICMP", 1)
        self.win.comboNetstatProto.addItem("ICMPv6", 58)
        self.win.comboNetstatProto.addItem("IGMP", 2)
        self.win.comboNetstatProto.addItem("RAW", 255)

        # These are sockets states. Conntrack uses a different enum.
        self.win.comboNetstatStates.clear()
        self.win.comboNetstatStates.addItem(QC.translate("stats", "ALL"), 0)
        self.win.comboNetstatStates.addItem("Established", 1)
        self.win.comboNetstatStates.addItem("TCP_SYN_SENT", 2)
        self.win.comboNetstatStates.addItem("TCP_SYN_RECV", 3)
        self.win.comboNetstatStates.addItem("TCP_FIN_WAIT1", 4)
        self.win.comboNetstatStates.addItem("TCP_FIN_WAIT2", 5)
        self.win.comboNetstatStates.addItem("TCP_TIME_WAIT", 6)
        self.win.comboNetstatStates.addItem("CLOSE", 7)
        self.win.comboNetstatStates.addItem("TCP_CLOSE_WAIT", 8)
        self.win.comboNetstatStates.addItem("TCP_LAST_ACK", 9)
        self.win.comboNetstatStates.addItem("LISTEN", 10)
        self.win.comboNetstatStates.addItem("TCP_CLOSING", 11)
        self.win.comboNetstatStates.addItem("TCP_NEW_SYN_RECV", 12)

        self.win.comboNetstatFamily.clear()
        self.win.comboNetstatFamily.addItem(QC.translate("stats", "ALL"), 0)
        self.win.comboNetstatFamily.addItem("AF_INET", 2)
        self.win.comboNetstatFamily.addItem("AF_INET6", 10)
        self.win.comboNetstatFamily.addItem("AF_PACKET", 17) # 0x11
        self.win.comboNetstatFamily.addItem("AF_XDP", 44)

    def configure_combos(self):
        self.win.comboNetstatStates.blockSignals(True);
        self.win.comboNetstatStates.setCurrentIndex(
            self.cfg.getInt(Config.STATS_NETSTAT_FILTER_STATE, 0)
        )
        self.win.comboNetstatStates.blockSignals(False);
        self.win.comboNetstatFamily.blockSignals(True);
        self.win.comboNetstatFamily.setCurrentIndex(
            self.cfg.getInt(Config.STATS_NETSTAT_FILTER_FAMILY, 0)
        )
        self.win.comboNetstatFamily.blockSignals(False);
        self.win.comboNetstatProto.blockSignals(True);
        self.win.comboNetstatProto.setCurrentIndex(
            self.cfg.getInt(Config.STATS_NETSTAT_FILTER_PROTO, 0)
        )
        self.win.comboNetstatProto.blockSignals(False);


    def update_node_list(self, count, node_list):
        prevNode = self.win.comboNetstatNodes.currentIndex()
        self.win.comboNetstatNodes.blockSignals(True)
        self.win.comboNetstatNodes.clear()

        for node in node_list:
            hostname = ""
            try:
                hostname = node_list[node]['data'].name
            except:
                pass
            node_lbl = f"{node}"
            if hostname != "":
                node_lbl = f"{node} - {hostname}"
            self.win.comboNetstatNodes.addItem(node_lbl, node)

        if prevNode == -1:
            prevNode = 0
        self.win.comboNetstatNodes.setCurrentIndex(prevNode)
        if count == 0:
            self.win.netstatLabel.setText("")
            self.win.comboNetstatInterval.setCurrentIndex(0)

        showNodes = len(node_list) > 1
        self.win.comboNetstatNodes.setVisible(showNodes)

        self.win.comboNetstatNodes.blockSignals(False);

    def monitor_node(self):
        self.win.netstatLabel.show()

        nIdx = self.win.comboNetstatNodes.currentIndex()
        node_addr = self.win.comboNetstatNodes.itemData(nIdx)
        if node_addr == "":
            self.win.netstatLabel.setText("")
            return
        if not self.win._nodes.is_connected(node_addr):
            print(f"monitor_node_netstat, node not connected: {node_addr}")
            self.win.netstatLabel.setText(f"{node_addr} node is not connected")
            return

        refreshIndex = self.win.comboNetstatInterval.currentIndex()
        if refreshIndex == 0:
            self.unmonitor_node(node_addr)
            return

        refreshInterval = self.win.comboNetstatInterval.currentText()
        proto = self.win.comboNetstatProto.currentIndex()
        family = self.win.comboNetstatFamily.currentIndex()
        state = self.win.comboNetstatStates.currentIndex()
        config = '{"name": "%s", "data": {"interval": "%s", "state": %d, "proto": %d, "family": %d}}' % (
            TASK_NAME,
            refreshInterval,
            int(self.win.comboNetstatStates.itemData(state)),
            int(self.win.comboNetstatProto.itemData(proto)),
            int(self.win.comboNetstatFamily.itemData(family))
        )

        self.win.netstatLabel.setText(QC.translate("stats", "loading in {0}...".format(refreshInterval)))

        noti = ui_pb2.Notification(
            clientName="",
            serverName="",
            type=ui_pb2.TASK_START,
            data=config,
            rules=[])
        nid = self.win._nodes.send_notification(
            node_addr, noti, self.win._notification_callback
        )
        if nid != None:
            self.win._notifications_sent[nid] = noti

        self.win.LAST_NETSTAT_NODE = node_addr

    def unmonitor_node(self, node_addr):
        self.win.netstatLabel.hide()
        self.win.netstatLabel.setText("")
        if node_addr == "":
            return

        if not self.win._nodes.is_connected(node_addr):
            print(f"unmonitor_node_netstat, node not connected: {node_addr}")
        else:
            noti = ui_pb2.Notification(
                clientName="",
                serverName="",
                type=ui_pb2.TASK_STOP,
                data='{"name": "%s", "data": {}}' % TASK_NAME,
                rules=[])
            nid = self.win._nodes.send_notification(
                node_addr, noti, self.win._notification_callback
            )
            if nid != None:
                self.win._notifications_sent[nid] = noti

        self.win.LAST_NETSTAT_NODE = None

    def update_node(self, node_addr, data):
        netstat = json.loads(data)
        fields = []
        values = []
        cols = "(last_seen, node, src_port, src_ip, dst_ip, dst_port, proto, uid, inode, iface, family, state, cookies, rqueue, wqueue, expires, retrans, timer, proc_path, proc_comm, proc_pid)"
        try:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # TODO: make this optional
            self.db.clean(self.win.TABLES[ constants.TAB_NETSTAT]['name'])
            self.db.transaction()
            for k in netstat['Table']:
                if k == None:
                    continue
                sck = k['Socket']
                iface = k['Socket']['ID']['Interface']
                if k['Iface'] != "":
                    iface = k['Iface']
                proc_comm = ""
                proc_path = ""
                proc_pid = ""
                if k['PID'] != -1 and str(k['PID']) in netstat['Processes'].keys():
                    proc_pid = str(k['PID'])
                    proc_path = netstat['Processes'][proc_pid]['Path']
                    proc_comm = netstat['Processes'][proc_pid]['Comm']
                self.db.insert(
                    self.win.TABLES[ constants.TAB_NETSTAT]['name'],
                    cols,
                    (
                        now,
                        node_addr,
                        k['Socket']['ID']['SourcePort'],
                        k['Socket']['ID']['Source'],
                        k['Socket']['ID']['Destination'],
                        k['Socket']['ID']['DestinationPort'],
                        k['Proto'],
                        k['Socket']['UID'],
                        k['Socket']['INode'],
                        iface,
                        k['Socket']['Family'],
                        k['Socket']['State'],
                        str(k['Socket']['ID']['Cookie']),
                        k['Socket']['RQueue'],
                        k['Socket']['WQueue'],
                        k['Socket']['Expires'],
                        k['Socket']['Retrans'],
                        k['Socket']['Timer'],
                        proc_path,
                        proc_comm,
                        proc_pid
                    )
                )
            self.db.commit()
            self.win.netstatLabel.setText(QC.translate("stats", "refreshing..."))
            self.win.refresh_active_table()
        except Exception as e:
            print("_update_netstat_table exception:", e)
            print(data)
            self.win.netstatLabel.setText("error loading netstat table")
            self.win.netstatLabel.setText(QC.translate("stats", "error loading: {0}".format(repr(e))))

