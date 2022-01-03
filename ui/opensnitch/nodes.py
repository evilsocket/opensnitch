from queue import Queue
from datetime import datetime
import time
import json

from opensnitch import ui_pb2
from opensnitch.database import Database
from opensnitch.config import Config

class Nodes():
    __instance = None
    LOG_TAG = "[Nodes]: "
    ONLINE = "\u2713 online"
    OFFLINE = "\u2613 offline"
    WARNING = "\u26a0"

    @staticmethod
    def instance():
        if Nodes.__instance == None:
            Nodes.__instance = Nodes()
        return Nodes.__instance

    def __init__(self):
        self._db = Database.instance()
        self._nodes = {}
        self._notifications_sent = {}

    def count(self):
        return len(self._nodes)

    def add(self, peer, client_config=None):
        try:
            proto, _addr = self.get_addr(peer)
            addr = "%s:%s" % (proto, _addr)
            if addr not in self._nodes:
                self._nodes[addr] = {
                        'notifications': Queue(),
                        'online':        True,
                        'last_seen':     datetime.now()
                        }
            else:
                self._nodes[addr]['last_seen'] = datetime.now()

            self._nodes[addr]['online'] = True
            self.add_data(addr, client_config)
            self.update(proto, _addr)

            return self._nodes[addr]

        except Exception as e:
            print(self.LOG_TAG, "exception adding/updating node: ", e, "addr:", addr, "config:", client_config)

        return None

    def add_data(self, addr, client_config):
        if client_config != None:
            self._nodes[addr]['data'] = self.get_client_config(client_config)
            self.add_rules(addr, client_config.rules)

    def add_rule(self, time, node, name, enabled, precedence, action, duration, op_type, op_sensitive, op_operand, op_data):
        # don't add rule if the user has selected to exclude temporary
        # rules
        if duration in Config.RULES_DURATION_FILTER:
            return

        self._db.insert("rules",
                  "(time, node, name, enabled, precedence, action, duration, operator_type, operator_sensitive, operator_operand, operator_data)",
                  (time, node, name, enabled, precedence, action, duration, op_type, op_sensitive, op_operand, op_data),
                        action_on_conflict="REPLACE")

    def add_rules(self, addr, rules):
        try:
            for _,r in enumerate(rules):
                self.add_rule(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                addr,
                                r.name, str(r.enabled), str(r.precedence), r.action, r.duration,
                                r.operator.type,
                                str(r.operator.sensitive),
                                r.operator.operand,
                                r.operator.data)
        except Exception as e:
            print(self.LOG_TAG + " exception adding node to db: ", e)

    def update_rule_time(self, time, rule_name, addr):
        self._db.update("rules",
                        "time=?",
                        (time, rule_name, addr),
                        "name=? AND node=?",
                        action_on_conflict="OR REPLACE"
                        )

    def delete_all(self):
        self.send_notifications(None)
        self._nodes = {}

    def delete(self, peer):
        proto, addr = self.get_addr(peer)
        addr = "%s:%s" % (proto, addr)
        # Force the node to get one new item from queue,
        # in order to loop and exit.
        self._nodes[addr]['notifications'].put(None)
        if addr in self._nodes:
            del self._nodes[addr]

    def get(self):
        return self._nodes

    def get_node(self, addr):
        try:
            return self._nodes[addr]
        except Exception as e:
            return None

    def get_nodes(self):
        return self._nodes

    def get_node_config(self, addr):
        try:
            return self._nodes[addr]['data'].config
        except Exception as e:
            print(self.LOG_TAG + " exception get_node_config(): ", e)
            return None

    def get_client_config(self, client_config):
        try:
            node_config = json.loads(client_config.config)
            if 'LogLevel' not in node_config:
                node_config['LogLevel'] = 1
                client_config.config = json.dumps(node_config)
        except Exception as e:
            print(self.LOG_TAG, "exception parsing client config", e)

        return client_config

    def get_addr(self, peer):
        peer = peer.split(":")
        # WA for backward compatibility
        if peer[0] == "unix" and peer[1] == "":
            peer[1] = "/local"
        return peer[0], peer[1]

    def get_notifications(self):
        notlist = []
        try:
            for c in self._nodes:
                if self._nodes[c]['online'] == False:
                    continue
                if self._nodes[c]['notifications'].empty():
                    continue
                notif = self._nodes[c]['notifications'].get(False)
                if notif != None:
                    self._nodes[c]['notifications'].task_done()
                    notlist.append(notif)
        except Exception as e:
            print(self.LOG_TAG + " exception get_notifications(): ", e)

        return notlist

    def save_node_config(self, addr, config):
        try:
            self._nodes[addr]['data'].config = config
        except Exception as e:
            print(self.LOG_TAG + " exception saving node config: ", e, addr, config)

    def save_nodes_config(self, config):
        try:
            for c in self._nodes:
                self._nodes[c]['data'].config = config
        except Exception as e:
            print(self.LOG_TAG + " exception saving nodes config: ", e, config)

    def start_interception(self, _addr=None, _callback=None):
        return self.firewall(not_type=ui_pb2.LOAD_FIREWALL, addr=_addr, callback=_callback)

    def stop_interception(self, _addr=None, _callback=None):
        return self.firewall(not_type=ui_pb2.UNLOAD_FIREWALL, addr=_addr, callback=_callback)

    def firewall(self, not_type=ui_pb2.LOAD_FIREWALL, addr=None, callback=None):
        noti = ui_pb2.Notification(clientName="", serverName="", type=not_type, data="", rules=[])
        if addr == None:
            nid = self.send_notifications(noti, callback)
        else:
            nid = self.send_notification(addr, noti, callback)

        return nid, noti

    def send_notification(self, addr, notification, callback_signal=None):
        try:
            notification.id = int(str(time.time()).replace(".", ""))
            if addr not in self._nodes:
                # FIXME: the reply is sent before we return the notification id
                if callback_signal != None:
                    callback_signal.emit(
                        ui_pb2.NotificationReply(
                            id=notification.id,
                            code=ui_pb2.ERROR,
                            data="node not connected: {0}".format(addr)
                        )
                    )
                return notification.id

            self._notifications_sent[notification.id] = {
                    'callback': callback_signal,
                    'type': notification.type
                    }
            self._nodes[addr]['notifications'].put(notification)
        except Exception as e:
            print(self.LOG_TAG + " exception sending notification: ", e, addr, notification)
            if callback_signal != None:
                callback_signal.emit(
                    ui_pb2.NotificationReply(
                        id=notification.id,
                        code=ui_pb2.ERROR,
                        data="Notification not sent ({0}):<br>{1}".format(addr, e)
                    )
                )

        return notification.id

    def send_notifications(self, notification, callback_signal=None):
        """
        Enqueues a notification to the clients queue.
        It'll be retrieved and delivered by get_notifications
        """
        try:
            notification.id = int(str(time.time()).replace(".", ""))
            for c in self._nodes:
                self._nodes[c]['notifications'].put(notification)
            self._notifications_sent[notification.id] = {
                    'callback': callback_signal,
                    'type': notification.type
                    }
        except Exception as e:
            print(self.LOG_TAG + " exception sending notifications: ", e, notification)

        return notification.id

    def reply_notification(self, addr, reply):
        if reply == None:
            print(self.LOG_TAG, " reply notification None")
            return

        if reply.id in self._notifications_sent:
            if self._notifications_sent[reply.id] != None:
                if self._notifications_sent[reply.id]['callback'] != None:
                    self._notifications_sent[reply.id]['callback'].emit(reply)

                # delete only one-time notifications
                # we need the ID of streaming notifications from the server
                # (monitor_process for example) to keep track of the data sent to us.
                if self._notifications_sent[reply.id]['type'] != ui_pb2.MONITOR_PROCESS:
                    del self._notifications_sent[reply.id]

    def update(self, proto, addr, status=ONLINE):
        try:
            self._db.update("nodes",
                    "hostname=?,version=?,last_connection=?,status=?",
                    (
                        self._nodes[proto+":"+addr]['data'].name,
                        self._nodes[proto+":"+addr]['data'].version,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        status,
                        addr),
                        "addr=?"
                    )
        except Exception as e:
            print(self.LOG_TAG + " exception updating DB: ", e, addr)

    def update_all(self, status=OFFLINE):
        try:
            for peer in self._nodes:
                proto, addr = self.get_addr(peer)
                self._db.update("nodes",
                        "hostname=?,version=?,last_connection=?,status=?",
                        (
                            self._nodes[proto+":"+addr]['data'].name,
                            self._nodes[proto+":"+addr]['data'].version,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            status,
                            addr),
                            "addr=?"
                        )
        except Exception as e:
            print(self.LOG_TAG + " exception updating nodes: ", e)

    def delete_rule(self, rule_name, addr, callback):
        rule = ui_pb2.Rule(name=rule_name)
        rule.enabled = False
        rule.action = ""
        rule.duration = ""
        rule.operator.type = ""
        rule.operator.operand = ""
        rule.operator.data = ""

        noti = ui_pb2.Notification(type=ui_pb2.DELETE_RULE, rules=[rule])
        if addr != None:
            nid = self.send_notification(addr, noti, None)
        else:
            nid = self.send_notifications(noti, None)
        self._db.delete_rule(rule.name, addr)

        return nid, noti
