from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot
from queue import Queue
from datetime import datetime
import time
import json

from opensnitch import ui_pb2
from opensnitch.database import Database
from opensnitch.config import Config
from opensnitch.utils import NetworkInterfaces
from opensnitch.rules import Rules

class Nodes(QObject):
    __instance = None
    nodesUpdated = pyqtSignal(int) # total

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
        QObject.__init__(self)
        self._db = Database.instance()
        self._rules = Rules()
        self._nodes = {}
        self._notifications_sent = {}
        self._interfaces = NetworkInterfaces()

    def count(self):
        return len(self._nodes)

    def add(self, _peer, client_config=None):
        try:
            proto, addr = self.get_addr(_peer)
            peer = proto+":"+addr
            if peer not in self._nodes:
                self._nodes[peer] = {
                        'notifications': Queue(),
                        'online':        True,
                        'last_seen':     datetime.now()
                        }
            else:
                self._nodes[peer]['last_seen'] = datetime.now()

            self._nodes[peer]['online'] = True
            self.add_data(peer, client_config)
            self.update(peer)

            self.nodesUpdated.emit(self.count())

            return self._nodes[peer], peer

        except Exception as e:
            print(self.LOG_TAG, "exception adding/updating node: ", e, "addr:", addr, "config:", client_config)

        return None, None

    def add_data(self, addr, client_config):
        if client_config != None:
            self._nodes[addr]['data'] = self.get_client_config(client_config)
            self.add_fw_config(addr, client_config.systemFirewall)
            self._rules.add_rules(addr, client_config.rules)

    def add_fw_config(self, addr, fwconfig):
        self._nodes[addr]['firewall'] = fwconfig

    def add_fw_rules(self, addr, fwconfig):
        self._nodes[addr]['fwrules'] = fwconfig

    def add_rule(self, time, node, name, description, enabled, precedence, nolog, action, duration, op_type, op_sensitive, op_operand, op_data, created):
        # don't add rule if the user has selected to exclude temporary
        # rules
        if duration in Config.RULES_DURATION_FILTER:
            return

        self._rules.add(time, node, name, description, enabled, precedence, nolog, action, duration, op_type, op_sensitive, op_operand, op_data, created)

    def add_rules(self, addr, rules):
        try:
            self._rules.add_rules(addr, rules)
        except Exception as e:
            print(self.LOG_TAG + " exception adding node to db: ", e)

    def delete_rule(self, rule_name, addr, callback):
        deleted_rule = self._rules.delete(rule_name, addr, callback)
        if deleted_rule == None:
            print(self.LOG_TAG, "error deleting rule", rule_name)
            return None, None

        noti = ui_pb2.Notification(type=ui_pb2.DELETE_RULE, rules=[deleted_rule])
        if addr != None:
            nid = self.send_notification(addr, noti, callback)
        else:
            nid = self.send_notifications(noti, callback)

        return nid, noti

    def delete_rule_by_field(self, field, values):
        return self._rules.delete_by_field(field, values)

    def rule_to_json(self, addr, rule_name):
        return self._rules.rule_to_json(addr, rule_name)

    def export_rule(self, addr, rule_name, outdir):
        return self._rules.export_rule(addr, rule_name, outdir)

    def export_rules(self, addr, outdir):
        return self._rules.export_rules(addr, outdir)

    def import_rules(self, addr=None, rulesdir="", callback=None):
        rules_list = self._rules.import_rules(rulesdir)
        if rules_list == None:
            return None, None, None

        notif = ui_pb2.Notification(
                id=int(str(time.time()).replace(".", "")),
                type=ui_pb2.CHANGE_RULE,
                data="",
                rules=rules_list)

        if addr != None:
            nid = self.send_notification(addr, notif, callback)
        else:
            nid = self.send_notifications(notif, callback)

        return nid, notif, rules_list

    def update_rule_time(self, time, rule_name, addr):
        self._rules.update_time(time, rule_name, addr)

    def delete_all(self):
        self.send_notifications(None)
        self._nodes = {}
        self.nodesUpdated.emit(self.count())

    def delete(self, peer):
        try:
            proto, addr = self.get_addr(peer)
            addr = "%s:%s" % (proto, addr)
            # Force the node to get one new item from queue,
            # in order to loop and exit.
            self._nodes[addr]['notifications'].put(None)
        except:
            addr = peer

        if addr in self._nodes:
            del self._nodes[addr]
            self.nodesUpdated.emit(self.count())

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
        try:
            peer = peer.split(":")
            # WA for backward compatibility
            if peer[0] == "unix" and peer[1] == "":
                peer[1] = "/local"
            return peer[0], peer[1]
        except:
            print(self.LOG_TAG, "get_addr() error getting addr:", peer)
            return peer

    def is_local(self, addr):
        if addr.startswith("unix"):
            return True

        if addr.startswith("ipv4") or addr.startswith("ipv6"):
            ifaces = self._interfaces.list()
            for name in ifaces:
                if ifaces[name] in addr:
                    return True

        return False

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

    def change_node_config(self, addr, config, _callback):
        _cfg = json.dumps(config, indent="    ")
        notif = ui_pb2.Notification(
            id=int(str(time.time()).replace(".", "")),
            type=ui_pb2.CHANGE_CONFIG,
            data=_cfg,
            rules=[])
        self.save_node_config(addr, _cfg)
        return self.send_notification(addr, notif, _callback), notif

    def start_interception(self, _addr=None, _callback=None):
        return self.firewall(not_type=ui_pb2.ENABLE_INTERCEPTION, addr=_addr, callback=_callback)

    def stop_interception(self, _addr=None, _callback=None):
        return self.firewall(not_type=ui_pb2.DISABLE_INTERCEPTION, addr=_addr, callback=_callback)

    def firewall(self, not_type=ui_pb2.ENABLE_INTERCEPTION, addr=None, callback=None):
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
        try:
            if reply == None:
                print(self.LOG_TAG, " reply notification None")
                return

            if reply.id not in self._notifications_sent:
                print(self.LOG_TAG, " reply notification not in the list:", reply.id)
                return

            if self._notifications_sent[reply.id] == None:
                print(self.LOG_TAG, " reply notification body empty:", reply.id)
                return

            if self._notifications_sent[reply.id]['callback'] != None:
                self._notifications_sent[reply.id]['callback'].emit(reply)

            # delete only one-time notifications
            # we need the ID of streaming notifications from the server
            # (monitor_process for example) to keep track of the data sent to us.
            if self._notifications_sent[reply.id]['type'] != ui_pb2.MONITOR_PROCESS:
                del self._notifications_sent[reply.id]
        except Exception as e:
            print(self.LOG_TAG, "notification exception:", e)

    def stop_notifications(self):
        """Send a dummy notification to force Notifications class to exit.
        """
        exit_noti = ui_pb2.Notification(clientName="", serverName="", type=0, data="", rules=[])
        self.send_notifications(exit_noti)

    def update(self, peer, status=ONLINE):
        try:
            proto, addr = self.get_addr(peer)
            self._db.update("nodes",
                    "hostname=?,version=?,last_connection=?,status=?",
                    (
                        self._nodes[proto+":"+addr]['data'].name,
                        self._nodes[proto+":"+addr]['data'].version,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        status,
                        "{0}:{1}".format(proto, addr)),
                        "addr=?"
                    )
        except Exception as e:
            print(self.LOG_TAG + " exception updating DB: ", e, peer)

    def update_all(self, status=OFFLINE):
        try:
            for peer in self._nodes:
                self._db.update("nodes",
                        "hostname=?,version=?,last_connection=?,status=?",
                        (
                            self._nodes[peer]['data'].name,
                            self._nodes[peer]['data'].version,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            status,
                            peer),
                            "addr=?"
                        )
        except Exception as e:
            print(self.LOG_TAG + " exception updating nodes: ", e)

    def reset_status(self):
        try:
            self._db.update("nodes", "status=?", (self.OFFLINE,))
        except Exception as e:
            print(self.LOG_TAG + " exception resetting nodes status: ", e)

    def reload_fw(self, addr, fw_config, callback):
        notif = ui_pb2.Notification(
                id=int(str(time.time()).replace(".", "")),
                type=ui_pb2.RELOAD_FW_RULES,
                sysFirewall=fw_config
        )
        nid = self.send_notification(addr, notif, callback)
        return nid, notif
