
from opensnitch.nodes import Nodes

class NodesManager:
    def __init__(self, parent):
        super(NodesManager, self).__init__(parent)
        self._nodes = Nodes.instance()

    def node_start_interception(self, addr, callback):
        return self._nodes.start_interception(_addr=addr, _callback=callback)

    def node_stop_interception(self, addr, callback):
        return self._nodes.stop_interception(_addr=addr, _callback=callback)

    def node_get(self, addr):
        return self._nodes.get_node(addr)

    def node_delete(self, addr):
        self._nodes.delete(addr)

    def node_del_rule(self, addr, name, callback):
        return self._nodes.delete_rule(name, addr, callback)

    def node_hostname(self, addr):
        return self._nodes.get_node_hostname(addr)

    def nodes_count(self):
        return self._nodes.count()

    def node_list(self):
        return self._nodes.get_nodes()

    def node_add_rules(self, addr, rules):
        self._nodes.add_rules(addr, rules)

    def node_rule_to_json(self, addr, name):
        return self._nodes.rule_to_json(addr, name)

    def node_export_rule(self, addr, name, outdir):
        return self._nodes.export_rule(addr, name, outdir)

    def node_export_rules(self, addr, outdir):
        return self._nodes.export_rules(addr, outdir)

    def node_import_all_rules(self, rulesdir, callback):
        """import rules to all nodes"""
        return self._nodes.import_rules(addr=None, rulesdir=rulesdir, callback=callback)

    def reload_fw(self, addr, fw_config, callback):
        return self._nodes.reload_fw(addr, fw_config, callback)

    def send_notification(self, addr, ntf, callback):
        return self._nodes.send_notification(addr, ntf, callback)

    def send_notifications(self, ntf, callback):
        nids = {}
        for addr in self.node_list():
            nid = self._nodes.send_notification(addr, ntf, callback)
            nids[addr] = nid

        return nids
