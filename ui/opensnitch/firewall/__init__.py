from PyQt5.QtCore import QObject

from opensnitch.nodes import Nodes
from .enums import *
from .rules import *
from .chains import *
from .utils import Utils
from .exprs import *

class Firewall(QObject):
    __instance = None

    @staticmethod
    def instance():
        if Firewall.__instance == None:
            Firewall.__instance = Firewall()
        return Firewall.__instance

    def __init__(self, parent=None):
        QObject.__init__(self)
        self._nodes = Nodes.instance()
        self.rules = Rules(self._nodes)
        self.chains = Chains(self._nodes)

    def switch_rules(self, key, old_pos, new_pos):
        pass

    def add_rule(self, addr, rule):
        return self.rules.add(addr, rule)

    def insert_rule(self, addr, rule, position=0):
        return self.rules.insert(addr, rule, position)

    def update_rule(self, addr, uuid, rule):
        return self.rules.update(addr, uuid, rule)

    def delete_rule(self, addr, uuid):
        return self.rules.delete(addr, uuid)

    def get_rule_by_uuid(self, uuid):
        if uuid == "":
            return None, None
        for addr in self._nodes.get_nodes():
            node = self._nodes.get_node(addr)
            if not 'fwrules' in node:
                continue
            r = node['fwrules'].get(uuid)
            if r != None:
                return addr, r

        return None, None

    def filter_rules(self, nail):
        """
        """
        chains = []
        for addr in self._nodes.get_nodes():
            node = self._nodes.get_node(addr)
            if not 'firewall' in node:
                return chains
            for n in node['firewall'].SystemRules:
                for c in n.Chains:
                    for r in c.Rules:
                        if nail in c.Family or \
                                nail in c.Hook or \
                                nail in r.Description or \
                                nail in r.Target or \
                                nail in r.TargetParameters:
                                # TODO: filter expressions
                                #nail in r.Expressions:
                            chains.append(Rules.to_array(addr, c, r))

        return chains

    def swap_rules(self, view, addr, uuid, old_pos, new_pos):
        return self.rules.swap(view, addr, uuid, old_pos, new_pos)

    def filter_by_table(self, addr, table, family):
        """get rules by table
        """
        chains = []
        node = self._nodes.get_node(addr)
        if not 'firewall' in node:
            return chains
        for n in node['firewall'].SystemRules:
            for c in n.Chains:
                for r in c.Rules:
                    if c.Table == table and c.Family == family:
                        chains.append(Rules.to_array(addr, c, r))

        return chains

    def filter_by_chain(self, addr, table, family, chain, hook):
        """get rules by chain
        """
        chains = []
        node = self._nodes.get_node(addr)
        if not 'firewall' in node:
            return chains
        for n in node['firewall'].SystemRules:
            for c in n.Chains:
                for r in c.Rules:
                    if c.Table == table and c.Family == family and c.Name == chain and c.Hook == hook:
                        chains.append(Rules.to_array(addr, c, r))

        return chains

    def get_node_rules(self, addr):
        return self.rules.get_by_node(addr)

    def get_chains(self):
        return self.chains.get()

    def get_rules(self):
        return self.rules.get()
