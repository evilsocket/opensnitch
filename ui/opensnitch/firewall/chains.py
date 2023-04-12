from opensnitch import ui_pb2
from .enums import *

class Chains():

    def __init__(self, nodes):
        self._nodes = nodes

    def get(self):
        chains = {}
        for node in self._nodes.get_nodes():
            chains[node] = self.get_node_chains(node)
        return chains

    def get_node_chains(self, addr):
        node = self._nodes.get_node(addr)
        if node == None:
            return rules
        if not 'firewall' in node:
            return rules

        chains = []
        for c in node['firewall'].SystemRules:
            # Chains node does not exist on <= v1.5.x
            try:
                chains.append(c.Chains)
            except Exception:
                pass
        return chains

    def get_node_chains(self, addr):
        node = self._nodes.get_node(addr)
        if node == None:
            return rules
        if not 'firewall' in node:
            return rules

        chains = []
        for c in node['firewall'].SystemRules:
            # Chains node does not exist on <= v1.5.x
            try:
                chains.append(c.Chains)
            except Exception:
                pass
        return chains



    def get_policy(self, node_addr=None, hook=Hooks.INPUT.value, _type=ChainType.FILTER.value, family=Family.INET.value):
        fwcfg = self._nodes.get_node(node_addr)['firewall']
        for sdx, n in enumerate(fwcfg.SystemRules):
            for cdx, c in enumerate(n.Chains):
                if c.Hook.lower() == hook and c.Type.lower() == _type and c.Family.lower() == family:
                    return c.Policy

        return None

    def set_policy(self, node_addr, hook=Hooks.INPUT.value, _type=ChainType.FILTER.value, family=Family.INET.value, policy=Policy.DROP):
        fwcfg = self._nodes.get_node(node_addr)['firewall']
        for sdx, n in enumerate(fwcfg.SystemRules):
            for cdx, c in enumerate(n.Chains):
                # XXX: support only "inet" family (ipv4/ipv6)? or allow to
                # specify ipv4 OR/AND ipv6? some systems have ipv6 disabled
                if c.Hook.lower() == hook and c.Type.lower() == _type and c.Family.lower() == family:
                    fwcfg.SystemRules[sdx].Chains[cdx].Policy = policy

                    if wantedHook == Fw.Hooks.INPUT.value and wantedPolicy == Fw.Policy.DROP.value:
                        fwcfg.SystemRules[sdx].Chains[cdx].Rules.extend([rule.Rules[0]])
                        self._nodes.add_fw_config(node_addr, fwcfg)
                    return True
        return False


    @staticmethod
    def new(
        name="",
        table=Table.FILTER.value,
        family=Family.INET.value,
        ctype="",
        hook=Hooks.INPUT.value
    ):
        chain = ui_pb2.FwChain()
        chain.Name = name
        chain.Table = table
        chain.Family = family
        chain.Type = ctype
        chain.Hook = hook

        return chain

# man nft
# Table 6. Standard priority names, family and hook compatibility matrix
# Name     │ Value │ Families                   │ Hooks
# raw      │ -300  │ ip, ip6, inet              │ all
# mangle   │ -150  │ ip, ip6, inet              │ all
# dstnat   │ -100  │ ip, ip6, inet              │ prerouting
# filter   │ 0     │ ip, ip6, inet, arp, netdev │ all
# security │ 50    │ ip, ip6, inet              │ all
# srcnat   │ 100   │ ip, ip6, inet              │ postrouting
#

class ChainFilter(Chains):
    """
    ChainFilter returns a new chain of type filter.

    The name of the chain is the one listed with: nft list table inet filter.
    It corresponds with the hook name, but can be a random name.
    """

    @staticmethod
    def input(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.INPUT.value
        chain.Table = Table.FILTER.value
        chain.Family = family
        chain.Type = ChainType.FILTER.value
        chain.Hook = Hooks.INPUT.value

        return chain

    @staticmethod
    def output(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.OUTPUT.value
        chain.Table = Table.FILTER.value
        chain.Family = family
        chain.Type = ChainType.FILTER.value
        chain.Hook = Hooks.OUTPUT.value

        return chain

    @staticmethod
    def forward(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.FORWARD.value
        chain.Table = Table.FILTER.value
        chain.Family = family
        chain.Type = ChainType.FILTER.value
        chain.Hook = Hooks.FORWARD.value

        return chain



class ChainMangle(Chains):
    """
    ChainMangle returns a new chain of type mangle.

    The name of the chain is the one listed with: nft list table inet mangle.
    It corresponds with the hook name, but can be a random name.
    """

    @staticmethod
    def output(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.OUTPUT.value
        chain.Table = Table.MANGLE.value

        chain.Family = family
        chain.Type = ChainType.MANGLE.value
        chain.Hook = Hooks.OUTPUT.value

        return chain

    @staticmethod
    def input(family=Family.INET.value):
        chain = ui_pb2.FwChain(family=Family.INET.value)
        chain.Name = Hooks.INPUT.value
        chain.Table = Table.MANGLE.value

        chain.Family = family
        chain.Type = ChainType.MANGLE.value
        chain.Hook = Hooks.INPUT.value

        return chain

    @staticmethod
    def forward(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.FORWARD.value
        chain.Table = Table.MANGLE.value

        chain.Family = family
        chain.Type = ChainType.MANGLE.value
        chain.Hook = Hooks.FORWARD.value

        return chain


    @staticmethod
    def prerouting(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.PREROUTING.value
        chain.Table = Table.MANGLE.value

        chain.Family = family
        chain.Type = ChainType.MANGLE.value
        chain.Hook = Hooks.PREROUTING.value

        return chain

    @staticmethod
    def postrouting(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.POSTROUTING.value
        chain.Table = Table.MANGLE.value

        chain.Family = family
        chain.Type = ChainType.MANGLE.value
        chain.Hook = Hooks.POSTROUTING.value

        return chain

class ChainDstNAT(Chains):
    """
    ChainDstNAT returns a new chain of type dstnat.

    The name of the chain is the one listed with: nft list table inet nat.
    It corresponds with the hook name, but can be a random name.
    """

    @staticmethod
    def prerouting(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.PREROUTING.value
        chain.Table = Table.NAT.value

        chain.Family = family
        chain.Type = ChainType.DNAT.value
        chain.Hook = Hooks.PREROUTING.value

        return chain

    @staticmethod
    def output(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.OUTPUT.value
        chain.Table = Table.NAT.value

        chain.Family = family
        chain.Type = ChainType.DNAT.value
        chain.Hook = Hooks.OUTPUT.value

        return chain

    @staticmethod
    def postrouting(family=Family.INET.value):
        chain = ui_pb2.FwChain()
        chain.Name = Hooks.POSTROUTING.value
        chain.Table = Table.NAT.value

        chain.Family = family
        chain.Type = ChainType.SNAT.value
        chain.Hook = Hooks.POSTROUTING.value

        return chain
