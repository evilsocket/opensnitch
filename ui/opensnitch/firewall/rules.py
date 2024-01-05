from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtCore import QCoreApplication as QC
from google.protobuf.json_format import MessageToJson
import uuid

from opensnitch import ui_pb2
from .enums import Operator
from .exprs import ExprLog

class Rules(QObject):
    rulesUpdated = pyqtSignal()

    # Fields defined in the protobuf, to be used as constants on other parts.
    FIELD_UUID = "UUID"
    FIELD_ENABLED = "Enabled"
    FIELD_TARGET = "Target"

    def __init__(self, nodes):
        QObject.__init__(self)
        self._nodes = nodes
        self.rulesUpdated.connect(self._cb_rules_updated)

    def _cb_rules_updated(self):
        pass

    def add(self, addr, rule):
        """Add a new rule to the corresponding table on the given node
        """
        node = self._nodes.get_node(addr)
        if node == None or not 'firewall' in node:
            return False, QC.translate("firewall", "rule not found by its ID.")
        if self.is_duplicated(addr, rule):
            return False, QC.translate("firewall", "duplicated.")

        for sdx, n in enumerate(node['firewall'].SystemRules):
            for cdx, c in enumerate(n.Chains):
                if c.Name == rule.Name and \
                        c.Hook == rule.Hook and \
                        c.Table == rule.Table and \
                        c.Family == rule.Family and \
                        c.Type == rule.Type:
                    node['firewall'].SystemRules[sdx].Chains[cdx].Rules.extend([rule.Rules[0]])
                    node['fwrules'][rule.Rules[0].UUID] = rule
                    self._nodes.add_fw_config(addr, node['firewall'])
                    self._nodes.add_fw_rules(addr, node['fwrules'])

                    self.rulesUpdated.emit()
                    return True

        return False, QC.translate("firewall", "firewall table/chain not properly configured.")

    def insert(self, addr, rule, position=0):
        """Insert a new rule to the corresponding table on the given node
        """
        node = self._nodes.get_node(addr)
        if node == None or not 'firewall' in node:
            return False, QC.translate("firewall", "this node doesn't have a firewall configuration, review it.")
        if self.is_duplicated(addr, rule):
            return False, QC.translate("firewall", "duplicated")

        for sdx, n in enumerate(node['firewall'].SystemRules):
            for cdx, c in enumerate(n.Chains):
                if c.Name == rule.Name and \
                        c.Hook == rule.Hook and \
                        c.Table == rule.Table and \
                        c.Family == rule.Family and \
                        c.Type == rule.Type:
                    if hasattr(node['firewall'].SystemRules[sdx].Chains[cdx].Rules, "insert"):
                        node['firewall'].SystemRules[sdx].Chains[cdx].Rules.insert(int(position), rule.Rules[0])
                    else:
                        node['firewall'].SystemRules[sdx].Chains[cdx].Rules.extend([rule.Rules[0]])
                    node['fwrules'][rule.Rules[0].UUID] = rule
                    self._nodes.add_fw_config(addr, node['firewall'])
                    self._nodes.add_fw_rules(addr, node['fwrules'])

                    self.rulesUpdated.emit()
                    return True, ""

        return False, QC.translate("firewall", "firewall table/chain not properly configured.")


    def update(self, addr, uuid, rule):
        node = self._nodes.get_node(addr)
        if node == None or not 'firewall' in node:
            return False, QC.translate("firewall", "this node doesn't have a firewall configuration, review it.")
        for sdx, n in enumerate(node['firewall'].SystemRules):
            for cdx, c in enumerate(n.Chains):
                for rdx, r in enumerate(c.Rules):
                    if r.UUID == uuid:
                        c.Rules[rdx].CopyFrom(rule.Rules[0])
                        node['firewall'].SystemRules[sdx].Chains[cdx].Rules[rdx].CopyFrom(rule.Rules[0])
                        self._nodes.add_fw_config(addr, node['firewall'])
                        node['fwrules'][uuid] = rule
                        self._nodes.add_fw_rules(addr, node['fwrules'])

                        self.rulesUpdated.emit()
                        return True, ""

        return False, QC.translate("firewall", "rule not found by its ID.")

    def get(self):
        rules = []
        for node in self._nodes.get_nodes():
            node_rules = self.get_by_node(node)
            rules += node_rules

        return rules

    def delete(self, addr, uuid):
        node = self._nodes.get_node(addr)
        if node == None or not 'firewall' in node:
            return False, None
        for sdx, n in enumerate(node['firewall'].SystemRules):
            for cdx, c in enumerate(n.Chains):
                for idx, r in enumerate(c.Rules):
                    if r.UUID == uuid:
                        del node['firewall'].SystemRules[sdx].Chains[cdx].Rules[idx]
                        self._nodes.add_fw_config(addr, node['firewall'])
                        if uuid in node['fwrules']:
                            del node['fwrules'][uuid]
                            self._nodes.add_fw_rules(addr, node['fwrules'])
                        else:
                            # raise Error("rules doesn't have UUID field")
                            return False, None

                        self.rulesUpdated.emit()
                        return True, node['firewall']

        return False, None

    def get_by_node(self, addr):
        rules = []
        node = self._nodes.get_node(addr)
        if node == None:
            return rules
        if not 'firewall' in node:
            return rules
        for u in node['firewall'].SystemRules:
            for c in u.Chains:
                for r in c.Rules:
                    rules.append(Rules.to_array(addr, c, r))
        return rules

    def get_by_uuid(self, addr, uuid):
        rules = []
        node = self._nodes.get_node(addr)
        if node == None:
            return rules
        if not 'firewall' in node:
            return rules
        for u in node['firewall'].SystemRules:
            for c in u.Chains:
                for r in c.Rules:
                    if r.UUID == uuid:
                        return r
        return None

    def swap(self, view, addr, uuid, old_pos, new_pos):
        """
        swap changes the order of 2 rows.

        The list of rules is ordered from top to bottom: 0,1,2,3...
        so a click on the down button sums +1, a click on the up button rest -1
        """
        node = self._nodes.get_node(addr)
        if node == None:
            return
        if not 'firewall' in node:
            return
        for sdx, c in enumerate(node['firewall'].SystemRules):
            for cdx, u in enumerate(c.Chains):
                nrules = len(u.Rules)
                for rdx, r in enumerate(u.Rules):
                    # is the last rule
                    if new_pos > nrules and new_pos < nrules:
                        break
                    if u.Rules[rdx].UUID == uuid:
                        old_rule = u.Rules[old_pos]
                        new_rule = ui_pb2.FwRule()
                        new_rule.CopyFrom(u.Rules[new_pos])

                        node['firewall'].SystemRules[sdx].Chains[cdx].Rules[new_pos].CopyFrom(old_rule)
                        node['firewall'].SystemRules[sdx].Chains[cdx].Rules[old_pos].CopyFrom(new_rule)

                        self._nodes.add_fw_config(addr, node['firewall'])
                        #self._nodes.add_fw_rules(addr, node['fwrules'])

                        self.rulesUpdated.emit()
                        return True
        return False

    def is_duplicated(self, addr, orig_rule):
        # we need to duplicate the rule, otherwise we'd modify the UUID of the
        # orig rule.
        temp_c = ui_pb2.FwChain()
        temp_c.CopyFrom(orig_rule)
        # the UUID will be different, so zero it out.
        # but keep a copy of the original one.
        orig_uuid = temp_c.Rules[0].UUID
        temp_c.Rules[0].UUID = ""
        node = self._nodes.get_node(addr)
        if node == None:
            return False
        if not 'firewall' in node:
            return False
        for n in node['firewall'].SystemRules:
            for c in n.Chains:
                if c.Name == temp_c.Name and \
                        c.Hook == temp_c.Hook and \
                        c.Table == temp_c.Table and \
                        c.Family == temp_c.Family and \
                        c.Type == temp_c.Type:
                    for rdx, r in enumerate(c.Rules):
                        uuid = c.Rules[rdx].UUID
                        c.Rules[rdx].UUID = ""
                        is_equal = (c.Rules[rdx].SerializeToString() == temp_c.Rules[0].SerializeToString() or orig_uuid == uuid)
                        c.Rules[rdx].UUID = uuid

                        if is_equal:
                            return True

        return False

    @staticmethod
    def new(
            enabled=True,
            _uuid="",
            description="",
            expressions=None,
            target="",
            target_parms=""
            ):
        rule = ui_pb2.FwRule()
        if _uuid == "":
            rule.UUID = str(uuid.uuid1())
        else:
            rule.UUID = _uuid
        rule.Enabled = enabled
        rule.Description = description
        if expressions != None:
            rule.Expressions.extend([expressions])
        rule.Target = target
        rule.TargetParameters = target_parms

        return rule

    @staticmethod
    def new_flat(c, r):
        """Create a new "flat" rule from a hierarchical one.
        Transform from:
            {
             xx:
                 {
                   yy: {
        to:
            {xx:, yy}
        """

        chain = ui_pb2.FwChain()
        chain.CopyFrom(c)
        del chain.Rules[:]
        chain.Rules.extend([r])

        return chain

    @staticmethod
    def to_dict(sysRules):
        """Transform json/protobuf struct to flat structure.
        This is the default format used to find rules in the table view.
        """
        rules={}
        for s in sysRules:
            for c in s.Chains:
                if len(c.Rules) == 0:
                    continue
                for r in c.Rules:
                    rules[r.UUID] = Rules.new_flat(c, r)

        return rules

    @staticmethod
    def to_json(rule):
        try:
            return MessageToJson(rule)
        except:
            return None

    @staticmethod
    def to_array(addr, chain, rule):
        cols = []
        cols.append(rule.UUID)
        cols.append(addr)
        cols.append(chain.Name)
        cols.append(chain.Table)
        cols.append(chain.Family)
        cols.append(chain.Hook)
        cols.append(str(rule.Enabled))
        cols.append(rule.Description)
        exprs = ""
        for e in rule.Expressions:
            exprs += "{0} {1}".format(
                e.Statement.Name,
                "".join(
                    [
                        "{0} {1}{2} ".format(
                            h.Key,
                            e.Statement.Op + " " if e.Statement.Op != Operator.EQUAL.value else "",
                            "\"{0}\"".format(h.Value) if h.Key == ExprLog.PREFIX.value else h.Value
                        ) for h in e.Statement.Values
                    ]
                )
            )
        cols.append(exprs)
        cols.append(rule.Target)
        cols.append(rule.TargetParameters)

        return cols
