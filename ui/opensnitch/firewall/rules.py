from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot
import uuid
from opensnitch import ui_pb2

class Rules(QObject):
    rulesUpdated = pyqtSignal()

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
        if not 'firewall' in node:
            return False
        for sidx, n in enumerate(node['firewall'].SystemRules):
            for cdx, c in enumerate(n.Chains):
                if c.Name == rule.Name and c.Hook == rule.Hook and \
                        c.Table == rule.Table and c.Family == rule.Family:
                    node['firewall'].SystemRules[sidx].Chains[cdx].Rules.append(rule.Rules[0])
                    node['fwrules'][rule.Rules[0].UUID] = rule
                    self._nodes.add_fw_config(addr, node['firewall'])
                    self._nodes.add_fw_rules(addr, node['fwrules'])

                    self.rulesUpdated.emit()
                    return True

        return False

    def insert(self, addr, rule, position=0):
        """Insert a new rule to the corresponding table on the given node
        """
        node = self._nodes.get_node(addr)
        if not 'firewall' in node:
            return False
        for sidx, n in enumerate(node['firewall'].SystemRules):
            for cdx, c in enumerate(n.Chains):
                if c.Name == rule.Name and c.Hook == rule.Hook and \
                        c.Table == rule.Table and c.Family == rule.Family and \
                        c.Type == rule.Type:
                    node['firewall'].SystemRules[sidx].Chains[cdx].Rules.insert(int(position), rule.Rules[0])
                    node['fwrules'][rule.Rules[0].UUID] = rule
                    self._nodes.add_fw_config(addr, node['firewall'])
                    self._nodes.add_fw_rules(addr, node['fwrules'])

                    self.rulesUpdated.emit()
                    return True

        return False



    def update(self, addr, uuid, rule):
        node = self._nodes.get_node(addr)
        if not 'firewall' in node:
            return False
        for sidx, n in enumerate(node['firewall'].SystemRules):
            for cdx, c in enumerate(n.Chains):
                for idx, r in enumerate(c.Rules):
                    if r.UUID == uuid:
                        c.Rules[idx].CopyFrom(rule.Rules[0])
                        node['firewall'].SystemRules[sidx].Chains[cdx].Rules[idx].CopyFrom(rule.Rules[0])
                        self._nodes.add_fw_config(addr, node['firewall'])
                        node['fwrules'][uuid] = rule
                        self._nodes.add_fw_rules(addr, node['fwrules'])

                        self.rulesUpdated.emit()
                        return True

        return False

    def get(self):
        rules = []
        for node in self._nodes.get_nodes():
            node_rules = self.get_by_node(node)
            rules += node_rules

        return rules

    def delete(self, addr, uuid):
        node = self._nodes.get_node(addr)
        if not 'firewall' in node:
            return False
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
                            print("[firewall] delete() error:", uuid)
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
            rule.Expressions.append(expressions)
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
        for c in sysRules:
            for c in c.Chains:
                if len(c.Rules) == 0:
                    continue
                for r in c.Rules:
                    rules[r.UUID] = Rules.new_flat(c, r)

        return rules

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
            exprs += "{0} {1} {2}".format(
                e.Statement.Op,
                e.Statement.Name,
                "".join(["{0} {1} ".format(h.Key, h.Value) for h in e.Statement.Values ])
            )
        cols.append(exprs)
        cols.append(rule.Target)

        return cols


