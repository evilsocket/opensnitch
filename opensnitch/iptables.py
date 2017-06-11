import iptc


class IPTCRules:

    def __init__(self):
        self.tables = {
            iptc.Table.FILTER: iptc.Table(iptc.Table.FILTER),
            iptc.Table.MANGLE: iptc.Table(iptc.Table.MANGLE),
        }
        for t in self.tables.values():
            t.autocommit = False

        self.chains = {
            c: r for c, r in (
                self.insert_dns_rule(),
                self.insert_connection_packet_rules(),
                self.insert_reject_rule())
        }

        self.commit()

    def commit(self):
        for t in self.tables.values():
            t.commit()
            t.refresh()

    def remove(self):
        for c, r in self.chains.items():
            c.delete_rule(r)

        self.commit()

    def insert_dns_rule(self):
        """Get DNS responses"""
        chain = iptc.Chain(self.tables[iptc.Table.FILTER], 'INPUT')
        rule = iptc.Rule()
        rule.protocol = 'udp'
        m = rule.create_match('udp')
        m.sport = '53'

        t = rule.create_target('NFQUEUE')
        t.set_parameter('queue-num', str(0))
        t.set_parameter('queue-bypass')

        chain.insert_rule(rule)
        return (chain, rule)

    def insert_connection_packet_rules(self):
        chain = iptc.Chain(self.tables[iptc.Table.MANGLE], 'OUTPUT')
        rule = iptc.Rule()

        t = rule.create_target('NFQUEUE')
        t.set_parameter('queue-num', str(0))
        t.set_parameter('queue-bypass')

        m = rule.create_match('conntrack')
        m.set_parameter('ctstate', 'NEW')

        chain.insert_rule(rule)
        return (chain, rule)

    def insert_reject_rule(self):
        chain = iptc.Chain(self.tables[iptc.Table.FILTER], 'OUTPUT')
        rule = iptc.Rule()
        rule.protol = 'tcp'

        rule.create_target('REJECT')

        m = rule.create_match('mark')
        m.mark = '0x18ba5'

        chain.insert_rule(rule)
        return (chain, rule)
