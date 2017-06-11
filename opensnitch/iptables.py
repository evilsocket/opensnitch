# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Adam Hose
# adis@blad.is
# http://www.evilsocket.net
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
            try:
                c.delete_rule(r)
            except iptc.ip4tc.IPTCError:
                pass

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
