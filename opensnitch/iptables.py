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
        self.insert_dns_rule()
        self.insert_connection_packet_rules()
        self.insert_reject_rule()

    def remove(self):
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, 'INPUT')
        for r in chain.rules:
            chain.delete_rule(r)

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, 'OUTPUT')
        for r in chain.rules:
            chain.delete_rule(r)

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, 'MANGLE')
        for r in chain.rules:
            chain.delete_rule(r)

    def insert_dns_rule(self):
        """Get DNS responses"""
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, 'INPUT')
        rule = iptc.Rule()
        rule.protocol = 'udp'
        m = rule.create_match('udp')
        m.sport = '53'

        t = rule.create_target('NFQUEUE')
        t.set_parameter('queue-num', str(0))
        t.set_parameter('queue-bypass')

        chain.insert_rule(rule)

    def insert_connection_packet_rules(self):
        table = iptc.Table(iptc.Table.MANGLE)
        chain = iptc.Chain(table, 'OUTPUT')
        rule = iptc.Rule()

        t = rule.create_target('NFQUEUE')
        t.set_parameter('queue-num', str(0))
        t.set_parameter('queue-bypass')

        m = rule.create_match('conntrack')
        m.set_parameter('ctstate', 'NEW')

        chain.insert_rule(rule)

    def insert_reject_rule(self):
        table = iptc.Table(iptc.Table.MANGLE)
        chain = iptc.Chain(table, 'OUTPUT')
        rule = iptc.Rule()
        rule.protol = 'tcp'

        rule.create_target('REJECT')

        m = rule.create_match('mark')
        m.mark = '0x18ba5'

        chain.insert_rule(rule)
