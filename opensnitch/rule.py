# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
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
import nfqueue
import logging
from threading import Lock

class Rule:
    def __init__(self):
        self.app_path = None
        self.address = None
        self.port = None
        self.proto = None
        self.verdict = nfqueue.NF_ACCEPT

    def matches( self, c ):
        if self.app_path != c.app_path:
            return False

        elif self.address is not None and self.address != c.dst_addr:
            return False

        elif self.port is not None and self.port != c.dst_port:
            return False

        elif self.proto is not None and self.proto != c.proto:
            return False

        else:
            return True

# TODO: Implement rules persistance on file.
class Rules:
    def __init__(self):
        self.mutex = Lock()
        self.rules = []

    def get_verdict( self, connection ):
        with self.mutex:
            for r in self.rules:
                if r.matches(connection):
                    return r.verdict

            return None

    def add_rule( self, connection, verdict, apply_to_all = False ):
        with self.mutex:
            logging.debug( "Adding %s rule for '%s' (all=%s)" % (
                           "ALLOW" if verdict == nfqueue.NF_ACCEPT else "DENY",
                           connection,
                           "true" if apply_to_all == True else "false" ) )
            r = Rule()
            r.verdict  = verdict
            r.app_path = connection.app_path
            if apply_to_all is False:
                r.address = connection.dst_addr
                r.port = connection.dst_port
                r.proto = connection.proto
            
            self.rules.append(r)


        
