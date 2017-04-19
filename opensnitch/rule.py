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
import logging
import os
from os.path import expanduser
from threading import Lock
import sqlite3

class Rule:
    ACCEPT = 0
    DROP   = 1

    ONCE = 0
    UNTIL_QUIT = 1
    FOREVER = 2

    def __init__( self, app_path=None, verdict=ACCEPT, address=None, port=None, proto=None ):
        self.app_path = app_path
        self.verdict = verdict
        self.address = address
        self.port = port
        self.proto = proto
       
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

class Rules:
    def __init__(self):
        self.mutex = Lock()
        self.db = RulesDB()
        self.rules = self.db.load_rules()

    def get_verdict( self, connection ):
        with self.mutex:
            for r in self.rules:
                if r.matches(connection):
                    return r.verdict

            return None

    def _remove_rules_for_path( self, path, remove_from_db=False ):
        for rule in self.rules:
            if rule.app_path == path:
                self.rules.remove(rule)

        if remove_from_db is True:
            self.db.remove_all_app_rules(path)

    def add_rule( self, connection, verdict, apply_to_all=False, save_option=Rule.UNTIL_QUIT ):
        with self.mutex:
            logging.debug( "Adding %s rule for '%s' (all=%s)" % (
                           "ALLOW" if verdict == Rule.ACCEPT else "DENY",
                           connection,
                           "true" if apply_to_all == True else "false" ) )
            r = Rule()
            r.verdict  = verdict
            r.app_path = connection.app_path

            if apply_to_all is True:
                self._remove_rules_for_path( r.app_path, (save_option == Rule.FOREVER) )

            elif apply_to_all is False:
                r.address = connection.dst_addr
                r.port = connection.dst_port
                r.proto = connection.proto

            self.rules.append(r)

            if save_option == Rule.FOREVER:
                self.db.save_rule(r)

class RulesDB:
    def __init__(self):
        if os.environ.has_key('SUDO_USER'):
            self.home = expanduser("~%s" % os.environ['SUDO_USER'] )
        else:
            self.home = expanduser("~%s" % os.environ['USER'] )
        self.filename = os.path.join( self.home,  "opensnitch.db" )

        logging.info( "Using rules database from %s" % self.filename )

        self.conn = sqlite3.connect(self.filename)
        self._create_table()

    def _create_table(self):
        c = self.conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS rules (app_path TEXT, verdict INTEGER, address TEXT, port INTEGER, proto TEXT)")

    def load_rules(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM rules")
        return [Rule(*item) for item in c.fetchall()]

    def save_rule( self, rule ):
        c = self.conn.cursor()
        c.execute("INSERT INTO rules VALUES (?, ?, ?, ?, ?)", (rule.app_path, rule.verdict, rule.address, rule.port, rule.proto,))
        self.conn.commit()

    def remove_all_app_rules ( self, app_path ):
        c = self.conn.cursor()
        c.execute("DELETE FROM rules WHERE app_path=?", (app_path,))
        self.conn.commit()

