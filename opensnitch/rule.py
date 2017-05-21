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
from collections import namedtuple
from threading import Lock
from enum import Enum
import logging
import sqlite3


Rule = namedtuple('Rule', ('app_path',
                           'verdict',
                           'address',
                           'port',
                           'proto'))


class RuleVerdict(Enum):

    ACCEPT = 0
    DROP = 1


class RuleSaveOption(Enum):

    ONCE = 0
    UNTIL_QUIT = 1
    FOREVER = 2


def matches(rule, conn):
    if rule.app_path != conn.app_path:
        return False

    elif rule.address is not None and rule.address != conn.dst_addr:
        return False

    elif rule.port is not None and rule.port != conn.dst_port:
        return False

    elif rule.proto is not None and rule.proto != conn.proto:
        return False

    else:
        return True


class Rules:
    def __init__(self, database):
        self.mutex = Lock()
        self.db = RulesDB(database)
        self.rules = self.db.load_rules()

    def get_verdict(self, connection):
        with self.mutex:
            for r in self.rules:
                if matches(r, connection):
                    return r.verdict

            return None

    def _remove_rules_for_path(self, path, remove_from_db=False):
        for rule in self.rules:
            if rule.app_path == path:
                self.rules.remove(rule)

        if remove_from_db is True:
            self.db.remove_all_app_rules(path)

    def add_rule(self, connection, verdict, apply_to_all=False,
                 save_option=RuleSaveOption.UNTIL_QUIT.value):

        with self.mutex:
            logging.debug("Adding %s rule for '%s' (all=%s)",
                          "ALLOW" if RuleVerdict(verdict) == RuleVerdict.ACCEPT else "DENY",  # noqa
                          connection,
                          "true" if apply_to_all is True else "false")

            if apply_to_all is True:
                self._remove_rules_for_path(
                    connection.app_path,
                    (RuleSaveOption(save_option) == RuleSaveOption.FOREVER))

            r = Rule(
                connection.app_path,
                verdict,
                connection.dst_addr if not apply_to_all else None,
                connection.dst_port if not apply_to_all else None,
                connection.proto if not apply_to_all else None)

            self.rules.append(r)

            if RuleSaveOption(save_option) == RuleSaveOption.FOREVER:
                self.db.save_rule(r)


class RulesDB:

    def __init__(self, filename):
        self._filename = filename
        self._lock = Lock()
        logging.info("Using rules database from %s" % filename)
        self._create_table()

    # Only call with lock!
    def _get_conn(self):
        return sqlite3.connect(self._filename)

    def _create_table(self):
        with self._lock:
            conn = self._get_conn()
            c = conn.cursor()
            c.execute("CREATE TABLE IF NOT EXISTS rules (app_path TEXT, verdict INTEGER, address TEXT, port INTEGER, proto TEXT, UNIQUE (app_path, verdict, address, port, proto))")  # noqa

    def load_rules(self):
        with self._lock:
            conn = self._get_conn()
            c = conn.cursor()
            c.execute("SELECT * FROM rules")
            return [Rule(*item) for item in c.fetchall()]

    def save_rule(self, rule):
        print(rule)
        with self._lock:
            conn = self._get_conn()
            c = conn.cursor()
            c.execute("INSERT INTO rules VALUES (?, ?, ?, ?, ?)", (rule.app_path, rule.verdict.value, rule.address, rule.port, rule.proto,))  # noqa
            conn.commit()

    def remove_all_app_rules(self, app_path):
        with self._lock:
            conn = self._get_conn()
            c = conn.cursor()
            c.execute("DELETE FROM rules WHERE app_path=?", (app_path,))
            conn.commit()
