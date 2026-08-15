#   Copyright (C) 2026 The OpenSnitch Authors
#
#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.

"""Storage of the review queue.

Two processes use this database at the same time: 'opensnitch-cli serve', which
writes the queue and drains the outbox, and 'opensnitch-cli review', which reads
the queue and writes decisions to the outbox. WAL is what makes that safe.

The outbox is the only channel between them. review never talks to the daemon:
it queues a notification, and serve sends it on the next tick. That way a
decision taken while the service is stopped is applied when it starts again.

The GUI's database (opensnitch.database) is built on QtSql, so it isn't reused.
"""

import json
import os
import sqlite3
import threading
import time

SCHEMA_VERSION = 2

STATE_PENDING = "pending"
STATE_DECIDED = "decided"
STATE_DROPPED = "dropped"

OUT_QUEUED = "queued"
OUT_SENT = "sent"
OUT_DONE = "done"
OUT_ERROR = "error"

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    addr TEXT PRIMARY KEY,
    hostname TEXT,
    version TEXT,
    online INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER,
    last_seen INTEGER
);

CREATE TABLE IF NOT EXISTS pending (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node TEXT NOT NULL,
    signature TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    hits INTEGER NOT NULL DEFAULT 1,
    first_seen INTEGER,
    last_seen INTEGER,
    provisional_name TEXT,
    provisional_action TEXT,
    provisional_duration TEXT,
    provisional_expires INTEGER,
    protocol TEXT,
    dst_ip TEXT,
    dst_host TEXT,
    dst_port INTEGER,
    user_id INTEGER,
    process_id INTEGER,
    process_path TEXT,
    process_cwd TEXT,
    process_args TEXT,
    process_checksums TEXT,
    decided_at INTEGER,
    decided_rule TEXT,
    UNIQUE(node, signature)
);
CREATE INDEX IF NOT EXISTS pending_state_idx ON pending(state, last_seen);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created INTEGER,
    node TEXT NOT NULL,
    ntf_type INTEGER NOT NULL,
    rule_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    sent_at INTEGER,
    ntf_id INTEGER,
    last_error TEXT,
    updated INTEGER,
    pending_id INTEGER
);
CREATE INDEX IF NOT EXISTS outbox_state_idx ON outbox(state, id);

CREATE TABLE IF NOT EXISTS rules (
    node TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER,
    action TEXT,
    duration TEXT,
    op_type TEXT,
    op_operand TEXT,
    op_data TEXT,
    updated INTEGER,
    rule_json TEXT,
    PRIMARY KEY(node, name)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node TEXT,
    time INTEGER,
    type INTEGER,
    what INTEGER,
    priority INTEGER,
    body TEXT
);
"""


class Database:
    """the review queue and the outbox.

    Every method is safe to call from several threads of the same process, and
    the file is safe to share with another process.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()

        if path != ":memory:":
            directory = os.path.dirname(path)
            if directory != "" and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700, exist_ok=True)

        # check_same_thread=False: the gRPC worker threads and the outbox thread
        # all use this connection, serialized by self._lock.
        self._db = sqlite3.connect(path, timeout=10.0, isolation_level=None,
                                   check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._setup()

    def _setup(self):
        with self._lock:
            if self.path != ":memory:":
                # WAL lets review read while serve writes. It's persistent, so
                # setting it on every open is harmless.
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute("PRAGMA busy_timeout=10000")
            self._db.executescript(SCHEMA)

            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    "{0} was created by a newer version of opensnitch-cli "
                    "(schema {1} > {2})".format(self.path, version, SCHEMA_VERSION))
            if version == 1:
                # schema 2 keeps the whole rule the daemon reported, so that
                # 'rule enable/disable' can send it back complete
                self._db.execute("ALTER TABLE rules ADD COLUMN rule_json TEXT")
            if version != SCHEMA_VERSION:
                self._db.execute("PRAGMA user_version={0}".format(SCHEMA_VERSION))

    def close(self):
        with self._lock:
            self._db.close()

    # nodes

    def node_seen(self, addr, hostname, version, online=True):
        now = int(time.time())
        with self._lock:
            self._db.execute(
                "INSERT INTO nodes (addr, hostname, version, online, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(addr) DO UPDATE SET hostname=excluded.hostname, "
                "version=excluded.version, online=excluded.online, last_seen=excluded.last_seen",
                (addr, hostname, version, 1 if online else 0, now, now))

    def node_offline(self, addr):
        with self._lock:
            self._db.execute("UPDATE nodes SET online=0 WHERE addr=?", (addr,))

    def nodes(self):
        with self._lock:
            return self._db.execute("SELECT * FROM nodes ORDER BY addr").fetchall()

    # the review queue

    def record_pending(self, node, signature, con, provisional):
        """adds the connection to the queue, or counts another attempt.

        provisional is the rule we answered with, so that review can tell the
        daemon to forget it once a real rule is in place.

        Returns (row id, True when it's the first time we see this signature).
        """
        now = int(time.time())
        expires = None
        if provisional.get("expires_in") is not None:
            expires = now + int(provisional["expires_in"])

        with self._lock:
            cur = self._db.execute("SELECT id FROM pending WHERE node=? AND signature=?",
                                   (node, signature))
            row = cur.fetchone()
            if row is not None:
                self._db.execute(
                    "UPDATE pending SET hits=hits+1, last_seen=?, state=?, "
                    "provisional_name=?, provisional_action=?, provisional_duration=?, "
                    "provisional_expires=? WHERE id=?",
                    (now, STATE_PENDING, provisional.get("name"), provisional.get("action"),
                     provisional.get("duration"), expires, row["id"]))
                return row["id"], False

            cur = self._db.execute(
                "INSERT INTO pending (node, signature, state, hits, first_seen, last_seen, "
                "provisional_name, provisional_action, provisional_duration, provisional_expires, "
                "protocol, dst_ip, dst_host, dst_port, user_id, process_id, process_path, "
                "process_cwd, process_args, process_checksums) "
                "VALUES (?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (node, signature, STATE_PENDING, now, now,
                 provisional.get("name"), provisional.get("action"),
                 provisional.get("duration"), expires,
                 con.protocol, con.dst_ip, con.dst_host, con.dst_port,
                 con.user_id, con.process_id, con.process_path, con.process_cwd,
                 json.dumps(list(con.process_args)),
                 json.dumps(dict(con.process_checksums))))
            return cur.lastrowid, True

    def pending_count(self):
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM pending WHERE state=?",
                                    (STATE_PENDING,)).fetchone()[0]

    def pending(self, node=None, limit=None, state=STATE_PENDING):
        query = "SELECT * FROM pending WHERE state=?"
        args = [state]
        if node is not None:
            query += " AND node=?"
            args.append(node)
        query += " ORDER BY id"
        if limit is not None:
            query += " LIMIT ?"
            args.append(limit)
        with self._lock:
            return self._db.execute(query, args).fetchall()

    def get_pending(self, entry_id):
        with self._lock:
            return self._db.execute("SELECT * FROM pending WHERE id=?", (entry_id,)).fetchone()

    def get_pending_by_signature(self, node, signature):
        with self._lock:
            return self._db.execute("SELECT * FROM pending WHERE node=? AND signature=?",
                                    (node, signature)).fetchone()

    def record_hit(self, entry_id):
        """another connection covered by an entry, without touching its state.

        Used when a decided entry is asked about again: unlike record_pending,
        the decision stands, we only note the attempt.
        """
        with self._lock:
            self._db.execute("UPDATE pending SET hits=hits+1, last_seen=? WHERE id=?",
                             (int(time.time()), entry_id))

    def set_pending_state(self, entry_id, state, rule_json=None):
        with self._lock:
            self._db.execute(
                "UPDATE pending SET state=?, decided_at=?, decided_rule=? WHERE id=?",
                (state, int(time.time()), rule_json, entry_id))

    def decided_by(self, node, rule_name):
        """the decided entries a rule of that name settled on a node.

        One approval can settle several queued connections (review.py
        resolve_covered), and they all record the same rule.
        """
        query = "SELECT * FROM pending WHERE state=? AND decided_rule IS NOT NULL"
        args = [STATE_DECIDED]
        if node is not None:
            query += " AND node=?"
            args.append(node)
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        found = []
        for row in rows:
            try:
                if json.loads(row["decided_rule"]).get("name") == rule_name:
                    found.append(row)
            except (ValueError, AttributeError):
                continue
        return found

    def decided_rule_names(self):
        """every rule name a decision has recorded, on any node."""
        with self._lock:
            rows = self._db.execute(
                "SELECT decided_rule FROM pending WHERE state=? AND decided_rule IS NOT NULL",
                (STATE_DECIDED,)).fetchall()
        names = set()
        for row in rows:
            try:
                name = json.loads(row["decided_rule"]).get("name")
            except (ValueError, AttributeError):
                continue
            if name:
                names.add(name)
        return names

    def reopen(self, entry_ids):
        """puts decided entries back in the queue, as if never answered."""
        with self._lock:
            for entry_id in entry_ids:
                self._db.execute(
                    "UPDATE pending SET state=?, decided_at=NULL, decided_rule=NULL WHERE id=?",
                    (STATE_PENDING, entry_id))

    def expire_provisionals(self):
        """clears the provisional rule of entries whose temporary rule has gone.

        The daemon removes the rule by itself; this only keeps the queue honest
        about what is currently covered.
        """
        now = int(time.time())
        with self._lock:
            cur = self._db.execute(
                "UPDATE pending SET provisional_name=NULL, provisional_action=NULL, "
                "provisional_duration=NULL, provisional_expires=NULL "
                "WHERE state=? AND provisional_expires IS NOT NULL AND provisional_expires<=?",
                (STATE_PENDING, now))
            return cur.rowcount

    # the outbox

    def queue_notification(self, node, ntf_type, rule_json, pending_id=None):
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO outbox (created, node, ntf_type, rule_json, state, updated, pending_id) "
                "VALUES (?,?,?,?,?,?,?)",
                (int(time.time()), node, ntf_type, rule_json, OUT_QUEUED,
                 int(time.time()), pending_id))
            return cur.lastrowid

    def queued_notifications(self, limit=50, node=None):
        query = "SELECT * FROM outbox WHERE state=?"
        args = [OUT_QUEUED]
        if node is not None:
            query += " AND node=?"
            args.append(node)
        query += " ORDER BY id LIMIT ?"
        args.append(limit)
        with self._lock:
            return self._db.execute(query, args).fetchall()

    def queued_count(self):
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM outbox WHERE state=?",
                                    (OUT_QUEUED,)).fetchone()[0]

    def mark_sent(self, outbox_id, ntf_id):
        with self._lock:
            self._db.execute(
                "UPDATE outbox SET state=?, sent_at=?, ntf_id=?, attempts=attempts+1, updated=? "
                "WHERE id=?",
                (OUT_SENT, int(time.time()), ntf_id, int(time.time()), outbox_id))

    def mark_result(self, ntf_id, ok, error=None):
        """records the daemon's answer to a notification we sent."""
        with self._lock:
            self._db.execute(
                "UPDATE outbox SET state=?, last_error=?, updated=? WHERE ntf_id=? AND state=?",
                (OUT_DONE if ok else OUT_ERROR, error, int(time.time()), ntf_id, OUT_SENT))
            if ok:
                self.reflect_result(ntf_id)

    def requeue_sent(self, node=None):
        """puts unanswered notifications back in the queue.

        Called at start up for everything (anything still marked as sent was in
        flight when the service stopped), and for one node when its stream
        closes before it answered. Re-sending is safe, the daemon replaces
        rules by name and deleting a rule that isn't there does nothing.
        """
        query = "UPDATE outbox SET state=? WHERE state=?"
        args = [OUT_QUEUED, OUT_SENT]
        if node is not None:
            query += " AND node=?"
            args.append(node)
        with self._lock:
            cur = self._db.execute(query, args)
            return cur.rowcount

    def undelivered(self, node, ntf_type):
        """notifications for a node that the daemon has not confirmed yet.

        'sent' counts too: the stream can be open without the daemon having
        answered, and an unanswered row goes back to 'queued' anyway when the
        stream closes.
        """
        with self._lock:
            return self._db.execute(
                "SELECT * FROM outbox WHERE node=? AND ntf_type=? AND state IN (?, ?) "
                "ORDER BY id",
                (node, ntf_type, OUT_QUEUED, OUT_SENT)).fetchall()

    def get_outbox(self, outbox_id):
        with self._lock:
            return self._db.execute("SELECT * FROM outbox WHERE id=?", (outbox_id,)).fetchone()

    def outbox_errors(self):
        with self._lock:
            return self._db.execute(
                "SELECT * FROM outbox WHERE state=? ORDER BY id", (OUT_ERROR,)).fetchall()

    def retry_errors(self):
        """sends the notifications the daemon rejected once more."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE outbox SET state=?, last_error=NULL, updated=? WHERE state=?",
                (OUT_QUEUED, int(time.time()), OUT_ERROR))
            return cur.rowcount

    def clear_errors(self):
        """forgets the notifications the daemon rejected.

        A rejected rule was never applied, so the connection it was meant to
        decide goes back to the review queue: the decision has to be taken
        again, differently. Returns the number of notifications dropped.
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT pending_id FROM outbox WHERE state=?", (OUT_ERROR,)).fetchall()
            for row in rows:
                if row["pending_id"] is None:
                    continue
                self._db.execute(
                    "UPDATE pending SET state=?, decided_at=NULL, decided_rule=NULL "
                    "WHERE id=? AND state=?",
                    (STATE_PENDING, row["pending_id"], STATE_DECIDED))
            self._db.execute("DELETE FROM outbox WHERE state=?", (OUT_ERROR,))
            return len(rows)

    # the daemon's rules, as reported on Subscribe

    def replace_rules(self, node, rules):
        """the rule set a node reported on Subscribe, whole."""
        from google.protobuf import json_format

        with self._lock:
            self._db.execute("DELETE FROM rules WHERE node=?", (node,))
            for r in rules:
                self._upsert_rule(node, r, json_format.MessageToJson(r))

    def _upsert_rule(self, node, r, rule_json):
        self._db.execute(
            "INSERT OR REPLACE INTO rules (node, name, enabled, action, duration, "
            "op_type, op_operand, op_data, updated, rule_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (node, r.name, 1 if r.enabled else 0, r.action, r.duration,
             r.operator.type, r.operator.operand, r.operator.data, int(time.time()),
             rule_json))

    def reflect_result(self, ntf_id):
        """keeps the rules table in step with a change the daemon confirmed.

        The daemon only lists its rules when it connects; after that, what we
        successfully sent it is the best knowledge we have.
        """
        from google.protobuf import json_format
        from opensnitch.cli.proto import ui_pb2

        with self._lock:
            row = self._db.execute(
                "SELECT node, ntf_type, rule_json FROM outbox WHERE ntf_id=? AND state=?",
                (ntf_id, OUT_DONE)).fetchone()
            if row is None:
                return
            rule = ui_pb2.Rule()
            try:
                json_format.Parse(row["rule_json"], rule)
            except json_format.ParseError:
                return
            if row["ntf_type"] == ui_pb2.DELETE_RULE:
                self._db.execute("DELETE FROM rules WHERE node=? AND name=?",
                                 (row["node"], rule.name))
            elif row["ntf_type"] in (ui_pb2.CHANGE_RULE, ui_pb2.ENABLE_RULE,
                                     ui_pb2.DISABLE_RULE):
                self._upsert_rule(row["node"], rule, row["rule_json"])

    def get_rule(self, node, name):
        with self._lock:
            return self._db.execute("SELECT * FROM rules WHERE node=? AND name=?",
                                    (node, name)).fetchone()

    def rules(self, node=None):
        query = "SELECT * FROM rules"
        args = []
        if node is not None:
            query += " WHERE node=?"
            args.append(node)
        query += " ORDER BY node, name"
        with self._lock:
            return self._db.execute(query, args).fetchall()

    def rule_names(self, node):
        """the names a new rule for this node must not take.

        What the daemon reported when it connected, plus every rule we have
        queued for it since: the rules table is only refreshed on Subscribe,
        and the daemon replaces rules by name, so a name handed out in an
        earlier review session would otherwise be handed out again and the
        second rule would silently overwrite the first.
        """
        with self._lock:
            rows = self._db.execute("SELECT name FROM rules WHERE node=?", (node,)).fetchall()
            sent = self._db.execute("SELECT rule_json FROM outbox WHERE node=?",
                                    (node,)).fetchall()
        names = set([r["name"] for r in rows])
        for row in sent:
            try:
                name = json.loads(row["rule_json"]).get("name")
            except (ValueError, AttributeError):
                continue
            if name:
                names.add(name)
        return names

    def add_alert(self, node, alert):
        with self._lock:
            self._db.execute(
                "INSERT INTO alerts (node, time, type, what, priority, body) VALUES (?,?,?,?,?,?)",
                (node, int(time.time()), alert.type, alert.what, alert.priority, str(alert)))

    def purge(self, retention_days):
        """drops decided entries and finished notifications after a while."""
        if retention_days <= 0:
            return 0
        cutoff = int(time.time()) - (retention_days * 86400)
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM pending WHERE state!=? AND decided_at IS NOT NULL AND decided_at<?",
                (STATE_PENDING, cutoff))
            removed = cur.rowcount
            self._db.execute("DELETE FROM outbox WHERE state=? AND updated<?", (OUT_DONE, cutoff))
        return removed
