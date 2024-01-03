from PyQt5.QtSql import QSqlDatabase, QSqlQueryModel, QSqlQuery
import threading
import sys
import os
from datetime import datetime, timedelta

class Database:
    db = None
    __instance = None
    DB_IN_MEMORY   = "file::memory:"
    DB_TYPE_MEMORY = 0
    DB_TYPE_FILE   = 1
    DB_JRNL_WAL    = False

    # Sqlite3 journal modes
    DB_JOURNAL_MODE_LIST = {
            0: "DELETE",
            1: "TRUNCATE",
            2: "PERSIST",
            3: "MEMORY",
            4: "WAL",
            5: "OFF",
            }

    # increase accordingly whenever the schema is updated
    DB_VERSION = 3

    @staticmethod
    def instance():
        if Database.__instance == None:
            Database.__instance = Database()
        return Database.__instance

    def __init__(self, dbname="db"):
        self._lock = threading.RLock()
        self.db = None
        self.db_file = Database.DB_IN_MEMORY
        self.db_jrnl_wal = Database.DB_JRNL_WAL
        self.db_name = dbname

    def initialize(self, dbtype=DB_TYPE_MEMORY, dbfile=DB_IN_MEMORY, dbjrnl_wal=DB_JRNL_WAL, db_name="db"):
        if dbtype != Database.DB_TYPE_MEMORY:
            self.db_file = dbfile
            self.db_jrnl_wal = dbjrnl_wal
        else:
            # Always disable under pure memory mode
            self.db_jrnl_wal = False

        is_new_file = not os.path.isfile(self.db_file)

        self.db = QSqlDatabase.addDatabase("QSQLITE", self.db_name)
        self.db.setDatabaseName(self.db_file)
        if dbtype == Database.DB_TYPE_MEMORY:
            self.db.setConnectOptions("QSQLITE_OPEN_URI;QSQLITE_ENABLE_SHARED_CACHE")
        if not self.db.open():
            print("\n ** Error opening DB: SQLite driver not loaded. DB name: %s\n" % self.db_file)
            print("\n    Available drivers: ", QSqlDatabase.drivers())
            sys.exit(-1)

        db_status, db_error = self.is_db_ok()
        if db_status is False:
            print("db.initialize() error:", db_error)
            return False, db_error


        if is_new_file:
            print("is new file, or IN MEMORY, setting initial schema version")
            self.set_schema_version(self.DB_VERSION)

        self._create_tables()
        self._upgrade_db_schema()
        return True, None

    def close(self):
        try:
            if self.db.isOpen():
                self.db.removeDatabase(self.db_name)
                self.db.close()
        except Exception as e:
            print("db.close() exception:", e)

    def is_db_ok(self):
        # XXX: quick_check may not be fast enough with some DBs on slow
        # hardware.
        q = QSqlQuery("PRAGMA quick_check;", self.db)
        if q.exec_() is not True:
            print(q.lastError().driverText())
            return False, q.lastError().driverText()

        if q.next() and q.value(0) != "ok":
            return False, "Database is corrupted (1)"

        return True, None

    def get_db(self):
        return self.db

    def get_db_file(self):
        return self.db_file

    def get_new_qsql_model(self):
        return QSqlQueryModel()

    def get_db_name(self):
        return self.db_name

    def _create_tables(self):
        # https://www.sqlite.org/wal.html
        if self.db_file == Database.DB_IN_MEMORY:
            self.set_schema_version(self.DB_VERSION)
            # Disable journal (default)
            self.set_journal_mode(5)
        elif self.db_jrnl_wal is True:
            # Set WAL mode (file+memory)
            self.set_journal_mode(4)
        else:
            # Set DELETE mode (file)
            self.set_journal_mode(0)
        q = QSqlQuery("create table if not exists connections (" \
                "time text, " \
                "node text, " \
                "action text, " \
                "protocol text, " \
                "src_ip text, " \
                "src_port text, " \
                "dst_ip text, " \
                "dst_host text, " \
                "dst_port text, " \
                "uid text, " \
                "pid text, " \
                "process text, " \
                "process_args text, " \
                "process_cwd text, " \
                "rule text, " \
                "UNIQUE(node, action, protocol, src_ip, src_port, dst_ip, dst_port, uid, pid, process, process_args))",
                self.db)
        q = QSqlQuery("create index time_index on connections (time)", self.db)
        q.exec_()
        q = QSqlQuery("create index action_index on connections (action)", self.db)
        q.exec_()
        q = QSqlQuery("create index protocol_index on connections (protocol)", self.db)
        q.exec_()
        q = QSqlQuery("create index dst_host_index on connections (dst_host)", self.db)
        q.exec_()
        q = QSqlQuery("create index process_index on connections (process)", self.db)
        q.exec_()
        q = QSqlQuery("create index dst_ip_index on connections (dst_ip)", self.db)
        q.exec_()
        q = QSqlQuery("create index dst_port_index on connections (dst_port)", self.db)
        q.exec_()
        q = QSqlQuery("create index rule_index on connections (rule)", self.db)
        q.exec_()
        q = QSqlQuery("create index node_index on connections (node)", self.db)
        q.exec_()
        q = QSqlQuery("CREATE INDEX details_query_index on connections (process, process_args, uid, pid, dst_ip, dst_host, dst_port, action, node, protocol)", self.db)
        q.exec_()

        q = QSqlQuery("create table if not exists nodes (" \
                "addr text primary key," \
                "hostname text," \
                "daemon_version text," \
                "daemon_uptime text," \
                "daemon_rules text," \
                "cons text," \
                "cons_dropped text," \
                "version text," \
                "status text, " \
                "last_connection text)"
                , self.db)
        q.exec_()

        q = QSqlQuery("create table if not exists rules (" \
                "time text, " \
                "node text, " \
                "name text, " \
                "enabled text, " \
                "precedence text, " \
                "action text, " \
                "duration text, " \
                "operator_type text, " \
                "operator_sensitive text, " \
                "operator_operand text, " \
                "operator_data text, " \
                "description text, " \
                "nolog text, " \
                "created text, " \
                "UNIQUE(node, name)"
                ")", self.db)
        q.exec_()

        q = QSqlQuery("create table if not exists alerts (" \
                "time text, " \
                "node text, " \
                "type text, " \
                "action text, " \
                "priority text, " \
                "what text, " \
                "body text, " \
                "status int " \
                ")", self.db)
        q.exec_()

        q = QSqlQuery("create index rules_index on rules (time)", self.db)
        q.exec_()

        q = QSqlQuery("create table if not exists hosts (what text primary key, hits integer)", self.db)
        q.exec_()
        q = QSqlQuery("create table if not exists procs (what text primary key, hits integer)", self.db)
        q.exec_()
        q = QSqlQuery("create table if not exists addrs (what text primary key, hits integer)", self.db)
        q.exec_()
        q = QSqlQuery("create table if not exists ports (what text primary key, hits integer)", self.db)
        q.exec_()
        q = QSqlQuery("create table if not exists users (what text primary key, hits integer)", self.db)
        q.exec_()

    def get_schema_version(self):
        q = QSqlQuery("PRAGMA user_version;", self.db)
        q.exec_()
        if q.next():
            print("schema version:", q.value(0))
            return int(q.value(0))

        return 0

    def set_schema_version(self, version):
        print("setting schema version to:", version)
        q = QSqlQuery("PRAGMA user_version = {0}".format(version), self.db)
        if q.exec_() == False:
            print("Error updating updating schema version:", q.lastError().text())

    def get_journal_mode(self):
        q = QSqlQuery("PRAGMA journal_mode;", self.db)
        q.exec_()
        if q.next():
            return str(q.value(0))

        return str("unknown")

    def set_journal_mode(self, mode):
        # https://www.sqlite.org/wal.html
        mode_str = Database.DB_JOURNAL_MODE_LIST[mode]
        if self.get_journal_mode().lower() != mode_str.lower():
            print("Setting journal_mode: ", mode_str)
            q = QSqlQuery("PRAGMA journal_mode = {modestr};".format(modestr = mode_str), self.db)
            if q.exec_() == False:
                print("Error updating PRAGMA journal_mode:", q.lastError().text())
                return False
        if mode == 3 or mode == 5:
            print("Setting DB memory optimizations")
            q = QSqlQuery("PRAGMA synchronous = OFF;", self.db)
            if q.exec_() == False:
                print("Error updating PRAGMA synchronous:", q.lastError().text())
                return False
            q = QSqlQuery("PRAGMA cache_size=10000;", self.db)
            if q.exec_() == False:
                print("Error updating PRAGMA cache_size:", q.lastError().text())
                return False
        else:
            print("Setting synchronous = NORMAL")
            q = QSqlQuery("PRAGMA synchronous = NORMAL;", self.db)
            if q.exec_() == False:
                print("Error updating PRAGMA synchronous:", q.lastError().text())

        return True

    def _upgrade_db_schema(self):
        migrations_path = os.path.dirname(os.path.realpath(__file__)) + "/migrations"
        schema_version = self.get_schema_version()
        if schema_version == self.DB_VERSION:
            print("db schema is up to date")
            return
        while schema_version < self.DB_VERSION:
            schema_version += 1
            try:
                print("applying schema upgrade:", schema_version)
                self._apply_db_upgrade("{0}/upgrade_{1}.sql".format(migrations_path, schema_version))
            except Exception as e:
                print("Not applying upgrade_{0}.sql:".format(schema_version), e)
                return
        self.set_schema_version(schema_version)

    def _apply_db_upgrade(self, file):
        print("applying upgrade from:", file)
        q = QSqlQuery(self.db)
        with open(file) as f:
            for line in f.readlines():
                # skip comments
                if line.startswith("--"):
                    continue
                print("applying upgrade:", line, end="")
                if q.exec(line) == False:
                    print("\tError:", q.lastError().text())
                else:
                    print("\tOK")

    def optimize(self):
        """https://www.sqlite.org/pragma.html#pragma_optimize
        """
        q = QSqlQuery("PRAGMA optimize;", self.db)
        q.exec_()

    def clean(self, table):
        with self._lock:
            q = QSqlQuery("delete from " + table, self.db)
            q.exec_()

    def vacuum(self):
        q = QSqlQuery("VACUUM;", self.db)
        q.exec_()

    def clone_db(self, name):
        return QSqlDatabase.cloneDatabase(self.db, name)

    def clone(self):
        q = QSqlQuery(".dump", self.db)
        q.exec_()

    def transaction(self):
        self.db.transaction()

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def get_total_records(self):
        try:
            q = QSqlQuery("SELECT count(*) FROM connections", self.db)
            if q.exec_() and q.first():
                r = q.value(0)
        except Exception as e:
            print("db, get_total_records() error:", e)

    def get_newest_record(self):
        try:
            q = QSqlQuery("SELECT time FROM connections ORDER BY 1 DESC LIMIT 1", self.db)
            if q.exec_() and q.first():
                return q.value(0)
        except Exception as e:
            print("db, get_newest_record() error:", e)
        return 0

    def get_oldest_record(self):
        try:
            q = QSqlQuery("SELECT time FROM connections ORDER BY 1 ASC LIMIT 1", self.db)
            if q.exec_() and q.first():
                return q.value(0)
        except Exception as e:
            print("db, get_oldest_record() error:", e)
        return 0

    def purge_oldest(self, max_days_to_keep):
        try:
            oldt = self.get_oldest_record()
            newt = self.get_newest_record()
            if oldt == None or newt == None or oldt == 0 or newt == 0:
                return -1

            oldest = datetime.strptime(oldt, "%Y-%m-%d %H:%M:%S.%f")
            newest = datetime.strptime(newt, "%Y-%m-%d %H:%M:%S.%f")
            diff = newest - oldest
            date_to_purge = datetime.now() - timedelta(days=max_days_to_keep)

            if diff.days >= max_days_to_keep:
                q = QSqlQuery(self.db)
                q.prepare("DELETE FROM connections WHERE time < ?")
                q.bindValue(0, str(date_to_purge))
                if q.exec_():
                    print("purge_oldest() {0} records deleted".format(q.numRowsAffected()))
                    return q.numRowsAffected()
        except Exception as e:
            print("db, purge_oldest() error:", e)

        return -1

    def select(self, qstr):
        try:
            return QSqlQuery(qstr, self.db)
        except Exception as e:
            print("db, select() exception: ", e)

        return None

    def remove(self, qstr):
        try:
            q = QSqlQuery(qstr, self.db)
            if q.exec_():
                return True
            else:
                print("db, remove() ERROR: ", qstr)
                print(q.lastError().driverText())
        except Exception as e:
            print("db, remove exception: ", e)

        return False

    def _insert(self, query_str, columns):
        with self._lock:
            try:

                q = QSqlQuery(self.db)
                q.prepare(query_str)
                for idx, v in enumerate(columns):
                    q.bindValue(idx, v)
                if q.exec_():
                    return True
                else:
                    print("_insert() ERROR", query_str)
                    print(q.lastError().driverText())

            except Exception as e:
                print("_insert exception", e)
            finally:
                q.finish()

        return False

    def insert(self, table, fields, columns, update_field=None, update_values=None, action_on_conflict="REPLACE"):
        if update_field != None:
            action_on_conflict = ""
        else:
            action_on_conflict = "OR " + action_on_conflict

        qstr = "INSERT " + action_on_conflict + " INTO " + table + " " + fields + " VALUES("
        update_fields=""
        for col in columns:
            qstr += "?,"
        qstr = qstr[0:len(qstr)-1] + ")"

        if update_field != None:
            # NOTE: UPSERTS on sqlite are only supported from v3.24 on.
            # On Ubuntu16.04/18 for example (v3.11/3.22) updating a record on conflict
            # fails with "Parameter count error"
            qstr += " ON CONFLICT (" + update_field + ") DO UPDATE SET "
            for idx, field in enumerate(update_values):
                qstr += str(field) + "=excluded." + str(field) + ","

            qstr = qstr[0:len(qstr)-1]

        return self._insert(qstr, columns)

    def update(self, table, fields, values, condition=None, action_on_conflict="OR IGNORE"):
        qstr = "UPDATE " + action_on_conflict + " " + table + " SET " + fields
        if condition != None:
            qstr += " WHERE " + condition
        try:
            with self._lock:
                q = QSqlQuery(qstr, self.db)
                q.prepare(qstr)
                for idx, v in enumerate(values):
                    q.bindValue(idx, v)
                if not q.exec_():
                    print("update ERROR:", qstr, "values:", values)
                    print(q.lastError().driverText())

        except Exception as e:
            print("update() exception:", e)
        finally:
            q.finish()

    def _insert_batch(self, query_str, fields, values):
        result=True
        with self._lock:
            try:
                q = QSqlQuery(self.db)
                q.prepare(query_str)
                q.addBindValue(fields)
                q.addBindValue(values)
                if not q.execBatch():
                    print("_insert_batch() db error:", query_str)
                    print(q.lastError().driverText())
                    print("\t", fields)
                    print("\t", values)

                    result=False
            except Exception as e:
                print("_insert_batch() exception:", e)
            finally:
                q.finish()

        return result

    def insert_batch(self, table, db_fields, db_columns, fields, values, update_field=None, update_value=None, action_on_conflict="REPLACE"):
        action = "OR " + action_on_conflict
        if update_field != None:
            action = ""

        qstr = "INSERT " + action + " INTO " + table + " (" + db_fields[0] + "," + db_fields[1] + ") VALUES("
        for idx in db_columns:
            qstr += "?,"
        qstr = qstr[0:len(qstr)-1] + ")"

        if self._insert_batch(qstr, fields, values) == False:
            self.update_batch(table, db_fields, db_columns, fields, values, update_field, update_value, action_on_conflict)

    def update_batch(self, table, db_fields, db_columns, fields, values, update_field=None, update_value=None, action_on_conflict="REPLACE"):
        for idx, i in enumerate(values):
            s = "UPDATE " + table + " SET " + "%s=(select hits from %s)+%s" % (db_fields[1], table, values[idx])
            s += "  WHERE %s=\"%s\"," % (db_fields[0], fields[idx])
            s = s[0:len(s)-1]
            with self._lock:
                q = QSqlQuery(s, self.db)
                if not q.exec_():
                    print("update batch ERROR", s)
                    print(q.lastError().driverText())

    def dump(self):
        q = QSqlQuery(".dump", db=self.db)
        q.exec_()

    def get_query(self, table, fields):
        return "SELECT " + fields + " FROM " + table

    def empty_rule(self, name=""):
        if name == "":
            return
        qstr = "DELETE FROM connections WHERE rule = ?"

        with self._lock:
            q = QSqlQuery(qstr, self.db)
            q.prepare(qstr)
            q.addBindValue(name)
            if not q.exec_():
                print("db, empty_rule() ERROR: ", qstr)
                print(q.lastError().driverText())

    def delete_rule(self, name, node_addr):
        qstr = "DELETE FROM rules WHERE name=?"
        if node_addr != None:
            qstr = qstr + " AND node=?"

        with self._lock:
            q = QSqlQuery(qstr, self.db)
            q.prepare(qstr)
            q.addBindValue(name)
            if node_addr != None:
                q.addBindValue(node_addr)
            if not q.exec_():
                print("db, delete_rule() ERROR: ", qstr)
                print(q.lastError().driverText())
                return False

        return True

    def delete_rules_by_field(self, field, values):
        if len(values) == 0:
            return True

        qstr = "DELETE FROM rules WHERE "
        for v in values:
            qstr += field + "=? OR "

        qstr = qstr[:-4]

        with self._lock:
            q = QSqlQuery(qstr, self.db)
            q.prepare(qstr)

            for v in values:
                q.addBindValue(v)

            if not q.exec_():
                print("db, delete_rule_by_field() ERROR: ", qstr)
                print(q.lastError().driverText())
                return False

        return True

    def get_connection_by_field(self, field, date):
        """
        """
        qstr = "SELECT * FROM connections WHERE {0}=?".format(field)

        q = QSqlQuery(qstr, self.db)
        q.prepare(qstr)
        q.addBindValue(date)
        q.exec_()

        return q

    def get_rule(self, rule_name, node_addr=None):
        """
        get rule records, given the name of the rule and the node
        """
        qstr = "SELECT * FROM rules WHERE name=?"
        if node_addr != None:
            qstr = qstr + " AND node=?"

        q = QSqlQuery(qstr, self.db)
        q.prepare(qstr)
        q.addBindValue(rule_name)
        if node_addr != None:
            q.addBindValue(node_addr)
        q.exec_()

        return q

    def get_rule_by_field(self, node_addr=None, field=None, value=None):
        """
        get rule records by field (process.path, etc)
        """
        qstr = "SELECT * FROM rules WHERE {0} LIKE ?".format(field)
        q = QSqlQuery(qstr, self.db)
        if node_addr != None:
            qstr = qstr + " AND node=?".format(node_addr)

        q.prepare(qstr)
        q.addBindValue("%" + value + "%")
        if node_addr != None:
            q.addBindValue(node_addr)
        if not q.exec_():
            print("get_rule_by_field() error:", q.lastError().driverText())
            return None

        return q

    def get_rules(self, node_addr):
        """
        get rule records, given the name of the rule and the node
        """
        qstr = "SELECT * FROM rules WHERE node=?"
        q = QSqlQuery(qstr, self.db)
        q.prepare(qstr)
        q.addBindValue(node_addr)
        if not q.exec_():
            return None

        return q

    def insert_rule(self, rule, node_addr):
        self.insert("rules",
            "(time, node, name, description, enabled, precedence, nolog, action, duration, operator_type, operator_sensitive, operator_operand, operator_data)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    node_addr, rule.name, rule.description,
                    str(rule.enabled), str(rule.precedence), str(rule.nolog),
                    rule.action, rule.duration, rule.operator.type,
                    str(rule.operator.sensitive), rule.operator.operand, rule.operator.data),
                action_on_conflict="IGNORE")

    def rule_exists(self, rule, node_addr):
        qstr = "SELECT node, name, action, duration, operator_type, operator_operand, operator_data " \
            " FROM rules WHERE " \
            "name=? AND " \
            "node=? AND " \
            "action=? AND " \
            "duration=? AND " \
            "operator_type=? AND " \
            "operator_operand=? AND " \
            "operator_data=?"
        q = QSqlQuery(qstr, self.db)
        q.prepare(qstr)
        q.addBindValue(rule.name)
        q.addBindValue(node_addr)
        q.addBindValue(rule.action)
        q.addBindValue(rule.duration)
        q.addBindValue(rule.operator.type)
        q.addBindValue(rule.operator.operand)
        q.addBindValue(rule.operator.data)
        if not q.exec_() or q.next() == False:
            return None

        return q


    def delete_alert(self, time, node_addr=None):
        qstr = "DELETE FROM alerts WHERE time=?"
        if node_addr != None:
            qstr = qstr + " AND node=?"

        with self._lock:
            q = QSqlQuery(qstr, self.db)
            q.prepare(qstr)
            q.addBindValue(time)
            if node_addr != None:
                q.addBindValue(node_addr)
            if not q.exec_():
                print("db, delete_alert() ERROR: ", qstr)
                print(q.lastError().driverText())
                return False

        return True

    def get_alert(self, alert_time, node_addr=None):
        """
        get alert, given the time of the alert and the node
        """
        qstr = "SELECT * FROM alerts WHERE time=?"
        if node_addr != None:
            qstr = qstr + " AND node=?"

        q = QSqlQuery(qstr, self.db)
        q.prepare(qstr)
        q.addBindValue(alert_time)
        if node_addr != None:
            q.addBindValue(node_addr)
        q.exec_()

        return q
