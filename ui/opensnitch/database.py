from PyQt5.QtSql import QSqlDatabase, QSqlQueryModel, QSqlQuery
import threading
import sys
from datetime import datetime, timedelta

class Database:
    db = None
    __instance = None
    DB_IN_MEMORY   = ":memory:"
    DB_TYPE_MEMORY = 0
    DB_TYPE_FILE   = 1

    @staticmethod
    def instance():
        if Database.__instance == None:
            Database.__instance = Database()
        return Database.__instance

    def __init__(self, dbname="db"):
        self._lock = threading.RLock()
        self.db = None
        self.db_file = Database.DB_IN_MEMORY
        self.db_name = dbname

    def initialize(self, dbtype=DB_TYPE_MEMORY, dbfile=DB_IN_MEMORY, db_name="db"):
        if dbtype != Database.DB_TYPE_MEMORY:
            self.db_file = dbfile

        self.db = QSqlDatabase.addDatabase("QSQLITE", self.db_name)
        self.db.setDatabaseName(self.db_file)
        if not self.db.open():
            print("\n ** Error opening DB: SQLite driver not loaded. DB name: %s\n" % self.db_file)
            print("\n    Available drivers: ", QSqlDatabase.drivers())
            sys.exit(-1)

        db_status, db_error = self.is_db_ok()
        if db_status is False:
            print("db.initialize() error:", db_error)
            return False, db_error

        self._create_tables()
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
            q = QSqlQuery("PRAGMA journal_mode = OFF", self.db)
            q.exec_()
            q = QSqlQuery("PRAGMA synchronous = OFF", self.db)
            q.exec_()
            q = QSqlQuery("PRAGMA cache_size=10000", self.db)
            q.exec_()
        else:
            q = QSqlQuery("PRAGMA synchronous = NORMAL", self.db)
            q.exec_()

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
                "UNIQUE(node, name)"
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

            oldest = datetime.fromisoformat(oldt)
            newest = datetime.fromisoformat(newt)
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

    def update(self, table, fields, values, condition, action_on_conflict="OR IGNORE"):
        qstr = "UPDATE " + action_on_conflict + " " + table + " SET " + fields + " WHERE " + condition
        try:
            with self._lock:
                q = QSqlQuery(qstr, self.db)
                q.prepare(qstr)
                for idx, v in enumerate(values):
                    q.bindValue(idx, v)
                if not q.exec_():
                    print("update ERROR", qstr)
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
                    print("_insert_batch() error", query_str)
                    print(q.lastError().driverText())

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

    def get_rule(self, rule_name, node_addr=None):
        """
        get rule records, given the name of the rule and the node
        """
        qstr = "SELECT * from rules WHERE name=?"
        if node_addr != None:
            qstr = qstr + " AND node=?"

        q = QSqlQuery(qstr, self.db)
        q.prepare(qstr)
        q.addBindValue(rule_name)
        if node_addr != None:
            q.addBindValue(node_addr)
        q.exec_()

        return q

    def insert_rule(self, rule, node_addr):
        self.insert("rules",
            "(time, node, name, enabled, precedence, action, duration, operator_type, operator_sensitive, operator_operand, operator_data)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    node_addr, rule.name,
                    str(rule.enabled), str(rule.precedence),
                    rule.action, rule.duration, rule.operator.type,
                    str(rule.operator.sensitive), rule.operator.operand, rule.operator.data),
                action_on_conflict="IGNORE")
