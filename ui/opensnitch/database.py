from PyQt5.QtSql import QSqlDatabase, QSqlQueryModel, QSqlQuery
import threading
import sys

class Database:
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
        self.db_type = Database.DB_IN_MEMORY
        self.db_name = dbname
        self.initialize()

    def initialize(self):
        self.db = QSqlDatabase.addDatabase("QSQLITE", self.db_name)
        self.db.setDatabaseName(self.db_type)
        if not self.db.open():
            print("\n ** Error opening DB: SQLite driver not loaded. DB name: %s\n" % self.db_type)
            print("\n    Available drivers: ", QSqlDatabase.drivers())
            sys.exit(-1)
        self._create_tables()

    def close(self):
        self.db.close()

    def get_db(self):
        return self.db

    def get_new_qsql_model(self):
        return QSqlQueryModel()

    def get_db_name(self):
        return self.db_name

    def _create_tables(self):
        # https://www.sqlite.org/wal.html
        q = QSqlQuery("PRAGMA journal_mode = OFF", self.db)
        q.exec_()
        q = QSqlQuery("PRAGMA synchronous = OFF", self.db)
        q.exec_()
        q = QSqlQuery("PRAGMA cache_size=10000", self.db)
        q.exec_()
        q = QSqlQuery("PRAGMA optimize", self.db)
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

    def clean(self, table):
        with self._lock:
            q = QSqlQuery("delete from " + table, self.db)
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
