from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtSql import QSqlDatabase, QSqlDatabase, QSqlQueryModel, QSqlQuery
import threading

class Database:
    __instance = None

    @staticmethod
    def instance():
        if Database.__instance == None:
            Database.__instance = Database()
        return Database.__instance

    def __init__(self):
        self._lock = threading.Lock()
        self.db = None
        self.initialize()

    def initialize(self):
        self.db = QSqlDatabase.addDatabase("QSQLITE", "db")
        self.db.setDatabaseName(":memory:")
        if not self.db.open():
            print("Error openening DB")
            return
        self._create_tables()

    def get_db(self):
        return self.db

    def _create_tables(self):
        # https://www.sqlite.org/wal.html
        q = QSqlQuery("PRAGMA journal_mode = OFF", self.db)
        q.exec_()
        q = QSqlQuery("PRAGMA synchronous = OFF", self.db)
        q.exec_()
        q = QSqlQuery("PRAGMA cache_size=10000", self.db)
        q.exec_()
        q = QSqlQuery("create table if not exists connections (" \
                "time text, " \
                "action text, " \
                "protocol text, " \
                "src_ip text, " \
                "src_port text, " \
                "dst_ip text, " \
                "dst_host text, " \
                "dst_port text, " \
                "uid text, " \
                "process text, " \
                "process_args text, " \
                "rule text, " \
                "UNIQUE(protocol, src_ip, src_port, dst_ip, dst_port, uid, process, process_args))", self.db)
        q.exec_()
        q = QSqlQuery("create table if not exists rules (" \
                "time text, "\
                "name text primary key, "\
                "action text, " \
                "duration text, " \
                "operator text " \
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

    def clean(self, table):
        q = QSqlQuery("delete from " + table, self.db)
        q.exec_()

    def clone(self):
        q = QSqlQuery(".dump", self.db)
        q.exec_()

    def transaction(self):
        self.db.transaction()

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def _insert(self, query_str, columns):
        try:
            with self._lock:

                q = QSqlQuery(self.db)
                q.prepare(query_str)
                for idx, v in enumerate(columns):
                    q.bindValue(idx, v)
                if not q.exec_():
                    print("ERROR",query_str)
                    print(q.lastError().driverText())
        except Exception as e:
            print("_insert exception", e)
        finally:
            q.finish()
    

    def insert(self, table, fields, columns, update_field=None, update_value=None, action_on_conflict="REPLACE"):
        if update_field != None:
            action_on_conflict = ""

        qstr = "INSERT OR " + action_on_conflict + " INTO " + table + " " + fields + " VALUES("
        update_fields=""
        for col in columns:
            qstr += "?,"
        qstr = qstr[0:len(qstr)-1] + ")"

        if update_field != None:
            for field in fields:
                update_fields += str(field) + "=excluded." + str(field)

            qstr += " ON CONFLICT(" + update_field + ") DO UPDATE SET " + \
                update_fields + \
                " WHERE " + update_field + "=excluded." + update_field

        self._insert(qstr, columns)

    def _insert_batch(self, query_str, fields, values):
        try:
            with self._lock:
                q = QSqlQuery(self.db)
                q.prepare(query_str)
                q.addBindValue(fields)
                q.addBindValue(values)
                if not q.execBatch():
                    print(query_str)
                    print(q.lastError().driverText())
                q.finish()
        except Exception as e:
            print("_insert_batch() exception:", e)

    def insert_batch(self, table, db_fields, db_columns, fields, values, update_field=None, update_value=None, action_on_conflict="REPLACE"):
        action = "OR " + action_on_conflict
        if update_field != None:
            action = ""

        qstr = "INSERT " + action + " INTO " + table + " " + db_fields + " VALUES("
        for idx in db_columns:
            qstr += "?,"
        qstr = qstr[0:len(qstr)-1] + ")"
        
        if update_field != None:
            if update_value == None:
                update_value = "excluded." + update_value
            qstr += " ON CONFLICT(" + update_field + ") DO UPDATE SET " + update_field + "=" + update_value

        self._insert_batch(qstr, fields, values)

    def dump(self):
        q = QSqlQuery(".dump", db=self.db)
        q.exec_()

    def get_query(self, table, fields):
        return "SELECT " + fields + " FROM " + table
