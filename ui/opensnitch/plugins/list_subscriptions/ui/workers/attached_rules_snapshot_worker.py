import json
import time
from typing import Any

from PyQt6.QtSql import QSqlDatabase, QSqlQuery

from opensnitch.plugins.list_subscriptions.ui import QtCore
from opensnitch.config import Config


def _is_sqlite_uri(db_file: str) -> bool:
    return str(db_file or "").strip().lower().startswith("file:")


def _worker_connection_name(prefix: str) -> str:
    thread_id = int(QtCore.QThread.currentThreadId())
    return f"{prefix}_{thread_id}_{time.time_ns()}"


def _open_worker_db(*, db_file: str, busy_timeout_ms: int, conn_name: str) -> QSqlDatabase | None:
    db = QSqlDatabase.addDatabase("QSQLITE", conn_name)
    db.setDatabaseName(db_file)
    options: list[str] = [f"QSQLITE_BUSY_TIMEOUT={busy_timeout_ms}"]
    if _is_sqlite_uri(db_file):
        options.extend(["QSQLITE_OPEN_URI", "QSQLITE_ENABLE_SHARED_CACHE"])
    db.setConnectOptions(";".join(options))
    if not db.open():
        return None
    return db


def _close_worker_db(*, conn_name: str, db: QSqlDatabase | None) -> None:
    if db is not None:
        try:
            if db.isOpen():
                db.close()
        except Exception:
            pass
    QSqlDatabase.removeDatabase(conn_name)


class AttachedRulesCountWorker(QtCore.QObject):
    count_done = QtCore.pyqtSignal(object)
    finished = QtCore.pyqtSignal()

    def __init__(self, *, db_file: str, local_nodes: list[str]):
        super().__init__()
        self._db_file = db_file
        self._local_nodes = local_nodes
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _should_stop(self) -> bool:
        return self._stop_requested

    @QtCore.pyqtSlot()
    def run(self):
        count: int | None = None
        started = time.monotonic()
        conn_name = _worker_connection_name("attached_rules_count")
        db: QSqlDatabase | None = None
        query: QSqlQuery | None = None
        try:
            if self._should_stop() or not self._local_nodes:
                count = 0
                return

            db = _open_worker_db(
                db_file=self._db_file,
                busy_timeout_ms=800,
                conn_name=conn_name,
            )
            if db is None:
                count = None
                return

            placeholders = ",".join("?" for _ in self._local_nodes)
            query = QSqlQuery(db)
            query.prepare(f"SELECT COUNT(*) FROM rules WHERE node IN ({placeholders})")
            for node in self._local_nodes:
                query.addBindValue(node)
            if not query.exec():
                count = None
                return
            if query.next():
                count = int((query.value(0) or 0) or 0)
            else:
                count = 0
        except Exception:
            count = None
        finally:
            if query is not None:
                try:
                    query.finish()
                except Exception:
                    pass
            query = None
            if db is not None:
                try:
                    if db.isOpen():
                        db.close()
                except Exception:
                    pass
            # Drop Python refs before removeDatabase to satisfy Qt lifetime rules.
            db = QSqlDatabase()
            _close_worker_db(conn_name=conn_name, db=None)
            elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
            if not self._should_stop():
                self.count_done.emit(
                    {
                        "count": count,
                        "over_limit": False,
                        "is_estimate": False,
                        "elapsed_ms": elapsed_ms,
                    }
                )
            self.finished.emit()


class AttachedRulesFetchWorker(QtCore.QObject):
    rows_done = QtCore.pyqtSignal(object)
    finished = QtCore.pyqtSignal()

    def __init__(self, *, db_file: str, local_nodes: list[str]):
        super().__init__()
        self._db_file = db_file
        self._local_nodes = local_nodes
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _should_stop(self) -> bool:
        return self._stop_requested

    @QtCore.pyqtSlot()
    def run(self):
        rows: list[tuple[str, str, bool, str, str, str]] = []
        started = time.monotonic()
        conn_name = _worker_connection_name("attached_rules_fetch")
        db: QSqlDatabase | None = None
        query: QSqlQuery | None = None
        try:
            if self._should_stop() or not self._local_nodes:
                return

            db = _open_worker_db(
                db_file=self._db_file,
                busy_timeout_ms=1000,
                conn_name=conn_name,
            )
            if db is None:
                rows = []
                return

            placeholders = ",".join("?" for _ in self._local_nodes)
            sql = (
                "SELECT node, name, enabled, operator_type, operator_operand, operator_data "
                f"FROM rules WHERE node IN ({placeholders})"
            )
            query = QSqlQuery(db)
            query.prepare(sql)
            for node in self._local_nodes:
                query.addBindValue(node)
            if not query.exec():
                rows = []
                return

            while query.next():
                if self._should_stop():
                    break
                addr = str(query.value(0) or "").strip()
                rule_name = str(query.value(1) or "").strip()
                enabled_raw = str(query.value(2) or "").strip().lower()
                op_type = str(query.value(3) or "").strip()
                op_operand = str(query.value(4) or "").strip()
                op_data = str(query.value(5) or "").strip()
                if addr == "" or rule_name == "":
                    continue
                rows.append(
                    (
                        addr,
                        rule_name,
                        enabled_raw == "true",
                        op_type,
                        op_operand,
                        op_data,
                    )
                )
        except Exception:
            rows = []
        finally:
            if query is not None:
                try:
                    query.finish()
                except Exception:
                    pass
            query = None
            if db is not None:
                try:
                    if db.isOpen():
                        db.close()
                except Exception:
                    pass
            # Drop Python refs before removeDatabase to satisfy Qt lifetime rules.
            db = QSqlDatabase()
            _close_worker_db(conn_name=conn_name, db=None)
            elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
            if not self._should_stop():
                self.rows_done.emit(
                    {
                        "rows": rows,
                        "elapsed_ms": elapsed_ms,
                        "row_count": len(rows),
                    }
                )
            self.finished.emit()


class AttachedRulesProcessWorker(QtCore.QObject):
    snapshot_done = QtCore.pyqtSignal(object)
    finished = QtCore.pyqtSignal()

    def __init__(self, *, rows: list[tuple[str, str, bool, str, str, str]]):
        super().__init__()
        self._rows = rows
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _should_stop(self) -> bool:
        return self._stop_requested

    @QtCore.pyqtSlot()
    def run(self):
        snapshot: dict[str, list[dict[str, Any]]] = {}
        started = time.monotonic()
        try:
            if self._should_stop() or not self._rows:
                return

            seen_entries: set[tuple[str, str, str]] = set()
            for row in self._rows:
                if self._should_stop():
                    break
                addr, rule_name, rule_enabled, op_type, op_operand, op_data = row

                if op_operand == Config.OPERAND_LIST_DOMAINS and op_data != "":
                    direct = op_data.strip()
                    entry_key = (direct, addr, rule_name)
                    if entry_key not in seen_entries:
                        seen_entries.add(entry_key)
                        snapshot.setdefault(direct, []).append(
                            {
                                "addr": addr,
                                "name": rule_name,
                                "enabled": rule_enabled,
                            }
                        )

                if op_type != Config.RULE_TYPE_LIST:
                    continue
                try:
                    operators = json.loads(op_data)
                except Exception:
                    continue
                if not isinstance(operators, list):
                    continue
                for op in operators:
                    if self._should_stop():
                        break
                    if not isinstance(op, dict):
                        continue
                    operand = str(op.get("operand") or "").strip()
                    data = str(op.get("data") or "").strip()
                    if operand != Config.OPERAND_LIST_DOMAINS or data == "":
                        continue
                    entry_key = (data, addr, rule_name)
                    if entry_key in seen_entries:
                        continue
                    seen_entries.add(entry_key)
                    snapshot.setdefault(data, []).append(
                        {
                            "addr": addr,
                            "name": rule_name,
                            "enabled": rule_enabled,
                        }
                    )
        except Exception:
            snapshot = {}
        finally:
            elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
            if not self._should_stop():
                self.snapshot_done.emit(
                    {
                        "snapshot": snapshot,
                        "elapsed_ms": elapsed_ms,
                        "row_count": len(self._rows),
                    }
                )
            self.finished.emit()


class AttachedRulesSnapshotWorker(AttachedRulesProcessWorker):
    """Backward-compatible alias for snapshot processing worker."""
