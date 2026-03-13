import os
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets, QC
from opensnitch.plugins.list_subscriptions.ui.views.attached_rules_dialog import (
    AttachedRulesDialog,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.attached_rules_index import (
    AttachedRulesIndex,
)
from opensnitch.plugins.list_subscriptions.ui.workers import attached_rules_snapshot_worker as attached_rules_workers
from opensnitch.database import Database
from opensnitch.config import Config
from opensnitch.rules import Rule, Rules
from opensnitch.proto import ui_pb2 as ui_pb2

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


def _is_memory_db_file(db_file: str) -> bool:
    value = str(db_file or "").strip().lower()
    if value in ("", ":memory:", "file::memory:"):
        return True
    if value.startswith("file::memory"):
        return True
    return "mode=memory" in value


def _is_shared_memory_db_file(db_file: str) -> bool:
    value = str(db_file or "").strip().lower()
    # OpenSnitch's default in-memory URI uses file::memory: and enables
    # shared-cache via connection options at DB initialization time.
    if value.startswith("file::memory:"):
        return True
    if "cache=shared" not in value:
        return False
    return "mode=memory" in value or value.startswith("file::memory:")


def _is_sqlite_uri(db_file: str) -> bool:
    return str(db_file or "").strip().lower().startswith("file:")


ATTACHED_RULES_SNAPSHOT_TIMEOUT_MS = 2000
ATTACHED_RULES_SNAPSHOT_WARN_RULES = 100
ATTACHED_RULES_COUNT_CACHE_TTL_SECONDS = 6 * 60 * 60
ATTACHED_RULES_COUNT_BASELINE_MS = 8
ATTACHED_RULES_TIMEOUT_MAX_MS = 8000
ATTACHED_RULES_FETCH_BASELINE_MS_PER_ROW = 0.1
ATTACHED_RULES_PROCESS_BASELINE_MS_PER_ROW = 0.05
ATTACHED_RULES_TIMEOUT_SAFETY_FACTOR = 3.0
ATTACHED_RULES_WARN_MIN_ESTIMATED_DELAY_MS = 2000


class RulesAttachmentController:
    def __init__(self, *, dialog: "ListSubscriptionsDialog"):
        self._dialog = dialog
        self._rules = Rules.instance()
        self._rules_index = AttachedRulesIndex()
        self._snapshot_cache_dirty = False
        self._snapshot_worker: Any = None
        self._snapshot_thread: QtCore.QThread | None = None
        self._snapshot_phase = "idle"
        self._snapshot_callbacks: list[
            Callable[[dict[str, list[dict[str, Any]]]], None]
        ] = []
        self._rules_count_cache: dict[
            tuple[str, tuple[str, ...]],
            tuple[int | None, bool, float],
        ] = {}
        self._pending_snapshot_db_file = ""
        self._pending_snapshot_local_nodes: list[str] = []
        self._pending_snapshot_in_memory_db = False
        self._pending_snapshot_shared_memory_db = False
        self._pending_snapshot_count_over_limit = False
        self._pending_snapshot_row_count = 0
        self._count_query_delay_factor = 1.0
        self._fetch_ms_per_row = ATTACHED_RULES_FETCH_BASELINE_MS_PER_ROW
        self._process_ms_per_row = ATTACHED_RULES_PROCESS_BASELINE_MS_PER_ROW
        self._snapshot_timeout_timer = QtCore.QTimer(dialog)
        self._snapshot_timeout_timer.setSingleShot(True)
        self._snapshot_timeout_timer.setInterval(ATTACHED_RULES_SNAPSHOT_TIMEOUT_MS)
        self._snapshot_timeout_timer.timeout.connect(self._on_snapshot_worker_timeout)
        self._snapshot_timed_out = False
        try:
            self._dialog._nodes.nodesUpdated.connect(self._on_nodes_updated)
        except Exception:
            pass
        try:
            self._rules.updated.connect(self._on_rules_updated)
        except Exception:
            pass
        dialog.destroyed.connect(self._on_dialog_destroyed)

    def _on_dialog_destroyed(self, *_args):
        worker = self._snapshot_worker
        thread = self._snapshot_thread
        if worker is None or thread is None:
            return
        try:
            worker.stop()
        except Exception:
            pass
        self._snapshot_timeout_timer.stop()
        if thread.isRunning():
            thread.quit()
            thread.wait(300)

    def attached_rules_snapshot(self):
        return self._rules_index.snapshot()

    def has_active_snapshot(self) -> bool:
        thread = self._snapshot_thread
        return bool(thread is not None and thread.isRunning())

    def cancel_active_snapshot(self) -> None:
        worker = self._snapshot_worker
        thread = self._snapshot_thread
        self._snapshot_timeout_timer.stop()
        if worker is None or thread is None or not thread.isRunning():
            return
        try:
            stop = getattr(worker, "stop", None)
            if callable(stop):
                stop()
        except Exception:
            pass
        thread.quit()
        self._snapshot_phase = "idle"
        if self._snapshot_callbacks:
            snapshot = self._rules_index.snapshot()
            callbacks = self._snapshot_callbacks[:]
            self._snapshot_callbacks.clear()
            for callback in callbacks:
                callback(snapshot)

    def apply_rule_editor_change(self, change: dict[str, Any]) -> None:
        if not self._rules_index.apply_rule_editor_change(change):
            self._mark_snapshot_cache_dirty("rule-editor-missing-addr")
            return
        self._snapshot_cache_dirty = False

    def update_cached_rule_enabled(self, addr: str, rule_name: str, enabled: bool) -> None:
        if not self._rules_index.update_rule_enabled(addr, rule_name, enabled):
            self._mark_snapshot_cache_dirty("rule-enabled-miss")
            return
        self._snapshot_cache_dirty = False

    def remove_cached_rule(self, addr: str, rule_name: str) -> None:
        self._rules_index.remove_rule(addr, rule_name)
        self._snapshot_cache_dirty = False

    def _mark_snapshot_cache_dirty(self, reason: str) -> None:
        self._snapshot_cache_dirty = True
        self._rules_count_cache.clear()
        self._dialog._status_controller.debug(
            QC.translate(
                "stats",
                "Attached-rules cache invalidated: {0}",
            ).format(reason),
            origin="ui:attached-rules",
        )

    def invalidate_snapshot_cache(self, reason: str) -> None:
        self._mark_snapshot_cache_dirty(reason)

    def _on_nodes_updated(self, _count: int) -> None:
        self._mark_snapshot_cache_dirty("nodes-updated")

    def _on_rules_updated(self, _value: int) -> None:
        self._mark_snapshot_cache_dirty("rules-updated")

    def _attached_rules_snapshot_sync(self):
        attached_rules_by_dir: dict[str, list[dict[str, Any]]] = {}
        seen_entries: set[tuple[str, str, str]] = set()
        for addr in self._dialog._nodes.get().keys():
            try:
                if not self._dialog._nodes.is_local(addr):
                    continue
            except Exception:
                continue

            records = self._dialog._nodes.get_rules(addr)
            if records is None or records == -1:
                continue

            while records.next():
                try:
                    rule = cast(ui_pb2.Rule, Rule.new_from_records(records))
                except Exception:
                    continue

                rule_name = str(getattr(rule, "name", "") or "").strip()
                if rule_name == "":
                    continue
                rule_enabled = bool(getattr(rule, "enabled", True))

                if rule.operator.operand == Config.OPERAND_LIST_DOMAINS:
                    direct = os.path.normpath(str(rule.operator.data or "").strip())
                    if direct != "":
                        entry_key = (direct, addr, rule_name)
                        if entry_key not in seen_entries:
                            seen_entries.add(entry_key)
                            attached_rules_by_dir.setdefault(direct, []).append(
                                {
                                    "addr": addr,
                                    "name": rule_name,
                                    "enabled": rule_enabled,
                                }
                            )

                for operator in getattr(rule.operator, "list", []):
                    if operator.operand != Config.OPERAND_LIST_DOMAINS:
                        continue
                    nested = os.path.normpath(str(operator.data or "").strip())
                    if nested != "":
                        entry_key = (nested, addr, rule_name)
                        if entry_key not in seen_entries:
                            seen_entries.add(entry_key)
                            attached_rules_by_dir.setdefault(nested, []).append(
                                {
                                    "addr": addr,
                                    "name": rule_name,
                                    "enabled": rule_enabled,
                                }
                            )

        return attached_rules_by_dir

    def _on_snapshot_worker_done(self, snapshot: object) -> None:
        self._snapshot_timeout_timer.stop()
        self._snapshot_phase = "idle"
        actual_snapshot: object = snapshot
        if isinstance(snapshot, dict) and "snapshot" in snapshot and "elapsed_ms" in snapshot:
            raw_elapsed = snapshot.get("elapsed_ms")
            raw_row_count = snapshot.get("row_count")
            if isinstance(raw_elapsed, int):
                row_count = raw_row_count if isinstance(raw_row_count, int) else 0
                self._update_process_ms_per_row(raw_elapsed, row_count)
                self._dialog._status_controller.debug(
                    QC.translate(
                        "stats",
                        "Attached-rules process: {0} ms for {1} rows ({2:.3f} ms/row EMA)",
                    ).format(raw_elapsed, row_count, self._process_ms_per_row),
                    origin="ui:attached-rules",
                )
            actual_snapshot = snapshot.get("snapshot") or {}
        data = self._rules_index.set_from_snapshot_obj(actual_snapshot)
        self._snapshot_cache_dirty = False
        if not self._snapshot_callbacks:
            return
        callbacks = self._snapshot_callbacks[:]
        self._snapshot_callbacks.clear()
        for callback in callbacks:
            callback(data)

    def _on_snapshot_worker_stopped(
        self,
        worker: Any,
        thread: QtCore.QThread,
    ) -> None:
        if self._snapshot_worker is worker:
            self._snapshot_worker = None
        if self._snapshot_thread is thread:
            self._snapshot_thread = None

    def _on_snapshot_worker_timeout(self) -> None:
        worker = self._snapshot_worker
        thread = self._snapshot_thread
        if worker is None or thread is None or not thread.isRunning():
            return
        self._snapshot_timed_out = True
        self._snapshot_phase = "timeout"
        try:
            stop = getattr(worker, "stop", None)
            if callable(stop):
                stop()
        except Exception:
            pass
        thread.quit()
        fallback_snapshot = self._rules_index.snapshot()
        if fallback_snapshot:
            self._dialog._status_controller.warn(
                QC.translate(
                    "stats",
                    "Attached-rules lookup timed out; showing cached results.",
                ),
                origin="ui:attached-rules",
            )
        else:
            self._dialog._status_controller.warn(
                QC.translate(
                    "stats",
                    "Attached-rules lookup timed out; showing no results.",
                ),
                origin="ui:attached-rules",
            )
        callbacks = self._snapshot_callbacks[:]
        self._snapshot_callbacks.clear()
        for callback in callbacks:
            callback(fallback_snapshot)

    def _snapshot_db_mode(self, db_file: str) -> tuple[str, str]:
        if _is_shared_memory_db_file(db_file):
            return "memory-shared", "async"
        if _is_memory_db_file(db_file):
            return "memory-private", "sync"
        if _is_sqlite_uri(db_file):
            return "file-uri", "async"
        return "file", "async"

    def _count_cache_key(self, db_file: str, local_nodes: list[str]) -> tuple[str, tuple[str, ...]]:
        return db_file, tuple(sorted(local_nodes))

    def _get_cached_rules_count(
        self,
        db_file: str,
        local_nodes: list[str],
    ) -> tuple[int | None, bool] | None:
        key = self._count_cache_key(db_file, local_nodes)
        cached = self._rules_count_cache.get(key)
        if cached is None:
            return None
        count, over_limit, ts = cached
        if (time.monotonic() - ts) > ATTACHED_RULES_COUNT_CACHE_TTL_SECONDS:
            self._rules_count_cache.pop(key, None)
            return None
        return count, over_limit

    def _set_cached_rules_count(
        self,
        db_file: str,
        local_nodes: list[str],
        count: int | None,
        over_limit: bool,
    ) -> None:
        key = self._count_cache_key(db_file, local_nodes)
        self._rules_count_cache[key] = (count, over_limit, time.monotonic())

    def _start_stage_worker(
        self,
        *,
        worker: Any,
        done_signal_name: str,
        done_handler: Callable[[object], None],
        thread_name: str,
    ) -> None:
        worker_thread = QtCore.QThread(self._dialog)
        worker_thread.setObjectName(thread_name)
        worker.moveToThread(worker_thread)
        self._snapshot_worker = worker
        self._snapshot_thread = worker_thread

        worker_thread.started.connect(worker.run)
        getattr(worker, done_signal_name).connect(done_handler)
        worker.finished.connect(worker_thread.quit)
        worker.finished.connect(worker.deleteLater)
        worker_thread.finished.connect(
            lambda w=worker, t=worker_thread: self._on_snapshot_worker_stopped(w, t)
        )
        worker_thread.finished.connect(worker_thread.deleteLater)
        worker_thread.start()

    def _confirm_potential_snapshot_delay(
        self,
        *,
        estimated_rules: int | None,
        count_over_limit: bool,
        in_memory_db: bool,
        shared_memory_db: bool,
    ) -> bool:
        may_freeze = in_memory_db and not shared_memory_db
        estimated_delay_ms: int | None = None
        if estimated_rules is not None and estimated_rules > 0:
            estimated_delay_ms = int(
                estimated_rules * (self._fetch_ms_per_row + self._process_ms_per_row)
            )
        may_delay = count_over_limit or (
            estimated_delay_ms is not None
            and estimated_delay_ms >= ATTACHED_RULES_WARN_MIN_ESTIMATED_DELAY_MS
        )

        if not may_freeze and not may_delay:
            return True

        if may_freeze and count_over_limit and estimated_rules is not None:
            message = QC.translate(
                "stats",
                "Loading attached rules may freeze the UI briefly (at least {0} rules on local nodes). Continue?",
            ).format(estimated_rules)
        elif may_freeze and estimated_rules is not None:
            message = QC.translate(
                "stats",
                "Loading attached rules may freeze the UI briefly (about {0} rules on local nodes). Continue?",
            ).format(estimated_rules)
        elif may_freeze:
            message = QC.translate(
                "stats",
                "Loading attached rules may freeze the UI briefly on this setup. Continue?",
            )
        elif count_over_limit and estimated_rules is not None:
            message = QC.translate(
                "stats",
                "Loading attached rules may take longer than usual (at least {0} rules on local nodes). Continue?",
            ).format(estimated_rules)
        elif estimated_rules is not None and estimated_delay_ms is not None:
            message = QC.translate(
                "stats",
                "Loading attached rules may take longer than usual (~{0:.1f}s, {1} rules on local nodes). Continue?",
            ).format(max(0.1, estimated_delay_ms / 1000.0), estimated_rules)
        else:
            message = QC.translate(
                "stats",
                "Loading attached rules may take longer than usual. Continue?",
            )

        reply = QtWidgets.QMessageBox.question(
            self._dialog,
            QC.translate("stats", "Attached rules lookup"),
            message,
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        return reply == QtWidgets.QMessageBox.StandardButton.Yes

    def _update_count_query_delay_factor(self, elapsed_ms: int) -> None:
        sample = max(0.25, min(4.0, elapsed_ms / ATTACHED_RULES_COUNT_BASELINE_MS))
        self._count_query_delay_factor = (0.7 * self._count_query_delay_factor) + (0.3 * sample)

    def _update_fetch_ms_per_row(self, elapsed_ms: int, row_count: int) -> None:
        if row_count < 1:
            return
        sample = max(0.001, min(50.0, elapsed_ms / row_count))
        self._fetch_ms_per_row = 0.7 * self._fetch_ms_per_row + 0.3 * sample

    def _update_process_ms_per_row(self, elapsed_ms: int, row_count: int) -> None:
        if row_count < 1:
            return
        sample = max(0.001, min(50.0, elapsed_ms / row_count))
        self._process_ms_per_row = 0.7 * self._process_ms_per_row + 0.3 * sample

    def _snapshot_timeout_interval_ms(self) -> int:
        count = self._pending_snapshot_row_count
        if count > 0:
            estimated = int(
                count
                * (self._fetch_ms_per_row + self._process_ms_per_row)
                * ATTACHED_RULES_TIMEOUT_SAFETY_FACTOR
            )
            return max(ATTACHED_RULES_SNAPSHOT_TIMEOUT_MS, min(ATTACHED_RULES_TIMEOUT_MAX_MS, estimated))
        # fallback: scale base timeout by count query delay factor
        scaled = int(ATTACHED_RULES_SNAPSHOT_TIMEOUT_MS * max(self._count_query_delay_factor, 0.75))
        return max(ATTACHED_RULES_SNAPSHOT_TIMEOUT_MS, min(ATTACHED_RULES_TIMEOUT_MAX_MS, scaled))

    def refresh_attached_rules_snapshot_async(
        self,
        callback: Callable[[dict[str, list[dict[str, Any]]]], None],
    ) -> None:
        self._snapshot_callbacks.append(callback)
        self._snapshot_timed_out = False
        thread = self._snapshot_thread
        if thread is not None and thread.isRunning():
            return

        local_nodes: list[str] = []
        for addr in self._dialog._nodes.get().keys():
            try:
                if self._dialog._nodes.is_local(addr):
                    local_nodes.append(addr)
            except Exception:
                continue

        db_file = str(Database.instance().get_db_file() or "").strip()
        in_memory_db = _is_memory_db_file(db_file)
        shared_memory_db = _is_shared_memory_db_file(db_file)
        self._pending_snapshot_db_file = db_file
        self._pending_snapshot_local_nodes = local_nodes
        self._pending_snapshot_in_memory_db = in_memory_db
        self._pending_snapshot_shared_memory_db = shared_memory_db
        db_mode, snapshot_mode = self._snapshot_db_mode(db_file)
        self._dialog._status_controller.debug(
            QC.translate(
                "stats",
                "Attached-rules snapshot DB mode: {0} ({1})",
            ).format(db_mode, snapshot_mode),
            origin="ui:attached-rules",
        )
        if self._snapshot_cache_dirty:
            self._dialog._status_controller.debug(
                QC.translate(
                    "stats",
                    "Attached-rules cache is dirty; forcing fresh snapshot.",
                ),
                origin="ui:attached-rules",
            )
        # Three DB modes:
        # 1) classic private in-memory -> no detached worker; use sync snapshot
        # 2) shared in-memory URI -> detached worker is safe
        # 3) file DB (path or file: URI) -> detached worker is safe
        if in_memory_db and not shared_memory_db:
            if not self._confirm_potential_snapshot_delay(
                estimated_rules=None,
                count_over_limit=False,
                in_memory_db=in_memory_db,
                shared_memory_db=shared_memory_db,
            ):
                snapshot = self._rules_index.snapshot()
                callbacks = self._snapshot_callbacks[:]
                self._snapshot_callbacks.clear()
                for pending_callback in callbacks:
                    pending_callback(snapshot)
                return
            snapshot = self._attached_rules_snapshot_sync()
            self._on_snapshot_worker_done(snapshot)
            return

        cached_rules_count = self._get_cached_rules_count(db_file, local_nodes)
        if cached_rules_count is None:
            self._snapshot_phase = "count"
            count_worker_cls = getattr(attached_rules_workers, "AttachedRulesCountWorker")
            count_worker = count_worker_cls(
                db_file=db_file,
                local_nodes=local_nodes,
            )
            self._start_stage_worker(
                worker=count_worker,
                done_signal_name="count_done",
                done_handler=self._on_rules_count_done,
                thread_name="AttachedRulesCountWorkerThread",
            )
            return

        cached_count, cached_over_limit = cached_rules_count
        self._pending_snapshot_count_over_limit = cached_over_limit
        self._continue_snapshot_after_count(cached_count)

    def _continue_snapshot_after_count(self, estimated_rules: int | None) -> None:
        if not self._confirm_potential_snapshot_delay(
            estimated_rules=estimated_rules,
            count_over_limit=self._pending_snapshot_count_over_limit,
            in_memory_db=self._pending_snapshot_in_memory_db,
            shared_memory_db=self._pending_snapshot_shared_memory_db,
        ):
            snapshot = self._rules_index.snapshot()
            callbacks = self._snapshot_callbacks[:]
            self._snapshot_callbacks.clear()
            for pending_callback in callbacks:
                pending_callback(snapshot)
            return

        self._pending_snapshot_row_count = estimated_rules if estimated_rules is not None else 0
        self._snapshot_timeout_timer.setInterval(self._snapshot_timeout_interval_ms())
        self._snapshot_timeout_timer.start()
        self._snapshot_phase = "fetch"
        fetch_worker_cls = getattr(attached_rules_workers, "AttachedRulesFetchWorker")
        fetch_worker = fetch_worker_cls(
            db_file=self._pending_snapshot_db_file,
            local_nodes=self._pending_snapshot_local_nodes,
        )
        self._start_stage_worker(
            worker=fetch_worker,
            done_signal_name="rows_done",
            done_handler=self._on_snapshot_rows_fetched,
            thread_name="AttachedRulesFetchWorkerThread",
        )

    def _on_rules_count_done(self, count_obj: object) -> None:
        db_file = self._pending_snapshot_db_file
        local_nodes = self._pending_snapshot_local_nodes
        count: int | None = None
        elapsed_ms: int | None = None
        over_limit = False
        if isinstance(count_obj, dict):
            raw_count = count_obj.get("count")
            raw_elapsed = count_obj.get("elapsed_ms")
            raw_over_limit = count_obj.get("over_limit")
            count = raw_count if isinstance(raw_count, int) else None
            elapsed_ms = raw_elapsed if isinstance(raw_elapsed, int) else None
            over_limit = bool(raw_over_limit)
        elif isinstance(count_obj, int):
            count = count_obj

        if elapsed_ms is not None:
            self._update_count_query_delay_factor(elapsed_ms)
            self._dialog._status_controller.debug(
                QC.translate(
                    "stats",
                    "Attached-rules count query: {0} ms (delay factor {1:.2f})",
                ).format(elapsed_ms, self._count_query_delay_factor),
                origin="ui:attached-rules",
            )
        self._pending_snapshot_count_over_limit = over_limit
        self._set_cached_rules_count(db_file, local_nodes, count, over_limit)
        self._continue_snapshot_after_count(count)

    def _on_snapshot_rows_fetched(self, rows_obj: object) -> None:
        rows: list = []
        if isinstance(rows_obj, dict):
            raw_rows = rows_obj.get("rows")
            raw_elapsed = rows_obj.get("elapsed_ms")
            raw_row_count = rows_obj.get("row_count")
            rows = raw_rows if isinstance(raw_rows, list) else []
            if isinstance(raw_elapsed, int):
                actual_count = raw_row_count if isinstance(raw_row_count, int) else len(rows)
                self._update_fetch_ms_per_row(raw_elapsed, actual_count)
                self._dialog._status_controller.debug(
                    QC.translate(
                        "stats",
                        "Attached-rules fetch: {0} ms for {1} rows ({2:.3f} ms/row EMA)",
                    ).format(raw_elapsed, actual_count, self._fetch_ms_per_row),
                    origin="ui:attached-rules",
                )
        elif isinstance(rows_obj, list):
            rows = rows_obj
        self._snapshot_phase = "process"
        process_worker_cls = getattr(attached_rules_workers, "AttachedRulesProcessWorker")
        process_worker = process_worker_cls(rows=rows)
        self._start_stage_worker(
            worker=process_worker,
            done_signal_name="snapshot_done",
            done_handler=self._on_snapshot_worker_done,
            thread_name="AttachedRulesSnapshotWorkerThread",
        )

    def show_attached_rules_dialog(self):
        rows = self._dialog._selection_controller.selected_rows()
        if len(rows) != 1:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select a single subscription row first."),
                error=True,
            )
            return

        row = rows[0]

        def _open_dialog(snapshot: dict[str, list[dict[str, Any]]]) -> None:
            if not self._dialog.isVisible():
                return

            def _get_attached_rules() -> list[dict[str, Any]]:
                from opensnitch.plugins.list_subscriptions._utils import (
                    DEFAULT_LISTS_DIR,
                    normalize_groups,
                    normalize_lists_dir,
                    safe_filename,
                )

                tdc = self._dialog._table_data_controller
                lists_dir = normalize_lists_dir(
                    self._dialog.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
                )
                filename = safe_filename(tdc.cell_text(row, tdc._col("filename")))
                list_type = (tdc.cell_text(row, tdc._col("format")) or "hosts").strip().lower()
                groups = normalize_groups(tdc.cell_text(row, tdc._col("group")))
                return self.aggregate_attached_rules(
                    tdc.rule_attachment_matches(
                        lists_dir,
                        filename,
                        list_type,
                        groups,
                        attached_rules_by_dir=snapshot,
                        include_disabled=True,
                    )
                )

            dlg = AttachedRulesDialog(
                self._dialog,
                get_attached_rules=_get_attached_rules,
                on_create_rule=self._dialog._rules_editor_controller.create_rule_from_selected,
                on_edit_rule=self.edit_attached_rule_entry,
                on_toggle_rule=self.toggle_attached_rule_entry,
                on_remove_rule=self.remove_attached_rule_entry,
            )
            dlg.exec()

        self._dialog._status_controller.set_status(
            QC.translate("stats", "Loading attached rules..."),
            error=False,
            log=False,
        )
        def _on_snapshot(snapshot: dict[str, list[dict[str, Any]]]) -> None:
            timed_out = self._snapshot_timed_out
            self._snapshot_timed_out = False
            if timed_out:
                if snapshot:
                    self._dialog._status_controller.set_status(
                        QC.translate(
                            "stats",
                            "Attached-rules lookup timed out; showing cached results.",
                        ),
                        error=True,
                        origin="ui:attached-rules",
                    )
                else:
                    self._dialog._status_controller.set_status(
                        QC.translate(
                            "stats",
                            "Attached-rules lookup timed out; showing no results.",
                        ),
                        error=True,
                        origin="ui:attached-rules",
                    )
            else:
                self._dialog._status_controller.set_status("", error=False, log=False)
            _open_dialog(snapshot)

        self.refresh_attached_rules_snapshot_async(_on_snapshot)

    def attached_rule_scope_parts(self, source: str):
        normalized = (source or "").strip()
        if normalized == "subscription":
            return "single", ""
        if normalized == "all":
            return "all", ""
        if normalized.startswith("group:"):
            return "group", normalized.split(":", 1)[1].strip()
        return normalized or "other", ""

    def aggregate_attached_rules(
        self,
        attached_rules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        aggregated: dict[tuple[str, str], dict[str, Any]] = {}
        for entry in attached_rules:
            addr = str(entry.get("addr", "")).strip()
            name = str(entry.get("name", "")).strip()
            if addr == "" or name == "":
                continue
            key = (addr, name)
            current = aggregated.get(key)
            if current is None:
                current = {
                    "addr": addr,
                    "name": name,
                    "enabled": bool(entry.get("enabled", True)),
                    "single": False,
                    "all": False,
                    "groups": set(),
                }
                aggregated[key] = current
            else:
                current["enabled"] = bool(entry.get("enabled", True))
            scope_kind, scope_value = self.attached_rule_scope_parts(
                str(entry.get("source", ""))
            )
            if scope_kind == "single":
                current["single"] = True
            elif scope_kind == "all":
                current["all"] = True
            elif scope_kind == "group" and scope_value != "":
                from typing import cast
                cast(set[str], current["groups"]).add(scope_value)
        aggregated_rows = list(aggregated.values())
        for entry in aggregated_rows:
            entry["groups"] = sorted(entry["groups"])
        aggregated_rows.sort(key=lambda item: (item["name"].lower(), item["addr"]))
        return aggregated_rows

    def rule_attachment_scope_summary(self, matches: list[dict[str, Any]]):
        has_single = False
        has_all = False
        groups: set[str] = set()
        other_sources: set[str] = set()

        for entry in matches:
            scope_kind, scope_value = self.attached_rule_scope_parts(
                str(entry.get("source", ""))
            )
            if scope_kind == "single":
                has_single = True
            elif scope_kind == "all":
                has_all = True
            elif scope_kind == "group" and scope_value != "":
                groups.add(scope_value)
            elif scope_kind != "":
                other_sources.add(scope_kind)

        parts: list[str] = []
        if has_single:
            parts.append(QC.translate("stats", "single"))
        if has_all:
            parts.append(QC.translate("stats", "all"))
        if groups:
            parts.append(
                QC.translate("stats", "groups: {0}").format(
                    ", ".join(sorted(groups))
                )
            )
        if other_sources:
            parts.extend(sorted(other_sources))
        return ", ".join(parts)

    def rule_entry_identity(self, entry: dict[str, Any]):
        addr = str(entry.get("addr", "")).strip()
        name = str(entry.get("name", "")).strip()
        if addr == "" or name == "":
            return None
        return addr, name

    def find_rule_record(self, addr: str, rule_name: str):
        records = self._dialog._nodes.get_rules(addr)
        if records is None or records == -1:
            return None

        while records.next():
            try:
                rule = cast(ui_pb2.Rule, Rule.new_from_records(records))
            except Exception:
                continue
            if str(rule.name or "").strip() == rule_name:
                return records
        return None

    def edit_attached_rule_entry(self, entry: dict[str, Any]):
        identity = self.rule_entry_identity(entry)
        if identity is None:
            return
        addr, name = identity
        self.open_attached_rule_in_editor(addr, name)

    def toggle_attached_rule_entry(self, entry: dict[str, Any]):
        identity = self.rule_entry_identity(entry)
        if identity is None:
            return
        addr, name = identity
        records = self.find_rule_record(addr, name)
        if records is None:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Rule not found: {0}").format(name),
                error=True,
            )
            return

        try:
            rule = cast(ui_pb2.Rule, Rule.new_from_records(records))
        except Exception:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Failed to load rule: {0}").format(name),
                error=True,
            )
            return

        if bool(getattr(rule, "enabled", True)):
            self._dialog._nodes.disable_rule(addr, name)
            self.update_cached_rule_enabled(addr, name, False)
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Rule updated: {0} disabled").format(name),
                error=False,
            )
        else:
            rule.enabled = True
            self._dialog._nodes.add_rules(addr, [rule])
            self._dialog._nodes.send_notification(
                addr,
                ui_pb2.Notification(
                    type=ui_pb2.CHANGE_RULE,
                    rules=[rule],
                ),
                None,
            )
            self.update_cached_rule_enabled(addr, name, True)
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Rule updated: {0} enabled").format(name),
                error=False,
            )

        self._dialog._table_data_controller.refresh_states()

    def remove_attached_rule_entry(self, entry: dict[str, Any]):
        identity = self.rule_entry_identity(entry)
        if identity is None:
            return
        addr, name = identity
        confirmed = QtWidgets.QMessageBox.question(
            self._dialog,
            QC.translate("stats", "Remove rule"),
            QC.translate(
                "stats",
                "Remove rule '{0}' on node {1}? This action cannot be undone.",
            ).format(name, addr),
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        if confirmed != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        nid, _noti = self._dialog._nodes.delete_rule(name, addr, None)
        if nid is None:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Failed to remove rule: {0}").format(name),
                error=True,
            )
            return

        self.remove_cached_rule(addr, name)
        self._dialog._table_data_controller.refresh_states()
        self._dialog._status_controller.set_status(
            QC.translate("stats", "Rule deleted: {0}").format(name),
            error=False,
        )

    def open_attached_rule_in_editor(self, addr: str, rule_name: str):
        records = self.find_rule_record(addr, rule_name)
        if records is None:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Rule not found: {0}").format(rule_name),
                error=True,
            )
            return

        rules_dialog = self._dialog._rules_editor_controller.ensure_rules_dialog()
        if rules_dialog is None:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Rules editor is not available."),
                error=True,
            )
            return

        rules_dialog.edit_rule(records, _addr=addr)
        self._dialog._table_data_controller.refresh_states()
