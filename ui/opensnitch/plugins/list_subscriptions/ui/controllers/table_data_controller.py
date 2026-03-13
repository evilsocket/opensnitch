import json
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import requests

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtGui, QtWidgets, QC
from opensnitch.plugins.list_subscriptions.models.subscriptions import (
    MutableSubscriptionSpec,
    SubscriptionSpec,
)
from opensnitch.plugins.list_subscriptions.models.events import (
    SubscriptionEventPayload,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.table_widgets import (
    SortableTableWidgetItem,
)
from opensnitch.plugins.list_subscriptions.ui.workers import (
    SubscriptionStateRefreshWorker,
)
from opensnitch.plugins.list_subscriptions._utils import (
    DEFAULT_LISTS_DIR,
    INTERVAL_UNITS,
    SIZE_UNITS,
    TIMEOUT_UNITS,
    derive_filename,
    display_str,
    ensure_filename_type_suffix,
    filename_from_content_disposition,
    list_file_path,
    normalize_groups,
    normalize_lists_dir,
    safe_filename,
    strip_or_none,
    subscription_rule_dir,
    timestamp_sort_key,
)

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


ATTACHED_RULES_REFRESH_INTERVAL_MS = 2_000


class TableDataController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns
        self._poll_timer = QtCore.QTimer(dialog)
        self._poll_timer.setInterval(2000)
        self._poll_timer.timeout.connect(
            lambda: dialog.isVisible()
            and dialog.isActiveWindow()
            and (not dialog._loading)
            and self.refresh_attached_rules_only()
        )
        self._refresh_generation = 0
        self._refresh_worker: SubscriptionStateRefreshWorker | None = None
        self._refresh_thread: QtCore.QThread | None = None
        self._refresh_stopped_callbacks: list[Callable[[], None]] = []
        self._pending_refresh_job: dict[str, Any] | None = None
        self._pending_attached_rules_refresh = False
        self._last_attached_rules_refresh_ms = 0
        self._shutting_down = False
        dialog.destroyed.connect(self._on_dialog_destroyed)
        app = QtCore.QCoreApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._on_app_about_to_quit)

    def start_poll(self):
        if self._shutting_down:
            return
        if not self._poll_timer.isActive():
            self._poll_timer.start()

    def stop_poll(self):
        if self._poll_timer.isActive():
            self._poll_timer.stop()

    def pause_for_focus_loss(self):
        self.stop_poll()
        self.cancel_active_refresh()

    def resume_for_focus_gain(self):
        if self._dialog.isVisible() and not self._dialog._loading:
            self.start_poll()

    def _on_dialog_destroyed(self, *_args):
        self.shutdown_refresh_worker(wait_ms=3000)

    def _on_app_about_to_quit(self):
        self.shutdown_refresh_worker(wait_ms=3000)

    def has_active_refresh(self) -> bool:
        thread = self._refresh_thread
        return bool(thread is not None and thread.isRunning())

    def on_refresh_stopped(self, callback: Callable[[], None]) -> None:
        if not self.has_active_refresh():
            callback()
            return
        self._refresh_stopped_callbacks.append(callback)

    def cancel_active_refresh(self):
        worker = self._refresh_worker
        thread = self._refresh_thread
        if worker is None or thread is None or not thread.isRunning():
            return
        worker.stop()
        thread.quit()

    def wait_for_active_refresh_stop(self, wait_ms: int = 1200) -> bool:
        worker = self._refresh_worker
        thread = self._refresh_thread
        if worker is None or thread is None:
            return True
        if not thread.isRunning():
            self._refresh_worker = None
            self._refresh_thread = None
            return True

        worker.stop()
        thread.quit()
        if wait_ms <= 0:
            stopped = thread.wait()
        else:
            stopped = thread.wait(wait_ms)
        if stopped:
            self._refresh_worker = None
            self._refresh_thread = None
        return bool(stopped)

    def shutdown_refresh_worker(self, wait_ms: int = 2000) -> bool:
        self._shutting_down = True
        self._pending_refresh_job = None
        self._refresh_generation += 1

        worker = self._refresh_worker
        thread = self._refresh_thread
        if worker is None or thread is None:
            self._refresh_worker = None
            self._refresh_thread = None
            return True

        try:
            worker.refresh_done.disconnect(self._on_state_refresh_worker_finished)
        except Exception:
            pass

        if thread.isRunning():
            worker.stop()
            thread.quit()
            if wait_ms <= 0:
                thread.wait()
            else:
                thread.wait(wait_ms)
        if thread.isRunning():
            thread.terminate()
            thread.wait(500)

        if thread.isRunning():
            self._refresh_worker = worker
            self._refresh_thread = thread
            return False

        self._refresh_worker = None
        self._refresh_thread = None
        return True

    # -- Shared primitives -------------------------------------------------
    def _col(self, key: str):
        return self._cols[key]

    def new_enabled_item(self, enabled: bool) -> SortableTableWidgetItem:
        item = SortableTableWidgetItem("")
        item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(
            QtCore.Qt.CheckState.Checked if enabled else QtCore.Qt.CheckState.Unchecked
        )
        item.setData(QtCore.Qt.ItemDataRole.UserRole, 1 if enabled else 0)
        return item

    def update_row_sort_keys(self, row: int):
        enabled_item = self._dialog.table.item(row, self._col("enabled"))
        if enabled_item is None:
            return
        enabled_rank = (
            0 if enabled_item.checkState() == QtCore.Qt.CheckState.Checked else 1
        )
        enabled_item.setData(QtCore.Qt.ItemDataRole.UserRole, enabled_rank)

    def sort_key_for_column(self, col: int, text: str):
        value = (text or "").strip()
        if col in (
            self._col("interval"),
            self._col("timeout"),
            self._col("max_size"),
        ):
            if value == "":
                return -1
            try:
                return int(value)
            except Exception:
                return value.lower()
        if col in (self._col("last_checked"), self._col("last_updated")):
            return timestamp_sort_key(value)
        if col == self._col("state"):
            normalized = (value or "").strip().lower()
            if normalized in ("updated", "not_modified"):
                return 0, normalized
            if normalized == "pending":
                return 1, normalized
            return 2, normalized
        return value.lower()

    def state_text_color(self, state: str):
        palette = self._dialog.table.palette()
        dark_theme = palette.base().color().lightness() < 128

        if dark_theme:
            colors = {
                "disabled": "#B8C0CC",
                "pending": "#F5D76E",
                "busy": "#F5D76E",
                "missing": "#FF8A80",
                "updated": "#7CE3A1",
                "not_modified": "#86C5FF",
                "error": "#FF8A80",
                "write_error": "#FF8A80",
                "request_error": "#FF8A80",
                "unexpected_error": "#FF8A80",
                "bad_format": "#FF8A80",
                "too_large": "#FF8A80",
                "other": "#F7E37A",
            }
        else:
            colors = {
                "disabled": "#6B7280",
                "pending": "#9A6700",
                "busy": "#9A6700",
                "missing": "#C62828",
                "updated": "#0F8A4B",
                "not_modified": "#1565C0",
                "error": "#C62828",
                "write_error": "#C62828",
                "request_error": "#C62828",
                "unexpected_error": "#C62828",
                "bad_format": "#C62828",
                "too_large": "#C62828",
                "other": "#8D6E00",
            }

        return QtGui.QColor(colors.get(state, colors["other"]))

    def status_log_level_color(self, level: str) -> str:
        normalized = (level or "").strip().upper()
        if normalized in ("TRACE",):
            return self.state_text_color("disabled").name()
        if normalized in ("DEBUG",):
            return self.state_text_color("other").name()
        if normalized in ("INFO",):
            return self.state_text_color("not_modified").name()
        if normalized in ("SUCCESS",):
            return self.state_text_color("updated").name()
        if normalized == "ERROR":
            return self.state_text_color("error").name()
        if normalized in ("WARN", "WARNING"):
            return self.state_text_color("pending").name()
        return self.state_text_color("not_modified").name()

    # -- Table interaction -------------------------------------------------
    def handle_table_clicked(self, index: QtCore.QModelIndex):
        if not index.isValid() or index.column() != self._col("enabled"):
            return
        item = self._dialog.table.item(index.row(), self._col("enabled"))
        if item is None:
            return
        checked = item.checkState() != QtCore.Qt.CheckState.Checked
        item.setCheckState(
            QtCore.Qt.CheckState.Checked if checked else QtCore.Qt.CheckState.Unchecked
        )
        self.update_row_sort_keys(index.row())
        self._dialog._table_view_controller.apply_table_view_mode()

    # -- Runtime refresh helpers ------------------------------------------
    def _find_runtime_subscription(self, plug: Any, url: str, filename: str):
        try:
            for sub in plug._config.subscriptions:
                if sub.url == url and sub.filename == filename:
                    return sub
        except Exception:
            return None
        return None

    def _build_subscription_from_row(
        self,
        *,
        plug: Any,
        row: int,
        enabled_from_row: bool,
    ):
        try:
            interval_ok, interval_val = self.optional_int_from_text(
                self.cell_text(row, self._col("interval")),
                "Interval",
                row=row,
            )
            timeout_ok, timeout_val = self.optional_int_from_text(
                self.cell_text(row, self._col("timeout")),
                "Timeout",
                row=row,
            )
            max_size_ok, max_size_val = self.optional_int_from_text(
                self.cell_text(row, self._col("max_size")),
                "Max size",
                row=row,
            )
            if not interval_ok or not timeout_ok or not max_size_ok:
                return None

            enabled = True
            if enabled_from_row:
                enabled_item = self._dialog.table.item(row, self._col("enabled"))
                enabled = (
                    enabled_item is None
                    or enabled_item.checkState() == QtCore.Qt.CheckState.Checked
                )

            row_sub_edit = MutableSubscriptionSpec(
                enabled=enabled,
                name=self.cell_text(row, self._col("name")),
                url=self.cell_text(row, self._col("url")),
                filename=self.cell_text(row, self._col("filename")),
                format=self.cell_text(row, self._col("format")) or "hosts",
                groups=normalize_groups(self.cell_text(row, self._col("group"))),
                interval=interval_val,
                interval_units=strip_or_none(
                    self.cell_text(row, self._col("interval_units"))
                ),
                timeout=timeout_val,
                timeout_units=strip_or_none(
                    self.cell_text(row, self._col("timeout_units"))
                ),
                max_size=max_size_val,
                max_size_units=strip_or_none(
                    self.cell_text(row, self._col("max_size_units"))
                ),
            )
            return SubscriptionSpec.from_dict(
                row_sub_edit.to_dict(),
                plug._config.defaults,
            )
        except Exception:
            return None

    def _resolve_target_subscription(
        self,
        *,
        plug: Any,
        row: int,
        enabled_from_row: bool,
    ):
        url = self.cell_text(row, self._col("url"))
        filename = self.cell_text(row, self._col("filename"))
        target_sub = self._find_runtime_subscription(plug, url, filename)
        if target_sub is not None:
            return target_sub
        return self._build_subscription_from_row(
            plug=plug,
            row=row,
            enabled_from_row=enabled_from_row,
        )

    # -- Runtime refresh actions ------------------------------------------
    def refresh_selected_now(self):
        rows = self._dialog._selection_controller.selected_rows()
        if not rows:
            row = self._dialog.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select one or more subscription rows first."),
                error=True,
            )
            return

        loaded = self._dialog._runtime_controller.find_loaded_action()
        _, _, plug = loaded if loaded is not None else (None, None, None)
        if plug is None:
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats", "Plugin is not loaded. Save configuration first."
                ),
                error=True,
            )
            return

        refresh_targets: list[tuple[SubscriptionSpec, str]] = []
        filename_changed = False
        for row in rows:
            url = self.cell_text(row, self._col("url"))
            filename, row_filename_changed = self.ensure_row_final_filename(row)
            if url == "" or filename == "":
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats", "URL and filename cannot be empty (row {0})."
                    ).format(row + 1),
                    error=True,
                )
                return
            filename_changed = filename_changed or row_filename_changed

        if filename_changed:
            self._dialog._action_file_controller.save_action_file()

        for row in rows:
            target_sub = self._resolve_target_subscription(
                plug=plug,
                row=row,
                enabled_from_row=False,
            )
            if target_sub is None:
                self._dialog._status_controller.set_status(
                    QC.translate("stats", "Internal error: target_sub is None."),
                    error=True,
                )
                return
            list_path, _ = plug._paths(target_sub)
            refresh_targets.append((target_sub, list_path))

        refresh_keys = {plug._sub_key(target_sub) for target_sub, _ in refresh_targets}
        self._dialog._runtime_controller.track_refresh_keys(refresh_keys)
        self._dialog._status_controller.append_log(
            QC.translate(
                "stats", "Manual refresh requested for {0} selected subscription(s)."
            ).format(len(refresh_targets)),
        )
        plug.signal_in.emit(
            {
                "plugin": plug.get_name(),
                "signal": plug.REFRESH_SUBSCRIPTIONS_SIGNAL,
                "action_path": self._dialog._action_path,
                "source": "manual_refresh",
                "items": [
                    SubscriptionEventPayload(
                        enabled=target_sub.enabled,
                        name=target_sub.name,
                        url=target_sub.url,
                        filename=target_sub.filename,
                        format=target_sub.format,
                        groups=list(target_sub.groups),
                        interval=target_sub.interval,
                        interval_units=target_sub.interval_units,
                        timeout=target_sub.timeout,
                        timeout_units=target_sub.timeout_units,
                        max_size=target_sub.max_size,
                        max_size_units=target_sub.max_size_units,
                    )
                    for target_sub, _ in refresh_targets
                ],
            }
        )
        if len(refresh_targets) == 1:
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats", "Subscription refresh triggered. Destination: {0}"
                ).format(refresh_targets[0][1]),
                error=False,
            )
            return

        self._dialog._status_controller.set_status(
            QC.translate(
                "stats", "Bulk refresh triggered for {0} selected subscriptions."
            ).format(len(refresh_targets)),
            error=False,
        )

    def refresh_all_now(self):
        loaded = self._dialog._runtime_controller.find_loaded_action()
        _, _, plug = loaded if loaded is not None else (None, None, None)
        if plug is None:
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats", "Plugin is not loaded. Save configuration first."
                ),
                error=True,
            )
            return

        rows = list(range(self._dialog.table.rowCount()))
        if not rows:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "No subscriptions available to refresh."),
                error=True,
            )
            return

        filename_changed = False
        for row in rows:
            url = self.cell_text(row, self._col("url"))
            filename, row_filename_changed = self.ensure_row_final_filename(row)
            if url == "" or filename == "":
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats", "URL and filename cannot be empty (row {0})."
                    ).format(row + 1),
                    error=True,
                )
                return
            filename_changed = filename_changed or row_filename_changed

        if filename_changed:
            self._dialog._action_file_controller.save_action_file()
            loaded = self._dialog._runtime_controller.find_loaded_action()
            _, _, plug = loaded if loaded is not None else (None, None, None)
            if plug is None:
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats", "Plugin is not loaded. Save configuration first."
                    ),
                    error=True,
                )
                return

        refresh_targets: list[SubscriptionSpec] = []
        for row in rows:
            target_sub = self._resolve_target_subscription(
                plug=plug,
                row=row,
                enabled_from_row=True,
            )
            if target_sub is not None:
                refresh_targets.append(target_sub)

        if not refresh_targets:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "No subscriptions available to refresh."),
                error=True,
            )
            return

        refresh_keys = {plug._sub_key(sub) for sub in refresh_targets}
        self._dialog._runtime_controller.track_refresh_keys(refresh_keys)
        self._dialog._status_controller.append_log(
            QC.translate(
                "stats", "Manual refresh requested for all listed subscriptions ({0})."
            ).format(len(refresh_targets)),
        )
        plug.signal_in.emit(
            {
                "plugin": plug.get_name(),
                "signal": plug.REFRESH_SUBSCRIPTIONS_SIGNAL,
                "action_path": self._dialog._action_path,
                "source": "manual_refresh",
                "items": [
                    SubscriptionEventPayload(
                        enabled=sub.enabled,
                        name=sub.name,
                        url=sub.url,
                        filename=sub.filename,
                        format=sub.format,
                        groups=list(sub.groups),
                        interval=sub.interval,
                        interval_units=sub.interval_units,
                        timeout=sub.timeout,
                        timeout_units=sub.timeout_units,
                        max_size=sub.max_size,
                        max_size_units=sub.max_size_units,
                    )
                    for sub in refresh_targets
                ],
            }
        )
        self._dialog._status_controller.set_status(
            QC.translate(
                "stats", "Bulk refresh triggered for all listed subscriptions."
            ),
            error=False,
        )

    # -- Subscription data collection -------------------------------------
    def collect_subscriptions(self):
        out: list[MutableSubscriptionSpec] = []
        auto_filled = 0
        for row in range(self._dialog.table.rowCount()):
            enabled_item = self._dialog.table.item(row, self._col("enabled"))
            interval = self.cell_text(row, self._col("interval"))
            interval_units = self.cell_text(row, self._col("interval_units"))
            timeout = self.cell_text(row, self._col("timeout"))
            timeout_units = self.cell_text(row, self._col("timeout_units"))
            max_size = self.cell_text(row, self._col("max_size"))
            max_size_units = self.cell_text(row, self._col("max_size_units"))
            name = self.cell_text(row, self._col("name"))
            url = self.cell_text(row, self._col("url"))
            list_type = (
                self.cell_text(row, self._col("format")) or "hosts"
            ).strip().lower()
            groups = normalize_groups(self.cell_text(row, self._col("group")))
            filename = safe_filename(self.cell_text(row, self._col("filename")))
            if filename == "":
                filename = self.guess_filename(name, url)
                if filename != "":
                    auto_filled += 1
            filename = ensure_filename_type_suffix(filename, list_type)
            self.set_text_item(row, self._col("filename"), filename)
            interval_ok, interval_val = self.optional_int_from_text(
                interval, "Interval", row=row
            )
            timeout_ok, timeout_val = self.optional_int_from_text(
                timeout, "Timeout", row=row
            )
            max_size_ok, max_size_val = self.optional_int_from_text(
                max_size, "Max size", row=row
            )
            if not interval_ok or not timeout_ok or not max_size_ok:
                return None
            sub = MutableSubscriptionSpec(
                enabled=enabled_item is not None
                and enabled_item.checkState() == QtCore.Qt.CheckState.Checked,
                name=name,
                url=url,
                filename=filename,
                format=list_type,
                groups=groups,
                interval=interval_val,
                interval_units=strip_or_none(interval_units),
                timeout=timeout_val,
                timeout_units=strip_or_none(timeout_units),
                max_size=max_size_val,
                max_size_units=strip_or_none(max_size_units),
            )
            if sub.url == "" or sub.filename == "":
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats", "URL and filename cannot be empty (row {0})."
                    ).format(row + 1),
                    error=True,
                )
                return None
            out.append(sub)

        if auto_filled > 0:
            self._dialog._status_controller.append_log(
                QC.translate(
                    "stats", "Auto-filled filename for {0} subscription(s)."
                ).format(auto_filled),
                level="WARN",
            )
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats", "Auto-filled filename for {0} subscription(s)."
                ).format(auto_filled),
                error=False,
            )
        return out

    # -- Filename derivation and normalization ----------------------------
    def guess_filename(self, name: str, url: str):
        from_header = self.filename_from_headers(url)
        return safe_filename(derive_filename(name, url, "", from_header))

    def filename_from_headers(self, url: str):
        if (url or "").strip() == "":
            return ""
        try:
            r = requests.head(url, allow_redirects=True, timeout=5)
            cd = r.headers.get("Content-Disposition", "")
            if cd:
                return filename_from_content_disposition(cd)
        except Exception:
            return ""
        return ""

    def ensure_row_final_filename(self, row: int):
        name = self.cell_text(row, self._col("name"))
        url = self.cell_text(row, self._col("url"))
        list_type = (
            self.cell_text(row, self._col("format")) or "hosts"
        ).strip().lower()
        original = safe_filename(self.cell_text(row, self._col("filename")))
        final_name = original
        changed = False

        if final_name == "":
            final_name = self.guess_filename(name, url)
            changed = final_name != ""
        final_name = ensure_filename_type_suffix(final_name, list_type)
        if final_name != original:
            changed = True

        if final_name != "":
            key = final_name
            existing: set[str] = set()
            for i in range(self._dialog.table.rowCount()):
                if i == row:
                    continue
                other = safe_filename(self.cell_text(i, self._col("filename")))
                if other != "":
                    existing.add(other)
            if key in existing:
                base, ext = os.path.splitext(final_name)
                n = 2
                candidate = final_name
                while candidate in existing:
                    suffix = f"-{n}"
                    candidate = f"{base}{suffix}{ext}" if ext else f"{base}{suffix}"
                    n += 1
                final_name = candidate
                changed = True

        if changed:
            self.set_text_item(row, self._col("filename"), final_name)
        return final_name, changed

    # -- Row state and metadata -------------------------------------------
    def row_meta_snapshot(self, row: int):
        lists_dir = normalize_lists_dir(
            self._dialog.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        filename = safe_filename(self.cell_text(row, self._col("filename")))
        list_type = (
            self.cell_text(row, self._col("format")) or "hosts"
        ).strip().lower()
        current_rule_attached = (
            self.cell_text(row, self._col("rule_attached")) or "no"
        ).strip().lower()
        if current_rule_attached not in ("yes", "no"):
            current_rule_attached = "no"
        list_path = list_file_path(lists_dir, filename, list_type)
        meta_path = list_path + ".meta.json"

        file_exists = os.path.exists(list_path)
        meta_exists = os.path.exists(meta_path)
        meta: dict[str, Any] = {}
        if meta_exists:
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                meta = {}

        return {
            "file_present": "yes" if file_exists else "no",
            "meta_present": "yes" if meta_exists else "no",
            "state": str(
                meta.get(
                    "last_result",
                    self.cell_text(row, self._col("state")) or "never",
                )
            ),
            "rule_attached": current_rule_attached,
            "rule_attached_detail": current_rule_attached,
            "last_checked": str(
                meta.get(
                    "last_checked",
                    self.cell_text(row, self._col("last_checked")) or "",
                )
            ),
            "last_updated": str(
                meta.get(
                    "last_updated",
                    self.cell_text(row, self._col("last_updated")) or "",
                )
            ),
            "failures": str(meta.get("fail_count", "0")),
            "error": str(meta.get("last_error", "")),
            "list_path": list_path,
            "meta_path": meta_path,
        }

    def apply_url_error_indicator(
        self,
        row: int,
        *,
        enabled: bool,
        state: str,
        last_error: str,
    ):
        url_item = self._dialog.table.item(row, self._col("url"))
        if url_item is None:
            return

        normalized_state = (state or "").strip().lower()
        has_error = enabled and (
            normalized_state
            in {
                "missing",
                "error",
                "write_error",
                "request_error",
                "unexpected_error",
                "bad_format",
                "too_large",
            }
            or (last_error or "").strip() != ""
        )

        if not has_error:
            url_item.setIcon(QtGui.QIcon())
            url_item.setToolTip(url_item.text())
            url_item.setForeground(
                self._dialog.table.palette().brush(QtGui.QPalette.ColorRole.Text)
            )
            return

        style = self._dialog.table.style()
        if style is not None:
            url_item.setIcon(
                style.standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MessageBoxWarning)
            )
        if (last_error or "").strip() != "":
            url_item.setToolTip(
                QC.translate("stats", "Subscription error: {0}").format(last_error)
            )
        else:
            url_item.setToolTip(
                QC.translate("stats", "Subscription error state: {0}").format(
                    normalized_state
                )
            )
        url_item.setForeground(QtGui.QBrush(self.state_text_color("other")))

    def refresh_states(self):
        if self._shutting_down:
            return
        if self._refresh_thread is not None and self._refresh_thread.isRunning():
            # Worker already running: defer the next refresh request without
            # recomputing expensive snapshots on the UI thread.
            self._pending_refresh_job = {"deferred": True}
            return
        lists_dir = normalize_lists_dir(
            self._dialog.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        rows: list[dict[str, Any]] = []
        for row in range(self._dialog.table.rowCount()):
            filename_item = self._dialog.table.item(row, self._col("filename"))
            enabled_item = self._dialog.table.item(row, self._col("enabled"))
            if filename_item is None or enabled_item is None:
                continue
            rows.append(
                {
                    "row": row,
                    "url": self.cell_text(row, self._col("url")),
                    "filename": safe_filename(filename_item.text()),
                    "list_type": (self.cell_text(row, self._col("format")) or "hosts")
                    .strip()
                    .lower(),
                    "enabled": enabled_item.checkState()
                    == QtCore.Qt.CheckState.Checked,
                    "groups": normalize_groups(self.cell_text(row, self._col("group"))),
                }
            )

        self._refresh_generation += 1
        job = {
            "generation": self._refresh_generation,
            "lists_dir": lists_dir,
            "rows": rows,
            # Attached-rules snapshot is intentionally omitted in background
            # refresh jobs to avoid automatic DB scans on the UI path.
            "attached_rules_by_dir": {},
        }

        self._start_state_refresh_worker(job)

    def refresh_attached_rules_only(self):
        # Attached-rules DB scan is on-demand only (explicit user action)
        # to avoid blocking UI/daemon during background polling.
        return

    def _start_state_refresh_worker(self, job: dict[str, Any]):
        if self._shutting_down:
            return
        self._pending_refresh_job = None
        thread = QtCore.QThread(self._dialog)
        thread.setObjectName("SubscriptionStateRefreshWorkerThread")
        worker = SubscriptionStateRefreshWorker(
            generation=int(job["generation"]),
            lists_dir=str(job["lists_dir"]),
            rows=list(job["rows"]),
            attached_rules_by_dir=dict(job["attached_rules_by_dir"]),
        )
        worker.setObjectName("SubscriptionStateRefreshWorker")
        worker.moveToThread(thread)
        self._refresh_worker = worker
        self._refresh_thread = thread
        thread.started.connect(worker.run)
        worker.refresh_done.connect(self._on_state_refresh_worker_finished)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_state_refresh_worker_stopped)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    def _on_state_refresh_worker_stopped(self) -> None:
        self._refresh_worker = None
        self._refresh_thread = None
        callbacks = self._refresh_stopped_callbacks[:]
        self._refresh_stopped_callbacks.clear()
        for callback in callbacks:
            callback()
        if not self._shutting_down and self._pending_refresh_job is not None:
            job = self._pending_refresh_job
            self._pending_refresh_job = None
            if bool(job.get("deferred")):
                self.refresh_states()
                return
            self._start_state_refresh_worker(job)
            return
        if not self._shutting_down and self._pending_attached_rules_refresh:
            self._pending_attached_rules_refresh = False
            self.refresh_attached_rules_only()

    def _on_state_refresh_worker_finished(
        self,
        generation: int,
        results: list[dict[str, Any]],
    ):
        if self._shutting_down:
            return

        if generation != self._refresh_generation:
            return

        result_by_row: dict[int, dict[str, Any]] = {
            int(item.get("row", -1)): item for item in results
        }

        with self._dialog._table_view_controller.sorting_suspended():
            for row in range(self._dialog.table.rowCount()):
                result = result_by_row.get(row)
                if result is None:
                    continue

                enabled = bool(result.get("enabled", True))
                state = str(result.get("state", ""))
                last_error = str(result.get("error", ""))
                rule_attached = str(result.get("rule_attached", "no"))
                last_checked = str(result.get("last_checked", ""))
                last_updated = str(result.get("last_updated", ""))
                attachment_matches = list(result.get("attachment_matches", []))
                rule_attached_detail = self.rule_attachment_detail(attachment_matches)

                fg_color = self.state_text_color(state if state != "" else "other")

                self.set_text_item(
                    row,
                    self._col("file"),
                    str(result.get("file_present", "no")),
                    editable=False,
                )
                self.set_text_item(
                    row,
                    self._col("meta"),
                    str(result.get("meta_present", "no")),
                    editable=False,
                )
                self.set_text_item(row, self._col("state"), state, editable=False)
                self.set_text_item(
                    row,
                    self._col("rule_attached"),
                    rule_attached,
                    editable=False,
                )
                self.set_text_item(
                    row,
                    self._col("last_checked"),
                    last_checked,
                    editable=False,
                )
                self.set_text_item(
                    row,
                    self._col("last_updated"),
                    last_updated,
                    editable=False,
                )
                self.apply_url_error_indicator(
                    row,
                    enabled=enabled,
                    state=state,
                    last_error=last_error,
                )

                for col in (
                    self._col("file"),
                    self._col("meta"),
                    self._col("state"),
                    self._col("rule_attached"),
                    self._col("last_checked"),
                    self._col("last_updated"),
                ):
                    item = self._dialog.table.item(row, col)
                    if item is not None:
                        item.setForeground(fg_color)

                self.update_row_sort_keys(row)
                self._dialog.subscription_state_refreshed.emit(
                    str(result.get("url", "")),
                    str(result.get("filename", "")),
                    {
                        "file_present": str(result.get("file_present", "no")),
                        "meta_present": str(result.get("meta_present", "no")),
                        "state": state,
                        "rule_attached": rule_attached,
                        "rule_attached_detail": rule_attached_detail,
                        "last_checked": last_checked,
                        "last_updated": last_updated,
                        "failures": str(result.get("failures", "0")),
                        "error": last_error,
                        "list_path": str(result.get("list_path", "")),
                        "meta_path": str(result.get("meta_path", "")),
                    },
                )

    def rule_attachment_matches(
        self,
        lists_dir: str,
        filename: str,
        list_type: str,
        groups: list[str],
        *,
        attached_rules_by_dir: dict[str, list[dict[str, Any]]] | None = None,
        include_disabled: bool = False,
    ):
        snapshot = (
            attached_rules_by_dir
            if attached_rules_by_dir is not None
            else self._dialog._rules_attachment_controller.attached_rules_snapshot()
        )
        rules_root = os.path.join(lists_dir, "rules.list.d")
        candidate_dirs = [
            (
                "subscription",
                os.path.normpath(subscription_rule_dir(lists_dir, filename, list_type)),
            ),
            ("all", os.path.normpath(os.path.join(rules_root, "all"))),
        ]
        candidate_dirs.extend(
            (f"group:{group}", os.path.normpath(os.path.join(rules_root, group)))
            for group in groups
        )

        matches: list[dict[str, Any]] = []
        seen_match: set[tuple[str, str, str]] = set()
        for source, directory in candidate_dirs:
            for rule_entry in snapshot.get(directory, []):
                addr = str(rule_entry.get("addr", "")).strip()
                name = str(rule_entry.get("name", "")).strip()
                enabled = bool(rule_entry.get("enabled", True))
                if addr == "" or name == "":
                    continue
                if not include_disabled and not enabled:
                    continue
                key = (addr, name, source)
                if key in seen_match:
                    continue
                seen_match.add(key)
                matches.append(
                    {
                        "addr": addr,
                        "name": name,
                        "enabled": enabled,
                        "source": source,
                        "directory": directory,
                    }
                )

        matches.sort(
            key=lambda item: (item["name"].lower(), item["addr"], item["source"])
        )
        return matches

    def rule_attachment_detail(self, matches: list[dict[str, Any]]):
        if not matches:
            return "no"

        unique_rules = {(entry["addr"], entry["name"]) for entry in matches}
        sources_text = (
            self._dialog._rules_attachment_controller.rule_attachment_scope_summary(
                matches
            )
        )
        return QC.translate("stats", "yes ({0} rules via {1})").format(
            len(unique_rules),
            sources_text,
        )

    def rule_attached_value(
        self,
        lists_dir: str,
        filename: str,
        list_type: str,
        groups: list[str],
        *,
        attached_rules_by_dir: dict[str, list[dict[str, Any]]] | None = None,
    ):
        matches = self.rule_attachment_matches(
            lists_dir,
            filename,
            list_type,
            groups,
            attached_rules_by_dir=attached_rules_by_dir,
        )
        return "yes" if matches else "no"

    def attached_rules_for_row(
        self,
        row: int,
        *,
        include_disabled: bool = False,
    ):
        lists_dir = normalize_lists_dir(
            self._dialog.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        filename = safe_filename(self.cell_text(row, self._col("filename")))
        list_type = (
            self.cell_text(row, self._col("format")) or "hosts"
        ).strip().lower()
        groups = normalize_groups(self.cell_text(row, self._col("group")))
        return self.rule_attachment_matches(
            lists_dir,
            filename,
            list_type,
            groups,
            include_disabled=include_disabled,
        )

    # -- Row creation and cell access -------------------------------------
    def append_row(self, sub: MutableSubscriptionSpec):
        row = self._dialog.table.rowCount()
        self._dialog.table.insertRow(row)
        enabled_item = self.new_enabled_item(bool(sub.enabled))
        self._dialog.table.setItem(row, self._col("enabled"), enabled_item)

        self.set_text_item(row, self._col("name"), str(sub.name))
        self.set_text_item(row, self._col("url"), str(sub.url))
        self.set_text_item(row, self._col("filename"), safe_filename(sub.filename))
        self.set_text_item(row, self._col("format"), str(sub.format))
        groups = normalize_groups(sub.groups)
        self.set_text_item(row, self._col("group"), ", ".join(groups))
        interval = sub.interval
        timeout = sub.timeout
        max_size = sub.max_size
        interval_units = sub.interval_units
        timeout_units = sub.timeout_units
        max_size_units = sub.max_size_units
        self.set_text_item(row, self._col("interval"), display_str(interval))
        self.set_text_item(
            row,
            self._col("interval_units"),
            display_str(interval_units),
        )
        self.set_text_item(row, self._col("timeout"), display_str(timeout))
        self.set_text_item(row, self._col("timeout_units"), display_str(timeout_units))
        self.set_text_item(row, self._col("max_size"), display_str(max_size))
        self.set_text_item(
            row,
            self._col("max_size_units"),
            display_str(max_size_units),
        )
        self._dialog._defaults_ui_controller.set_units_combo(
            row,
            self._col("interval_units"),
            INTERVAL_UNITS,
            display_str(interval_units),
        )
        self._dialog._defaults_ui_controller.set_units_combo(
            row,
            self._col("timeout_units"),
            TIMEOUT_UNITS,
            display_str(timeout_units),
        )
        self._dialog._defaults_ui_controller.set_units_combo(
            row,
            self._col("max_size_units"),
            SIZE_UNITS,
            display_str(max_size_units),
        )

        self.set_text_item(row, self._col("file"), "", editable=False)
        self.set_text_item(row, self._col("meta"), "", editable=False)
        self.set_text_item(row, self._col("state"), "", editable=False)
        self.set_text_item(row, self._col("rule_attached"), "", editable=False)
        self.set_text_item(row, self._col("last_checked"), "", editable=False)
        self.set_text_item(row, self._col("last_updated"), "", editable=False)
        self.apply_url_error_indicator(
            row,
            enabled=bool(sub.enabled),
            state="",
            last_error="",
        )
        self.update_row_sort_keys(row)

    def set_text_item(self, row: int, col: int, text: str, editable: bool = True):
        item = self._dialog.table.item(row, col)
        if item is None:
            item = SortableTableWidgetItem()
            self._dialog.table.setItem(row, col, item)
        item.setText(text)
        item.setData(
            QtCore.Qt.ItemDataRole.UserRole,
            self.sort_key_for_column(col, text),
        )
        if editable:
            item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsEditable)
        else:
            item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)

    def cell_text(self, row: int, col: int):
        widget = self._dialog.table.cellWidget(row, col)
        if isinstance(widget, QtWidgets.QComboBox):
            return (widget.currentText() or "").strip()
        item = self._dialog.table.item(row, col)
        if item is None:
            return ""
        return (item.text() or "").strip()

    def optional_int_from_text(
        self, value: Any, field_name: str, row: int | None = None
    ):
        if value == "":
            return True, None
        parsed = self.to_int_or_keep(value, field_name, row=row)
        if parsed is None:
            return False, None
        return True, parsed

    def to_int_or_keep(self, value: Any, field_name: str, row: int | None = None):
        try:
            parsed = int(value)
        except Exception:
            row_suffix = (
                QC.translate("stats", " (row {0})").format(row + 1)
                if row is not None
                else ""
            )
            self._dialog._status_controller.set_status(
                QC.translate("stats", "{0} must be a positive integer{1}.").format(
                    field_name, row_suffix
                ),
                error=True,
            )
            return None
        if parsed < 1:
            row_suffix = (
                QC.translate("stats", " (row {0})").format(row + 1)
                if row is not None
                else ""
            )
            self._dialog._status_controller.set_status(
                QC.translate("stats", "{0} must be a positive integer{1}.").format(
                    field_name, row_suffix
                ),
                error=True,
            )
            return None
        return parsed
