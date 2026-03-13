from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets, QC
from opensnitch.plugins.list_subscriptions.ui.views.text_inspect_dialog import (
    TextInspectDialog,
)
from opensnitch.plugins.list_subscriptions._utils import safe_filename, timestamp_sort_key

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class InspectorController:
    def __init__(
        self,
        *,
        dialog: "ListSubscriptionsDialog",
        columns: dict[str, int],
        error_preview_limit: int,
    ):
        self._dialog = dialog
        self._cols = columns
        self._error_preview_limit = error_preview_limit

    def _col(self, key: str):
        return self._cols[key]

    def show_error_inspect_dialog(self):
        text = (self._dialog._inspect_error_full_text or "").strip()
        dlg = TextInspectDialog(
            self._dialog,
            title=QC.translate("stats", "Error details"),
            text=text,
        )
        dlg.exec()

    def set_inspector_toggle_icon(self):
        style = self._dialog.style()
        if style is None:
            return
        if not self._dialog._inspect_has_selection:
            icon = style.standardIcon(
                QtWidgets.QStyle.StandardPixmap.SP_ArrowLeft
            )
            tip = QC.translate("stats", "Select a subscription to inspect")
            self._dialog._inspect_toggle_button.setIcon(icon)
            self._dialog._inspect_toggle_button.setToolTip(tip)
            self._dialog._inspect_toggle_button.setEnabled(False)
            return
        if self._dialog._inspect_collapsed:
            icon = style.standardIcon(
                QtWidgets.QStyle.StandardPixmap.SP_ArrowLeft
            )
            tip = QC.translate("stats", "Expand inspector")
        else:
            icon = style.standardIcon(
                QtWidgets.QStyle.StandardPixmap.SP_ArrowRight
            )
            tip = QC.translate("stats", "Collapse inspector")
        self._dialog._inspect_toggle_button.setEnabled(True)
        self._dialog._inspect_toggle_button.setIcon(icon)
        self._dialog._inspect_toggle_button.setToolTip(tip)

    def toggle_inspector_collapsed(self):
        if not self._dialog._inspect_has_selection:
            return
        self._dialog._inspect_collapsed = not self._dialog._inspect_collapsed
        if not self._dialog._inspect_panel.isVisible():
            return
        if self._dialog._inspect_collapsed:
            self._dialog._inspect_scroll.setVisible(False)
            self._dialog._inspect_title_label.setVisible(False)
            self._dialog._inspect_header_separator.setVisible(False)
            self._dialog._inspect_panel.setMinimumWidth(36)
            self._dialog._inspect_panel.setMaximumWidth(36)
            total = max(36, self._dialog._table_inspect_splitter.width())
            self._dialog._table_inspect_splitter.setSizes([max(1, total - 36), 36])
        else:
            self._dialog._inspect_scroll.setVisible(True)
            self._dialog._inspect_title_label.setVisible(True)
            self._dialog._inspect_header_separator.setVisible(True)
            self._dialog._inspect_panel.setMinimumWidth(240)
            self._dialog._inspect_panel.setMaximumWidth(16777215)
            total = max(300, self._dialog._table_inspect_splitter.width())
            width = min(self._dialog._inspect_default_width, max(280, total // 2))
            self._dialog._table_inspect_splitter.setSizes([max(1, total - width), width])
        self.set_inspector_toggle_icon()

    def set_inspector_visible(self, visible: bool):
        if not hasattr(self._dialog, "_inspect_panel"):
            return
        self._dialog._inspect_has_selection = bool(visible)
        self._dialog._inspect_panel.setVisible(True)
        if not self._dialog._inspect_has_selection:
            self._dialog._inspect_collapsed = True
            self._dialog._inspect_scroll.setVisible(False)
            self._dialog._inspect_title_label.setVisible(False)
            self._dialog._inspect_header_separator.setVisible(False)
            self._dialog._inspect_panel.setMinimumWidth(36)
            self._dialog._inspect_panel.setMaximumWidth(36)
            total = max(36, self._dialog._table_inspect_splitter.width())
            self._dialog._table_inspect_splitter.setSizes([max(1, total - 36), 36])
            self.set_inspector_toggle_icon()
            return
        if self._dialog._inspect_collapsed:
            self._dialog._inspect_scroll.setVisible(False)
            self._dialog._inspect_title_label.setVisible(False)
            self._dialog._inspect_header_separator.setVisible(False)
            self._dialog._inspect_panel.setMinimumWidth(36)
            self._dialog._inspect_panel.setMaximumWidth(36)
            total = max(36, self._dialog._table_inspect_splitter.width())
            self._dialog._table_inspect_splitter.setSizes([max(1, total - 36), 36])
        else:
            self._dialog._inspect_scroll.setVisible(True)
            self._dialog._inspect_title_label.setVisible(True)
            self._dialog._inspect_header_separator.setVisible(True)
            self._dialog._inspect_panel.setMinimumWidth(240)
            self._dialog._inspect_panel.setMaximumWidth(16777215)
            total = max(300, self._dialog._table_inspect_splitter.width())
            width = min(self._dialog._inspect_default_width, max(240, total // 3))
            self._dialog._table_inspect_splitter.setSizes([max(1, total - width), width])
        self.set_inspector_toggle_icon()

    def set_inspector_values(
        self,
        *,
        row: int,
        name: str,
        url: str,
        filename: str,
        meta: dict[str, str],
    ):
        enabled_item = self._dialog.table.item(row, self._col("enabled"))
        enabled = enabled_item is not None and (
            enabled_item.checkState() == QtCore.Qt.CheckState.Checked
        )
        interval_value = self._dialog._table_data_controller.cell_text(
            row, self._col("interval")
        )
        interval_units = self._dialog._table_data_controller.cell_text(
            row, self._col("interval_units")
        )
        timeout_value = self._dialog._table_data_controller.cell_text(
            row, self._col("timeout")
        )
        timeout_units = self._dialog._table_data_controller.cell_text(
            row, self._col("timeout_units")
        )
        max_size_value = self._dialog._table_data_controller.cell_text(
            row, self._col("max_size")
        )
        max_size_units = self._dialog._table_data_controller.cell_text(
            row, self._col("max_size_units")
        )
        values = {
            "enabled": QC.translate("stats", "Yes") if enabled else QC.translate("stats", "No"),
            "name": name,
            "url": url,
            "filename": filename,
            "format": self._dialog._table_data_controller.cell_text(
                row, self._col("format")
            ),
            "groups": self._dialog._table_data_controller.cell_text(
                row, self._col("group")
            ),
            "interval": " ".join(
                part for part in (interval_value, interval_units) if (part or "").strip() != ""
            ),
            "timeout": " ".join(
                part for part in (timeout_value, timeout_units) if (part or "").strip() != ""
            ),
            "max_size": " ".join(
                part for part in (max_size_value, max_size_units) if (part or "").strip() != ""
            ),
            "state": meta.get("state", ""),
            "last_checked": meta.get("last_checked", ""),
            "last_updated": meta.get("last_updated", ""),
            "failures": meta.get("failures", ""),
            "error": meta.get("error", ""),
            "list_path": meta.get("list_path", ""),
            "meta_path": meta.get("meta_path", ""),
        }
        for key, value in values.items():
            label = self._dialog._inspect_value_labels.get(key)
            if label is None:
                continue
            text = (str(value or "")).strip() or "-"
            if key == "error":
                self.set_error_preview(text)
                continue
            if key == "state":
                label.setText(text)
                label.setStyleSheet(
                    f"color: {self.state_bucket_color(text).name()};"
                )
                continue
            label.setText(text)

    def state_bucket_color(self, state: str):
        normalized = (state or "").strip().lower()
        if normalized in ("updated", "not_modified"):
            return self._dialog._table_data_controller.state_text_color("updated")
        if normalized == "pending":
            return self._dialog._table_data_controller.state_text_color("pending")
        return self._dialog._table_data_controller.state_text_color("error")

    def set_error_preview(self, text: str):
        error_label = self._dialog._inspect_value_labels.get("error")
        if error_label is None:
            return

        normalized = (text or "").strip()
        if normalized in ("", "-"):
            self._dialog._inspect_error_full_text = ""
            error_label.setText("-")
            error_label.setToolTip("")
            if self._dialog._inspect_error_button is not None:
                self._dialog._inspect_error_button.setVisible(False)
            return

        self._dialog._inspect_error_full_text = normalized
        if len(normalized) <= self._error_preview_limit:
            error_label.setText(normalized)
            error_label.setToolTip(normalized)
            if self._dialog._inspect_error_button is not None:
                self._dialog._inspect_error_button.setVisible(False)
            return

        preview = normalized[: self._error_preview_limit - 1].rstrip() + "..."
        error_label.setText(preview)
        error_label.setToolTip(normalized)
        if self._dialog._inspect_error_button is not None:
            self._dialog._inspect_error_button.setVisible(True)
            self._dialog._inspect_error_button.setEnabled(True)

    def set_inspector_multi_selection_mode(self, enabled: bool):
        if enabled:
            self._dialog._inspect_details_widget.setVisible(False)
            self._dialog._inspect_summary_widget.setVisible(True)
            return
        self._dialog._inspect_details_widget.setVisible(True)
        self._dialog._inspect_summary_widget.setVisible(False)

    def set_inspector_summary_values(self, rows: list[int]):
        selected_count = len(rows)
        enabled_count = 0
        healthy_count = 0
        pending_count = 0
        problematic_count = 0
        total_failures = 0
        with_errors = 0
        newest_checked = ""
        oldest_checked = ""
        newest_key = None
        oldest_key = None

        for row in rows:
            enabled_item = self._dialog.table.item(row, self._col("enabled"))
            if enabled_item is not None and (
                enabled_item.checkState() == QtCore.Qt.CheckState.Checked
            ):
                enabled_count += 1

            meta = self._dialog._table_data_controller.row_meta_snapshot(row)
            state = (meta.get("state", "") or "").strip().lower()
            if state in ("updated", "not_modified"):
                healthy_count += 1
            elif state == "pending":
                pending_count += 1
            else:
                problematic_count += 1

            failures_text = (meta.get("failures", "") or "").strip()
            try:
                total_failures += int(failures_text or "0")
            except Exception:
                pass

            if (meta.get("error", "") or "").strip() != "":
                with_errors += 1

            checked = (meta.get("last_checked", "") or "").strip()
            if checked == "":
                continue
            checked_key = timestamp_sort_key(checked)
            if newest_key is None or checked_key > newest_key:
                newest_key = checked_key
                newest_checked = checked
            if oldest_key is None or checked_key < oldest_key:
                oldest_key = checked_key
                oldest_checked = checked

        values = {
            "selected": str(selected_count),
            "enabled": f"{enabled_count}/{selected_count}",
            "healthy": str(healthy_count),
            "pending": str(pending_count),
            "problematic": str(problematic_count),
            "failures": str(total_failures),
            "with_errors": str(with_errors),
            "newest_checked": newest_checked,
            "oldest_checked": oldest_checked,
        }
        for key, value in values.items():
            label = self._dialog._inspect_summary_labels.get(key)
            if label is None:
                continue
            label.setText((value or "").strip() or "-")

    def update_inspector_panel(self):
        if not hasattr(self._dialog, "_inspect_panel"):
            return

        rows = self._dialog._selection_controller.selected_rows()
        if not rows:
            self.set_inspector_visible(False)
            return

        self.set_inspector_multi_selection_mode(len(rows) > 1)
        if len(rows) > 1:
            self.set_inspector_summary_values(rows)
            self.set_inspector_visible(True)
            return

        row = rows[0]
        name = self._dialog._table_data_controller.cell_text(row, self._col("name"))
        url = self._dialog._table_data_controller.cell_text(row, self._col("url"))
        filename = safe_filename(
            self._dialog._table_data_controller.cell_text(row, self._col("filename"))
        )
        meta = self._dialog._table_data_controller.row_meta_snapshot(row)
        self.set_inspector_values(
            row=row,
            name=name,
            url=url,
            filename=filename,
            meta=meta,
        )
        self.set_inspector_visible(True)

    def handle_table_selection_changed(self, *_):
        self._dialog._selection_controller.update_selected_actions_state()
        self.update_inspector_panel()

    def on_subscription_state_refreshed(self, url: str, filename: str, meta: dict[str, str]):
        if not hasattr(self._dialog, "_inspect_panel"):
            return
        if not self._dialog._inspect_panel.isVisible():
            return

        rows = self._dialog._selection_controller.selected_rows()
        if not rows:
            self.set_inspector_visible(False)
            return
        if len(rows) > 1:
            changed_row = self._dialog._subscription_status_controller.find_row_by_identity(
                url,
                filename,
            )
            if changed_row in rows:
                self.set_inspector_summary_values(rows)
            return
        row = rows[0]
        row_url = self._dialog._table_data_controller.cell_text(row, self._col("url"))
        row_filename = safe_filename(
            self._dialog._table_data_controller.cell_text(row, self._col("filename"))
        )
        if row_url != url or row_filename != filename:
            return
        self.set_inspector_values(
            row=row,
            name=self._dialog._table_data_controller.cell_text(row, self._col("name")),
            url=row_url,
            filename=row_filename,
            meta=meta,
        )
