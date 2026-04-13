import os
from typing import TYPE_CHECKING, Any

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets, QC
from opensnitch.plugins.list_subscriptions._utils import (
    DEFAULT_LISTS_DIR,
    list_file_path,
    normalize_group,
    normalize_groups,
    normalize_lists_dir,
    safe_filename,
    subscription_rule_dir,
)
from opensnitch.config import Config
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
from opensnitch.dialogs.ruleseditor import constants as ruleseditor_constants
from opensnitch.rules import Rules

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class _RulesDialogEventFilter(QtCore.QObject):
    def __init__(self, controller: "RulesEditorController"):
        super().__init__(controller._dialog)
        self._controller = controller

    def eventFilter(self, a0, a1):
        event_type = a1.type() if a1 is not None else None
        if event_type == QtCore.QEvent.Type.Show:
            self._controller._on_rules_dialog_shown()
        elif event_type in (
            QtCore.QEvent.Type.Hide,
            QtCore.QEvent.Type.Close,
        ):
            self._controller._on_rules_dialog_hidden()
        return super().eventFilter(a0, a1)


class RulesEditorController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns
        self._rules = Rules.instance()
        self._pending_rule_change: dict[str, Any] | None = None
        self._rules_dialog_event_filter: _RulesDialogEventFilter | None = None
        self._rules.updated.connect(self._handle_rules_updated)

    def _col(self, key: str):
        return self._cols[key]

    def ensure_rules_dialog(self):
        if self._dialog._rules_dialog is None:
            appicon = (
                self._dialog.windowIcon()
                if self._dialog.windowIcon() is not None
                else None
            )
            try:
                self._dialog._rules_dialog = RulesEditorDialog(
                    parent=None,
                    appicon=appicon,
                )
            except TypeError:
                self._dialog._rules_dialog = RulesEditorDialog()
        self._install_rules_dialog_event_filter()
        self._connect_rules_dialog_signals()
        return self._dialog._rules_dialog

    def _install_rules_dialog_event_filter(self):
        rules_dialog = self._dialog._rules_dialog
        if rules_dialog is None:
            return
        if self._rules_dialog_event_filter is None:
            self._rules_dialog_event_filter = _RulesDialogEventFilter(self)
        rules_dialog.installEventFilter(self._rules_dialog_event_filter)

    def _connect_rules_dialog_signals(self):
        rules_dialog = self._dialog._rules_dialog
        if rules_dialog is None:
            return
        save_button = rules_dialog.buttonBox.button(
            QtWidgets.QDialogButtonBox.StandardButton.Save
        )
        if save_button is None:
            return
        try:
            save_button.pressed.disconnect(self._capture_rule_save_context)
        except Exception:
            pass
        save_button.pressed.connect(self._capture_rule_save_context)

    def _capture_rule_save_context(self):
        rules_dialog = self._dialog._rules_dialog
        if rules_dialog is None:
            return
        node_index = rules_dialog.nodesCombo.currentIndex()
        node_addr = str(rules_dialog.nodesCombo.itemData(node_index) or "").strip()
        rule_dirs: list[str] = []
        if rules_dialog.dstListsCheck.isChecked():
            rule_dir = str(rules_dialog.dstListsLine.text() or "").strip()
            if rule_dir != "":
                rule_dirs.append(rule_dir)
        self._pending_rule_change = {
            "mode": int(getattr(ruleseditor_constants, "WORK_MODE", 0)),
            "old_name": str(getattr(rules_dialog, "_old_rule_name", "") or "").strip(),
            "new_name": str(rules_dialog.ruleNameEdit.text() or "").strip(),
            "addr": node_addr,
            "enabled": bool(rules_dialog.enableCheck.isChecked()),
            "directories": rule_dirs,
            "apply_all": bool(rules_dialog.nodeApplyAllCheck.isChecked()),
        }

    def _handle_rules_updated(self, _value: int):
        if self._pending_rule_change is None:
            return
        # Defer so we exit cb_save_clicked's call chain before touching the DB.
        # Running a DB scan synchronously inside Rules.updated (which is emitted
        # from cb_save_clicked) blocks the main thread while the gRPC reply for
        # the CHANGE_RULE notification is still pending, causing the daemon to
        # appear locked.
        QtCore.QTimer.singleShot(0, self._finalize_pending_rule_change)

    def _finalize_pending_rule_change(self):
        pending = self._pending_rule_change
        self._pending_rule_change = None
        if pending is None:
            return

        mode = int(pending.get("mode") or 0)
        old_name = str(pending.get("old_name") or "").strip()
        new_name = str(pending.get("new_name") or "").strip()

        if mode == ruleseditor_constants.ADD_RULE:
            message = QC.translate("stats", "Rule created: {0}").format(
                new_name or old_name
            )
        elif old_name != "" and new_name != "" and old_name != new_name:
            message = QC.translate(
                "stats", "Rule updated: {0} (renamed from {1})"
            ).format(new_name, old_name)
        else:
            message = QC.translate("stats", "Rule updated: {0}").format(
                new_name or old_name
            )

        if bool(pending.get("apply_all", False)):
            self._dialog._rules_attachment_controller.invalidate_snapshot_cache(
                "rule-editor-apply-all"
            )
        else:
            self._dialog._rules_attachment_controller.apply_rule_editor_change(pending)

        self._dialog._status_controller.set_status(message, error=False)
        self._dialog._table_data_controller.refresh_states()
        self._dialog._selection_controller.update_selected_actions_state()

    def _on_rules_dialog_shown(self):
        self._dialog._table_data_controller.stop_poll()

    def _on_rules_dialog_hidden(self):
        self._pending_rule_change = None
        # Restart polling right away, but defer the DB-heavy refresh so it
        # runs after the dialog teardown event chain has fully unwound.
        self._dialog._table_data_controller.start_poll()
        if self._dialog.isVisible() and not self._dialog._loading:
            QtCore.QTimer.singleShot(0, self._deferred_post_editor_refresh)

    def _deferred_post_editor_refresh(self):
        if not self._dialog.isVisible() or self._dialog._loading:
            return
        self._dialog._table_data_controller.refresh_states()
        self._dialog._selection_controller.update_selected_actions_state()

    def configure_rules_dialog_for_local_user(self):
        rules_dialog = self._dialog._rules_dialog
        if rules_dialog is None:
            return False

        local_addr = None
        for addr in self._dialog._nodes.get().keys():
            try:
                if self._dialog._nodes.is_local(addr):
                    local_addr = addr
                    break
            except Exception:
                continue

        if local_addr is None:
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats",
                    "No local OpenSnitch node is connected. Rules can only be created for the local user.",
                ),
                error=True,
            )
            rules_dialog.hide()
            return False

        nodes_combo = rules_dialog.nodesCombo
        node_idx = nodes_combo.findData(local_addr)
        if node_idx != -1:
            nodes_combo.setCurrentIndex(node_idx)
        nodes_combo.setEnabled(False)
        rules_dialog.nodeApplyAllCheck.setChecked(False)
        rules_dialog.nodeApplyAllCheck.setEnabled(False)
        rules_dialog.nodeApplyAllCheck.setVisible(False)

        uid_text = str(os.getuid())
        uid_combo = rules_dialog.uidCombo
        uid_idx = uid_combo.findData(int(uid_text))
        rules_dialog.uidCheck.setChecked(True)
        uid_combo.setEnabled(True)
        if uid_idx != -1:
            uid_combo.setCurrentIndex(uid_idx)
        else:
            uid_combo.setCurrentText(uid_text)
        return True

    def apply_rule_editor_defaults(self):
        rules_dialog = self._dialog._rules_dialog
        if rules_dialog is None:
            return
        rules_dialog.enableCheck.setChecked(True)
        duration_idx = rules_dialog.durationCombo.findData(Config.DURATION_ALWAYS)
        if duration_idx < 0:
            duration_idx = rules_dialog.durationCombo.findText(
                Config.DURATION_ALWAYS,
                QtCore.Qt.MatchFlag.MatchFixedString,
            )
        if duration_idx < 0:
            duration_idx = 8
        rules_dialog.durationCombo.setCurrentIndex(duration_idx)

    def choose_group_for_selected(self, rows: list[int]):
        if not rows:
            return None
        selected_group_sets = [
            set(
                normalize_groups(
                    self._dialog._table_data_controller.cell_text(
                        r,
                        self._col("group"),
                    )
                )
            )
            for r in rows
        ]
        common = (
            set.intersection(*selected_group_sets) if selected_group_sets else set()
        )
        known = self._dialog._selection_controller.known_groups()
        default_group = ""
        if common:
            default_group = sorted(common)[0]
        if default_group != "" and default_group not in known:
            known.append(default_group)
        known = sorted(set(known)) or [""]
        try:
            default_idx = known.index(default_group)
        except ValueError:
            default_idx = 0
        value, ok = QtWidgets.QInputDialog.getItem(
            self._dialog,
            QC.translate("stats", "Create rule from multiple subscriptions"),
            QC.translate(
                "stats", "Select or enter a group to aggregate selected subscriptions:"
            ),
            known,
            default_idx,
            True,
        )
        if not ok:
            return None
        group = normalize_group(value)
        if group in ("", "all"):
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Group cannot be empty."), error=True
            )
            return None
        return group

    def assign_group_to_rows(self, rows: list[int], group: str):
        if not rows:
            return False
        target_group = normalize_group(group)
        for row in rows:
            groups = normalize_groups(
                self._dialog._table_data_controller.cell_text(row, self._col("group"))
            )
            groups.append(target_group)
            groups = normalize_groups(groups)
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("group"),
                ", ".join(groups),
            )
        return True

    def prepare_rule_dir(
        self,
        url: str,
        filename: str,
        list_path: str,
        lists_dir: str,
        list_type: str,
    ):
        _ = (url, list_path)
        rule_dir = subscription_rule_dir(lists_dir, filename, list_type)
        try:
            os.makedirs(rule_dir, mode=0o700, exist_ok=True)
            return rule_dir
        except Exception as e:
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats", "Error preparing list rule directory: {0}"
                ).format(str(e)),
                error=True,
            )
            return None

    def create_rule_from_selected(self):
        rows = self._dialog._selection_controller.selected_rows()
        if not rows:
            row = self._dialog.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select one or more subscriptions first."),
                error=True,
            )
            return

        lists_dir = normalize_lists_dir(
            self._dialog.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        if len(rows) == 1:
            row = rows[0]
            url = self._dialog._table_data_controller.cell_text(row, self._col("url"))
            filename, filename_changed = (
                self._dialog._table_data_controller.ensure_row_final_filename(row)
            )
            if url == "" or filename == "":
                self._dialog._status_controller.set_status(
                    QC.translate("stats", "URL and filename cannot be empty."),
                    error=True,
                )
                return
            if filename_changed:
                self._dialog._action_file_controller.save_action_file()

            list_type = (
                self._dialog._table_data_controller.cell_text(row, self._col("format"))
            ) or "hosts"
            list_type = list_type.strip().lower()
            list_path = list_file_path(lists_dir, filename, list_type)
            rule_dir = self.prepare_rule_dir(
                url,
                filename,
                list_path,
                lists_dir,
                list_type,
            )
            if rule_dir is None:
                return
            rule_token = os.path.splitext(safe_filename(filename))[0]
            rule_name = f"00-blocklist-{rule_token}"
            desc = f"From list subscription : {filename}"
        else:
            rule_group = self.choose_group_for_selected(rows)
            if rule_group is None:
                return
            if not self.assign_group_to_rows(rows, rule_group):
                return
            self._dialog._action_file_controller.save_action_file()
            rule_dir = os.path.join(lists_dir, "rules.list.d", rule_group)
            try:
                os.makedirs(rule_dir, mode=0o700, exist_ok=True)
            except Exception as e:
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats", "Error preparing grouped rule directory: {0}"
                    ).format(str(e)),
                    error=True,
                )
                return
            rule_name = f"00-blocklist-{rule_group}"
            desc = f"From list subscription : {rule_group}"

        rules_dialog = self.ensure_rules_dialog()
        if rules_dialog is None:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Rules editor is not available."),
                error=True,
            )
            return
        rules_dialog.new_rule()
        if not self.configure_rules_dialog_for_local_user():
            return
        self.apply_rule_editor_defaults()
        rules_dialog.dstListsCheck.setChecked(True)
        rules_dialog.dstListsLine.setText(rule_dir)
        if rules_dialog.ruleNameEdit.text().strip() == "":
            rules_dialog.ruleNameEdit.setText(rule_name)
        if rules_dialog.ruleDescEdit.toPlainText().strip() == "":
            rules_dialog.ruleDescEdit.setPlainText(desc)
        rules_dialog.raise_()
        rules_dialog.activateWindow()
        self._dialog._status_controller.set_status(
            QC.translate(
                "stats", "Rules Editor opened with prefilled list directory path."
            ),
            error=False,
        )

    def create_global_rule(self):
        lists_dir = normalize_lists_dir(
            self._dialog.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        rule_dir = os.path.join(lists_dir, "rules.list.d", "all")
        try:
            os.makedirs(rule_dir, mode=0o700, exist_ok=True)
        except Exception as e:
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats", "Error preparing global rule directory: {0}"
                ).format(str(e)),
                error=True,
            )
            return

        rules_dialog = self.ensure_rules_dialog()
        if rules_dialog is None:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Rules editor is not available."),
                error=True,
            )
            return
        rules_dialog.new_rule()
        if not self.configure_rules_dialog_for_local_user():
            return
        self.apply_rule_editor_defaults()
        rule_name = "00-blocklist-all"
        rules_dialog.dstListsCheck.setChecked(True)
        rules_dialog.dstListsLine.setText(rule_dir)
        if rules_dialog.ruleNameEdit.text().strip() == "":
            rules_dialog.ruleNameEdit.setText(rule_name)
        if rules_dialog.ruleDescEdit.toPlainText().strip() == "":
            rules_dialog.ruleDescEdit.setPlainText("From list subscription : all")
        rules_dialog.raise_()
        rules_dialog.activateWindow()
        self._dialog._status_controller.set_status(
            QC.translate(
                "stats", "Rules Editor opened with global list directory path."
            ),
            error=False,
        )
