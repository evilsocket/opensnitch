import os
from typing import TYPE_CHECKING, Any, cast

from opensnitch.plugins.list_subscriptions.ui import QtWidgets, QC
from opensnitch.plugins.list_subscriptions.ui.views.attached_rules_dialog import (
    AttachedRulesDialog,
)
from opensnitch.config import Config
from opensnitch.rules import Rule
from opensnitch.proto import ui_pb2 as ui_pb2

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class RulesAttachmentController:
    def __init__(self, *, dialog: "ListSubscriptionsDialog"):
        self._dialog = dialog

    def attached_rules_snapshot(self):
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

    def show_attached_rules_dialog(self):
        rows = self._dialog._selection_controller.selected_rows()
        if len(rows) != 1:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Select a single subscription row first."),
                error=True,
            )
            return

        row = rows[0]
        dlg = AttachedRulesDialog(
            self._dialog,
            get_attached_rules=lambda: self.aggregate_attached_rules(
                self._dialog._table_data_controller.attached_rules_for_row(
                    row,
                    include_disabled=True,
                )
            ),
            on_create_rule=self._dialog._rules_editor_controller.create_rule_from_selected,
            on_edit_rule=self.edit_attached_rule_entry,
            on_toggle_rule=self.toggle_attached_rule_entry,
            on_remove_rule=self.remove_attached_rule_entry,
        )
        dlg.exec()

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
