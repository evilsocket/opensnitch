import os
from typing import Any


class AttachedRulesIndex:
    def __init__(self) -> None:
        self._snapshot: dict[str, list[dict[str, Any]]] = {}

    def snapshot(self) -> dict[str, list[dict[str, Any]]]:
        return dict(self._snapshot)

    def set_from_snapshot_obj(
        self,
        snapshot: object,
    ) -> dict[str, list[dict[str, Any]]]:
        data: dict[str, list[dict[str, Any]]] = {}
        if isinstance(snapshot, dict):
            for key, value in snapshot.items():
                if not isinstance(key, str) or not isinstance(value, list):
                    continue
                normalized_key = os.path.normpath(key)
                items: list[dict[str, Any]] = []
                for entry in value:
                    if isinstance(entry, dict):
                        items.append(entry)
                data[normalized_key] = items
        self._snapshot = data
        return data

    def apply_rule_editor_change(self, change: dict[str, Any]) -> bool:
        addr = str(change.get("addr", "") or "").strip()
        if addr == "":
            return False

        old_name = str(change.get("old_name", "") or "").strip()
        new_name = str(change.get("new_name", "") or "").strip()
        enabled = bool(change.get("enabled", True))
        directories = [
            str(path).strip()
            for path in list(change.get("directories", []))
            if str(path).strip() != ""
        ]

        names_to_remove = {name for name in (old_name, new_name) if name != ""}
        self._remove_rule_from_snapshot(addr, names_to_remove)
        if new_name != "" and directories:
            self._upsert_rule_in_snapshot(
                addr=addr,
                rule_name=new_name,
                enabled=enabled,
                directories=directories,
            )
        return True

    def update_rule_enabled(self, addr: str, rule_name: str, enabled: bool) -> bool:
        changed = False
        for entries in self._snapshot.values():
            for entry in entries:
                if (
                    str(entry.get("addr", "")).strip() == addr
                    and str(entry.get("name", "")).strip() == rule_name
                ):
                    entry["enabled"] = bool(enabled)
                    changed = True
        return changed

    def remove_rule(self, addr: str, rule_name: str) -> None:
        self._remove_rule_from_snapshot(addr, {rule_name})

    def _remove_rule_from_snapshot(self, addr: str, rule_names: set[str]) -> None:
        if not rule_names:
            return
        for directory, entries in list(self._snapshot.items()):
            filtered = [
                entry
                for entry in entries
                if not (
                    str(entry.get("addr", "")).strip() == addr
                    and str(entry.get("name", "")).strip() in rule_names
                )
            ]
            if filtered:
                self._snapshot[directory] = filtered
            else:
                del self._snapshot[directory]

    def _upsert_rule_in_snapshot(
        self,
        *,
        addr: str,
        rule_name: str,
        enabled: bool,
        directories: list[str],
    ) -> None:
        normalized_dirs = [
            os.path.normpath(path)
            for path in directories
            if path.strip()
        ]
        if not normalized_dirs:
            return
        for directory in normalized_dirs:
            entries = self._snapshot.setdefault(directory, [])
            for entry in entries:
                if (
                    str(entry.get("addr", "")).strip() == addr
                    and str(entry.get("name", "")).strip() == rule_name
                ):
                    entry["enabled"] = bool(enabled)
                    break
            else:
                entries.append(
                    {
                        "addr": addr,
                        "name": rule_name,
                        "enabled": bool(enabled),
                    }
                )
