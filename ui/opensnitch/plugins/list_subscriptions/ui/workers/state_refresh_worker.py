import json
import os
from typing import Any

from opensnitch.plugins.list_subscriptions.ui import QtCore
from opensnitch.plugins.list_subscriptions._utils import (
    list_file_path,
    subscription_rule_dir,
)


class SubscriptionStateRefreshWorker(QtCore.QObject):
    refresh_done = QtCore.pyqtSignal(int, object)
    finished = QtCore.pyqtSignal()

    def __init__(
        self,
        *,
        generation: int,
        lists_dir: str,
        rows: list[dict[str, Any]],
        attached_rules_by_dir: dict[str, list[dict[str, Any]]],
    ):
        super().__init__()
        self._generation = generation
        self._lists_dir = lists_dir
        self._rows = rows
        self._attached_rules_by_dir = attached_rules_by_dir
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def _should_stop(self) -> bool:
        return self._stop_requested

    @staticmethod
    def _rule_attachment_matches(
        *,
        lists_dir: str,
        filename: str,
        list_type: str,
        groups: list[str],
        attached_rules_by_dir: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
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
            for rule_entry in attached_rules_by_dir.get(directory, []):
                addr = str(rule_entry.get("addr", "")).strip()
                name = str(rule_entry.get("name", "")).strip()
                enabled = bool(rule_entry.get("enabled", True))
                if addr == "" or name == "" or not enabled:
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

    @QtCore.pyqtSlot()
    def run(self):
        results: list[dict[str, Any]] = []
        try:
            for row_data in self._rows:
                if self._should_stop():
                    return

                row = int(row_data.get("row", -1))
                url = str(row_data.get("url", "") or "")
                filename = str(row_data.get("filename", "") or "")
                list_type = str(row_data.get("list_type", "hosts") or "hosts")
                enabled = bool(row_data.get("enabled", True))
                groups = list(row_data.get("groups", []))

                list_path = list_file_path(self._lists_dir, filename, list_type)
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

                last_result = str(meta.get("last_result", "never")) if meta else "never"
                last_checked = str(meta.get("last_checked", "")) if meta else ""
                last_updated = str(meta.get("last_updated", "")) if meta else ""
                fail_count = str(meta.get("fail_count", 0)) if meta else "0"
                last_error = str(meta.get("last_error", "")) if meta else ""

                attachment_matches = self._rule_attachment_matches(
                    lists_dir=self._lists_dir,
                    filename=filename,
                    list_type=list_type,
                    groups=groups,
                    attached_rules_by_dir=self._attached_rules_by_dir,
                )
                rule_attached = "yes" if attachment_matches else "no"

                if not enabled:
                    state = "disabled"
                elif not file_exists:
                    if not meta_exists or last_result in ("never", "", "busy"):
                        state = "pending"
                    else:
                        state = "missing"
                elif last_result in ("updated", "not_modified"):
                    state = last_result
                elif last_result in (
                    "error",
                    "write_error",
                    "request_error",
                    "unexpected_error",
                    "bad_format",
                    "too_large",
                ):
                    state = last_result
                elif last_result == "busy":
                    state = "busy"
                else:
                    state = last_result

                results.append(
                    {
                        "row": row,
                        "url": url,
                        "filename": filename,
                        "enabled": enabled,
                        "file_present": "yes" if file_exists else "no",
                        "meta_present": "yes" if meta_exists else "no",
                        "state": state,
                        "rule_attached": rule_attached,
                        "attachment_matches": attachment_matches,
                        "last_checked": last_checked,
                        "last_updated": last_updated,
                        "failures": fail_count,
                        "error": last_error,
                        "list_path": list_path,
                        "meta_path": meta_path,
                    }
                )

            if not self._should_stop():
                self.refresh_done.emit(self._generation, results)
        finally:
            self.finished.emit()