import os
from typing import TYPE_CHECKING

from opensnitch.plugins.list_subscriptions.io.storage import (
    read_json_locked,
    write_json_atomic_locked,
)
from opensnitch.plugins.list_subscriptions.models.action import MutableActionConfig
from opensnitch.plugins.list_subscriptions.models.config import PluginConfig
from opensnitch.plugins.list_subscriptions.models.global_defaults import GlobalDefaults
from opensnitch.plugins.list_subscriptions.ui import QC
from opensnitch.plugins.list_subscriptions._utils import (
    DEFAULT_LISTS_DIR,
    normalize_lists_dir,
    safe_filename,
)

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class ActionFileController:
    def __init__(
        self, *, dialog: "ListSubscriptionsDialog", columns: dict[str, int]
    ):
        self._dialog = dialog
        self._cols = columns

    def _col(self, key: str):
        return self._cols[key]

    def load_action_file(self):
        with self._dialog._table_view_controller.sorting_suspended():
            self._dialog._loading = True
            self._dialog._status_controller.set_status("")
            self._dialog._defaults_ui_controller.reload_nodes()
            self._dialog.table.setRowCount(0)
            self._dialog.create_file_button.setVisible(True)
            self._dialog.lists_dir_edit.setText(DEFAULT_LISTS_DIR)
            self._dialog.enable_plugin_check.setChecked(True)
            self._dialog._runtime_controller.set_runtime_state(active=False)
            self._dialog._global_defaults = GlobalDefaults.from_dict(
                {}, lists_dir=DEFAULT_LISTS_DIR
            )
            self._dialog._defaults_ui_controller.apply_defaults_to_widgets()

            if not os.path.exists(self._dialog._action_path):
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats", "Action file not found. Click 'Create action file'."
                    ),
                    error=False,
                )
                self._dialog._loading = False
                return

            try:
                data = read_json_locked(self._dialog._action_path)
            except Exception as e:
                self._dialog._status_controller.set_status(
                    QC.translate("stats", "Error reading action file: {0}").format(
                        str(e)
                    ),
                    error=True,
                )
                self._dialog._loading = False
                return

            action_model = MutableActionConfig.from_action_dict(
                data, lists_dir=DEFAULT_LISTS_DIR
            )
            self._dialog._global_defaults = action_model.plugin.defaults
            self._dialog.enable_plugin_check.setChecked(True)
            self._dialog._runtime_controller.sync_runtime_binding_state()
            self._dialog.lists_dir_edit.setText(
                normalize_lists_dir(self._dialog._global_defaults.lists_dir)
            )
            self._dialog._defaults_ui_controller.apply_defaults_to_widgets()

            normalized_subs = action_model.plugin.subscriptions
            actions_obj = data.get("actions", {})
            action_cfg = (
                actions_obj.get("list_subscriptions", {})
                if isinstance(actions_obj, dict)
                else {}
            )
            plugin_cfg_raw = (
                action_cfg.get("config", {}) if isinstance(action_cfg, dict) else {}
            )
            plugin_cfg = plugin_cfg_raw if isinstance(plugin_cfg_raw, dict) else {}
            raw_subs = plugin_cfg.get("subscriptions")
            migrated_legacy_group = False
            if isinstance(raw_subs, list):
                for item in raw_subs:
                    if (
                        isinstance(item, dict)
                        and ("group" in item)
                        and ("groups" not in item)
                    ):
                        migrated_legacy_group = True
                        break
            normalized_subs_dicts = [s.to_dict() for s in normalized_subs]
            fixed_count = (
                1
                if (isinstance(raw_subs, list) and raw_subs != normalized_subs_dicts)
                else 0
            )

            for sub in normalized_subs:
                self._dialog._table_data_controller.append_row(sub)

            self._dialog._loading = False
            self._dialog._table_data_controller.refresh_states()
            self._dialog._selection_controller.update_selected_actions_state()
            self._dialog.create_file_button.setVisible(False)
            if migrated_legacy_group:
                self._dialog._status_controller.append_log(
                    QC.translate(
                        "stats",
                        "Detected legacy 'group' fields and migrated them to 'groups'.",
                    ),
                    level="WARN",
                )
                self.save_action_file()
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats",
                        "Migrated legacy 'group' entries to 'groups' and auto-saved configuration.",
                    ),
                    error=False,
                )
                return
            if fixed_count > 0:
                self._dialog._status_controller.append_log(
                    QC.translate(
                        "stats",
                        "Normalized subscription fields while loading configuration.",
                    ),
                    level="WARN",
                )
                self._dialog._status_controller.set_status(
                    QC.translate(
                        "stats",
                        "Loaded configuration with normalized subscription fields.",
                    ),
                    error=False,
                )
            else:
                self._dialog._status_controller.set_status(
                    QC.translate("stats", "List subscriptions configuration loaded."),
                    error=False,
                )

    def create_action_file(self):
        try:
            os.makedirs(
                os.path.dirname(self._dialog._action_path), mode=0o700, exist_ok=True
            )
            if not os.path.exists(self._dialog._action_path):
                action_model = MutableActionConfig.default(DEFAULT_LISTS_DIR)
                write_json_atomic_locked(
                    self._dialog._action_path,
                    action_model.to_action_dict(),
                )
            self.load_action_file()
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Action file created."),
                error=False,
            )
        except Exception as e:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Error creating action file: {0}").format(str(e)),
                error=True,
            )

    def save_action_file(self):
        if self._dialog._loading:
            return

        if not os.path.exists(self._dialog._action_path):
            self.create_action_file()
            if not os.path.exists(self._dialog._action_path):
                return

        subscriptions = self._dialog._table_data_controller.collect_subscriptions()
        if subscriptions is None:
            return

        lists_dir = normalize_lists_dir(
            self._dialog.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        try:
            os.makedirs(lists_dir, mode=0o700, exist_ok=True)
        except Exception:
            pass
        defaults = GlobalDefaults(
            lists_dir=lists_dir,
            interval=max(1, int(self._dialog.default_interval_spin.value())),
            interval_units=self._dialog.default_interval_units.currentText(),
            timeout=max(1, int(self._dialog.default_timeout_spin.value())),
            timeout_units=self._dialog.default_timeout_units.currentText(),
            max_size=max(1, int(self._dialog.default_max_size_spin.value())),
            max_size_units=self._dialog.default_max_size_units.currentText(),
            user_agent=(self._dialog.default_user_agent.text() or "").strip(),
        )
        action_model = MutableActionConfig.default(lists_dir)
        action_model.enabled = True
        action_model.plugin.defaults = defaults
        action_model.plugin.subscriptions = subscriptions
        normalized_subscriptions = action_model.plugin.normalize_subscriptions(
            invalidate_duplicates=True
        )
        if normalized_subscriptions is None:
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats",
                    "Invalid subscriptions: duplicate filename for the same URL.",
                ),
                error=True,
            )
            return
        action = action_model.to_action_dict()

        compiled_cfg = PluginConfig.from_dict(
            action_model.plugin.to_dict(),
            lists_dir=lists_dir,
            invalidate_duplicates=True,
        )
        if len(compiled_cfg.subscriptions) != len(normalized_subscriptions):
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats", "Invalid subscriptions: URL and filename are mandatory."
                ),
                error=True,
            )
            return

        for row, sub in enumerate(normalized_subscriptions):
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("name"),
                sub.name,
            )
            self._dialog._table_data_controller.set_text_item(
                row,
                self._col("filename"),
                safe_filename(sub.filename),
            )

        try:
            write_json_atomic_locked(self._dialog._action_path, action)
        except Exception as e:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Error saving action file: {0}").format(str(e)),
                error=True,
            )
            return

        self._dialog._status_controller.append_log(
            QC.translate(
                "stats",
                "Saving configuration: {0} subscriptions, runtime {1}.",
            ).format(
                len(normalized_subscriptions),
                QC.translate("stats", "enabled")
                if action_model.enabled
                else QC.translate("stats", "disabled"),
            ),
        )
        self._dialog._runtime_controller.apply_runtime_state(
            action_model.enabled
        )
        self._dialog._table_data_controller.refresh_states()
        self._dialog._status_controller.set_status(
            QC.translate("stats", "List subscriptions configuration saved."),
            error=False,
        )