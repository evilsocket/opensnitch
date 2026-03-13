import os
from typing import TYPE_CHECKING, Any, cast

from opensnitch.plugins import PluginSignal
from opensnitch.plugins.list_subscriptions.list_subscriptions import ListSubscriptions
from opensnitch.plugins.list_subscriptions.ui import QtWidgets, QC
from opensnitch.plugins.list_subscriptions.models.events import RuntimeEventType

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class RuntimeController:
    def __init__(
        self,
        *,
        dialog: "ListSubscriptionsDialog",
        status_label: QtWidgets.QLabel,
        start_button: QtWidgets.QPushButton,
        stop_button: QtWidgets.QPushButton,
    ):
        self._dialog = dialog
        self._status_label = status_label
        self._start_button = start_button
        self._stop_button = stop_button

    # -- UI state -----------------------------------------------------------

    def set_runtime_state(self, active: bool | None, text: str | None = None):
        if text is None:
            if active is True:
                text = QC.translate("stats", "Runtime: active")
            elif active is False:
                text = QC.translate("stats", "Runtime: inactive")
            else:
                text = QC.translate("stats", "Runtime: pending")

        if active is True:
            style = "color: green;"
        elif active is False:
            style = "color: #666666;"
        else:
            style = "color: #b36b00;"

        self._status_label.setStyleSheet(style)
        self._status_label.setText(text)
        self._start_button.setEnabled(active is not True)
        self._stop_button.setEnabled(active is not False)

    # -- Refresh busy state -------------------------------------------------

    def set_refresh_busy(self, busy: bool):
        self._dialog.refresh_state_button.setEnabled(not busy)
        self._dialog.refresh_now_button.setEnabled(
            not busy and len(self._dialog._selection_controller.selected_rows()) > 0
        )

    def track_refresh_keys(self, keys: set[str]):
        if not keys:
            return
        self._dialog._pending_refresh_keys.update(keys)
        self.set_refresh_busy(True)

    def clear_refresh_key(self, key: str):
        self._dialog._pending_refresh_keys.discard(key)
        self._dialog._active_refresh_keys.discard(key)
        if not self._dialog._pending_refresh_keys and not self._dialog._active_refresh_keys:
            self.set_refresh_busy(False)

    def refresh_keys_from_payload(self, payload: dict[str, Any]):
        items_raw = payload.get("items")
        keys: set[str] = set()
        if isinstance(items_raw, list):
            for item in items_raw:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("key") or "").strip()
                if key != "":
                    keys.add(key)
        return keys

    def runtime_event_items(self, payload: dict[str, Any]):
        items_raw = payload.get("items")
        if not isinstance(items_raw, list):
            return []
        return [item for item in items_raw if isinstance(item, dict)]

    def runtime_download_message(
        self,
        event_name: RuntimeEventType | None,
        payload: dict[str, Any],
        fallback: str,
    ):
        items = self.runtime_event_items(payload)
        if not items:
            return fallback
        count = len(items)
        first_name = str(items[0].get("name") or "").strip()
        if event_name == RuntimeEventType.DOWNLOAD_STARTED:
            if count == 1 and first_name != "":
                return QC.translate("stats", "Refreshing subscription '{0}'.").format(
                    first_name
                )
            return QC.translate("stats", "Refreshing {0} subscriptions.").format(count)
        if event_name == RuntimeEventType.DOWNLOAD_FINISHED:
            if count == 1 and first_name != "":
                return QC.translate("stats", "Subscription '{0}' refreshed.").format(
                    first_name
                )
            return QC.translate("stats", "Refreshed {0} subscriptions.").format(count)
        if event_name == RuntimeEventType.DOWNLOAD_FAILED:
            if count == 1 and first_name != "":
                return QC.translate(
                    "stats", "Subscription '{0}' refresh failed."
                ).format(first_name)
            return QC.translate(
                "stats", "Refresh failed for {0} subscriptions."
            ).format(count)
        return fallback

    def handle_runtime_event(self, event: dict[str, Any]):
        payload = event if isinstance(event, dict) else {}
        message = str(payload.get("message") or "").strip()
        error_detail = str(payload.get("error") or "").strip()
        event_keys = self.refresh_keys_from_payload(payload)
        event_value = payload.get("event")
        if isinstance(event_value, int):
            try:
                event_name = RuntimeEventType(event_value)
            except Exception:
                event_name = None
        else:
            event_name = None
        is_error = event_name in (
            RuntimeEventType.RUNTIME_ERROR,
            RuntimeEventType.DOWNLOAD_FAILED,
            RuntimeEventType.FILE_SAVE_ERROR,
            RuntimeEventType.FILE_LOAD_ERROR,
        )
        if event_name == RuntimeEventType.DOWNLOAD_STARTED:
            for key in event_keys:
                if key in self._dialog._pending_refresh_keys:
                    self._dialog._pending_refresh_keys.discard(key)
                    self._dialog._active_refresh_keys.add(key)
            self.set_refresh_busy(True)
        elif event_name in (
            RuntimeEventType.DOWNLOAD_FINISHED,
            RuntimeEventType.DOWNLOAD_FAILED,
        ):
            for key in event_keys:
                self.clear_refresh_key(key)
            if event_name in (
                RuntimeEventType.DOWNLOAD_FINISHED,
                RuntimeEventType.DOWNLOAD_FAILED,
            ):
                self._dialog._table_data_controller.refresh_states()
                self._dialog._selection_controller.update_selected_actions_state()
        if event_name == RuntimeEventType.RUNTIME_ENABLED:
            self.set_runtime_state(active=True)
        elif event_name in (
            RuntimeEventType.RUNTIME_DISABLED,
            RuntimeEventType.RUNTIME_STOPPED,
        ):
            self.set_runtime_state(active=False)
        elif self._dialog._pending_runtime_reload is not None:
            self.set_runtime_state(
                active=None,
                text=QC.translate("stats", "Runtime: reloading"),
            )
        elif is_error:
            self.set_runtime_state(
                active=None, text=QC.translate("stats", "Runtime: error")
            )
        if self._dialog._pending_runtime_reload == "waiting_config_reload":
            if event_name == RuntimeEventType.CONFIG_RELOADED:
                self._dialog._pending_runtime_reload = None
                self._dialog._action_file_controller.load_action_file()
                return
            if is_error:
                self._dialog._pending_runtime_reload = None
        if message == "":
            message = QC.translate("stats", "Plugin runtime event: {0}").format(
                str(event_value or "unknown")
            )
        if event_name in (
            RuntimeEventType.DOWNLOAD_STARTED,
            RuntimeEventType.DOWNLOAD_FINISHED,
            RuntimeEventType.DOWNLOAD_FAILED,
        ):
            message = self.runtime_download_message(event_name, payload, message)
        if is_error and error_detail != "":
            message = f"{message} {error_detail}".strip()
        self._dialog._status_controller.set_status(
            message,
            error=is_error,
            origin="backend:event",
        )

    # -- Lifecycle ----------------------------------------------------------

    def _runtime_reload_failed_message(self):
        return QC.translate(
            "stats", "Config saved but runtime reload failed. Restart UI."
        )

    def start_runtime_clicked(self):
        runtime_plugin = self.sync_runtime_binding_state()
        if runtime_plugin is not None and bool(getattr(runtime_plugin, "enabled", False)):
            self.bind_runtime_plugin(runtime_plugin)
            self.set_runtime_state(active=True)
            self._dialog._status_controller.set_status(QC.translate("stats", "Runtime is already active."))
            return

        if not os.path.exists(self._dialog._action_path):
            self._dialog._status_controller.set_status(
                QC.translate(
                    "stats",
                    "Action file not found. Create and save the configuration first.",
                ),
                error=True,
            )
            return

        if runtime_plugin is None:
            runtime_plugin = ListSubscriptions({})

        self.bind_runtime_plugin(runtime_plugin)
        self.set_runtime_state(
            active=None,
            text=QC.translate("stats", "Runtime: starting"),
        )
        self._dialog._status_controller.append_log(
            QC.translate("stats", "Runtime start requested."),
        )
        try:
            runtime_plugin.signal_in.emit(
                {
                    "plugin": runtime_plugin.get_name(),
                    "signal": PluginSignal.ENABLE,
                    "action_path": self._dialog._action_path,
                }
            )
        except Exception:
            self.set_runtime_state(active=False)
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Failed to start runtime."),
                error=True,
            )

    def stop_runtime_clicked(self):
        runtime_plugin = self.sync_runtime_binding_state()
        if runtime_plugin is None or not bool(getattr(runtime_plugin, "enabled", False)):
            self.set_runtime_state(active=False)
            self._dialog._status_controller.set_status(QC.translate("stats", "Runtime is already inactive."))
            return

        self.bind_runtime_plugin(runtime_plugin)
        self.set_runtime_state(
            active=None,
            text=QC.translate("stats", "Runtime: stopping"),
        )
        self._dialog._status_controller.append_log(
            QC.translate("stats", "Runtime stop requested."),
        )
        try:
            runtime_plugin.signal_in.emit(
                {
                    "plugin": runtime_plugin.get_name(),
                    "signal": PluginSignal.DISABLE,
                    "action_path": self._dialog._action_path,
                }
            )
        except Exception:
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Failed to stop runtime."),
                error=True,
            )

    def reload_runtime_and_config(self):
        runtime_plugin = self.sync_runtime_binding_state()
        if runtime_plugin is None or not bool(getattr(runtime_plugin, "enabled", False)):
            self._dialog._action_file_controller.load_action_file()
            return

        self.bind_runtime_plugin(runtime_plugin)
        self._dialog._pending_runtime_reload = "waiting_config_reload"
        self._dialog._status_controller.append_log(
            QC.translate("stats", "Runtime config reload requested."),
        )
        try:
            runtime_plugin.signal_in.emit(
                {
                    "plugin": runtime_plugin.get_name(),
                    "signal": PluginSignal.CONFIG_UPDATE,
                    "action_path": self._dialog._action_path,
                }
            )
        except Exception:
            self._dialog._pending_runtime_reload = None
            self._dialog._status_controller.set_status(
                QC.translate("stats", "Runtime reload failed to start. Restart UI."),
                error=True,
            )

    def apply_runtime_state(self, enabled: bool):
        loaded = self.find_loaded_action()
        old_key, _old_action, old_plugin = loaded if loaded is not None else (None, None, None)
        runtime_plugin = ListSubscriptions.get_instance()
        target_plugin = runtime_plugin if runtime_plugin is not None else old_plugin
        was_enabled = bool(getattr(target_plugin, "enabled", False))

        if target_plugin is not None:
            self.bind_runtime_plugin(target_plugin)
            try:
                signal = None
                if enabled:
                    signal = (
                        PluginSignal.CONFIG_UPDATE
                        if was_enabled
                        else PluginSignal.ENABLE
                    )
                elif was_enabled:
                    signal = PluginSignal.DISABLE

                if signal is not None:
                    target_plugin.signal_in.emit(
                        {
                            "plugin": target_plugin.get_name(),
                            "signal": signal,
                            "action_path": self._dialog._action_path,
                        }
                    )
            except Exception:
                self._dialog._status_controller.set_status(
                    self._runtime_reload_failed_message(),
                    error=True,
                )
                return
            if not enabled and old_key is not None:
                self._dialog._actions.delete(old_key)
            return

        if not enabled:
            if old_key is not None:
                self._dialog._actions.delete(old_key)
            return

        obj, compiled = self._dialog._actions.load(self._dialog._action_path)
        if obj is None or compiled is None:
            self._dialog._status_controller.set_status(
                self._runtime_reload_failed_message(),
                error=True,
            )
            return

        obj = cast(dict[str, Any], obj)
        compiled = cast(dict[str, Any], compiled)
        action_name = obj.get("name")
        if old_key is not None and old_key != action_name:
            self._dialog._actions.delete(old_key)
        if isinstance(action_name, str) and action_name != "":
            self._dialog._actions._actions_list[action_name] = compiled

        compiled_actions = cast(dict[str, Any], compiled.get("actions", {}))
        plug = cast(
            ListSubscriptions | None, compiled_actions.get("list_subscriptions")
        )
        if plug is None:
            self._dialog._status_controller.set_status(
                self._runtime_reload_failed_message(),
                error=True,
            )
            return
        self.bind_runtime_plugin(plug)
        try:
            plug.signal_in.emit(
                {
                    "plugin": plug.get_name(),
                    "signal": PluginSignal.ENABLE,
                    "action_path": self._dialog._action_path,
                }
            )
        except Exception:
            self._dialog._status_controller.set_status(
                self._runtime_reload_failed_message(),
                error=True,
            )

    def sync_runtime_binding_state(self):
        runtime_plugin = ListSubscriptions.get_instance()
        if runtime_plugin is None:
            loaded = self.find_loaded_action()
            runtime_plugin = loaded[2] if loaded is not None else None

        if runtime_plugin is not None:
            self.bind_runtime_plugin(runtime_plugin)
            self.set_runtime_state(
                active=bool(getattr(runtime_plugin, "enabled", False)),
            )
            return runtime_plugin

        self._dialog._runtime_plugin = None
        self._dialog._status_controller.set_backend_log_sink(None)
        self.set_runtime_state(active=False)
        self.set_refresh_busy(False)
        return None

    def bind_runtime_plugin(self, plug: ListSubscriptions | None):
        if plug is None:
            self._dialog._status_controller.set_backend_log_sink(None)
            return
        try:
            plug.signal_out.disconnect(self.handle_runtime_event)
        except Exception:
            pass
        try:
            plug.log_out.disconnect(self._dialog._status_controller.ingest_backend_log)
        except Exception:
            pass
        try:
            plug.signal_out.connect(self.handle_runtime_event)
            plug.log_out.connect(self._dialog._status_controller.ingest_backend_log)
            self._dialog._status_controller.set_backend_log_sink(plug.ingest_ui_log)
            self._dialog._runtime_plugin = plug
        except Exception:
            self._dialog._status_controller.set_backend_log_sink(None)
            self._dialog._runtime_plugin = None

    def find_loaded_action(self):
        for action_key, action_obj in self._dialog._actions.getAll().items():
            if action_obj is None:
                continue
            action_obj_dict = cast(dict[str, Any], action_obj)
            action_cfg = cast(dict[str, Any], action_obj_dict.get("actions", {}))
            plug = cast(ListSubscriptions | None, action_cfg.get("list_subscriptions"))
            if plug is not None:
                return str(action_key), action_obj_dict, plug
