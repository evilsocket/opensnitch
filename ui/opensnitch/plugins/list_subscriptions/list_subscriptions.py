import os
import logging
import hashlib
import threading
import shutil
import sys
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast
from abc import ABCMeta
from datetime import datetime, timedelta
from queue import Queue
import requests

if TYPE_CHECKING:
    from PyQt6 import QtCore, QtGui, QtWidgets
elif "PyQt6" in sys.modules:
    from PyQt6 import QtCore, QtGui, QtWidgets
elif "PyQt5" in sys.modules:
    from PyQt5 import QtCore, QtGui, QtWidgets
else:
    try:
        from PyQt6 import QtCore, QtGui, QtWidgets
    except Exception:
        from PyQt5 import QtCore, QtGui, QtWidgets

from opensnitch.plugins.list_subscriptions._compat import StatsDialog
from opensnitch.plugins.list_subscriptions._annotations import StatsDialogProto
if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )

from opensnitch.plugins.list_subscriptions.io.lock import FileLock
from opensnitch.plugins.list_subscriptions.io.storage import read_json_locked
from opensnitch.plugins.list_subscriptions.models.config import PluginConfig
from opensnitch.plugins.list_subscriptions.models.events import (
    RuntimeEventType,
    SubscriptionEventItem,
)
from opensnitch.plugins.list_subscriptions.models.metadata import ListMetadata
from opensnitch.plugins.list_subscriptions.models.subscriptions import SubscriptionSpec
from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.notifications import DesktopNotifications
from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.rules import Rule
from opensnitch.database import Database
from opensnitch.utils import GenericTimer
from opensnitch.plugins.list_subscriptions._utils import (
    ACTION_FILE,
    DEFAULT_LISTS_DIR,
    DEFAULT_UA,
    is_hosts_file_like,
    list_file_path,
    normalize_groups,
    normalize_lists_dir,
    now_iso,
    parse_iso,
    subscription_dirname,
)
from opensnitch.plugins.list_subscriptions.io.storage import (
    write_json_atomic_locked,
)
from opensnitch.proto import ui_pb2 as ui_pb2


ch: Final[logging.StreamHandler] = logging.StreamHandler()
# ch.setLevel(logging.ERROR)
formatter: Final[logging.Formatter] = logging.Formatter(
    "%(asctime)s - %(name)s - [%(levelname)s] %(message)s"
)
ch.setFormatter(formatter)
logger: Final[logging.Logger] = logging.getLogger(__name__)
logger.addHandler(ch)
logger.setLevel(logging.WARNING)


# -------------------- plugin core --------------------


class _LogSignalWrapper(QtCore.QObject):
    """Thin QObject container for the (message, level) log signal.
    Follows the same pattern as PluginSignal so the runtime can emit
    structured log entries directly to the UI status controller.
    """
    signal = QtCore.pyqtSignal(str, str, str)

    def emit(self, message: str, level: str = "INFO", origin: str = "backend") -> None:
        self.signal.emit(message, level, origin)

    def connect(self, callback: Any) -> None:
        self.signal.connect(callback)

    def disconnect(self, callback: Any) -> None: # pyright: ignore[reportIncompatibleMethodOverride]
        self.signal.disconnect(callback)


class _UiLogBridgeHandler(logging.Handler):
    """Relays backend logger records into the UI live log signal."""

    def __init__(self, sink: _LogSignalWrapper):
        super().__init__(level=logging.DEBUG)
        self._sink = sink

    @staticmethod
    def _level_name(record: logging.LogRecord) -> str:
        if record.levelno >= logging.ERROR:
            return "ERROR"
        if record.levelno >= logging.WARNING:
            return "WARN"
        if record.levelno >= logging.INFO:
            return "INFO"
        return "DEBUG"

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if bool(getattr(record, "_skip_ui_bridge", False)):
                return
            message = record.getMessage().strip()
            if message == "":
                return
            self._sink.emit(message, self._level_name(record), "backend")
        except Exception:
            pass


class SingletonABCMeta(ABCMeta):
    _instances: dict[type, object] = {}
    _lock = threading.Lock()

    def __call__(cls, *args: Any, **kwargs: Any):
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class ListSubscriptions(PluginBase, metaclass=SingletonABCMeta):
    """A plugin to manage list subscriptions (e.g. blocklists).

    The plugin is configured via a JSON file specifying a list of subscriptions.
    Each subscription has a URL and a local filename to save to.
    The plugin periodically checks each URL for updates, using HTTP cache validators to avoid unnecessary downloads.
    Metadata about each subscription is stored in a metadata JSON file (same name + .meta.json) to track last update time, errors, backoff, etc.
    The plugin exposes a results queue for the UI to display subscription status and errors.
    """

    # fields overriden from parent class
    name: ClassVar[str] = "List_subscriptions"
    version: ClassVar[int] = 0
    author: ClassVar[str] = "opensnitch"
    created: ClassVar[str] = ""
    modified: ClassVar[str] = ""
    enabled: bool = False
    description: ClassVar[str] = (
        "Manage list subscriptions (e.g. blocklists) with periodic updates"
    )

    # default
    TYPE: ClassVar[list[Any]] = [PluginBase.TYPE_GLOBAL]

    # UI log signal — connect to DialogStatusController.log to forward
    # runtime messages to the main window's live log facility.
    log_out: ClassVar[_LogSignalWrapper] = _LogSignalWrapper()
    _ui_log_bridge_handler_installed: ClassVar[bool] = False

    # runtime state
    scheduled_tasks: dict[str, GenericTimer] = {}
    default_conf: ClassVar[str] = ACTION_FILE
    default_lists_dir: ClassVar[str] = DEFAULT_LISTS_DIR
    REFRESH_SUBSCRIPTIONS_SIGNAL: ClassVar[str] = "refresh_subscriptions"

    @classmethod
    def get_instance(cls) -> "ListSubscriptions | None":
        instance = SingletonABCMeta._instances.get(cls)
        if isinstance(instance, cls):
            return instance
        return None

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        if getattr(self, "_initialized", False):
            self._load_action_config(config)
            return

        self._initialized = True
        self._ensure_ui_log_bridge_handler()
        self.signal_in.connect(self.cb_signal)
        self._desktop_notifications = DesktopNotifications()
        self._db = Database.instance()
        self._nodes = Nodes.instance()
        self._ok_msg = ""
        self._err_msg = ""
        self._notify: dict[str, Any] | None = None
        self._notify_title = "[OpenSnitch] List subscriptions downloader"
        self._resultsQueue: Queue[tuple[str, bool, str]] = Queue()
        self._app_icon = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "../../res/icon-white.svg"
        )
        self._cfg_dialog: ListSubscriptionsDialog | None = None
        self._cfg_action: QtGui.QAction | None = None
        self._cfg_toolbar_button: QtWidgets.QPushButton | None = None
        self.scheduled_tasks = {}
        self._startup_recheck_lock = threading.Lock()
        self._startup_recheck_pending = False
        self._startup_recheck_scheduled = False
        self._nodes.nodesUpdated.connect(self._on_nodes_updated)
        self._load_action_config(config)

        # Set up requests session with default UA
        self._session: requests.Session = requests.Session()
        if self._config.defaults.user_agent:
            self._session.headers.update(
                {"User-Agent": self._config.defaults.user_agent}
            )
        else:
            self._session.headers.update({"User-Agent": DEFAULT_UA})

    @classmethod
    def _ensure_ui_log_bridge_handler(cls) -> None:
        if cls._ui_log_bridge_handler_installed:
            return
        logger.addHandler(_UiLogBridgeHandler(cls.log_out))
        cls._ui_log_bridge_handler_installed = True

    @staticmethod
    def _backend_level(level: str) -> int:
        normalized = (level or "INFO").strip().upper()
        if normalized in ("TRACE", "DEBUG"):
            return logging.DEBUG
        if normalized in ("WARN", "WARNING"):
            return logging.WARNING
        if normalized == "ERROR":
            return logging.ERROR
        if normalized == "CRITICAL":
            return logging.CRITICAL
        return logging.INFO

    def _log_backend(
        self,
        message: str,
        level: str = "INFO",
        *,
        suppress_ui_bridge: bool = False,
    ) -> None:
        full_text = (message or "").strip()
        if full_text == "":
            return
        logger.log(
            self._backend_level(level),
            full_text,
            extra={"_skip_ui_bridge": bool(suppress_ui_bridge)},
        )

    def ingest_ui_log(
        self,
        message: str,
        level: str = "INFO",
        origin: str = "ui",
    ) -> None:
        """UI -> backend bridge: write UI logs to the backend true logger."""
        self._log_backend(
            f"[{origin}] {message}",
            level,
            suppress_ui_bridge=True,
        )

    def log_debug(self, message: str) -> None:
        self._log_backend(message, "DEBUG")

    def log_info(self, message: str) -> None:
        self._log_backend(message, "INFO")

    def log_warn(self, message: str) -> None:
        self._log_backend(message, "WARN")

    def log_error(self, message: str) -> None:
        self._log_backend(message, "ERROR")

    def _emit_runtime_event(
        self,
        event: RuntimeEventType,
        message: str,
        *,
        error: str | None = None,
        action_path: str | None = None,
        target: str | None = None,
        path: str | None = None,
        source: str | None = None,
        state: str | None = None,
        items: list[dict[str, Any]] | list[SubscriptionEventItem] | None = None,
    ):
        payload: dict[str, Any] = {
            "plugin": self.get_name(),
            "event": event,
            "message": message,
        }
        if action_path:
            payload["action_path"] = action_path
        if error:
            payload["error"] = error
        if target:
            payload["target"] = target
        if path:
            payload["path"] = path
        if source:
            payload["source"] = source
        if state:
            payload["state"] = state
        if items:
            payload["items"] = items
        self.signal_out.emit(payload)

    def _load_action_config(self, action_cfg: dict[str, Any] | None = None):
        action_cfg = action_cfg or {}
        self.enabled = bool(action_cfg.get("enabled") is True)

        plugin_cfg: Any = action_cfg.get("config", {})
        if not isinstance(plugin_cfg, dict):
            plugin_cfg = {}
        self._config = PluginConfig.from_dict(
            plugin_cfg,
            lists_dir=self.default_lists_dir,
        )
        self._notify = plugin_cfg.get("notify")
        self._ok_msg = ""
        self._err_msg = ""
        if isinstance(self._notify, dict):
            ok = self._notify.get("success")
            err = self._notify.get("error")
            if isinstance(ok, dict):
                ok_msg = ok.get("desktop")
                if ok_msg:
                    self._ok_msg = ok_msg
            if isinstance(err, dict):
                err_msg = err.get("desktop")
                if err_msg:
                    self._err_msg = err_msg
        else:
            self._notify = None

    def _config_update_diff_targets(
        self,
        previous_subscriptions: list[SubscriptionSpec],
    ):
        previous_enabled_by_key = {
            self._sub_key(sub): bool(sub.enabled) for sub in previous_subscriptions
        }
        targets: list[SubscriptionSpec] = []
        try:
            current_subscriptions = list(self._config.subscriptions)
        except Exception:
            current_subscriptions = []
        for sub in current_subscriptions:
            if not sub.enabled:
                continue
            old_enabled = previous_enabled_by_key.get(self._sub_key(sub))
            if old_enabled is None or old_enabled is False:
                targets.append(sub)
        return targets

    def _apply_config_update_diff(
        self,
        previous_subscriptions: list[SubscriptionSpec],
    ):
        refresh_targets = self._config_update_diff_targets(previous_subscriptions)
        if not refresh_targets:
            return
        th = threading.Thread(
            target=self.refresh_subscriptions,
            args=(refresh_targets, "config_update"),
            daemon=True,
        )
        th.start()

    def _start_runtime(self, *, recheck: bool):
        if not self.enabled:
            return

        for t in self.scheduled_tasks.values():
            try:
                t.start()
            except Exception:
                pass

        if recheck:
            if self._has_ready_local_node():
                self._schedule_startup_recheck(delay=0.5)
            else:
                with self._startup_recheck_lock:
                    self._startup_recheck_pending = True
                logger.info(
                    "deferring startup refresh until a local node is connected"
                )

    def disable_runtime(self):
        self.enabled = False
        with self._startup_recheck_lock:
            self._startup_recheck_pending = False
        self.stop()

    def _has_ready_local_node(self) -> bool:
        for addr in self._nodes.get().keys():
            if not self._nodes.is_local(addr):
                continue
            if self._nodes.is_connected(addr):
                return True
        return False

    def _schedule_startup_recheck(self, *, delay: float):
        with self._startup_recheck_lock:
            if self._startup_recheck_scheduled:
                return
            self._startup_recheck_pending = False
            self._startup_recheck_scheduled = True

        def _run():
            try:
                self._startup_recheck_all()
            finally:
                with self._startup_recheck_lock:
                    self._startup_recheck_scheduled = False

        timer = threading.Timer(delay, _run)
        timer.daemon = True
        timer.start()

    def _on_nodes_updated(self, total: int):
        if total <= 0 or not self.enabled:
            return
        with self._startup_recheck_lock:
            pending = self._startup_recheck_pending
        if pending and self._has_ready_local_node():
            logger.info("local node connected, running deferred startup refresh")
            self._schedule_startup_recheck(delay=0.5)

    def _reload_from_action_file(self, action_path: str | None = None):
        action_path = (action_path or self.default_conf).strip() or self.default_conf
        try:
            raw_action = read_json_locked(action_path)
            self._emit_runtime_event(
                RuntimeEventType.FILE_LOAD_FINISHED,
                "Runtime configuration loaded.",
                action_path=action_path,
                target="action_config",
                path=action_path,
            )
        except Exception as exc:
            logger.warning(
                "failed to read action file %s: %r",
                action_path,
                exc,
            )
            self._emit_runtime_event(
                RuntimeEventType.FILE_LOAD_ERROR,
                "Failed to load runtime configuration.",
                error=str(exc),
                action_path=action_path,
                target="action_config",
                path=action_path,
            )
            return False, str(exc)

        if not isinstance(raw_action, dict):
            logger.warning(
                "invalid action payload in %s: %r",
                action_path,
                type(raw_action).__name__, # pyright: ignore[reportCallIssue]
            )
            return False, f"invalid action payload type: {type(raw_action).__name__}"

        actions_obj = raw_action.get("actions", {})
        if not isinstance(actions_obj, dict):
            actions_obj = {}
        action_cfg = actions_obj.get("list_subscriptions", {})
        if not isinstance(action_cfg, dict):
            action_cfg = {}
        self._load_action_config(action_cfg)

        self._session.headers.update(
            {"User-Agent": self._config.defaults.user_agent or DEFAULT_UA}
        )
        self.compile()
        return True, None

    # -------- metadata/files handling --------

    def _paths(self, sub: SubscriptionSpec):
        if self._config is None:
            raise RuntimeError("PluginConfig is not loaded")
        lists_dir = normalize_lists_dir(self._config.defaults.lists_dir)
        os.makedirs(lists_dir, mode=0o700, exist_ok=True)
        sources_dir = os.path.join(lists_dir, "sources.list.d")
        os.makedirs(sources_dir, mode=0o700, exist_ok=True)
        list_path = list_file_path(lists_dir, sub.filename, sub.format)
        meta_path = list_path + ".meta.json"
        return list_path, meta_path

    def _subscription_dirname(self, sub: SubscriptionSpec):
        return subscription_dirname(sub.filename, sub.format)

    def _rules_root_dir(self):
        if self._config is None:
            return os.path.join(self.default_lists_dir, "rules.list.d")
        return os.path.join(
            normalize_lists_dir(self._config.defaults.lists_dir), "rules.list.d"
        )

    def _sources_root_dir(self):
        if self._config is None:
            return os.path.join(self.default_lists_dir, "sources.list.d")
        return os.path.join(
            normalize_lists_dir(self._config.defaults.lists_dir), "sources.list.d"
        )

    def _sync_sources_dirs(self):
        if self._config is None:
            return
        sources_dir = self._sources_root_dir()
        os.makedirs(sources_dir, mode=0o700, exist_ok=True)

        desired_paths: set[str] = set()
        for sub in self._config.subscriptions:
            list_path, meta_path = self._paths(sub)
            desired_paths.add(list_path)
            desired_paths.add(meta_path)

        for entry in os.listdir(sources_dir):
            p = os.path.join(sources_dir, entry)
            try:
                if p not in desired_paths:
                    os.unlink(p)
            except Exception:
                pass

    def _sync_global_symlinks(self):
        if self._config is None:
            return
        rules_dir = self._rules_root_dir()
        os.makedirs(rules_dir, mode=0o700, exist_ok=True)
        desired: dict[str, dict[str, str]] = {}
        for idx, sub in enumerate(self._config.subscriptions):
            if not getattr(sub, "enabled", True):
                continue
            list_path, _ = self._paths(sub)
            if not os.path.exists(list_path):
                continue
            raw_groups: tuple[str, ...] = getattr(sub, "groups", tuple())
            groups = [
                self._subscription_dirname(sub),
                "all",
                *normalize_groups(raw_groups),
            ]
            link_name = f"{idx:02d}-{os.path.basename(list_path)}"
            for group in groups:
                desired.setdefault(group, {})[link_name] = list_path

        existing_groups: set[str] = set()
        for name in os.listdir(rules_dir):
            p = os.path.join(rules_dir, name)
            if os.path.isdir(p) and not os.path.islink(p):
                existing_groups.add(name)
                if name not in desired:
                    try:
                        shutil.rmtree(p)
                    except Exception:
                        pass
            else:
                try:
                    os.unlink(p)
                except Exception:
                    pass

        for group_name in existing_groups | set(desired.keys()):
            group_dir = os.path.join(rules_dir, group_name)
            desired_links = desired.get(group_name, {})
            if desired_links:
                os.makedirs(group_dir, mode=0o700, exist_ok=True)
            try:
                existing_entries = os.listdir(group_dir)
            except Exception:
                existing_entries = []

            for entry in existing_entries:
                entry_path = os.path.join(group_dir, entry)
                if entry not in desired_links:
                    try:
                        if os.path.isdir(entry_path) and not os.path.islink(entry_path):
                            shutil.rmtree(entry_path)
                        else:
                            os.unlink(entry_path)
                    except Exception:
                        pass
                    continue

                expected_target = desired_links[entry]
                in_sync = False
                try:
                    if os.path.islink(entry_path):
                        in_sync = os.path.realpath(entry_path) == os.path.realpath(
                            expected_target
                        )
                except Exception:
                    in_sync = False

                if not in_sync:
                    try:
                        if os.path.isdir(entry_path) and not os.path.islink(entry_path):
                            shutil.rmtree(entry_path)
                        else:
                            os.unlink(entry_path)
                    except Exception:
                        pass

            for link_name, target in desired_links.items():
                link_path = os.path.join(group_dir, link_name)
                if os.path.lexists(link_path):
                    continue
                try:
                    os.symlink(target, link_path)
                except Exception:
                    try:
                        shutil.copy2(target, link_path)
                    except Exception:
                        pass

    def _load_meta(self, meta_path: str):
        try:
            meta = ListMetadata.from_dict(read_json_locked(meta_path))
            self._emit_runtime_event(
                RuntimeEventType.FILE_LOAD_FINISHED,
                "Subscription metadata loaded.",
                target="subscription_meta",
                path=meta_path,
            )
            return meta
        except Exception as exc:
            self._emit_runtime_event(
                RuntimeEventType.FILE_LOAD_ERROR,
                "Failed to load subscription metadata.",
                error=str(exc),
                target="subscription_meta",
                path=meta_path,
            )
            return ListMetadata()

    def _save_meta(self, meta_path: str, meta: ListMetadata):
        try:
            write_json_atomic_locked(meta_path, meta.to_dict())
            self._emit_runtime_event(
                RuntimeEventType.FILE_SAVE_FINISHED,
                "Subscription metadata saved.",
                target="subscription_meta",
                path=meta_path,
                state=meta.last_result or None,
            )
        except Exception as exc:
            self._emit_runtime_event(
                RuntimeEventType.FILE_SAVE_ERROR,
                "Failed to save subscription metadata.",
                error=str(exc),
                target="subscription_meta",
                path=meta_path,
                state=meta.last_result or None,
            )
            raise

    def _fsync_parent_dir(self, path: str):
        parent = os.path.dirname(path)
        if parent == "":
            return
        try:
            dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except Exception:
            return
        try:
            os.fsync(dir_fd)
        except Exception:
            pass
        finally:
            os.close(dir_fd)

    def _affected_rule_dirs(self, sub: SubscriptionSpec):
        affected_dirs = {
            os.path.join(self._rules_root_dir(), self._subscription_dirname(sub))
        }
        rules_root = self._rules_root_dir()
        affected_dirs.add(os.path.join(rules_root, "all"))
        for group in normalize_groups(sub.groups):
            affected_dirs.add(os.path.join(rules_root, group))
        return {os.path.normpath(path) for path in affected_dirs if path.strip() != ""}

    def _reload_rules_for_updated_subscription(self, sub: SubscriptionSpec):
        try:
            affected_dirs = self._affected_rule_dirs(sub)
            found_match = False
            for addr in self._nodes.get().keys():
                if not self._nodes.is_local(addr):
                    continue
                records = self._db.get_rules(addr)
                if records is None or records == -1:
                    continue
                matched = False
                while records.next():
                    rule = cast(ui_pb2.Rule, Rule.new_from_records(records))
                    if rule.operator.operand == Config.OPERAND_LIST_DOMAINS:
                        direct_dir = os.path.normpath(
                            str(rule.operator.data or "").strip()
                        )
                        if direct_dir in affected_dirs:
                            matched = True
                    if not matched:
                        for operator in getattr(rule.operator, "list", []):
                            if operator.operand != Config.OPERAND_LIST_DOMAINS:
                                continue
                            nested_dir = os.path.normpath(
                                str(operator.data or "").strip()
                            )
                            if nested_dir in affected_dirs:
                                matched = True
                                break
                    if not matched:
                        continue

                    notification = ui_pb2.Notification(
                        type=ui_pb2.CHANGE_RULE,
                        rules=[rule],
                    )
                    self._nodes.send_notification(addr, notification, None)
                    found_match = True
                    logger.info(
                        "signaling affected rule '%s' for updated subscription '%s'",
                        rule.name,
                        sub.name,
                    )
                    break
            if found_match is False:
                logger.info(
                    "no matching rules found for updated subscription '%s'",
                    sub.name,
                )
        except Exception as e:
            logger.warning(
                "reload rules after updating '%s' failed: %s",
                sub.name,
                repr(e),
            )

    # -------- timer lifecycle --------

    def _sub_key(self, sub: SubscriptionSpec):
        base = f"{sub.url}|{sub.filename}"
        return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]

    def configure(self, parent: StatsDialogProto | None = None):
        if isinstance(parent, StatsDialog):
            if self._cfg_action is not None or self._cfg_toolbar_button is not None:
                return

            icon_path = os.path.join(
                os.path.abspath(os.path.dirname(__file__)), "res", "blocklist.svg"
            )
            icon = (
                QtGui.QIcon(icon_path) if os.path.exists(icon_path) else QtGui.QIcon()
            )
            if self._install_toolbar_button(parent, icon):
                self._remove_menu_action(parent)
                return
            self._install_menu_action(parent, icon)

    def _install_toolbar_button(self, parent: StatsDialogProto, icon: QtGui.QIcon):
        actions_button = getattr(parent, "actionsButton", None)
        if not isinstance(actions_button, QtWidgets.QPushButton):
            return False
        button_parent = actions_button.parentWidget()
        if button_parent is None:
            return False
        layout = self._find_layout_containing_widget(
            button_parent.layout(), actions_button
        )
        if not isinstance(layout, QtWidgets.QHBoxLayout):
            return False

        insert_at = -1
        reference_button: QtWidgets.QPushButton | None = None
        for idx in range(layout.count()):
            item = layout.itemAt(idx)
            if item is None:
                continue
            if item.spacerItem() is not None:
                insert_at = idx
                break
            widget = item.widget()
            if isinstance(widget, QtWidgets.QPushButton):
                reference_button = widget
        if insert_at < 0:
            insert_at = layout.count()
        if reference_button is None:
            return False

        button = QtWidgets.QPushButton(button_parent)  # pyright: ignore[reportCallIssue,reportArgumentType]
        button.setObjectName("listSubscriptionsButton")
        button.setText("")
        button.setToolTip("List subscriptions")
        button.setStatusTip("Open list subscriptions")
        button.setFlat(True)
        if not icon.isNull():
            button.setIcon(icon)
        button.setCursor(reference_button.cursor())  # pyright: ignore[reportArgumentType]
        button.setFocusPolicy(reference_button.focusPolicy())  # pyright: ignore[reportArgumentType]
        button.setSizePolicy(reference_button.sizePolicy())  # pyright: ignore[reportArgumentType]
        button.setMinimumSize(reference_button.minimumSize())  # pyright: ignore[reportArgumentType]
        button.setMaximumHeight(reference_button.maximumHeight())  # pyright: ignore[reportArgumentType]
        button.setIconSize(reference_button.iconSize())  # pyright: ignore[reportArgumentType]

        layout.insertWidget(insert_at, button)  # pyright: ignore[reportArgumentType]
        button.clicked.connect(lambda *_: self._open_config_dialog(parent))
        self._cfg_toolbar_button = button
        return True

    def _find_layout_containing_widget(
        self,
        layout: QtWidgets.QLayout | None,
        target: QtWidgets.QWidget,
    ):
        if layout is None:
            return None
        for idx in range(layout.count()):
            item = layout.itemAt(idx)
            if item is None:
                continue
            widget = item.widget()
            if widget is target:
                return layout
            if isinstance(widget, QtWidgets.QWidget):
                found = self._find_layout_containing_widget(widget.layout(), target)
                if found is not None:
                    return found
            child_layout = item.layout()
            if child_layout is not None:
                found = self._find_layout_containing_widget(child_layout, target)
                if found is not None:
                    return found
        return None

    def _install_menu_action(self, parent: StatsDialogProto, icon: QtGui.QIcon):
        menu = parent.actionsButton.menu()
        if menu is None:
            return

        quit_action = self._find_quit_action(menu)
        if quit_action is not None:
            if not icon.isNull():
                self._cfg_action = menu.addAction(icon, "List subscriptions")
            else:
                self._cfg_action = menu.addAction("List subscriptions")
            menu.insertAction(quit_action, self._cfg_action)
        else:
            acts = menu.actions()
            if acts and not acts[-1].isSeparator():
                menu.addSeparator()
            if not icon.isNull():
                self._cfg_action = menu.addAction(icon, "List subscriptions")
            else:
                self._cfg_action = menu.addAction("List subscriptions")

        if self._cfg_action is not None:
            self._cfg_action.triggered.connect(lambda *_: self._open_config_dialog(parent))

    def _remove_menu_action(self, parent: StatsDialogProto):
        menu = parent.actionsButton.menu()
        if menu is None:
            return
        text = "list subscriptions"
        for action in list(menu.actions()):
            if (action.text() or "").replace("&", "").strip().lower() == text:
                menu.removeAction(action)
                if action is self._cfg_action:
                    self._cfg_action = None
                break

    def _find_quit_action(self, menu: QtWidgets.QMenu) -> QtGui.QAction | None:
        qt_key = getattr(getattr(QtCore, "Qt", object()), "Key", None)
        key_q = getattr(qt_key, "Key_Q", None) if qt_key is not None else None
        for act in menu.actions():
            if act.isSeparator():
                continue
            txt = (act.text() or "").replace("&", "").strip().lower()
            if txt == "quit":
                return act
            shortcut = act.shortcut()
            if (
                key_q is not None
                and shortcut
                and shortcut.matches(QtGui.QKeySequence(key_q))
            ):
                return act
        # In OpenSnitch main actions menu, Quit is typically the last entry.
        acts = [a for a in menu.actions() if not a.isSeparator()]
        if acts:
            return acts[-1]
        return None

    def _open_config_dialog(self, parent: StatsDialogProto):
        from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
            ListSubscriptionsDialog,
        )

        appicon = None
        try:
            appicon = parent.windowIcon()
        except Exception:
            appicon = None

        if self._cfg_dialog is None:
            # Some wrapped dialog types are not accepted as QWidget parents by
            # PyQt6 constructors in plugin context. Use a top-level dialog.
            self._cfg_dialog = ListSubscriptionsDialog(
                parent=None, appicon=appicon
            )
        self._cfg_dialog.show()
        self._cfg_dialog.raise_()
        self._cfg_dialog.activateWindow()

    def compile(self):
        """
        Build one GenericTimer per subscription.
        Stops timers removed from config.
        """
        if not self._config:
            return

        latest_keys: set[str] = set()

        for sub in self._config.subscriptions:
            if not sub.enabled:
                continue

            key = self._sub_key(sub)
            latest_keys.add(key)

            if self._config is None:
                continue
            interval_s = sub.interval_seconds

            # recreate timer (simple, applies interval changes)
            if key in self.scheduled_tasks:
                try:
                    self.scheduled_tasks[key].stop()
                except Exception:
                    pass

            self.scheduled_tasks[key] = GenericTimer(
                interval_s, True, self.cb_run_tasks, (key, sub)
            )

        # stop removed timers
        for key in list(self.scheduled_tasks.keys()):
            if key not in latest_keys:
                try:
                    self.scheduled_tasks[key].stop()
                except Exception:
                    pass
                self.scheduled_tasks.pop(key, None)
        self._sync_sources_dirs()
        self._sync_global_symlinks()

    def run(self, parent: StatsDialogProto | None = None, args: tuple[Any, ...] = ()):  # type: ignore[override]
        """
        Start timers.
        """

        if isinstance(parent, StatsDialog):
            pass
        self._start_runtime(recheck=True)

    def _startup_recheck_all(self):
        if self._config is None or not self.enabled:
            return
        if not self._has_ready_local_node():
            with self._startup_recheck_lock:
                self._startup_recheck_pending = True
            logger.info("startup refresh skipped, no local node is ready yet")
            return
        for sub in self._config.subscriptions:
            if not sub.enabled:
                continue
            try:
                self.refresh_subscriptions(sub, source="startup_recheck")
            except Exception as e:
                logger.error(
                    "startup recheck error name='%s' err=%s",
                    sub.name,
                    repr(e),
                )
        self._sync_global_symlinks()

    def stop(self):
        """
        Stop timers and clear them from memory.
        """
        for t in self.scheduled_tasks.values():
            try:
                t.stop()
            except Exception:
                pass
        self.scheduled_tasks.clear()

    # -------- scheduled execution --------

    def cb_run_tasks(self, args: tuple[str, SubscriptionSpec]):
        """
        Timer callback for one subscription.
        Mirrors downloader behavior: start worker thread, join it,
        then immediately evaluate queued result.
        """
        key: str
        sub: SubscriptionSpec
        key, sub = args

        # due/backoff gate via metadata
        _, meta_path = self._paths(sub)
        meta = self._load_meta(meta_path)

        if self._in_backoff(meta):
            logger.info("skip '%s' (in backoff)", sub.name)
            return
        if not self._is_due(meta, sub):
            logger.info("skip '%s' (not due yet)", sub.name)
            return

        th = threading.Thread(target=self.download, args=(sub,))
        th.start()
        th.join()

        matched: list[tuple[str, bool, str]] = []
        unmatched: list[tuple[str, bool, str]] = []
        while not self._resultsQueue.empty():
            item = self._resultsQueue.get_nowait()
            if len(item) >= 3 and item[0] == key:
                matched.append(item)
            else:
                unmatched.append(item)
        for item in unmatched:
            self._resultsQueue.put(item)

        if not matched:
            logger.debug("cb_run_tasks: no result for key=%s sub=%s", key, sub.name)
            return

        updated: bool = False
        statuses: list[str] = []
        for _, ok, status in matched:
            updated = ok
            statuses.append(status)
        if updated:
            result_msg = self._ok_msg or f"{sub.name}: {', '.join(statuses)}"
        else:
            result_msg = self._err_msg or f"{sub.name} failed: {', '.join(statuses)}"

        if (
            self._notify is not None
            and self._desktop_notifications.is_available()
            and self._desktop_notifications.are_enabled()
        ):
            self._desktop_notifications.show(
                self._notify_title, result_msg, self._app_icon
            )

    def refresh_subscriptions(
        self,
        subscriptions: SubscriptionSpec | list[SubscriptionSpec],
        source: str = "scheduled",
        force: bool = False,
    ):
        ok = self.download(
            subscriptions,
            force=force,
            source=source,
            emit_download_events=True,
        )
        self._sync_global_symlinks()
        return ok

    def cb_signal(self, signal: dict[str, Any]):
        try:
            sig = signal.get("signal")
            action_path = signal.get("action_path")

            if sig == PluginSignal.ENABLE:
                logger.debug(
                    "cb_signal: ENABLE action_path=%r",
                    action_path,
                )
                ok, err = self._reload_from_action_file(action_path)
                if ok:
                    self.enabled = True
                    self.run()
                    self._emit_runtime_event(
                        RuntimeEventType.RUNTIME_ENABLED,
                        "Plugin runtime enabled.",
                        action_path=action_path,
                    )
                    logger.info("plugin runtime enabled")
                else:
                    self._emit_runtime_event(
                        RuntimeEventType.RUNTIME_ERROR,
                        "Failed to enable plugin runtime.",
                        error=err,
                        action_path=action_path,
                    )
                    logger.error("Failed to enable plugin runtime: %s", repr(err))

                return

            if sig == self.REFRESH_SUBSCRIPTIONS_SIGNAL:
                raw_items = signal.get("items")
                source = str(signal.get("source") or "manual_refresh")
                subscriptions: list[SubscriptionSpec] = []
                if isinstance(raw_items, list):
                    for raw_item in raw_items:
                        if not isinstance(raw_item, dict):
                            continue
                        try:
                            sub = SubscriptionSpec.from_dict(
                                raw_item,
                                self._config.defaults,
                            )
                        except Exception:
                            sub = None
                        if sub is not None:
                            subscriptions.append(sub)
                if not subscriptions:
                    self._emit_runtime_event(
                        RuntimeEventType.RUNTIME_ERROR,
                        "No subscriptions were provided for refresh.",
                        action_path=action_path,
                    )
                    return
                th = threading.Thread(
                    target=self.refresh_subscriptions,
                    args=(subscriptions, source, True),
                    daemon=True,
                )
                th.start()
                return

            if sig == PluginSignal.CONFIG_UPDATE:
                logger.debug(
                    "cb_signal: CONFIG_UPDATE action_path=%r",
                    action_path,
                )
                previous_subscriptions: list[SubscriptionSpec] = []
                try:
                    previous_subscriptions = list(self._config.subscriptions)
                except Exception:
                    previous_subscriptions = []
                self.stop()
                ok, err = self._reload_from_action_file(action_path)
                if ok:
                    if self.enabled:
                        self._start_runtime(recheck=False)
                        self._apply_config_update_diff(previous_subscriptions)
                    self._emit_runtime_event(
                        RuntimeEventType.CONFIG_RELOADED,
                        "Plugin runtime configuration reloaded.",
                        action_path=action_path,
                    )
                    logger.info("plugin runtime configuration reloaded")
                else:
                    self._emit_runtime_event(
                        RuntimeEventType.RUNTIME_ERROR,
                        "Failed to reload plugin runtime configuration.",
                        error=err,
                        action_path=action_path,
                    )
                    logger.error("Failed to reload plugin runtime configuration: %s", repr(err))
                return

            if sig == PluginSignal.DISABLE or sig == PluginSignal.STOP:
                logger.debug(
                    "cb_signal: %s action_path=%r",
                    "DISABLE" if sig == PluginSignal.DISABLE else "STOP",
                    action_path,
                )
                self.enabled = False
                self.stop()
                self._emit_runtime_event(
                    (
                        RuntimeEventType.RUNTIME_DISABLED
                        if sig == PluginSignal.DISABLE
                        else RuntimeEventType.RUNTIME_STOPPED
                    ),
                    (
                        "Plugin runtime disabled."
                        if sig == PluginSignal.DISABLE
                        else "Plugin runtime stopped."
                    ),
                    action_path=action_path,
                )
                logger.info(
                    "plugin runtime %s",
                    "disabled" if sig == PluginSignal.DISABLE else "stopped",
                )
                return

            if sig == PluginSignal.ERROR:
                err = str(signal.get("error") or signal.get("message") or "")
                self._emit_runtime_event(
                    RuntimeEventType.RUNTIME_ERROR,
                    "Plugin runtime reported an error.",
                    error=err or None,
                    action_path=action_path,
                )
                return

            raise ValueError(f"unrecognized signal: {sig}")
        except Exception as e:
            logger.error("cb_signal: exception: %s", repr(e))

    def _in_backoff(self, meta: ListMetadata):
        if not meta.backoff_until:
            return False
        dt = parse_iso(meta.backoff_until)
        if not dt:
            return False
        return datetime.now().astimezone() < dt

    def _is_due(self, meta: ListMetadata, sub: SubscriptionSpec):
        if not meta.last_checked:
            return True
        lc = parse_iso(meta.last_checked)
        if not lc:
            return True
        return (
            datetime.now().astimezone() - lc
        ).total_seconds() >= sub.interval_seconds

    # -------- worker: download + update metadata --------

    def _mark_failure(self, meta: ListMetadata, err: str):
        meta.fail_count = int(meta.fail_count or 0) + 1
        meta.last_error = err
        meta.last_result = "error"

        seconds = min((2 ** max(0, meta.fail_count)) * 60, 6 * 3600)
        meta.backoff_until = (
            datetime.now().astimezone() + timedelta(seconds=seconds)
        ).isoformat()

    def _download_one(
        self,
        key: str,
        sub: SubscriptionSpec,
        force: bool = False,
        source: str = "scheduled",
        emit_download_events: bool = True,
    ):
        list_path, meta_path = self._paths(sub)
        os.makedirs(os.path.dirname(list_path), exist_ok=True)

        meta = self._load_meta(meta_path)

        # keep meta aligned
        meta.version = 1
        meta.url = sub.url
        meta.format = sub.format

        meta.last_checked = now_iso()
        meta.last_error = ""
        event_item = SubscriptionEventItem(
            key=key,
            name=sub.name,
            url=sub.url,
            filename=sub.filename,
            format=sub.format,
            path=list_path,
        )
        if emit_download_events:
            self._emit_runtime_event(
                RuntimeEventType.DOWNLOAD_STARTED,
                f"Downloading subscription '{sub.name}'.",
                target="subscription_list",
                path=list_path,
                source=source,
                items=[event_item],
            )

        # conditional headers
        headers: dict[str, str] = {}
        if not force and meta.etag:
            headers["If-None-Match"] = meta.etag
        if not force and meta.last_modified:
            headers["If-Modified-Since"] = meta.last_modified

        headers["User-Agent"] = self._config.defaults.user_agent or DEFAULT_UA

        lock = FileLock(list_path + ".lock")
        if not lock.acquire():
            meta.last_result = "busy"
            self._save_meta(meta_path, meta)
            if emit_download_events:
                self._emit_runtime_event(
                    RuntimeEventType.DOWNLOAD_FAILED,
                    f"Subscription '{sub.name}' is busy.",
                    target="subscription_list",
                    path=list_path,
                    source=source,
                    state="busy",
                    items=[
                        SubscriptionEventItem(
                            key=key,
                            name=sub.name,
                            url=sub.url,
                            filename=sub.filename,
                            format=sub.format,
                            state="busy",
                            path=list_path,
                        )
                    ],
                )
            self._resultsQueue.put((key, False, "busy"))
            return False

        try:
            # requests defaults except UA; timeout is used
            try:
                r: requests.Response = self._session.get(
                    sub.url, headers=headers, timeout=sub.timeout_seconds, stream=True
                )
            except Exception as e:
                self._mark_failure(meta, repr(e))
                self._save_meta(meta_path, meta)
                if emit_download_events:
                    self._emit_runtime_event(
                        RuntimeEventType.DOWNLOAD_FAILED,
                        f"Subscription download failed for '{sub.name}'.",
                        error=repr(e),
                        target="subscription_list",
                        path=list_path,
                        source=source,
                        state="request_error",
                        items=[
                            SubscriptionEventItem(
                                key=key,
                                name=sub.name,
                                url=sub.url,
                                filename=sub.filename,
                                format=sub.format,
                                state="request_error",
                                path=list_path,
                            )
                        ],
                    )
                self._resultsQueue.put((key, False, "request_error"))
                return False

            response_closed = False
            try:
                if r.status_code == 304:
                    meta.fail_count = 0
                    meta.backoff_until = ""
                    meta.last_result = "not_modified"
                    self._save_meta(meta_path, meta)
                    if emit_download_events:
                        self._emit_runtime_event(
                            RuntimeEventType.DOWNLOAD_FINISHED,
                            f"Subscription '{sub.name}' is up to date.",
                            target="subscription_list",
                            path=list_path,
                            source=source,
                            state="not_modified",
                            items=[
                                SubscriptionEventItem(
                                    key=key,
                                    name=sub.name,
                                    url=sub.url,
                                    filename=sub.filename,
                                    format=sub.format,
                                    state="not_modified",
                                    path=list_path,
                                )
                            ],
                        )
                    self._resultsQueue.put((key, True, "not_modified"))
                    logger.info("subscription not-modified name='%s'", sub.name)
                    return True

                if r.status_code != 200:
                    self._mark_failure(meta, f"http_{r.status_code}")
                    self._save_meta(meta_path, meta)
                    if emit_download_events:
                        self._emit_runtime_event(
                            RuntimeEventType.DOWNLOAD_FAILED,
                            f"Subscription download failed for '{sub.name}'.",
                            error=f"http_{r.status_code}",
                            target="subscription_list",
                            path=list_path,
                            source=source,
                            state=f"http_{r.status_code}",
                            items=[
                                SubscriptionEventItem(
                                    key=key,
                                    name=sub.name,
                                    url=sub.url,
                                    filename=sub.filename,
                                    format=sub.format,
                                    state=f"http_{r.status_code}",
                                    path=list_path,
                                )
                            ],
                        )
                    self._resultsQueue.put((key, False, f"http_{r.status_code}"))
                    logger.error(
                        "subscription download http-error name='%s' code=%s",
                        sub.name,
                        r.status_code,
                    )
                    return False

                cl: str | None = r.headers.get("Content-Length")
                if cl:
                    try:
                        if int(cl) > sub.max_bytes:
                            self._mark_failure(meta, f"too_large:{cl}")
                            self._save_meta(meta_path, meta)
                            if emit_download_events:
                                self._emit_runtime_event(
                                    RuntimeEventType.DOWNLOAD_FAILED,
                                    f"Subscription download exceeded max size for '{sub.name}'.",
                                    error=f"too_large:{cl}",
                                    target="subscription_list",
                                    path=list_path,
                                    source=source,
                                    state="too_large",
                                    items=[
                                        SubscriptionEventItem(
                                            key=key,
                                            name=sub.name,
                                            url=sub.url,
                                            filename=sub.filename,
                                            format=sub.format,
                                            state="too_large",
                                            path=list_path,
                                        )
                                    ],
                                )
                            self._resultsQueue.put((key, False, "too_large"))
                            logger.error(
                                "subscription download too-large name='%s' len=%s",
                                sub.name,
                                cl,
                            )
                            return False
                    except Exception:
                        pass

                tmp = list_path + ".tmp"
                downloaded = 0
                sample_lines: list[str] = []

                try:
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=32 * 1024):
                            if not chunk:
                                continue
                            downloaded += len(chunk)
                            if downloaded > sub.max_bytes:
                                raise RuntimeError("too_large_streamed")
                            f.write(chunk)

                            if (
                                sub.format.lower() == "hosts"
                                and len(sample_lines) < 200
                            ):
                                txt = chunk.decode("utf-8", errors="ignore")
                                for ln in txt.splitlines():
                                    if len(sample_lines) < 200:
                                        sample_lines.append(ln)
                                    else:
                                        break

                        f.flush()
                        os.fsync(f.fileno())

                    if sub.format.lower() == "hosts" and not is_hosts_file_like(
                        sample_lines
                    ):
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
                        self._mark_failure(meta, "bad_format_hosts")
                        self._save_meta(meta_path, meta)
                        if emit_download_events:
                            self._emit_runtime_event(
                                RuntimeEventType.DOWNLOAD_FAILED,
                                f"Subscription file format is invalid for '{sub.name}'.",
                                error="bad_format_hosts",
                                target="subscription_list",
                                path=list_path,
                                source=source,
                                state="bad_format",
                                items=[
                                    SubscriptionEventItem(
                                        key=key,
                                        name=sub.name,
                                        url=sub.url,
                                        filename=sub.filename,
                                        format=sub.format,
                                        state="bad_format",
                                        path=list_path,
                                    )
                                ],
                            )
                        self._resultsQueue.put((key, False, "bad_format"))
                        logger.error(
                            "subscription file bad-format name='%s'",
                            sub.name,
                        )
                        return False

                    os.replace(tmp, list_path)
                    self._fsync_parent_dir(list_path)
                    self._emit_runtime_event(
                        RuntimeEventType.FILE_SAVE_FINISHED,
                        f"Subscription file saved for '{sub.name}'.",
                        target="subscription_list",
                        path=list_path,
                        source=source,
                        items=[event_item],
                    )

                except Exception as e:
                    try:
                        if os.path.exists(tmp):
                            os.remove(tmp)
                    except Exception:
                        pass
                    self._mark_failure(meta, repr(e))
                    self._save_meta(meta_path, meta)
                    self._emit_runtime_event(
                        RuntimeEventType.FILE_SAVE_ERROR,
                        f"Failed to save subscription file for '{sub.name}'.",
                        error=repr(e),
                        target="subscription_list",
                        path=list_path,
                        source=source,
                        state="write_error",
                        items=[
                            SubscriptionEventItem(
                                key=key,
                                name=sub.name,
                                url=sub.url,
                                filename=sub.filename,
                                format=sub.format,
                                state="write_error",
                                path=list_path,
                            )
                        ],
                    )
                    if emit_download_events:
                        self._emit_runtime_event(
                            RuntimeEventType.DOWNLOAD_FAILED,
                            f"Subscription download failed for '{sub.name}'.",
                            error=repr(e),
                            target="subscription_list",
                            path=list_path,
                            source=source,
                            state="write_error",
                            items=[
                                SubscriptionEventItem(
                                    key=key,
                                    name=sub.name,
                                    url=sub.url,
                                    filename=sub.filename,
                                    format=sub.format,
                                    state="write_error",
                                    path=list_path,
                                )
                            ],
                        )
                    self._resultsQueue.put((key, False, "write_error"))
                    logger.error(
                        "subscription file write-error name='%s' err=%s",
                        sub.name,
                        repr(e),
                    )
                    return False

                # update cache validators
                et = r.headers.get("ETag")
                lm = r.headers.get("Last-Modified")
                if et:
                    meta.etag = et
                if lm:
                    meta.last_modified = lm

                meta.bytes = downloaded
                meta.last_updated = now_iso()
                meta.fail_count = 0
                meta.backoff_until = ""
                meta.last_result = "updated"
                self._save_meta(meta_path, meta)
                if emit_download_events:
                    self._emit_runtime_event(
                        RuntimeEventType.DOWNLOAD_FINISHED,
                        f"Subscription '{sub.name}' updated.",
                        target="subscription_list",
                        path=list_path,
                        source=source,
                        state="updated",
                        items=[
                            SubscriptionEventItem(
                                key=key,
                                name=sub.name,
                                url=sub.url,
                                filename=sub.filename,
                                format=sub.format,
                                state="updated",
                                path=list_path,
                            )
                        ],
                    )
                logger.info(
                    "subscription updated name='%s' bytes=%s",
                    sub.name,
                    downloaded,
                )
                r.close()
                response_closed = True
                self._reload_rules_for_updated_subscription(sub)
                self._resultsQueue.put((key, True, "updated"))
                return True
            finally:
                if not response_closed:
                    r.close()
        except Exception as e:
            self._mark_failure(meta, repr(e))
            self._save_meta(meta_path, meta)
            if emit_download_events:
                self._emit_runtime_event(
                    RuntimeEventType.DOWNLOAD_FAILED,
                    f"Subscription download failed for '{sub.name}'.",
                    error=repr(e),
                    target="subscription_list",
                    path=list_path,
                    source=source,
                    state="unexpected_error",
                    items=[
                        SubscriptionEventItem(
                            key=key,
                            name=sub.name,
                            url=sub.url,
                            filename=sub.filename,
                            format=sub.format,
                            state="unexpected_error",
                            path=list_path,
                        )
                    ],
                )
            self._resultsQueue.put((key, False, "unexpected_error"))
            logger.error(
                "subscription download unexpected-error name='%s' err=%s",
                sub.name,
                repr(e),
            )
            return False

        finally:
            lock.release()

    def download(
        self,
        subscriptions: SubscriptionSpec | list[SubscriptionSpec],
        force: bool = False,
        source: str = "scheduled",
        emit_download_events: bool = True,
    ):
        if isinstance(subscriptions, SubscriptionSpec):
            return self._download_one(
                self._sub_key(subscriptions),
                subscriptions,
                force=force,
                source=source,
                emit_download_events=emit_download_events,
            )

        if not subscriptions:
            return True

        items: list[SubscriptionEventItem] = []
        if emit_download_events:
            self._emit_runtime_event(
                RuntimeEventType.DOWNLOAD_STARTED,
                "Batch subscription refresh started.",
                target="subscription_list",
                source=source,
                items=[
                    SubscriptionEventItem(
                        key=self._sub_key(sub),
                        name=sub.name,
                        url=sub.url,
                        filename=sub.filename,
                        format=sub.format,
                    )
                    for sub in subscriptions
                ],
            )
        had_errors = False
        for sub in subscriptions:
            key = self._sub_key(sub)
            list_path, meta_path = self._paths(sub)
            item_state = "unexpected_error"
            try:
                ok = self._download_one(
                    key,
                    sub,
                    force=force,
                    source=source,
                    emit_download_events=False,
                )
                item_state = "updated" if ok else "error"
                if not ok:
                    had_errors = True
            except Exception as exc:
                had_errors = True
                logger.error(
                    "batch download failed for '%s': %r",
                    sub.name,
                    exc,
                )
            try:
                item_state = self._load_meta(meta_path).last_result or item_state
            except Exception:
                pass
            items.append(
                SubscriptionEventItem(
                    key=key,
                    name=sub.name,
                    url=sub.url,
                    filename=sub.filename,
                    format=sub.format,
                    state=item_state,
                    path=list_path,
                )
            )
        if emit_download_events:
            self._emit_runtime_event(
                (
                    RuntimeEventType.DOWNLOAD_FAILED
                    if had_errors
                    else RuntimeEventType.DOWNLOAD_FINISHED
                ),
                (
                    "Batch subscription refresh finished with errors."
                    if had_errors
                    else "Batch subscription refresh finished."
                ),
                target="subscription_list",
                source=source,
                state="batch_failed" if had_errors else "batch_finished",
                items=items,
            )
        logger.error(
            "batch subscription refresh failed for %d/%d items",
            sum(1 for i in items if i.get('state') != "updated"),
            len(items),
        ) if had_errors else logger.info(
            "batch subscription refresh finished for %d items",
            len(items),
        )
        return not had_errors
