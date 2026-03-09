import json
import logging
import os
import re
import sys
import threading
from urllib.parse import urlparse, unquote
from datetime import datetime
from typing import cast, Any, TYPE_CHECKING

if TYPE_CHECKING:
    # Keep static typing deterministic for linters/IDEs.
    # Runtime still supports both PyQt6/PyQt5 below.
    from PyQt6 import QtCore, QtGui, QtWidgets, uic
    from PyQt6.QtCore import QCoreApplication as QC
else:
    if "PyQt5" in sys.modules:
        from PyQt5 import QtCore, QtGui, QtWidgets, uic
        from PyQt5.QtCore import QCoreApplication as QC
    elif "PyQt6" in sys.modules:
        from PyQt6 import QtCore, QtGui, QtWidgets, uic
        from PyQt6.QtCore import QCoreApplication as QC
    else:
        try:
            from PyQt6 import QtCore, QtGui, QtWidgets, uic
            from PyQt6.QtCore import QCoreApplication as QC
        except Exception:
            from PyQt5 import QtCore, QtGui, QtWidgets, uic
            from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.actions import Actions
from opensnitch.nodes import Nodes
from opensnitch.utils.xdg import xdg_config_home
from opensnitch.plugins.list_subscriptions._models import (
    GlobalDefaults,
    MutableActionConfig,
    MutableSubscriptionSpec,
    PluginConfig,
    SubscriptionSpec,
    ensure_filename_type_suffix,
    normalize_group,
    normalize_groups,
    normalize_lists_dir,
)
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
import requests
from .list_subscriptions import ListSubscriptions


ACTION_FILE = os.path.join(xdg_config_home, "opensnitch", "actions", "list_subscriptions.json")
DEFAULT_LISTS_DIR = os.path.join(xdg_config_home, "opensnitch", "list_subscriptions")
PLUGIN_DIR = os.path.abspath(os.path.dirname(__file__))
LIST_SUBSCRIPTIONS_DIALOG_UI_PATH = os.path.join(PLUGIN_DIR, "list_subscriptions_dialog.ui")
SUBSCRIPTION_DIALOG_UI_PATH = os.path.join(PLUGIN_DIR, "subscription_dialog.ui")
BULK_EDIT_DIALOG_UI_PATH = os.path.join(PLUGIN_DIR, "bulk_edit_dialog.ui")

SubscriptionDialogUI = uic.loadUiType(SUBSCRIPTION_DIALOG_UI_PATH)[0] # type: ignore
BulkEditDialogUI = uic.loadUiType(BULK_EDIT_DIALOG_UI_PATH)[0] # type: ignore
ListSubscriptionsDialogUI = uic.loadUiType(LIST_SUBSCRIPTIONS_DIALOG_UI_PATH)[0] # type: ignore

INTERVAL_UNITS = ("seconds", "minutes", "hours", "days", "weeks")
TIMEOUT_UNITS = ("seconds", "minutes", "hours", "days", "weeks")
SIZE_UNITS = ("bytes", "KB", "MB", "GB")

COL_ENABLED = 0
COL_NAME = 1
COL_URL = 2
COL_FILENAME = 3
COL_FORMAT = 4
COL_GROUP = 5
COL_INTERVAL = 6
COL_INTERVAL_UNITS = 7
COL_TIMEOUT = 8
COL_TIMEOUT_UNITS = 9
COL_MAX_SIZE = 10
COL_MAX_SIZE_UNITS = 11
COL_FILE = 12
COL_META = 13
COL_STATE = 14
COL_LAST_CHECKED = 15
COL_LAST_UPDATED = 16
COL_FAILS = 17
COL_ERROR = 18

logger = logging.getLogger(__name__)


class SubscriptionDialog(QtWidgets.QDialog, SubscriptionDialogUI):
    if TYPE_CHECKING:
        enabled_check: QtWidgets.QCheckBox
        name_edit: QtWidgets.QLineEdit
        url_edit: QtWidgets.QLineEdit
        filename_edit: QtWidgets.QLineEdit
        format_combo: QtWidgets.QComboBox
        group_combo: QtWidgets.QComboBox
        interval_spin: QtWidgets.QSpinBox
        interval_units: QtWidgets.QComboBox
        timeout_spin: QtWidgets.QSpinBox
        timeout_units: QtWidgets.QComboBox
        max_size_spin: QtWidgets.QSpinBox
        max_size_units: QtWidgets.QComboBox
        meta_group: QtWidgets.QGroupBox
        meta_file_present: QtWidgets.QLabel
        meta_meta_present: QtWidgets.QLabel
        meta_state: QtWidgets.QLabel
        meta_last_checked: QtWidgets.QLabel
        meta_last_updated: QtWidgets.QLabel
        meta_failures: QtWidgets.QLabel
        meta_error: QtWidgets.QLabel
        meta_list_path: QtWidgets.QLabel
        meta_meta_path: QtWidgets.QLabel
        error_label: QtWidgets.QLabel
        cancel_button: QtWidgets.QPushButton
        add_button: QtWidgets.QPushButton
        _title: str
        _defaults: GlobalDefaults
        _groups: list[str]
        _sub: MutableSubscriptionSpec
        _meta: dict[str, str]

    def __init__(
        self,
        parent: QtWidgets.QWidget | None,
        defaults: GlobalDefaults,
        groups: list[str] | None = None,
        sub: MutableSubscriptionSpec | None = None,
        meta: dict[str, str] | None = None,
        title: str = "Subscription",
    ):
        super().__init__(parent)
        self.setWindowTitle(QC.translate("stats", title))
        self._title = title
        self._defaults = defaults
        self._groups = groups or ["all"]
        self._sub = sub or MutableSubscriptionSpec(
            enabled=True,
            groups=["all"],
            interval=self._defaults.interval,
            interval_units=self._defaults.interval_units,
            timeout=self._defaults.timeout,
            timeout_units=self._defaults.timeout_units,
            max_size=self._defaults.max_size,
            max_size_units=self._defaults.max_size_units,
        )
        self._meta = meta or {}
        self._build_ui()

    def _build_ui(self):
        self.setupUi(self)
        self.error_label.setStyleSheet("color: red;")
        self.group_combo.setEditable(True)
        self.add_button.clicked.connect(self._validate_then_accept)
        self.cancel_button.clicked.connect(self.reject)

        self.enabled_check.setChecked(bool(self._sub.enabled))
        self.name_edit.setText(str(self._sub.name))
        self.url_edit.setText(str(self._sub.url))
        self.filename_edit.setText(str(self._sub.filename))
        self.format_combo.clear()
        self.format_combo.addItems(("hosts",))
        self.format_combo.setCurrentText(str(self._sub.format or "hosts"))
        for g in self._groups:
            ng = normalize_group(g)
            if ng != "":
                self.group_combo.addItem(ng)
        current_groups = normalize_groups(self._sub.groups)
        current_group_text = ", ".join(current_groups)
        if self.group_combo.findText(current_group_text) < 0:
            self.group_combo.addItem(current_group_text)
        self.group_combo.setCurrentText(current_group_text)
        self.interval_spin.setRange(1, 999999)
        self.interval_spin.setValue(max(1, int(self._sub.interval)))
        self.interval_units.clear()
        self.interval_units.addItems(INTERVAL_UNITS)
        self.interval_units.setCurrentText(
            self._normalize_unit(str(self._sub.interval_units), INTERVAL_UNITS, "hours")
        )
        self.timeout_spin.setRange(1, 999999)
        self.timeout_spin.setValue(max(1, int(self._sub.timeout)))
        self.timeout_units.clear()
        self.timeout_units.addItems(TIMEOUT_UNITS)
        self.timeout_units.setCurrentText(
            self._normalize_unit(str(self._sub.timeout_units), TIMEOUT_UNITS, "seconds")
        )
        self.max_size_spin.setRange(1, 999999)
        self.max_size_spin.setValue(max(1, int(self._sub.max_size)))
        self.max_size_units.clear()
        self.max_size_units.addItems(SIZE_UNITS)
        self.max_size_units.setCurrentText(
            self._normalize_unit(str(self._sub.max_size_units), SIZE_UNITS, "MB")
        )
        self.meta_file_present.setText(str(self._meta.get("file_present", "")))
        self.meta_meta_present.setText(str(self._meta.get("meta_present", "")))
        self.meta_state.setText(str(self._meta.get("state", "")))
        self.meta_last_checked.setText(str(self._meta.get("last_checked", "")))
        self.meta_last_updated.setText(str(self._meta.get("last_updated", "")))
        self.meta_failures.setText(str(self._meta.get("failures", "")))
        self.meta_error.setText(str(self._meta.get("error", "")))
        self.meta_list_path.setText(str(self._meta.get("list_path", "")))
        self.meta_meta_path.setText(str(self._meta.get("meta_path", "")))
        if "new" in (self._title or "").strip().lower():
            self.meta_group.setVisible(False)
        self.resize(920, 420)

    def _normalize_unit(self, value: str, allowed: tuple[str, ...], fallback: str):
        normalized = (value or "").strip().lower()
        for unit in allowed:
            if unit.lower() == normalized:
                return unit
        return fallback

    def _validate_then_accept(self):
        url = (self.url_edit.text() or "").strip()
        if url == "":
            self.error_label.setText(QC.translate("stats", "URL is required."))
            return
        name = (self.name_edit.text() or "").strip()
        filename = os.path.basename((self.filename_edit.text() or "").strip())
        list_type = (self.format_combo.currentText() or "hosts").strip().lower()

        if name == "" and filename == "":
            self.error_label.setText(QC.translate("stats", "Provide at least a name or a filename."))
            return

        if filename == "" and name != "":
            filename = self._slugify_name(name)
        filename = ensure_filename_type_suffix(filename, list_type)

        if name == "" and filename != "":
            name = self._deslugify_filename(filename, list_type)

        self.name_edit.setText(name)
        self.filename_edit.setText(filename)

        groups = normalize_groups(self.group_combo.currentText())
        if not groups:
            self.error_label.setText(QC.translate("stats", "At least one group is required."))
            return
        self.error_label.setText("")
        self.accept()

    def _slugify_name(self, name: str):
        raw = (name or "").strip().lower()
        if raw == "":
            return "subscription.list"
        slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
        if slug == "":
            slug = "subscription"
        if "." not in slug:
            slug += ".list"
        return slug

    def _deslugify_filename(self, filename: str, list_type: str):
        safe = os.path.basename((filename or "").strip())
        base, _ext = os.path.splitext(safe)
        suffix = f"-{(list_type or 'hosts').strip().lower()}"
        if base.lower().endswith(suffix):
            base = base[: -len(suffix)]
        pretty = re.sub(r"[-_.]+", " ", base).strip()
        pretty = re.sub(r"\s+", " ", pretty)
        if pretty == "":
            return safe
        return pretty.title()

    def subscription_spec(self):
        groups = normalize_groups((self.group_combo.currentText() or "all").strip())
        return MutableSubscriptionSpec(
            enabled=self.enabled_check.isChecked(),
            name=(self.name_edit.text() or "").strip(),
            url=(self.url_edit.text() or "").strip(),
            filename=(self.filename_edit.text() or "").strip(),
            format=(self.format_combo.currentText() or "hosts").strip().lower(),
            groups=groups,
            interval=int(self.interval_spin.value()),
            interval_units=self.interval_units.currentText(),
            timeout=int(self.timeout_spin.value()),
            timeout_units=self.timeout_units.currentText(),
            max_size=int(self.max_size_spin.value()),
            max_size_units=self.max_size_units.currentText(),
        )


class BulkEditDialog(QtWidgets.QDialog, BulkEditDialogUI):
    if TYPE_CHECKING:
        apply_enabled: QtWidgets.QCheckBox
        enabled_value: QtWidgets.QCheckBox
        apply_group: QtWidgets.QCheckBox
        group_value: QtWidgets.QComboBox
        apply_format: QtWidgets.QCheckBox
        format_value: QtWidgets.QComboBox
        apply_interval: QtWidgets.QCheckBox
        interval_spin: QtWidgets.QSpinBox
        interval_units: QtWidgets.QComboBox
        apply_timeout: QtWidgets.QCheckBox
        timeout_spin: QtWidgets.QSpinBox
        timeout_units: QtWidgets.QComboBox
        apply_max_size: QtWidgets.QCheckBox
        max_size_spin: QtWidgets.QSpinBox
        max_size_units: QtWidgets.QComboBox
        error_label: QtWidgets.QLabel
        cancel_button: QtWidgets.QPushButton
        save_button: QtWidgets.QPushButton
        _defaults: GlobalDefaults
        _groups: list[str]

    def __init__(
        self,
        parent: QtWidgets.QWidget | None,
        defaults: GlobalDefaults,
        groups: list[str] | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(QC.translate("stats", "Edit selected subscriptions"))
        self._defaults = defaults
        self._groups = groups or ["all"]
        self._build_ui()

    def _build_ui(self):
        self.setupUi(self)
        self.error_label.setStyleSheet("color: red;")
        self.group_value.setEditable(True)
        self.cancel_button.clicked.connect(self.reject)
        self.save_button.clicked.connect(self._validate_then_accept)

        self.enabled_value.setChecked(True)
        self.group_value.clear()
        for g in self._groups:
            ng = normalize_group(g)
            if ng != "":
                self.group_value.addItem(ng)
        if self.group_value.findText("all") < 0:
            self.group_value.addItem("all")
        self.group_value.setCurrentText("all")
        self.format_value.clear()
        self.format_value.addItems(("hosts",))
        self.interval_spin.setRange(1, 999999)
        self.interval_spin.setValue(max(1, int(self._defaults.interval)))
        self.interval_units.clear()
        self.interval_units.addItems(INTERVAL_UNITS)
        self.interval_units.setCurrentText(self._normalize_unit(self._defaults.interval_units, INTERVAL_UNITS, "hours"))
        self.timeout_spin.setRange(1, 999999)
        self.timeout_spin.setValue(max(1, int(self._defaults.timeout)))
        self.timeout_units.clear()
        self.timeout_units.addItems(TIMEOUT_UNITS)
        self.timeout_units.setCurrentText(self._normalize_unit(self._defaults.timeout_units, TIMEOUT_UNITS, "seconds"))
        self.max_size_spin.setRange(1, 999999)
        self.max_size_spin.setValue(max(1, int(self._defaults.max_size)))
        self.max_size_units.clear()
        self.max_size_units.addItems(SIZE_UNITS)
        self.max_size_units.setCurrentText(self._normalize_unit(self._defaults.max_size_units, SIZE_UNITS, "MB"))
        self.resize(640, 360)

    def _normalize_unit(self, value: str, allowed: tuple[str, ...], fallback: str):
        normalized = (value or "").strip().lower()
        for unit in allowed:
            if unit.lower() == normalized:
                return unit
        return fallback

    def _validate_then_accept(self):
        if not any(
            (
                self.apply_enabled.isChecked(),
                self.apply_group.isChecked(),
                self.apply_format.isChecked(),
                self.apply_interval.isChecked(),
                self.apply_timeout.isChecked(),
                self.apply_max_size.isChecked(),
            )
        ):
            self.error_label.setText(QC.translate("stats", "Select at least one field to apply."))
            return
        self.error_label.setText("")
        self.accept()

    def values(self):
        return {
            "enabled": self.enabled_value.isChecked() if self.apply_enabled.isChecked() else None,
            "groups": normalize_groups(self.group_value.currentText()) if self.apply_group.isChecked() else None,
            "format": (self.format_value.currentText() or "hosts").strip().lower() if self.apply_format.isChecked() else None,
            "interval": int(self.interval_spin.value()) if self.apply_interval.isChecked() else None,
            "interval_units": self.interval_units.currentText() if self.apply_interval.isChecked() else None,
            "timeout": int(self.timeout_spin.value()) if self.apply_timeout.isChecked() else None,
            "timeout_units": self.timeout_units.currentText() if self.apply_timeout.isChecked() else None,
            "max_size": int(self.max_size_spin.value()) if self.apply_max_size.isChecked() else None,
            "max_size_units": self.max_size_units.currentText() if self.apply_max_size.isChecked() else None,
        }


class ListSubscriptionsDialog(QtWidgets.QDialog, ListSubscriptionsDialogUI):
    if TYPE_CHECKING:
        enable_plugin_check: QtWidgets.QCheckBox
        create_file_button: QtWidgets.QPushButton
        save_button: QtWidgets.QPushButton
        reload_button: QtWidgets.QPushButton
        lists_dir_edit: QtWidgets.QLineEdit
        default_interval_spin: QtWidgets.QSpinBox
        default_interval_units: QtWidgets.QComboBox
        default_timeout_spin: QtWidgets.QSpinBox
        default_timeout_units: QtWidgets.QComboBox
        default_max_size_spin: QtWidgets.QSpinBox
        default_max_size_units: QtWidgets.QComboBox
        default_user_agent: QtWidgets.QLineEdit
        nodes_combo: QtWidgets.QComboBox
        table: QtWidgets.QTableWidget
        add_sub_button: QtWidgets.QPushButton
        refresh_state_button: QtWidgets.QPushButton
        create_global_rule_button: QtWidgets.QPushButton
        edit_sub_button: QtWidgets.QPushButton
        remove_sub_button: QtWidgets.QPushButton
        refresh_now_button: QtWidgets.QPushButton
        create_rule_button: QtWidgets.QPushButton
        status_label: QtWidgets.QLabel
        _nodes: Nodes
        _actions: Actions
        _action_path: str
        _loading: bool
        _global_defaults: GlobalDefaults
        _state_poll_timer: QtCore.QTimer

    _download_finished = QtCore.pyqtSignal()

    def __init__(
        self,
        parent: QtWidgets.QWidget | None = None,
        appicon: QtGui.QIcon | None = None,
    ):
        dlg_parent = parent if isinstance(parent, QtWidgets.QWidget) else None
        super().__init__(dlg_parent)
        self.setWindowTitle(QC.translate("stats", "List subscriptions"))
        if appicon is not None:
            self.setWindowIcon(appicon)

        self._nodes = Nodes.instance()
        self._actions = Actions.instance()
        self._action_path = ACTION_FILE
        self._loading = False
        self._global_defaults: GlobalDefaults = GlobalDefaults.from_dict({}, lists_dir=DEFAULT_LISTS_DIR)
        self._rules_dialog: RulesEditorDialog | None = None
        self._state_poll_timer = QtCore.QTimer(self)
        self._state_poll_timer.setInterval(2000)
        self._state_poll_timer.timeout.connect(self._refresh_states_if_visible)
        self._download_finished.connect(self.refresh_states)
        self._build_ui()

    def showEvent(self, event: QtGui.QShowEvent):  # type: ignore
        super().showEvent(event)
        self.load_action_file()
        if not self._state_poll_timer.isActive():
            self._state_poll_timer.start()

    def hideEvent(self, event: QtGui.QHideEvent):  # type: ignore
        if self._state_poll_timer.isActive():
            self._state_poll_timer.stop()
        super().hideEvent(event)

    def closeEvent(self, event: QtGui.QCloseEvent):  # type: ignore
        if self._state_poll_timer.isActive():
            self._state_poll_timer.stop()
        super().closeEvent(event)

    def _build_ui(self):
        self.setupUi(self)
        self.setWindowTitle(QC.translate("stats", "List subscriptions"))
        self.resize(1180, 680)

        self.default_interval_spin.setRange(1, 999999)
        self.default_interval_units.clear()
        self.default_interval_units.addItems(INTERVAL_UNITS)
        self.default_timeout_spin.setRange(1, 999999)
        self.default_timeout_units.clear()
        self.default_timeout_units.addItems(TIMEOUT_UNITS)
        self.default_max_size_spin.setRange(1, 999999)
        self.default_max_size_units.clear()
        self.default_max_size_units.addItems(SIZE_UNITS)

        self.table.setColumnCount(19)
        self.table.setHorizontalHeaderLabels([
            QC.translate("stats", "Enabled"),
            QC.translate("stats", "Name"),
            QC.translate("stats", "URL"),
            QC.translate("stats", "Filename"),
            QC.translate("stats", "Format"),
            QC.translate("stats", "Groups"),
            QC.translate("stats", "Interval"),
            QC.translate("stats", "Interval units"),
            QC.translate("stats", "Timeout"),
            QC.translate("stats", "Timeout units"),
            QC.translate("stats", "Max size"),
            QC.translate("stats", "Max size units"),
            QC.translate("stats", "List file present"),
            QC.translate("stats", "List meta present"),
            QC.translate("stats", "State"),
            QC.translate("stats", "Last checked"),
            QC.translate("stats", "Last updated"),
            QC.translate("stats", "Failures"),
            QC.translate("stats", "Error"),
        ])
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        header = self.table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
            header.setSectionResizeMode(COL_URL, QtWidgets.QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(COL_ERROR, QtWidgets.QHeaderView.ResizeMode.Stretch)
        # Keep advanced tuning + verbose metadata available internally but
        # reduce visible table complexity; edit dialog exposes full details.
        for col in (
            COL_INTERVAL,
            COL_INTERVAL_UNITS,
            COL_TIMEOUT,
            COL_TIMEOUT_UNITS,
            COL_MAX_SIZE,
            COL_MAX_SIZE_UNITS,
            COL_FILE,
            COL_META,
            COL_FAILS,
            COL_ERROR,
        ):
            self.table.setColumnHidden(col, True)

        self.create_file_button.clicked.connect(self.create_action_file)
        self.save_button.clicked.connect(self.save_action_file)
        self.reload_button.clicked.connect(self.load_action_file)
        self.add_sub_button.clicked.connect(self.add_subscription_row)
        self.create_global_rule_button.clicked.connect(self.create_global_rule)
        self.edit_sub_button.clicked.connect(self.edit_action_clicked)
        self.remove_sub_button.clicked.connect(self.remove_selected_subscription)
        self.refresh_state_button.clicked.connect(self.refresh_all_now)
        self.refresh_now_button.clicked.connect(self.refresh_selected_now)
        self.create_rule_button.clicked.connect(self.create_rule_from_selected)
        self.table.itemDoubleClicked.connect(lambda *_: self.edit_selected_subscription())
        self.table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._open_table_context_menu)
        sel_model = self.table.selectionModel()
        if sel_model is not None:
            sel_model.selectionChanged.connect(lambda *_: self._update_selected_actions_state())
        self._update_selected_actions_state()

    def load_action_file(self):
        self._loading = True
        self._set_status("")
        self._reload_nodes()
        self.table.setRowCount(0)
        self.create_file_button.setVisible(True)
        self.lists_dir_edit.setText(DEFAULT_LISTS_DIR)
        self.enable_plugin_check.setChecked(False)
        self._global_defaults = GlobalDefaults.from_dict({}, lists_dir=DEFAULT_LISTS_DIR)
        self._apply_defaults_to_widgets()

        if not os.path.exists(self._action_path):
            self._set_status(QC.translate("stats", "Action file not found. Click 'Create action file'."), error=False)
            self._loading = False
            return

        try:
            with open(self._action_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            self._set_status(QC.translate("stats", "Error reading action file: {0}").format(str(e)), error=True)
            self._loading = False
            return

        action_model = MutableActionConfig.from_action_dict(data, lists_dir=DEFAULT_LISTS_DIR)
        self._global_defaults = action_model.defaults
        self.enable_plugin_check.setChecked(action_model.enabled)
        self.lists_dir_edit.setText(normalize_lists_dir(self._global_defaults.lists_dir))
        self._apply_defaults_to_widgets()

        normalized_subs = action_model.subscriptions
        actions_obj = data.get("actions", {})
        action_cfg = actions_obj.get("list_subscriptions", {}) if isinstance(actions_obj, dict) else {}
        plugin_cfg_raw = action_cfg.get("config", {}) if isinstance(action_cfg, dict) else {}
        plugin_cfg = plugin_cfg_raw if isinstance(plugin_cfg_raw, dict) else {}
        raw_subs = plugin_cfg.get("subscriptions")
        migrated_legacy_group = False
        if isinstance(raw_subs, list):
            for item in raw_subs:
                if isinstance(item, dict) and ("group" in item) and ("groups" not in item):
                    migrated_legacy_group = True
                    break
        normalized_subs_dicts = [s.to_dict() for s in normalized_subs]
        fixed_count = 1 if (isinstance(raw_subs, list) and raw_subs != normalized_subs_dicts) else 0

        for sub in normalized_subs:
            self._append_row(sub)

        self._loading = False
        self.refresh_states()
        self._update_selected_actions_state()
        self.create_file_button.setVisible(False)
        if migrated_legacy_group:
            self.save_action_file()
            self._set_status(
                QC.translate("stats", "Migrated legacy 'group' entries to 'groups' and auto-saved configuration."),
                error=False,
            )
            return
        if fixed_count > 0:
            self._set_status(
                QC.translate("stats", "Loaded configuration with normalized subscription fields."),
                error=False,
            )
        else:
            self._set_status(QC.translate("stats", "List subscriptions configuration loaded."), error=False)

    def create_action_file(self):
        try:
            os.makedirs(os.path.dirname(self._action_path), mode=0o700, exist_ok=True)
            if not os.path.exists(self._action_path):
                action_model = MutableActionConfig.default(DEFAULT_LISTS_DIR)
                with open(self._action_path, "w", encoding="utf-8") as f:
                    json.dump(action_model.to_action_dict(), f, indent=2)
            self.load_action_file()
            self._set_status(QC.translate("stats", "Action file created."), error=False)
        except Exception as e:
            self._set_status(QC.translate("stats", "Error creating action file: {0}").format(str(e)), error=True)

    def save_action_file(self):
        if self._loading:
            return

        if not os.path.exists(self._action_path):
            self.create_action_file()
            if not os.path.exists(self._action_path):
                return

        subscriptions = self._collect_subscriptions()
        if subscriptions is None:
            return

        lists_dir = normalize_lists_dir(self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR)
        try:
            os.makedirs(lists_dir, mode=0o700, exist_ok=True)
        except Exception:
            pass
        defaults = GlobalDefaults(
            lists_dir=lists_dir,
            interval=max(1, int(self.default_interval_spin.value())),
            interval_units=self.default_interval_units.currentText(),
            timeout=max(1, int(self.default_timeout_spin.value())),
            timeout_units=self.default_timeout_units.currentText(),
            max_size=max(1, int(self.default_max_size_spin.value())),
            max_size_units=self.default_max_size_units.currentText(),
            user_agent=(self.default_user_agent.text() or "").strip(),
        )
        action_model = MutableActionConfig.default(lists_dir)
        action_model.enabled = self.enable_plugin_check.isChecked()
        action_model.defaults = defaults
        action_model.subscriptions = subscriptions
        action = action_model.to_action_dict()
        action["updated"] = datetime.now().astimezone().isoformat()

        compiled_cfg = PluginConfig.from_dict(action_model.to_plugin_dict(), lists_dir=lists_dir)
        if len(compiled_cfg.subscriptions) != len(subscriptions):
            self._set_status(QC.translate("stats", "Invalid subscriptions: URL and filename are mandatory."), error=True)
            return

        tmp_path = self._action_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(action, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self._action_path)
        except Exception as e:
            self._set_status(QC.translate("stats", "Error saving action file: {0}").format(str(e)), error=True)
            return

        self._apply_runtime_state(action_model.enabled)
        self.refresh_states()
        self._set_status(QC.translate("stats", "List subscriptions configuration saved."), error=False)

    def refresh_states(self):
        lists_dir = normalize_lists_dir(self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR)
        for row in range(self.table.rowCount()):
            filename_item = self.table.item(row, COL_FILENAME)
            enabled_item = self.table.item(row, COL_ENABLED)
            if filename_item is None or enabled_item is None:
                continue

            filename = self._safe_filename(filename_item.text())
            list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
            enabled = enabled_item.checkState() == QtCore.Qt.CheckState.Checked
            list_path = self._list_file_path(lists_dir, filename, list_type)
            meta_path = list_path + ".meta.json"

            file_exists = os.path.exists(list_path)
            meta_exists = os.path.exists(meta_path)
            meta = {}
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

            if not enabled:
                state = "disabled"
                color = QtGui.QColor("lightgray")
            elif not file_exists:
                # New/manual subscriptions may not be downloaded yet.
                # Expose that as pending instead of an error-like missing state.
                if not meta_exists or last_result in ("never", "", "busy"):
                    state = "pending"
                    color = QtGui.QColor("khaki")
                else:
                    state = "missing"
                    color = QtGui.QColor("tomato")
            elif last_result in ("updated", "not_modified"):
                state = last_result
                color = QtGui.QColor("lightgreen")
            elif last_result in ("error", "write_error", "request_error", "unexpected_error", "bad_format", "too_large"):
                state = last_result
                color = QtGui.QColor("salmon")
            elif last_result == "busy":
                state = "busy"
                color = QtGui.QColor("khaki")
            else:
                state = last_result
                color = QtGui.QColor("lightyellow")

            self._set_text_item(row, COL_FILE, "yes" if file_exists else "no", editable=False)
            self._set_text_item(row, COL_META, "yes" if meta_exists else "no", editable=False)
            self._set_text_item(row, COL_STATE, state, editable=False)
            self._set_text_item(row, COL_LAST_CHECKED, last_checked, editable=False)
            self._set_text_item(row, COL_LAST_UPDATED, last_updated, editable=False)
            self._set_text_item(row, COL_FAILS, fail_count, editable=False)
            self._set_text_item(row, COL_ERROR, last_error, editable=False)

            for col in (COL_FILE, COL_META, COL_STATE, COL_LAST_CHECKED, COL_LAST_UPDATED, COL_FAILS, COL_ERROR):
                item = self.table.item(row, col)
                if item is not None:
                    item.setBackground(color)

    def add_subscription_row(self):
        dlg = SubscriptionDialog(
            self,
            self._global_defaults,
            groups=self._known_groups(),
            sub=MutableSubscriptionSpec(
                enabled=True,
                name="",
                url="",
                filename="",
                format="hosts",
                groups=["all"],
                interval=self._global_defaults.interval,
                interval_units=self._global_defaults.interval_units,
                timeout=self._global_defaults.timeout,
                timeout_units=self._global_defaults.timeout_units,
                max_size=self._global_defaults.max_size,
                max_size_units=self._global_defaults.max_size_units,
            ),
            title="New subscription",
        )
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return

        sub = dlg.subscription_spec()
        self._append_row(sub)
        row = self.table.rowCount() - 1
        _, changed = self._ensure_row_final_filename(row)
        if changed:
            self.refresh_states()

        if not os.path.exists(self._action_path):
            self.create_action_file()
        self.save_action_file()
        self._update_selected_actions_state()

    def edit_selected_subscription(self):
        row = self.table.currentRow()
        if row < 0:
            self._set_status(QC.translate("stats", "Select a subscription row first."), error=True)
            return

        enabled_item = self.table.item(row, COL_ENABLED)
        if enabled_item is None:
            enabled_item = QtWidgets.QTableWidgetItem("")
            enabled_item.setFlags(enabled_item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
            self.table.setItem(row, COL_ENABLED, enabled_item)

        interval_val = self._to_int_or_keep(self._cell_text(row, COL_INTERVAL))
        timeout_val = self._to_int_or_keep(self._cell_text(row, COL_TIMEOUT))
        max_size_val = self._to_int_or_keep(self._cell_text(row, COL_MAX_SIZE))
        sub = MutableSubscriptionSpec(
            enabled=enabled_item.checkState() == QtCore.Qt.CheckState.Checked,
            name=self._cell_text(row, COL_NAME),
            url=self._cell_text(row, COL_URL),
            filename=self._cell_text(row, COL_FILENAME),
            format=self._cell_text(row, COL_FORMAT) or "hosts",
            groups=normalize_groups(self._cell_text(row, COL_GROUP) or "all"),
            interval=interval_val if isinstance(interval_val, int) else self._global_defaults.interval,
            interval_units=self._cell_text(row, COL_INTERVAL_UNITS) or self._global_defaults.interval_units,
            timeout=timeout_val if isinstance(timeout_val, int) else self._global_defaults.timeout,
            timeout_units=self._cell_text(row, COL_TIMEOUT_UNITS) or self._global_defaults.timeout_units,
            max_size=max_size_val if isinstance(max_size_val, int) else self._global_defaults.max_size,
            max_size_units=self._cell_text(row, COL_MAX_SIZE_UNITS) or self._global_defaults.max_size_units,
        )
        meta = self._row_meta_snapshot(row)
        dlg = SubscriptionDialog(
            self,
            self._global_defaults,
            groups=self._known_groups(),
            sub=sub,
            meta=meta,
            title="Edit subscription",
        )
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        updated = dlg.subscription_spec()

        enabled_item = self.table.item(row, COL_ENABLED)
        if enabled_item is None:
            enabled_item = QtWidgets.QTableWidgetItem("")
            enabled_item.setFlags(enabled_item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
            self.table.setItem(row, COL_ENABLED, enabled_item)
        enabled_item.setCheckState(
            QtCore.Qt.CheckState.Checked if bool(updated.enabled) else QtCore.Qt.CheckState.Unchecked
        )
        self._set_text_item(row, COL_NAME, updated.name)
        self._set_text_item(row, COL_URL, updated.url)
        self._set_text_item(row, COL_FILENAME, self._safe_filename(updated.filename))
        self._set_text_item(row, COL_FORMAT, updated.format)
        self._set_text_item(row, COL_GROUP, ", ".join(normalize_groups(updated.groups)))
        self._set_text_item(row, COL_INTERVAL, self._to_str(updated.interval))
        interval_units_val = self._to_str(updated.interval_units)
        self._set_text_item(row, COL_INTERVAL_UNITS, interval_units_val)
        self._set_text_item(row, COL_TIMEOUT, self._to_str(updated.timeout))
        timeout_units_val = self._to_str(updated.timeout_units)
        self._set_text_item(row, COL_TIMEOUT_UNITS, timeout_units_val)
        self._set_text_item(row, COL_MAX_SIZE, self._to_str(updated.max_size))
        max_size_units_val = self._to_str(updated.max_size_units)
        self._set_text_item(row, COL_MAX_SIZE_UNITS, max_size_units_val)
        self._set_units_combo(row, COL_INTERVAL_UNITS, INTERVAL_UNITS, interval_units_val)
        self._set_units_combo(row, COL_TIMEOUT_UNITS, TIMEOUT_UNITS, timeout_units_val)
        self._set_units_combo(row, COL_MAX_SIZE_UNITS, SIZE_UNITS, max_size_units_val)

        _, changed = self._ensure_row_final_filename(row)
        self.save_action_file()
        self.refresh_states()
        if changed:
            self._set_status(QC.translate("stats", "Subscription updated and filename normalized."), error=False)
        else:
            self._set_status(QC.translate("stats", "Subscription updated."), error=False)

    def edit_action_clicked(self):
        rows = self._selected_rows()
        if len(rows) == 0:
            self._set_status(QC.translate("stats", "Select one or more subscriptions first."), error=True)
            return
        if len(rows) == 1:
            self.edit_selected_subscription()
            return
        self._bulk_edit(rows)

    def remove_selected_subscription(self):
        rows = self._selected_rows()
        if not rows:
            row = self.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._set_status(QC.translate("stats", "Select one or more subscription rows first."), error=True)
            return
        for row in sorted(rows, reverse=True):
            self.table.removeRow(row)
        self.save_action_file()
        self.refresh_states()
        self._update_selected_actions_state()
        self._set_status(QC.translate("stats", "Selected subscriptions removed."), error=False)

    def _selected_rows(self):
        idx = self.table.selectionModel()
        if idx is None:
            return []
        return sorted({i.row() for i in idx.selectedRows()})

    def _update_selected_actions_state(self):
        count = len(self._selected_rows())
        has_selection = count > 0
        single = count == 1
        self.edit_sub_button.setEnabled(has_selection)
        self.remove_sub_button.setEnabled(has_selection)
        self.refresh_now_button.setEnabled(single)
        self.create_rule_button.setEnabled(has_selection)

    def _open_table_context_menu(self, pos: QtCore.QPoint):
        rows = self._selected_rows()
        if not rows:
            row = self.table.rowAt(pos.y())
            if row >= 0:
                self.table.selectRow(row)
                rows = [row]
        if not rows:
            return

        menu = QtWidgets.QMenu(self.table)
        viewport = self.table.viewport()
        if viewport is None:
            return
        if len(rows) == 1:
            act_edit = menu.addAction(QC.translate("stats", "Edit"))
            act_remove = menu.addAction(QC.translate("stats", "Delete"))
            act_refresh = menu.addAction(QC.translate("stats", "Refresh now"))
            act_rule = menu.addAction(QC.translate("stats", "Create rule"))
            chosen = menu.exec(viewport.mapToGlobal(pos))
            if chosen is act_edit:
                self.edit_selected_subscription()
            elif chosen is act_remove:
                self.remove_selected_subscription()
            elif chosen is act_refresh:
                self.refresh_selected_now()
            elif chosen is act_rule:
                self.create_rule_from_selected()
            return

        act_edit = menu.addAction(QC.translate("stats", "Edit"))
        act_remove = menu.addAction(QC.translate("stats", "Delete"))
        act_rule = menu.addAction(QC.translate("stats", "Create rule"))
        chosen = menu.exec(viewport.mapToGlobal(pos))
        if chosen is act_edit:
            self._bulk_edit(rows)
        elif chosen is act_remove:
            self.remove_selected_subscription()
        elif chosen is act_rule:
            self.create_rule_from_selected()

    def _bulk_edit(self, rows: list[int]):
        if not rows:
            return
        dlg = BulkEditDialog(self, self._global_defaults, groups=self._known_groups())
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        values = dlg.values()
        for row in rows:
            if values.get("enabled") is not None:
                enabled_item = self.table.item(row, COL_ENABLED)
                if enabled_item is None:
                    enabled_item = QtWidgets.QTableWidgetItem("")
                    enabled_item.setFlags(enabled_item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
                    self.table.setItem(row, COL_ENABLED, enabled_item)
                enabled_item.setCheckState(
                    QtCore.Qt.CheckState.Checked if bool(values["enabled"]) else QtCore.Qt.CheckState.Unchecked
                )
            if values.get("groups") is not None:
                self._set_text_item(row, COL_GROUP, ", ".join(normalize_groups(values["groups"])))
            if values.get("format") is not None:
                self._set_text_item(row, COL_FORMAT, str(values["format"]))
            if values.get("interval") is not None:
                self._set_text_item(row, COL_INTERVAL, str(values["interval"]))
            if values.get("interval_units") is not None:
                self._set_text_item(row, COL_INTERVAL_UNITS, str(values["interval_units"]))
                self._set_units_combo(row, COL_INTERVAL_UNITS, INTERVAL_UNITS, str(values["interval_units"]))
            if values.get("timeout") is not None:
                self._set_text_item(row, COL_TIMEOUT, str(values["timeout"]))
            if values.get("timeout_units") is not None:
                self._set_text_item(row, COL_TIMEOUT_UNITS, str(values["timeout_units"]))
                self._set_units_combo(row, COL_TIMEOUT_UNITS, TIMEOUT_UNITS, str(values["timeout_units"]))
            if values.get("max_size") is not None:
                self._set_text_item(row, COL_MAX_SIZE, str(values["max_size"]))
            if values.get("max_size_units") is not None:
                self._set_text_item(row, COL_MAX_SIZE_UNITS, str(values["max_size_units"]))
                self._set_units_combo(row, COL_MAX_SIZE_UNITS, SIZE_UNITS, str(values["max_size_units"]))
            self._ensure_row_final_filename(row)
        self.save_action_file()
        self.refresh_states()
        self._set_status(
            QC.translate("stats", "Updated {0} selected subscriptions.").format(len(rows)),
            error=False,
        )

    def _known_groups(self):
        groups: set[str] = {"all"}
        for row in range(self.table.rowCount()):
            for g in normalize_groups(self._cell_text(row, COL_GROUP) or "all"):
                if g != "":
                    groups.add(g)
        return sorted(groups)

    def refresh_selected_now(self):
        row = self.table.currentRow()
        if row < 0:
            self._set_status(QC.translate("stats", "Select a subscription row first."), error=True)
            return

        url = self._cell_text(row, COL_URL)
        filename, filename_changed = self._ensure_row_final_filename(row)
        if url == "" or filename == "":
            self._set_status(QC.translate("stats", "URL and filename cannot be empty."), error=True)
            return
        if filename_changed:
            # Persist the resolved filename to action/config immediately.
            self.save_action_file()

        _, _, plug = self._find_loaded_action()
        if plug is None:
            self._set_status(QC.translate("stats", "Plugin is not loaded. Save configuration first."), error=True)
            return

        target_sub: SubscriptionSpec | None = None
        try:
            for sub in plug._config.subscriptions:
                if sub.url == url and sub.filename == filename:
                    target_sub = sub
                    break
        except Exception:
            target_sub = None

        if target_sub is None:
            try:
                interval_val = self._to_int_or_keep(self._cell_text(row, COL_INTERVAL))
                timeout_val = self._to_int_or_keep(self._cell_text(row, COL_TIMEOUT))
                max_size_val = self._to_int_or_keep(self._cell_text(row, COL_MAX_SIZE))
                row_sub_edit = MutableSubscriptionSpec(
                    enabled=True,
                    name=self._cell_text(row, COL_NAME),
                    url=url,
                    filename=filename,
                    format=self._cell_text(row, COL_FORMAT) or "hosts",
                    groups=normalize_groups(self._cell_text(row, COL_GROUP) or "all"),
                    interval=interval_val if isinstance(interval_val, int) else self._global_defaults.interval,
                    interval_units=self._cell_text(row, COL_INTERVAL_UNITS),
                    timeout=timeout_val if isinstance(timeout_val, int) else self._global_defaults.timeout,
                    timeout_units=self._cell_text(row, COL_TIMEOUT_UNITS),
                    max_size=max_size_val if isinstance(max_size_val, int) else self._global_defaults.max_size,
                    max_size_units=self._cell_text(row, COL_MAX_SIZE_UNITS),
                )
                row_sub = SubscriptionSpec.from_dict(
                    row_sub_edit.to_dict(),
                    plug._config.defaults,
                )
            except Exception:
                row_sub = None
            if row_sub is None:
                self._set_status(
                    QC.translate("stats", "Subscription not found in runtime config. Save first, then retry."),
                    error=True,
                )
                return
            target_sub = row_sub

        key = plug._sub_key(target_sub)
        list_path, _ = plug._paths(target_sub)

        def _run_refresh():
            try:
                logger.warning(
                    "list_subscriptions.gui: manual refresh start key=%s name='%s' url='%s' file='%s'",
                    key, target_sub.name, target_sub.url, target_sub.filename
                )
                if hasattr(plug, "force_refresh_subscription"):
                    plug.force_refresh_subscription(target_sub)
                else:
                    # fallback for older plugin objects
                    plug.download(key, target_sub)
            finally:
                logger.warning("list_subscriptions.gui: manual refresh finished key=%s", key)
                self._download_finished.emit()

        th = threading.Thread(target=_run_refresh, daemon=True)
        th.start()
        self._set_status(
            QC.translate("stats", "Subscription refresh triggered. Destination: {0}").format(list_path),
            error=False,
        )

    def refresh_all_now(self):
        _, _, plug = self._find_loaded_action()
        if plug is None:
            self._set_status(QC.translate("stats", "Plugin is not loaded. Save configuration first."), error=True)
            return

        def _run_all_refresh():
            try:
                subs: list[SubscriptionSpec] = []
                try:
                    subs = list(getattr(plug._config, "subscriptions", []))
                except Exception:
                    subs = []
                for sub in subs:
                    if not getattr(sub, "enabled", True):
                        continue
                    try:
                        if hasattr(plug, "force_refresh_subscription"):
                            plug.force_refresh_subscription(sub)
                        else:
                            key = plug._sub_key(sub)
                            plug.download(key, sub)
                    except Exception:
                        continue
            finally:
                self._download_finished.emit()

        th = threading.Thread(target=_run_all_refresh, daemon=True)
        th.start()
        self._set_status(QC.translate("stats", "Bulk refresh triggered for all enabled subscriptions."), error=False)

    def create_rule_from_selected(self):
        rows = self._selected_rows()
        if not rows:
            row = self.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._set_status(QC.translate("stats", "Select one or more subscriptions first."), error=True)
            return

        lists_dir = normalize_lists_dir(self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR)
        if len(rows) == 1:
            row = rows[0]
            url = self._cell_text(row, COL_URL)
            filename, filename_changed = self._ensure_row_final_filename(row)
            if url == "" or filename == "":
                self._set_status(QC.translate("stats", "URL and filename cannot be empty."), error=True)
                return
            if filename_changed:
                # Persist resolved filename so subsequent plugin runs keep the same path.
                self.save_action_file()

            name = self._cell_text(row, COL_NAME) or filename
            list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
            list_path = self._list_file_path(lists_dir, filename, list_type)
            rule_dir = self._prepare_rule_dir(url, filename, list_path, lists_dir)
            if rule_dir is None:
                return
            desc = f"From list subscription: {name}"
        else:
            rule_group = self._choose_group_for_selected(rows)
            if rule_group is None:
                return
            if not self._assign_group_to_rows(rows, rule_group):
                return
            self.save_action_file()
            rule_dir = os.path.join(lists_dir, "rules.list.d", rule_group)
            try:
                os.makedirs(rule_dir, mode=0o700, exist_ok=True)
            except Exception as e:
                self._set_status(QC.translate("stats", "Error preparing grouped rule directory: {0}").format(str(e)), error=True)
                return
            desc = f"From list subscriptions group: {rule_group}"

        if self._rules_dialog is None:
            appicon = self.windowIcon() if self.windowIcon() is not None else None
            try:
                self._rules_dialog = RulesEditorDialog(parent=None, appicon=appicon)
            except TypeError:
                self._rules_dialog = RulesEditorDialog()

        self._rules_dialog.new_rule()

        # Rules editor expects a directory containing one or more hosts files.
        self._rules_dialog.dstListsCheck.setChecked(True)
        self._rules_dialog.dstListsLine.setText(rule_dir)
        if self._rules_dialog.ruleDescEdit.toPlainText().strip() == "":
            self._rules_dialog.ruleDescEdit.setPlainText(desc)
        self._rules_dialog.raise_()
        self._rules_dialog.activateWindow()
        self._set_status(QC.translate("stats", "Rules Editor opened with prefilled list directory path."), error=False)

    def create_global_rule(self):
        lists_dir = normalize_lists_dir(self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR)
        rule_dir = os.path.join(lists_dir, "rules.list.d", "all")
        try:
            os.makedirs(rule_dir, mode=0o700, exist_ok=True)
        except Exception as e:
            self._set_status(QC.translate("stats", "Error preparing global rule directory: {0}").format(str(e)), error=True)
            return

        if self._rules_dialog is None:
            appicon = self.windowIcon() if self.windowIcon() is not None else None
            try:
                self._rules_dialog = RulesEditorDialog(parent=None, appicon=appicon)
            except TypeError:
                self._rules_dialog = RulesEditorDialog()

        self._rules_dialog.new_rule()
        self._rules_dialog.dstListsCheck.setChecked(True)
        self._rules_dialog.dstListsLine.setText(rule_dir)
        if self._rules_dialog.ruleDescEdit.toPlainText().strip() == "":
            self._rules_dialog.ruleDescEdit.setPlainText("From list subscriptions group: all")
        self._rules_dialog.raise_()
        self._rules_dialog.activateWindow()
        self._set_status(QC.translate("stats", "Rules Editor opened with global list directory path."), error=False)

    def _choose_group_for_selected(self, rows: list[int]):
        if not rows:
            return None
        selected_group_sets = [set(normalize_groups(self._cell_text(r, COL_GROUP) or "all")) for r in rows]
        common = set.intersection(*selected_group_sets) if selected_group_sets else {"all"}
        known = self._known_groups()
        default_group = "all"
        if common:
            default_group = sorted(common)[0]
        if default_group not in known:
            known.append(default_group)
        known = sorted(set(known))
        try:
            default_idx = known.index(default_group)
        except ValueError:
            default_idx = 0
        value, ok = QtWidgets.QInputDialog.getItem(
            self,
            QC.translate("stats", "Create rule from multiple subscriptions"),
            QC.translate("stats", "Select or enter a group to aggregate selected subscriptions:"),
            known,
            default_idx,
            True,
        )
        if not ok:
            return None
        group = normalize_group(value)
        if group == "":
            self._set_status(QC.translate("stats", "Group cannot be empty."), error=True)
            return None
        return group

    def _assign_group_to_rows(self, rows: list[int], group: str):
        if not rows:
            return False
        target_group = normalize_group(group)
        for row in rows:
            groups = normalize_groups(self._cell_text(row, COL_GROUP) or "all")
            groups.append(target_group)
            groups = normalize_groups(groups)
            self._set_text_item(row, COL_GROUP, ", ".join(groups))
        return True

    def _prepare_rule_dir(self, url: str, filename: str, list_path: str, lists_dir: str):
        _ = (url, filename, lists_dir)
        rule_dir = os.path.dirname(list_path)
        # Rules should point to the directory that already contains the
        # subscription list file. Do not rewrite/copy/symlink the file here.
        try:
            os.makedirs(rule_dir, mode=0o700, exist_ok=True)
            return rule_dir
        except Exception as e:
            self._set_status(QC.translate("stats", "Error preparing list rule directory: {0}").format(str(e)), error=True)
            return None

    def _list_file_path(self, lists_dir: str, filename: str, list_type: str):
        safe_name = self._safe_filename(filename)
        if safe_name == "":
            safe_name = "subscription.list"
        safe_name = ensure_filename_type_suffix(safe_name, list_type)
        base, _ext = os.path.splitext(safe_name)
        suffix = f"-{(list_type or 'hosts').strip().lower()}"
        sub_dirname = base if base else "subscription"
        if not sub_dirname.lower().endswith(suffix):
            sub_dirname = f"{sub_dirname}{suffix}"
        return os.path.join(lists_dir, "sources.list.d", sub_dirname, safe_name)

    def _apply_runtime_state(self, enabled: bool):
        old_key, old_action, old_plugin = self._find_loaded_action()
        if old_plugin is not None:
            try:
                old_plugin.stop()
            except Exception:
                pass

        if old_key is not None:
            self._actions.delete(old_key)

        if not enabled:
            return

        obj, compiled = self._actions.load(self._action_path)
        if obj is None or compiled is None:
            self._set_status(QC.translate("stats", "Config saved but runtime reload failed. Restart UI."), error=True)
            return

        obj = cast(dict[str, Any], obj)
        compiled = cast(dict[str, Any], compiled)
        self._actions._actions_list[obj["name"]] = compiled
        compiled_actions: dict[str, Any] = compiled.get("actions", {})
        plug = cast(ListSubscriptions | None, compiled_actions.get("list_subscriptions"))
        if plug is not None:
            try:
                plug.run()
            except Exception:
                self._set_status(QC.translate("stats", "Plugin enabled but failed to start. Restart UI."), error=True)

    def _find_loaded_action(self):
        for action_key, action_obj in self._actions.getAll().items():
            if action_obj is None:
                continue
            action_obj_dict = cast(dict[str, Any], action_obj)
            action_cfg: dict[str, Any] = action_obj_dict.get("actions", {})
            plug = cast(ListSubscriptions | None, action_cfg.get("list_subscriptions"))
            if plug is not None:
                return str(action_key), action_obj_dict, plug
        return None, None, None

    def _collect_subscriptions(self):
        out: list[MutableSubscriptionSpec] = []
        auto_filled = 0
        seen_filenames: dict[str, int] = {}
        for row in range(self.table.rowCount()):
            enabled_item = self.table.item(row, COL_ENABLED)
            interval = self._cell_text(row, COL_INTERVAL)
            interval_units = self._cell_text(row, COL_INTERVAL_UNITS)
            timeout = self._cell_text(row, COL_TIMEOUT)
            timeout_units = self._cell_text(row, COL_TIMEOUT_UNITS)
            max_size = self._cell_text(row, COL_MAX_SIZE)
            max_size_units = self._cell_text(row, COL_MAX_SIZE_UNITS)
            name = self._cell_text(row, COL_NAME)
            url = self._cell_text(row, COL_URL)
            list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
            groups = normalize_groups(self._cell_text(row, COL_GROUP) or "all")
            filename = self._safe_filename(self._cell_text(row, COL_FILENAME))
            if filename == "":
                filename = self._guess_filename(name, url)
                if filename != "":
                    auto_filled += 1
            filename = ensure_filename_type_suffix(filename, list_type)
            self._set_text_item(row, COL_FILENAME, filename)
            file_key = os.path.normcase(filename)
            if file_key in seen_filenames:
                first_row = seen_filenames[file_key] + 1
                self._set_status(
                    QC.translate("stats", "Conflicting filename '{0}' on rows {1} and {2}.").format(
                        filename, first_row, row + 1
                    ),
                    error=True,
                )
                return None
            seen_filenames[file_key] = row
            interval_val = self._to_int_or_keep(interval or self._global_defaults.interval)
            timeout_val = self._to_int_or_keep(timeout or self._global_defaults.timeout)
            max_size_val = self._to_int_or_keep(max_size or self._global_defaults.max_size)
            sub = MutableSubscriptionSpec(
                enabled=enabled_item is not None and enabled_item.checkState() == QtCore.Qt.CheckState.Checked,
                name=name,
                url=url,
                filename=filename,
                format=list_type,
                groups=groups,
                interval=interval_val if isinstance(interval_val, int) else self._global_defaults.interval,
                interval_units=interval_units or self._global_defaults.interval_units,
                timeout=timeout_val if isinstance(timeout_val, int) else self._global_defaults.timeout,
                timeout_units=timeout_units or self._global_defaults.timeout_units,
                max_size=max_size_val if isinstance(max_size_val, int) else self._global_defaults.max_size,
                max_size_units=max_size_units or self._global_defaults.max_size_units,
            )
            if sub.url == "" or sub.filename == "":
                self._set_status(QC.translate("stats", "URL and filename cannot be empty (row {0}).").format(row + 1), error=True)
                return None
            out.append(sub)

        if auto_filled > 0:
            self._set_status(
                QC.translate("stats", "Auto-filled filename for {0} subscription(s).").format(auto_filled),
                error=False,
            )
        return out

    def _row_meta_snapshot(self, row: int):
        lists_dir = normalize_lists_dir(self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR)
        filename = self._safe_filename(self._cell_text(row, COL_FILENAME))
        list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
        list_path = self._list_file_path(lists_dir, filename, list_type)
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
            "state": str(meta.get("last_result", self._cell_text(row, COL_STATE) or "never")),
            "last_checked": str(meta.get("last_checked", self._cell_text(row, COL_LAST_CHECKED) or "")),
            "last_updated": str(meta.get("last_updated", self._cell_text(row, COL_LAST_UPDATED) or "")),
            "failures": str(meta.get("fail_count", self._cell_text(row, COL_FAILS) or "0")),
            "error": str(meta.get("last_error", self._cell_text(row, COL_ERROR) or "")),
            "list_path": list_path,
            "meta_path": meta_path,
        }

    def _ensure_row_final_filename(self, row: int):
        name = self._cell_text(row, COL_NAME)
        url = self._cell_text(row, COL_URL)
        list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
        original = self._safe_filename(self._cell_text(row, COL_FILENAME))
        final_name = original
        changed = False

        if final_name == "":
            final_name = self._guess_filename(name, url)
            changed = final_name != ""
        final_name = ensure_filename_type_suffix(final_name, list_type)
        if final_name != original:
            changed = True

        if final_name != "":
            key = os.path.normcase(final_name)
            existing: set[str] = set()
            for i in range(self.table.rowCount()):
                if i == row:
                    continue
                other = self._safe_filename(self._cell_text(i, COL_FILENAME))
                if other != "":
                    existing.add(os.path.normcase(other))
            if key in existing:
                base, ext = os.path.splitext(final_name)
                n = 2
                candidate = final_name
                while os.path.normcase(candidate) in existing:
                    suffix = f"-{n}"
                    candidate = f"{base}{suffix}{ext}" if ext else f"{base}{suffix}"
                    n += 1
                final_name = candidate
                changed = True

        if changed:
            self._set_text_item(row, COL_FILENAME, final_name)
        return final_name, changed

    def _append_row(self, sub: MutableSubscriptionSpec):
        row = self.table.rowCount()
        self.table.insertRow(row)

        enabled_item = QtWidgets.QTableWidgetItem("")
        enabled_item.setFlags(enabled_item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
        enabled_item.setCheckState(QtCore.Qt.CheckState.Checked if bool(sub.enabled) else QtCore.Qt.CheckState.Unchecked)
        self.table.setItem(row, COL_ENABLED, enabled_item)

        self._set_text_item(row, COL_NAME, str(sub.name))
        self._set_text_item(row, COL_URL, str(sub.url))
        self._set_text_item(row, COL_FILENAME, self._safe_filename(sub.filename))
        self._set_text_item(row, COL_FORMAT, str(sub.format))
        groups = normalize_groups(sub.groups)
        self._set_text_item(row, COL_GROUP, ", ".join(groups))
        interval = sub.interval
        timeout = sub.timeout
        max_size = sub.max_size
        interval_units = sub.interval_units
        timeout_units = sub.timeout_units
        max_size_units = sub.max_size_units
        self._set_text_item(
            row,
            COL_INTERVAL,
            self._to_str(interval if interval not in ("", None) else self._global_defaults.interval),
        )
        self._set_text_item(
            row,
            COL_INTERVAL_UNITS,
            self._to_str(interval_units if interval_units not in ("", None) else self._global_defaults.interval_units),
        )
        self._set_text_item(
            row,
            COL_TIMEOUT,
            self._to_str(timeout if timeout not in ("", None) else self._global_defaults.timeout),
        )
        self._set_text_item(
            row,
            COL_TIMEOUT_UNITS,
            self._to_str(timeout_units if timeout_units not in ("", None) else self._global_defaults.timeout_units),
        )
        self._set_text_item(
            row,
            COL_MAX_SIZE,
            self._to_str(max_size if max_size not in ("", None) else self._global_defaults.max_size),
        )
        self._set_text_item(
            row,
            COL_MAX_SIZE_UNITS,
            self._to_str(max_size_units if max_size_units not in ("", None) else self._global_defaults.max_size_units),
        )
        self._set_units_combo(
            row,
            COL_INTERVAL_UNITS,
            INTERVAL_UNITS,
            self._to_str(interval_units if interval_units not in ("", None) else self._global_defaults.interval_units),
        )
        self._set_units_combo(
            row,
            COL_TIMEOUT_UNITS,
            TIMEOUT_UNITS,
            self._to_str(timeout_units if timeout_units not in ("", None) else self._global_defaults.timeout_units),
        )
        self._set_units_combo(
            row,
            COL_MAX_SIZE_UNITS,
            SIZE_UNITS,
            self._to_str(max_size_units if max_size_units not in ("", None) else self._global_defaults.max_size_units),
        )

        self._set_text_item(row, COL_FILE, "", editable=False)
        self._set_text_item(row, COL_META, "", editable=False)
        self._set_text_item(row, COL_STATE, "", editable=False)
        self._set_text_item(row, COL_LAST_CHECKED, "", editable=False)
        self._set_text_item(row, COL_LAST_UPDATED, "", editable=False)
        self._set_text_item(row, COL_FAILS, "", editable=False)
        self._set_text_item(row, COL_ERROR, "", editable=False)

    def _reload_nodes(self):
        self.nodes_combo.blockSignals(True)
        self.nodes_combo.clear()
        for addr in self._nodes.get_nodes():
            self.nodes_combo.addItem(addr, addr)
        self.nodes_combo.blockSignals(False)

    def _apply_defaults_to_widgets(self):
        self.default_interval_spin.setValue(max(1, int(self._global_defaults.interval)))
        self.default_interval_units.setCurrentText(
            self._normalize_unit(self._global_defaults.interval_units, INTERVAL_UNITS, "hours")
        )
        self.default_timeout_spin.setValue(max(1, int(self._global_defaults.timeout)))
        self.default_timeout_units.setCurrentText(
            self._normalize_unit(self._global_defaults.timeout_units, TIMEOUT_UNITS, "seconds")
        )
        self.default_max_size_spin.setValue(max(1, int(self._global_defaults.max_size)))
        self.default_max_size_units.setCurrentText(
            self._normalize_unit(self._global_defaults.max_size_units, SIZE_UNITS, "MB")
        )
        self.default_user_agent.setText((self._global_defaults.user_agent or "").strip())

    def _normalize_unit(self, value: str, allowed: tuple[str, ...], fallback: str):
        normalized = (value or "").strip().lower()
        for unit in allowed:
            if unit.lower() == normalized:
                return unit
        return fallback

    def _set_units_combo(self, row: int, col: int, allowed: tuple[str, ...], value: str):
        combo = QtWidgets.QComboBox()
        combo.addItems(allowed)
        combo.setCurrentText(self._normalize_unit(value, allowed, allowed[0]))
        self.table.setCellWidget(row, col, combo)

    def _safe_filename(self, value: Any):
        return os.path.basename((self._to_str(value) or "").strip())

    def _guess_filename(self, name: str, url: str):
        from_header = self._filename_from_headers(url)
        if from_header != "":
            return self._safe_filename(from_header)

        from_url = self._filename_from_url(url)
        if from_url != "":
            return self._safe_filename(from_url)

        slug = self._slugify_name(name)
        return self._safe_filename(slug)

    def _filename_from_headers(self, url: str):
        if (url or "").strip() == "":
            return ""
        try:
            r = requests.head(url, allow_redirects=True, timeout=5)
            cd = r.headers.get("Content-Disposition", "")
            if cd:
                # Prefer RFC 5987 filename*; fallback to filename
                filename = ""
                m_star = re.search(r'filename\*\s*=\s*[^\'";]+\'[^\'";]*\'([^;]+)', cd, re.IGNORECASE)
                if m_star:
                    filename = unquote(m_star.group(1).strip().strip('"'))
                if filename == "":
                    params = requests.utils.parse_dict_header(";".join(cd.split(";")[1:]))
                    raw = params.get("filename")
                    if raw:
                        filename = requests.utils.unquote_header_value(str(raw)).strip()
                if filename:
                    return unquote(str(filename)).strip()
        except Exception:
            return ""
        return ""

    def _filename_from_url(self, url: str):
        u = (url or "").strip()
        if u == "":
            return ""
        try:
            parsed = urlparse(u)
            base = os.path.basename(unquote(parsed.path or ""))
            return base.strip()
        except Exception:
            return ""

    def _slugify_name(self, name: str):
        raw = (name or "").strip().lower()
        if raw == "":
            return "subscription.list"
        slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
        if slug == "":
            slug = "subscription"
        if "." not in slug:
            slug += ".list"
        return slug

    def _set_text_item(self, row: int, col: int, text: str, editable: bool = True):
        item = self.table.item(row, col)
        if item is None:
            item = QtWidgets.QTableWidgetItem()
            self.table.setItem(row, col, item)
        item.setText(text)
        if editable:
            item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsEditable)
        else:
            item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)

    def _cell_text(self, row: int, col: int):
        w = self.table.cellWidget(row, col)
        if isinstance(w, QtWidgets.QComboBox):
            return (w.currentText() or "").strip()
        item = self.table.item(row, col)
        if item is None:
            return ""
        return (item.text() or "").strip()

    def _to_int_or_keep(self, value: Any):
        if value == "":
            return value
        try:
            return int(value)
        except Exception:
            return value

    def _to_str(self, value: Any):
        if value is None:
            return ""
        return str(value)

    def _set_status(self, msg: str, error: bool = False):
        self.status_label.setStyleSheet("color: red;" if error else "color: green;")
        self.status_label.setText(msg)

    def _refresh_states_if_visible(self):
        if self.isVisible() and not self._loading:
            self.refresh_states()
