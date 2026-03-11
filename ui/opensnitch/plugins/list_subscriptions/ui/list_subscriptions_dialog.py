import json
import logging
import os
import sys
from contextlib import contextmanager
from typing import cast, Any, TYPE_CHECKING, Final

if TYPE_CHECKING:
    # Keep static typing deterministic for linters/IDEs.
    # Runtime still supports both PyQt6/PyQt5 below.
    from PyQt6 import QtCore, QtGui, QtWidgets, uic
    from PyQt6.QtCore import QCoreApplication as QC
    from PyQt6.uic.load_ui import loadUiType as load_ui_type
else:
    if "PyQt6" in sys.modules:
        from PyQt6 import QtCore, QtGui, QtWidgets, uic
        from PyQt6.QtCore import QCoreApplication as QC
        from PyQt6.uic.load_ui import loadUiType as load_ui_type
    elif "PyQt5" in sys.modules:
        from PyQt5 import QtCore, QtGui, QtWidgets, uic
        from PyQt5.QtCore import QCoreApplication as QC

        load_ui_type = uic.loadUiType
    else:
        try:
            from PyQt6 import QtCore, QtGui, QtWidgets, uic
            from PyQt6.QtCore import QCoreApplication as QC
            from PyQt6.uic.load_ui import loadUiType as load_ui_type
        except Exception:
            from PyQt5 import QtCore, QtGui, QtWidgets, uic  # noqa: F401
            from PyQt5.QtCore import QCoreApplication as QC

            load_ui_type = uic.loadUiType

from opensnitch.plugins.list_subscriptions.io.storage import read_json_locked
from opensnitch.plugins.list_subscriptions.models.config import PluginConfig
from opensnitch.plugins.list_subscriptions.models.subscriptions import (
    MutableSubscriptionSpec,
    SubscriptionSpec,
)
from opensnitch.plugins.list_subscriptions.models.global_defaults import GlobalDefaults
from opensnitch.plugins.list_subscriptions.models.events import RuntimeEvent
from opensnitch.actions import Actions
from opensnitch.nodes import Nodes
from opensnitch.plugins import PluginSignal
from opensnitch.plugins.list_subscriptions.models.action import (
    MutableActionConfig,
)
from opensnitch.plugins.list_subscriptions.ui.helpers import (
    _section_background_color_name,
    _section_border_color_name,
    _apply_section_bar_style,
)
from opensnitch.plugins.list_subscriptions.ui.toggle_switch_widget import (
    _replace_checkbox_with_toggle,
)
from opensnitch.plugins.list_subscriptions.ui.subscription_dialog import (
    SubscriptionDialog,
)
from opensnitch.plugins.list_subscriptions.ui.bulk_edit_dialog import BulkEditDialog
from opensnitch.plugins.list_subscriptions._utils import (
    ACTION_FILE,
    DEFAULT_LISTS_DIR,
    RES_DIR,
    INTERVAL_UNITS,
    TIMEOUT_UNITS,
    SIZE_UNITS,
    display_str,
    derive_filename,
    ensure_filename_type_suffix,
    filename_from_content_disposition,
    list_file_path,
    normalize_group,
    normalize_groups,
    normalize_lists_dir,
    normalize_unit,
    safe_filename,
    strip_or_none,
    subscription_payload_dict,
    subscription_rule_dir,
    timestamp_sort_key,
)
from opensnitch.plugins.list_subscriptions.io.storage import (
    write_json_atomic_locked,
)
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
import requests
from opensnitch.plugins.list_subscriptions.list_subscriptions import ListSubscriptions

LIST_SUBSCRIPTIONS_DIALOG_UI_PATH: Final[str] = os.path.join(
    RES_DIR, "list_subscriptions_dialog.ui"
)

ListSubscriptionsDialogUI: Final[Any] = load_ui_type(LIST_SUBSCRIPTIONS_DIALOG_UI_PATH)[
    0
]

COL_ENABLED: Final[int] = 0
COL_NAME: Final[int] = 1
COL_URL: Final[int] = 2
COL_FILENAME: Final[int] = 3
COL_FORMAT: Final[int] = 4
COL_GROUP: Final[int] = 5
COL_INTERVAL: Final[int] = 6
COL_INTERVAL_UNITS: Final[int] = 7
COL_TIMEOUT: Final[int] = 8
COL_TIMEOUT_UNITS: Final[int] = 9
COL_MAX_SIZE: Final[int] = 10
COL_MAX_SIZE_UNITS: Final[int] = 11
COL_FILE: Final[int] = 12
COL_META: Final[int] = 13
COL_STATE: Final[int] = 14
COL_LAST_CHECKED: Final[int] = 15
COL_LAST_UPDATED: Final[int] = 16
COL_FAILS: Final[int] = 17
COL_ERROR: Final[int] = 18

logger: Final[logging.Logger] = logging.getLogger(__name__)


class KeepForegroundOnSelectionDelegate(QtWidgets.QStyledItemDelegate):
    def initStyleOption(
        self,
        option: QtWidgets.QStyleOptionViewItem | None,
        index: QtCore.QModelIndex,
    ):
        super().initStyleOption(option, index)
        if option is None or index is None:
            return
        foreground = index.data(QtCore.Qt.ItemDataRole.ForegroundRole)
        if foreground is None:
            return
        brush = (
            foreground
            if isinstance(foreground, QtGui.QBrush)
            else QtGui.QBrush(foreground)
        )
        option.palette.setBrush(
            QtGui.QPalette.ColorRole.Text,
            brush,
        )
        option.palette.setBrush(
            QtGui.QPalette.ColorRole.HighlightedText,
            brush,
        )


class CenteredCheckDelegate(QtWidgets.QStyledItemDelegate):
    def _indicator_rect(
        self,
        option: QtWidgets.QStyleOptionViewItem,
    ) -> QtCore.QRect:
        style = (
            option.widget.style()
            if option.widget is not None
            else QtWidgets.QApplication.style()
        )
        if style is None:
            return option.rect
        indicator_rect = style.subElementRect(
            QtWidgets.QStyle.SubElement.SE_ItemViewItemCheckIndicator,
            option,
            option.widget,
        )
        return QtCore.QRect(
            option.rect.x() + (option.rect.width() - indicator_rect.width()) // 2,
            option.rect.y() + (option.rect.height() - indicator_rect.height()) // 2,
            indicator_rect.width(),
            indicator_rect.height(),
        )

    def initStyleOption(
        self,
        option: QtWidgets.QStyleOptionViewItem | None,
        index: QtCore.QModelIndex,
    ) -> None:
        super().initStyleOption(option, index)
        if option is None:
            return
        option.displayAlignment = QtCore.Qt.AlignmentFlag.AlignCenter

    def paint(
        self,
        painter: QtGui.QPainter | None,
        option: QtWidgets.QStyleOptionViewItem,
        index: QtCore.QModelIndex,
    ) -> None:
        if painter is None:
            return
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        if not (
            opt.features
            & QtWidgets.QStyleOptionViewItem.ViewItemFeature.HasCheckIndicator
        ):
            super().paint(painter, option, index)
            return

        style = (
            opt.widget.style()
            if opt.widget is not None
            else QtWidgets.QApplication.style()
        )
        if style is None:
            return

        draw_opt = QtWidgets.QStyleOptionViewItem(opt)
        draw_opt.features &= (
            ~QtWidgets.QStyleOptionViewItem.ViewItemFeature.HasCheckIndicator
        )
        draw_opt.text = ""
        draw_opt.checkState = QtCore.Qt.CheckState.Unchecked
        style.drawControl(
            QtWidgets.QStyle.ControlElement.CE_ItemViewItem,
            draw_opt,
            painter,
            draw_opt.widget,
        )

        indicator_opt = QtWidgets.QStyleOptionViewItem(opt)
        indicator_opt.rect = self._indicator_rect(opt)
        indicator_opt.state &= ~(
            QtWidgets.QStyle.StateFlag.State_On
            | QtWidgets.QStyle.StateFlag.State_Off
            | QtWidgets.QStyle.StateFlag.State_NoChange
        )
        check_state_raw = index.data(QtCore.Qt.ItemDataRole.CheckStateRole)
        check_state = (
            int(check_state_raw.value)
            if isinstance(check_state_raw, QtCore.Qt.CheckState)
            else int(check_state_raw or 0)
        )
        if check_state == int(QtCore.Qt.CheckState.Checked.value):
            indicator_opt.state |= QtWidgets.QStyle.StateFlag.State_On
            indicator_opt.checkState = QtCore.Qt.CheckState.Checked
        elif check_state == int(QtCore.Qt.CheckState.PartiallyChecked.value):
            indicator_opt.state |= QtWidgets.QStyle.StateFlag.State_NoChange
            indicator_opt.checkState = QtCore.Qt.CheckState.PartiallyChecked
        else:
            indicator_opt.state |= QtWidgets.QStyle.StateFlag.State_Off
            indicator_opt.checkState = QtCore.Qt.CheckState.Unchecked
        style.drawPrimitive(
            QtWidgets.QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck,
            indicator_opt,
            painter,
            opt.widget,
        )


class SortableTableWidgetItem(QtWidgets.QTableWidgetItem):
    def __lt__(self, other: QtWidgets.QTableWidgetItem) -> bool:
        left = self.data(QtCore.Qt.ItemDataRole.UserRole)
        right = other.data(QtCore.Qt.ItemDataRole.UserRole)
        if left is not None or right is not None:
            return (left, self.text().lower()) < (right, other.text().lower())
        return super().__lt__(other)


class ListSubscriptionsDialog(QtWidgets.QDialog, ListSubscriptionsDialogUI):
    if TYPE_CHECKING:
        rootLayout: QtWidgets.QVBoxLayout
        topRowLayout: QtWidgets.QHBoxLayout
        defaultsSectionLayout: QtWidgets.QVBoxLayout
        defaultsGridLayout: QtWidgets.QGridLayout
        tableSectionLayout: QtWidgets.QVBoxLayout
        table_section_bar: QtWidgets.QFrame
        table_section_label: QtWidgets.QLabel
        tableContentLayout: QtWidgets.QVBoxLayout
        actionsRowLayout: QtWidgets.QHBoxLayout
        actionsSeparatorLayout: QtWidgets.QVBoxLayout
        globalActionsLayout: QtWidgets.QHBoxLayout
        ruleActionsLayout: QtWidgets.QHBoxLayout
        enable_plugin_check: QtWidgets.QCheckBox
        create_file_button: QtWidgets.QPushButton
        save_button: QtWidgets.QPushButton
        reload_button: QtWidgets.QPushButton
        start_runtime_button: QtWidgets.QPushButton
        stop_runtime_button: QtWidgets.QPushButton
        runtime_status_title_label: QtWidgets.QLabel
        runtime_status_label: QtWidgets.QLabel
        defaults_section_bar: QtWidgets.QFrame
        defaults_section_label: QtWidgets.QLabel
        lists_dir_label: QtWidgets.QLabel
        lists_dir_edit: QtWidgets.QLineEdit
        default_interval_label: QtWidgets.QLabel
        default_interval_spin: QtWidgets.QSpinBox
        default_interval_units: QtWidgets.QComboBox
        default_timeout_label: QtWidgets.QLabel
        default_timeout_spin: QtWidgets.QSpinBox
        default_timeout_units: QtWidgets.QComboBox
        default_max_size_label: QtWidgets.QLabel
        default_max_size_spin: QtWidgets.QSpinBox
        default_max_size_units: QtWidgets.QComboBox
        default_user_agent_label: QtWidgets.QLabel
        default_user_agent: QtWidgets.QLineEdit
        node_label: QtWidgets.QLabel
        nodes_combo: QtWidgets.QComboBox
        table: QtWidgets.QTableWidget
        global_actions_bar: QtWidgets.QFrame
        global_actions_label: QtWidgets.QLabel
        actions_vertical_separator: QtWidgets.QFrame
        add_sub_button: QtWidgets.QPushButton
        refresh_state_button: QtWidgets.QPushButton
        create_global_rule_button: QtWidgets.QPushButton
        selected_actions_bar: QtWidgets.QFrame
        selected_actions_label: QtWidgets.QLabel
        edit_sub_button: QtWidgets.QPushButton
        remove_sub_button: QtWidgets.QPushButton
        refresh_now_button: QtWidgets.QPushButton
        create_rule_button: QtWidgets.QPushButton
        status_separator_line: QtWidgets.QFrame
        status_label: QtWidgets.QLabel
        _nodes: Nodes
        _actions: Actions
        _action_path: str
        _loading: bool
        _global_defaults: GlobalDefaults
        _state_poll_timer: QtCore.QTimer
        _runtime_plugin: ListSubscriptions | None
        _pending_runtime_reload: str | None
        _pending_refresh_keys: set[str]
        _active_refresh_keys: set[str]

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
        self._global_defaults: GlobalDefaults = GlobalDefaults.from_dict(
            {}, lists_dir=DEFAULT_LISTS_DIR
        )
        self._rules_dialog: RulesEditorDialog | None = None
        self._runtime_plugin: ListSubscriptions | None = None
        self._pending_runtime_reload: str | None = None
        self._pending_refresh_keys: set[str] = set()
        self._active_refresh_keys: set[str] = set()
        self._state_poll_timer = QtCore.QTimer(self)
        self._state_poll_timer.setInterval(2000)
        self._state_poll_timer.timeout.connect(self._refresh_states_if_visible)
        self._build_ui()

    def showEvent(self, event: QtGui.QShowEvent | None):  # type: ignore[override]
        super().showEvent(event)
        self.load_action_file()
        if not self._state_poll_timer.isActive():
            self._state_poll_timer.start()

    def hideEvent(self, event: QtGui.QHideEvent | None):  # type: ignore[override]
        if self._state_poll_timer.isActive():
            self._state_poll_timer.stop()
        super().hideEvent(event)

    def closeEvent(self, event: QtGui.QCloseEvent | None):  # type: ignore[override]
        if self._state_poll_timer.isActive():
            self._state_poll_timer.stop()
        super().closeEvent(event)

    def _build_ui(self):
        self.setupUi(self)
        self.enable_plugin_check = _replace_checkbox_with_toggle(
            self.enable_plugin_check
        )
        self.setWindowTitle(QC.translate("stats", "List subscriptions"))
        self.resize(1180, 680)
        self.rootLayout.setContentsMargins(0, 0, 0, 0)
        self.rootLayout.setSpacing(0)
        self.rootLayout.setStretch(0, 0)
        self.rootLayout.setStretch(1, 0)
        self.rootLayout.setStretch(2, 1)
        self.rootLayout.setStretch(3, 0)
        self.rootLayout.setStretch(4, 0)
        self.topRowLayout.setContentsMargins(12, 10, 12, 4)
        self.topRowLayout.setSpacing(8)
        self.topRowLayout.setAlignment(QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.defaultsSectionLayout.setContentsMargins(0, 8, 0, 0)
        self.defaultsGridLayout.setContentsMargins(12, 10, 12, 10)
        self.tableSectionLayout.setContentsMargins(0, 8, 0, 0)
        self.tableContentLayout.setContentsMargins(0, 0, 0, 0)
        self.actionsRowLayout.setContentsMargins(0, 0, 0, 0)
        self.actionsRowLayout.setSpacing(0)
        self.globalActionsLayout.setContentsMargins(12, 10, 12, 10)
        self.ruleActionsLayout.setContentsMargins(12, 10, 12, 10)
        self.status_label.setContentsMargins(12, 8, 12, 8)
        self.status_label.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        self._apply_section_header_style(
            self.defaults_section_bar,
            self.defaults_section_label,
        )
        self._apply_section_header_style(
            self.table_section_bar,
            self.table_section_label,
        )
        self._apply_section_header_style(
            self.global_actions_bar,
            self.global_actions_label,
        )
        self._apply_section_header_style(
            self.selected_actions_bar,
            self.selected_actions_label,
        )
        self.actionsRowLayout.setStretch(0, 1)
        self.actionsRowLayout.setStretch(2, 1)
        self.actions_vertical_separator.hide()
        section_border_color = _section_border_color_name(self)
        self.global_actions_bar.setStyleSheet(
            "QFrame {"
            f"background-color: {_section_background_color_name(self)};"
            f"border-top: 1px solid {section_border_color};"
            f"border-bottom: 1px solid {section_border_color};"
            f"border-right: 1px solid {section_border_color};"
            "}"
        )
        self.runtime_status_label.setContentsMargins(12, 0, 0, 0)
        self.runtime_status_label.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        self.runtime_status_title_label.setContentsMargins(12, 0, 0, 0)
        self.runtime_status_title_label.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        runtime_status_title_font = self.runtime_status_title_label.font()
        runtime_status_title_font.setBold(True)
        self.runtime_status_title_label.setFont(runtime_status_title_font)
        footer_role = (
            QtGui.QPalette.ColorRole.Midlight
            if self.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128
            else QtGui.QPalette.ColorRole.Dark
        )
        footer_border = self.palette().color(footer_role).name()
        self.status_separator_line.setStyleSheet(f"color: {footer_border};")
        self.status_label.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Fixed,
        )
        self.status_label.setStyleSheet(
            f"QLabel {{ background-color: {self.palette().color(QtGui.QPalette.ColorRole.Window).name()}; padding: 8px 12px 8px 12px; }}"
        )
        for widget in (
            self.enable_plugin_check,
            self.create_file_button,
            self.save_button,
            self.reload_button,
            self.start_runtime_button,
            self.stop_runtime_button,
            self.runtime_status_title_label,
            self.runtime_status_label,
        ):
            self.topRowLayout.setAlignment(widget, QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.table.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.table.setLineWidth(0)
        self.table.setContentsMargins(0, 0, 0, 0)
        self.table.setMinimumHeight(0)
        self.table.setMaximumHeight(16777215)
        defaults_label_width = 120
        for label in (
            self.lists_dir_label,
            self.default_interval_label,
            self.default_timeout_label,
            self.default_max_size_label,
            self.default_user_agent_label,
            self.node_label,
        ):
            label.setMinimumWidth(defaults_label_width)

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
        self.table.setHorizontalHeaderLabels(
            [
                "☑",
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
            ]
        )
        for col in (
            COL_INTERVAL,
            COL_INTERVAL_UNITS,
            COL_TIMEOUT,
            COL_TIMEOUT_UNITS,
            COL_MAX_SIZE,
            COL_MAX_SIZE_UNITS,
        ):
            header_item = self.table.horizontalHeaderItem(col)
            if header_item is not None:
                header_item.setToolTip(
                    QC.translate(
                        "stats",
                        "Leave blank to inherit the global default for this subscription.",
                    )
                )
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self.table.setItemDelegateForColumn(
            COL_ENABLED, CenteredCheckDelegate(self.table)
        )
        state_delegate = KeepForegroundOnSelectionDelegate(self.table)
        for col in (
            COL_STATE,
            COL_LAST_CHECKED,
            COL_LAST_UPDATED,
        ):
            self.table.setItemDelegateForColumn(col, state_delegate)
        header = self.table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
            header.setSortIndicatorShown(True)
            header.setSortIndicator(COL_ENABLED, QtCore.Qt.SortOrder.AscendingOrder)
            header.setSectionResizeMode(
                COL_ENABLED, QtWidgets.QHeaderView.ResizeMode.Fixed
            )
            style = self.table.style()
            if style is not None:
                indicator_w = style.pixelMetric(
                    QtWidgets.QStyle.PixelMetric.PM_IndicatorWidth,
                    None,
                    self.table,
                )
                indicator_h = style.pixelMetric(
                    QtWidgets.QStyle.PixelMetric.PM_IndicatorHeight,
                    None,
                    self.table,
                )
                self.table.setColumnWidth(
                    COL_ENABLED, max(indicator_w, indicator_h) + 18
                )
            header.setSectionResizeMode(
                COL_URL, QtWidgets.QHeaderView.ResizeMode.Stretch
            )
            header.setSectionResizeMode(
                COL_ERROR, QtWidgets.QHeaderView.ResizeMode.Stretch
            )
        self.table.setSortingEnabled(True)
        self.table.sortItems(COL_ENABLED, QtCore.Qt.SortOrder.AscendingOrder)
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
        self.reload_button.clicked.connect(self.reload_runtime_and_config)
        self.start_runtime_button.clicked.connect(self.start_runtime_clicked)
        self.stop_runtime_button.clicked.connect(self.stop_runtime_clicked)
        self.add_sub_button.clicked.connect(self.add_subscription_row)
        self.create_global_rule_button.clicked.connect(self.create_global_rule)
        self.edit_sub_button.clicked.connect(self.edit_action_clicked)
        self.remove_sub_button.clicked.connect(self.remove_selected_subscription)
        self.refresh_state_button.clicked.connect(self.refresh_all_now)
        self.refresh_now_button.clicked.connect(self.refresh_selected_now)
        self.create_rule_button.clicked.connect(self.create_rule_from_selected)
        self.table.itemDoubleClicked.connect(
            lambda *_: self.edit_selected_subscription()
        )
        self.table.clicked.connect(self._handle_table_clicked)
        self.table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._open_table_context_menu)
        sel_model = self.table.selectionModel()
        if sel_model is not None:
            sel_model.selectionChanged.connect(
                lambda *_: self._update_selected_actions_state()
            )
        self._set_runtime_state(active=False)
        self._update_selected_actions_state()

    def _apply_section_header_style(
        self, container: QtWidgets.QFrame, label: QtWidgets.QLabel
    ):
        _apply_section_bar_style(
            self,
            container,
            label,
            expanding_label=True,
        )

    @contextmanager
    def _sorting_suspended(self):
        header = self.table.horizontalHeader()
        sorting_enabled = self.table.isSortingEnabled()
        sort_section = header.sortIndicatorSection() if header is not None else -1
        sort_order = (
            header.sortIndicatorOrder()
            if header is not None
            else QtCore.Qt.SortOrder.AscendingOrder
        )
        self.table.setSortingEnabled(False)
        try:
            yield
        finally:
            self.table.setSortingEnabled(sorting_enabled)
            if sorting_enabled and header is not None and sort_section >= 0:
                self.table.sortItems(sort_section, sort_order)

    def _sort_key_for_column(self, col: int, text: str):
        value = (text or "").strip()
        if col in (
            COL_INTERVAL,
            COL_TIMEOUT,
            COL_MAX_SIZE,
            COL_FAILS,
        ):
            if value == "":
                return -1
            try:
                return int(value)
            except Exception:
                return value.lower()
        if col in (COL_LAST_CHECKED, COL_LAST_UPDATED):
            return timestamp_sort_key(value)
        if col == COL_STATE:
            return self._state_sort_value(value)
        return value.lower()

    def _state_sort_value(self, value: str):
        normalized = (value or "").strip().lower()
        if normalized in ("updated", "not_modified"):
            return 0, normalized
        if normalized == "pending":
            return 1, normalized
        return 2, normalized

    def _update_row_sort_keys(self, row: int):
        enabled_item = self.table.item(row, COL_ENABLED)
        state_item = self.table.item(row, COL_STATE)
        last_checked_item = self.table.item(row, COL_LAST_CHECKED)
        if enabled_item is None:
            return

        enabled_rank = (
            0 if enabled_item.checkState() == QtCore.Qt.CheckState.Checked else 1
        )
        state_text = state_item.text() if state_item is not None else ""
        state_rank = self._state_sort_value(state_text)
        last_checked_text = (
            last_checked_item.text() if last_checked_item is not None else ""
        )
        last_checked_rank = timestamp_sort_key(last_checked_text)
        combined_rank = (enabled_rank, state_rank, last_checked_rank)

        enabled_item.setData(QtCore.Qt.ItemDataRole.UserRole, combined_rank)

    def _new_enabled_item(self, enabled: bool) -> SortableTableWidgetItem:
        item = SortableTableWidgetItem("")
        item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(
            QtCore.Qt.CheckState.Checked if enabled else QtCore.Qt.CheckState.Unchecked
        )
        item.setData(QtCore.Qt.ItemDataRole.UserRole, 1 if enabled else 0)
        return item

    def _sync_runtime_binding_state(self):
        runtime_plugin = ListSubscriptions.get_instance()
        if runtime_plugin is None:
            _action_key, _action_obj, loaded_plugin = self._find_loaded_action()
            runtime_plugin = loaded_plugin

        if runtime_plugin is not None:
            self._bind_runtime_plugin(runtime_plugin)
            self._set_runtime_state(
                active=bool(getattr(runtime_plugin, "enabled", False)),
            )
            return runtime_plugin

        self._runtime_plugin = None
        self._set_runtime_state(active=False)
        self._set_refresh_busy(False)
        return None

    def _set_refresh_busy(self, busy: bool):
        self.refresh_state_button.setEnabled(not busy)
        self.refresh_now_button.setEnabled(not busy and len(self._selected_rows()) > 0)

    def _track_refresh_keys(self, keys: set[str]):
        if not keys:
            return
        self._pending_refresh_keys.update(keys)
        self._set_refresh_busy(True)

    def _clear_refresh_key(self, key: str):
        self._pending_refresh_keys.discard(key)
        self._active_refresh_keys.discard(key)
        if not self._pending_refresh_keys and not self._active_refresh_keys:
            self._set_refresh_busy(False)

    def _refresh_keys_from_payload(self, payload: dict[str, Any]):
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

    def _runtime_event_items(self, payload: dict[str, Any]):
        items_raw = payload.get("items")
        if not isinstance(items_raw, list):
            return []
        return [item for item in items_raw if isinstance(item, dict)]

    def _runtime_download_message(
        self,
        event_name: RuntimeEvent | None,
        payload: dict[str, Any],
        fallback: str,
    ):
        items = self._runtime_event_items(payload)
        if not items:
            return fallback
        count = len(items)
        first_name = str(items[0].get("name") or "").strip()
        if event_name == RuntimeEvent.DOWNLOAD_STARTED:
            if count == 1 and first_name != "":
                return QC.translate("stats", "Refreshing subscription '{0}'.").format(
                    first_name
                )
            return QC.translate("stats", "Refreshing {0} subscriptions.").format(count)
        if event_name == RuntimeEvent.DOWNLOAD_FINISHED:
            if count == 1 and first_name != "":
                return QC.translate("stats", "Subscription '{0}' refreshed.").format(
                    first_name
                )
            return QC.translate("stats", "Refreshed {0} subscriptions.").format(count)
        if event_name == RuntimeEvent.DOWNLOAD_FAILED:
            if count == 1 and first_name != "":
                return QC.translate(
                    "stats", "Subscription '{0}' refresh failed."
                ).format(first_name)
            return QC.translate(
                "stats", "Refresh failed for {0} subscriptions."
            ).format(count)
        return fallback

    def load_action_file(self):
        with self._sorting_suspended():
            self._loading = True
            self._set_status("")
            self._reload_nodes()
            self.table.setRowCount(0)
            self.create_file_button.setVisible(True)
            self.lists_dir_edit.setText(DEFAULT_LISTS_DIR)
            self.enable_plugin_check.setChecked(False)
            self._set_runtime_state(active=False)
            self._global_defaults = GlobalDefaults.from_dict(
                {}, lists_dir=DEFAULT_LISTS_DIR
            )
            self._apply_defaults_to_widgets()

            if not os.path.exists(self._action_path):
                self._set_status(
                    QC.translate(
                        "stats", "Action file not found. Click 'Create action file'."
                    ),
                    error=False,
                )
                self._loading = False
                return

            try:
                data = read_json_locked(self._action_path)
            except Exception as e:
                self._set_status(
                    QC.translate("stats", "Error reading action file: {0}").format(
                        str(e)
                    ),
                    error=True,
                )
                self._loading = False
                return

            action_model = MutableActionConfig.from_action_dict(
                data, lists_dir=DEFAULT_LISTS_DIR
            )
            self._global_defaults = action_model.plugin.defaults
            self.enable_plugin_check.setChecked(action_model.enabled)
            self._sync_runtime_binding_state()
            self.lists_dir_edit.setText(
                normalize_lists_dir(self._global_defaults.lists_dir)
            )
            self._apply_defaults_to_widgets()

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
                self._append_row(sub)

            self._loading = False
            self.refresh_states()
            self._update_selected_actions_state()
            self.create_file_button.setVisible(False)
            if migrated_legacy_group:
                self.save_action_file()
                self._set_status(
                    QC.translate(
                        "stats",
                        "Migrated legacy 'group' entries to 'groups' and auto-saved configuration.",
                    ),
                    error=False,
                )
                return
            if fixed_count > 0:
                self._set_status(
                    QC.translate(
                        "stats",
                        "Loaded configuration with normalized subscription fields.",
                    ),
                    error=False,
                )
            else:
                self._set_status(
                    QC.translate("stats", "List subscriptions configuration loaded."),
                    error=False,
                )

    def start_runtime_clicked(self):
        runtime_plugin = self._sync_runtime_binding_state()
        if runtime_plugin is not None and bool(
            getattr(runtime_plugin, "enabled", False)
        ):
            self._bind_runtime_plugin(runtime_plugin)
            self._set_runtime_state(active=True)
            self._set_status(QC.translate("stats", "Runtime is already active."))
            return

        if not os.path.exists(self._action_path):
            self._set_status(
                QC.translate(
                    "stats",
                    "Action file not found. Create and save the configuration first.",
                ),
                error=True,
            )
            return

        if runtime_plugin is not None:
            self._bind_runtime_plugin(runtime_plugin)
            self._set_runtime_state(
                active=None, text=QC.translate("stats", "Runtime: starting")
            )
            try:
                runtime_plugin.signal_in.emit(
                    {
                        "plugin": runtime_plugin.get_name(),
                        "signal": PluginSignal.ENABLE,
                        "action_path": self._action_path,
                    }
                )
            except Exception:
                self._set_runtime_state(active=False)
                self._set_status(
                    QC.translate("stats", "Failed to start runtime."),
                    error=True,
                )
            return

        plug = ListSubscriptions({})
        self._bind_runtime_plugin(plug)
        self._set_runtime_state(
            active=None,
            text=QC.translate("stats", "Runtime: starting"),
        )
        try:
            plug.signal_in.emit(
                {
                    "plugin": plug.get_name(),
                    "signal": PluginSignal.ENABLE,
                    "action_path": self._action_path,
                }
            )
        except Exception:
            self._set_runtime_state(active=False)
            self._set_status(
                QC.translate("stats", "Failed to start runtime."),
                error=True,
            )

    def stop_runtime_clicked(self):
        runtime_plugin = self._sync_runtime_binding_state()
        if runtime_plugin is None or not bool(
            getattr(runtime_plugin, "enabled", False)
        ):
            self._set_runtime_state(active=False)
            self._set_status(QC.translate("stats", "Runtime is already inactive."))
            return

        self._bind_runtime_plugin(runtime_plugin)
        self._set_runtime_state(
            active=None, text=QC.translate("stats", "Runtime: stopping")
        )
        try:
            runtime_plugin.signal_in.emit(
                {
                    "plugin": runtime_plugin.get_name(),
                    "signal": PluginSignal.DISABLE,
                    "action_path": self._action_path,
                }
            )
        except Exception:
            self._set_status(
                QC.translate("stats", "Failed to stop runtime."),
                error=True,
            )

    def reload_runtime_and_config(self):
        runtime_plugin = self._sync_runtime_binding_state()
        if runtime_plugin is None or not bool(
            getattr(runtime_plugin, "enabled", False)
        ):
            self.load_action_file()
            return

        self._bind_runtime_plugin(runtime_plugin)
        self._pending_runtime_reload = "waiting_config_reload"
        try:
            runtime_plugin.signal_in.emit(
                {
                    "plugin": runtime_plugin.get_name(),
                    "signal": PluginSignal.CONFIG_UPDATE,
                    "action_path": self._action_path,
                }
            )
        except Exception:
            self._pending_runtime_reload = None
            self._set_status(
                QC.translate("stats", "Runtime reload failed to start. Restart UI."),
                error=True,
            )

    def create_action_file(self):
        try:
            os.makedirs(os.path.dirname(self._action_path), mode=0o700, exist_ok=True)
            if not os.path.exists(self._action_path):
                action_model = MutableActionConfig.default(DEFAULT_LISTS_DIR)
                write_json_atomic_locked(
                    self._action_path,
                    action_model.to_action_dict(),
                )
            self.load_action_file()
            self._set_status(QC.translate("stats", "Action file created."), error=False)
        except Exception as e:
            self._set_status(
                QC.translate("stats", "Error creating action file: {0}").format(str(e)),
                error=True,
            )

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

        lists_dir = normalize_lists_dir(
            self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
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
        action_model.plugin.defaults = defaults
        action_model.plugin.subscriptions = subscriptions
        normalized_subscriptions = action_model.plugin.normalize_subscriptions(
            invalidate_duplicates=True
        )
        if normalized_subscriptions is None:
            self._set_status(
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
            self._set_status(
                QC.translate(
                    "stats", "Invalid subscriptions: URL and filename are mandatory."
                ),
                error=True,
            )
            return

        for row, sub in enumerate(normalized_subscriptions):
            self._set_text_item(row, COL_NAME, sub.name)
            self._set_text_item(row, COL_FILENAME, safe_filename(sub.filename))

        try:
            write_json_atomic_locked(self._action_path, action)
        except Exception as e:
            self._set_status(
                QC.translate("stats", "Error saving action file: {0}").format(str(e)),
                error=True,
            )
            return

        self._apply_runtime_state(action_model.enabled)
        self.refresh_states()
        self._set_status(
            QC.translate("stats", "List subscriptions configuration saved."),
            error=False,
        )

    def refresh_states(self):
        with self._sorting_suspended():
            lists_dir = normalize_lists_dir(
                self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
            )
            for row in range(self.table.rowCount()):
                filename_item = self.table.item(row, COL_FILENAME)
                enabled_item = self.table.item(row, COL_ENABLED)
                if filename_item is None or enabled_item is None:
                    continue

                filename = safe_filename(filename_item.text())
                list_type = (
                    (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
                )
                enabled = enabled_item.checkState() == QtCore.Qt.CheckState.Checked
                list_path = list_file_path(lists_dir, filename, list_type)
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
                fg_color: QtGui.QColor

                if not enabled:
                    state = "disabled"
                    fg_color = self._state_text_color("disabled")
                elif not file_exists:
                    # New/manual subscriptions may not be downloaded yet.
                    # Expose that as pending instead of an error-like missing state.
                    if not meta_exists or last_result in ("never", "", "busy"):
                        state = "pending"
                        fg_color = self._state_text_color("pending")
                    else:
                        state = "missing"
                        fg_color = self._state_text_color("missing")
                elif last_result in ("updated", "not_modified"):
                    state = last_result
                    fg_color = self._state_text_color(last_result)
                elif last_result in (
                    "error",
                    "write_error",
                    "request_error",
                    "unexpected_error",
                    "bad_format",
                    "too_large",
                ):
                    state = last_result
                    fg_color = self._state_text_color(last_result)
                elif last_result == "busy":
                    state = "busy"
                    fg_color = self._state_text_color("busy")
                else:
                    state = last_result
                    fg_color = self._state_text_color("other")

                self._set_text_item(
                    row, COL_FILE, "yes" if file_exists else "no", editable=False
                )
                self._set_text_item(
                    row, COL_META, "yes" if meta_exists else "no", editable=False
                )
                self._set_text_item(row, COL_STATE, state, editable=False)
                self._set_text_item(row, COL_LAST_CHECKED, last_checked, editable=False)
                self._set_text_item(row, COL_LAST_UPDATED, last_updated, editable=False)
                self._set_text_item(row, COL_FAILS, fail_count, editable=False)
                self._set_text_item(row, COL_ERROR, last_error, editable=False)

                for col in (
                    COL_FILE,
                    COL_META,
                    COL_STATE,
                    COL_LAST_CHECKED,
                    COL_LAST_UPDATED,
                    COL_FAILS,
                    COL_ERROR,
                ):
                    item = self.table.item(row, col)
                    if item is not None:
                        item.setForeground(fg_color)
                self._update_row_sort_keys(row)

    def _state_text_color(self, state: str):
        palette = self.table.palette()
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

    def add_subscription_row(self):
        dlg = SubscriptionDialog(
            self,
            self._global_defaults,
            groups=self._known_groups(),
            sub=MutableSubscriptionSpec.from_dict(
                {"enabled": True},
                defaults=self._global_defaults,
                require_url=False,
                ensure_suffix=False,
            ),
            title="New subscription",
        )
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return

        sub = dlg.subscription_spec()
        with self._sorting_suspended():
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
            self._set_status(
                QC.translate("stats", "Select a subscription row first."), error=True
            )
            return
        with self._sorting_suspended():
            enabled_item = self.table.item(row, COL_ENABLED)
            if enabled_item is None:
                enabled_item = self._new_enabled_item(False)
                self.table.setItem(row, COL_ENABLED, enabled_item)

        interval_ok, interval_val = self._optional_int_from_text(
            self._cell_text(row, COL_INTERVAL), "Interval", row=row
        )
        timeout_ok, timeout_val = self._optional_int_from_text(
            self._cell_text(row, COL_TIMEOUT), "Timeout", row=row
        )
        max_size_ok, max_size_val = self._optional_int_from_text(
            self._cell_text(row, COL_MAX_SIZE), "Max size", row=row
        )
        if not interval_ok or not timeout_ok or not max_size_ok:
            return
        sub = MutableSubscriptionSpec(
            enabled=enabled_item.checkState() == QtCore.Qt.CheckState.Checked,
            name=self._cell_text(row, COL_NAME),
            url=self._cell_text(row, COL_URL),
            filename=self._cell_text(row, COL_FILENAME),
            format=self._cell_text(row, COL_FORMAT) or "hosts",
            groups=normalize_groups(self._cell_text(row, COL_GROUP)),
            interval=interval_val,
            interval_units=strip_or_none(self._cell_text(row, COL_INTERVAL_UNITS)),
            timeout=timeout_val,
            timeout_units=strip_or_none(self._cell_text(row, COL_TIMEOUT_UNITS)),
            max_size=max_size_val,
            max_size_units=strip_or_none(self._cell_text(row, COL_MAX_SIZE_UNITS)),
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

        with self._sorting_suspended():
            enabled_item = self.table.item(row, COL_ENABLED)
            if enabled_item is None:
                enabled_item = self._new_enabled_item(False)
                self.table.setItem(row, COL_ENABLED, enabled_item)
            enabled_item.setCheckState(
                QtCore.Qt.CheckState.Checked
                if bool(updated.enabled)
                else QtCore.Qt.CheckState.Unchecked
            )
            enabled_item.setData(
                QtCore.Qt.ItemDataRole.UserRole, 1 if bool(updated.enabled) else 0
            )
            self._set_text_item(row, COL_NAME, updated.name)
            self._set_text_item(row, COL_URL, updated.url)
            self._set_text_item(row, COL_FILENAME, safe_filename(updated.filename))
            self._set_text_item(row, COL_FORMAT, updated.format)
            self._set_text_item(
                row, COL_GROUP, ", ".join(normalize_groups(updated.groups))
            )
            self._set_text_item(row, COL_INTERVAL, display_str(updated.interval))
            interval_units_val = display_str(updated.interval_units)
            self._set_text_item(row, COL_INTERVAL_UNITS, interval_units_val)
            self._set_text_item(row, COL_TIMEOUT, display_str(updated.timeout))
            timeout_units_val = display_str(updated.timeout_units)
            self._set_text_item(row, COL_TIMEOUT_UNITS, timeout_units_val)
            self._set_text_item(row, COL_MAX_SIZE, display_str(updated.max_size))
            max_size_units_val = display_str(updated.max_size_units)
            self._set_text_item(row, COL_MAX_SIZE_UNITS, max_size_units_val)
            self._set_units_combo(
                row, COL_INTERVAL_UNITS, INTERVAL_UNITS, interval_units_val
            )
            self._set_units_combo(
                row, COL_TIMEOUT_UNITS, TIMEOUT_UNITS, timeout_units_val
            )
            self._set_units_combo(
                row, COL_MAX_SIZE_UNITS, SIZE_UNITS, max_size_units_val
            )

            _, changed = self._ensure_row_final_filename(row)
            self._update_row_sort_keys(row)
        self.save_action_file()
        self.refresh_states()
        if changed:
            self._set_status(
                QC.translate("stats", "Subscription updated and filename normalized."),
                error=False,
            )
        else:
            self._set_status(
                QC.translate("stats", "Subscription updated."), error=False
            )

    def edit_action_clicked(self):
        rows = self._selected_rows()
        if len(rows) == 0:
            self._set_status(
                QC.translate("stats", "Select one or more subscriptions first."),
                error=True,
            )
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
            self._set_status(
                QC.translate("stats", "Select one or more subscription rows first."),
                error=True,
            )
            return
        for row in sorted(rows, reverse=True):
            self.table.removeRow(row)
        self.save_action_file()
        self.refresh_states()
        self._update_selected_actions_state()
        self._set_status(
            QC.translate("stats", "Selected subscriptions removed."), error=False
        )

    def _selected_rows(self):
        idx = self.table.selectionModel()
        if idx is None:
            return []
        return sorted({i.row() for i in idx.selectedRows()})

    def _handle_table_clicked(self, index: QtCore.QModelIndex):
        if not index.isValid() or index.column() != COL_ENABLED:
            return
        item = self.table.item(index.row(), COL_ENABLED)
        if item is None:
            return
        checked = item.checkState() != QtCore.Qt.CheckState.Checked
        item.setCheckState(
            QtCore.Qt.CheckState.Checked if checked else QtCore.Qt.CheckState.Unchecked
        )
        self._update_row_sort_keys(index.row())
        header = self.table.horizontalHeader()
        if (
            self.table.isSortingEnabled()
            and header is not None
            and header.sortIndicatorSection()
            in (COL_ENABLED, COL_STATE, COL_LAST_CHECKED)
        ):
            self.table.sortItems(
                header.sortIndicatorSection(), header.sortIndicatorOrder()
            )

    def _update_selected_actions_state(self):
        count = len(self._selected_rows())
        has_selection = count > 0
        self.edit_sub_button.setEnabled(has_selection)
        self.remove_sub_button.setEnabled(has_selection)
        self.refresh_now_button.setEnabled(
            has_selection
            and not self._pending_refresh_keys
            and not self._active_refresh_keys
        )
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
            act_refresh = menu.addAction(QC.translate("stats", "Refresh"))
            act_rule = menu.addAction(QC.translate("stats", "Create rule"))
            chosen = QtWidgets.QMenu.exec(
                menu.actions(),
                viewport.mapToGlobal(pos),
                None,
                menu,
            )
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
        act_refresh = menu.addAction(QC.translate("stats", "Refresh"))
        act_rule = menu.addAction(QC.translate("stats", "Create rule"))
        chosen = QtWidgets.QMenu.exec(
            menu.actions(),
            viewport.mapToGlobal(pos),
            None,
            menu,
        )
        if chosen is act_edit:
            self._bulk_edit(rows)
        elif chosen is act_remove:
            self.remove_selected_subscription()
        elif chosen is act_refresh:
            self.refresh_selected_now()
        elif chosen is act_rule:
            self.create_rule_from_selected()

    def _bulk_edit(self, rows: list[int]):
        if not rows:
            return
        dlg = BulkEditDialog(
            self,
            self._global_defaults,
            groups=self._known_groups(),
            selected_count=len(rows),
        )
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        values = dlg.values()
        with self._sorting_suspended():
            for row in rows:
                if values.get("enabled") is not None:
                    enabled_item = self.table.item(row, COL_ENABLED)
                    if enabled_item is None:
                        enabled_item = self._new_enabled_item(False)
                        self.table.setItem(row, COL_ENABLED, enabled_item)
                    enabled_item.setCheckState(
                        QtCore.Qt.CheckState.Checked
                        if bool(values["enabled"])
                        else QtCore.Qt.CheckState.Unchecked
                    )
                if values.get("groups") is not None:
                    self._set_text_item(
                        row, COL_GROUP, ", ".join(normalize_groups(values["groups"]))
                    )
                if values.get("format") is not None:
                    self._set_text_item(row, COL_FORMAT, str(values["format"]))
                if values.get("apply_interval"):
                    self._set_text_item(
                        row, COL_INTERVAL, display_str(values.get("interval"))
                    )
                    interval_units = display_str(values.get("interval_units"))
                    self._set_text_item(row, COL_INTERVAL_UNITS, interval_units)
                    self._set_units_combo(
                        row, COL_INTERVAL_UNITS, INTERVAL_UNITS, interval_units
                    )
                if values.get("apply_timeout"):
                    self._set_text_item(
                        row, COL_TIMEOUT, display_str(values.get("timeout"))
                    )
                    timeout_units = display_str(values.get("timeout_units"))
                    self._set_text_item(row, COL_TIMEOUT_UNITS, timeout_units)
                    self._set_units_combo(
                        row, COL_TIMEOUT_UNITS, TIMEOUT_UNITS, timeout_units
                    )
                if values.get("apply_max_size"):
                    self._set_text_item(
                        row, COL_MAX_SIZE, display_str(values.get("max_size"))
                    )
                    max_size_units = display_str(values.get("max_size_units"))
                    self._set_text_item(row, COL_MAX_SIZE_UNITS, max_size_units)
                    self._set_units_combo(
                        row, COL_MAX_SIZE_UNITS, SIZE_UNITS, max_size_units
                    )
                self._ensure_row_final_filename(row)
                self._update_row_sort_keys(row)
        self.save_action_file()
        self.refresh_states()
        self._set_status(
            QC.translate("stats", "Updated {0} selected subscriptions.").format(
                len(rows)
            ),
            error=False,
        )

    def _known_groups(self):
        groups: set[str] = set()
        for row in range(self.table.rowCount()):
            for g in normalize_groups(self._cell_text(row, COL_GROUP)):
                if g not in ("", "all"):
                    groups.add(g)
        return sorted(groups)

    def refresh_selected_now(self):
        rows = self._selected_rows()
        if not rows:
            row = self.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._set_status(
                QC.translate("stats", "Select one or more subscription rows first."),
                error=True,
            )
            return

        _, _, plug = self._find_loaded_action()
        if plug is None:
            self._set_status(
                QC.translate(
                    "stats", "Plugin is not loaded. Save configuration first."
                ),
                error=True,
            )
            return

        refresh_targets: list[tuple[SubscriptionSpec, str]] = []
        filename_changed = False
        for row in rows:
            url = self._cell_text(row, COL_URL)
            filename, row_filename_changed = self._ensure_row_final_filename(row)
            if url == "" or filename == "":
                self._set_status(
                    QC.translate(
                        "stats", "URL and filename cannot be empty (row {0})."
                    ).format(row + 1),
                    error=True,
                )
                return
            filename_changed = filename_changed or row_filename_changed

        if filename_changed:
            self.save_action_file()

        for row in rows:
            url = self._cell_text(row, COL_URL)
            filename = self._cell_text(row, COL_FILENAME)
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
                    interval_ok, interval_val = self._optional_int_from_text(
                        self._cell_text(row, COL_INTERVAL), "Interval", row=row
                    )
                    timeout_ok, timeout_val = self._optional_int_from_text(
                        self._cell_text(row, COL_TIMEOUT), "Timeout", row=row
                    )
                    max_size_ok, max_size_val = self._optional_int_from_text(
                        self._cell_text(row, COL_MAX_SIZE), "Max size", row=row
                    )
                    if not interval_ok or not timeout_ok or not max_size_ok:
                        return
                    row_sub_edit = MutableSubscriptionSpec(
                        enabled=True,
                        name=self._cell_text(row, COL_NAME),
                        url=url,
                        filename=filename,
                        format=self._cell_text(row, COL_FORMAT) or "hosts",
                        groups=normalize_groups(self._cell_text(row, COL_GROUP)),
                        interval=interval_val,
                        interval_units=strip_or_none(
                            self._cell_text(row, COL_INTERVAL_UNITS)
                        ),
                        timeout=timeout_val,
                        timeout_units=strip_or_none(
                            self._cell_text(row, COL_TIMEOUT_UNITS)
                        ),
                        max_size=max_size_val,
                        max_size_units=strip_or_none(
                            self._cell_text(row, COL_MAX_SIZE_UNITS)
                        ),
                    )
                    row_sub = SubscriptionSpec.from_dict(
                        row_sub_edit.to_dict(),
                        plug._config.defaults,
                    )
                except Exception:
                    row_sub = None
                if row_sub is None:
                    self._set_status(
                        QC.translate(
                            "stats",
                            "Subscription not found in runtime config. Save first, then retry.",
                        ),
                        error=True,
                    )
                    return
                target_sub = row_sub
            if target_sub is None:
                self._set_status(QC.translate("stats", "Internal error: target_sub is None."), error=True)
                return
            list_path, _ = plug._paths(target_sub)
            refresh_targets.append((target_sub, list_path))

        refresh_keys = {plug._sub_key(target_sub) for target_sub, _ in refresh_targets}
        self._track_refresh_keys(refresh_keys)
        plug.signal_in.emit(
            {
                "plugin": plug.get_name(),
                "signal": plug.REFRESH_SUBSCRIPTIONS_SIGNAL,
                "action_path": self._action_path,
                "source": "manual_refresh",
                "items": [
                    subscription_payload_dict(
                        enabled=target_sub.enabled,
                        name=target_sub.name,
                        url=target_sub.url,
                        filename=target_sub.filename,
                        list_type=target_sub.format,
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
            self._set_status(
                QC.translate(
                    "stats", "Subscription refresh triggered. Destination: {0}"
                ).format(refresh_targets[0][1]),
                error=False,
            )
            return

        self._set_status(
            QC.translate(
                "stats", "Bulk refresh triggered for {0} selected subscriptions."
            ).format(len(refresh_targets)),
            error=False,
        )

    def refresh_all_now(self):
        _, _, plug = self._find_loaded_action()
        if plug is None:
            self._set_status(
                QC.translate(
                    "stats", "Plugin is not loaded. Save configuration first."
                ),
                error=True,
            )
            return

        rows = list(range(self.table.rowCount()))
        if not rows:
            self._set_status(
                QC.translate("stats", "No subscriptions available to refresh."),
                error=True,
            )
            return

        filename_changed = False
        for row in rows:
            url = self._cell_text(row, COL_URL)
            filename, row_filename_changed = self._ensure_row_final_filename(row)
            if url == "" or filename == "":
                self._set_status(
                    QC.translate(
                        "stats", "URL and filename cannot be empty (row {0})."
                    ).format(row + 1),
                    error=True,
                )
                return
            filename_changed = filename_changed or row_filename_changed

        if filename_changed:
            self.save_action_file()
            _, _, plug = self._find_loaded_action()
            if plug is None:
                self._set_status(
                    QC.translate(
                        "stats", "Plugin is not loaded. Save configuration first."
                    ),
                    error=True,
                )
                return

        refresh_targets: list[SubscriptionSpec] = []
        for row in rows:
            url = self._cell_text(row, COL_URL)
            filename = self._cell_text(row, COL_FILENAME)
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
                    enabled_item = self.table.item(row, COL_ENABLED)
                    interval_ok, interval_val = self._optional_int_from_text(
                        self._cell_text(row, COL_INTERVAL), "Interval", row=row
                    )
                    timeout_ok, timeout_val = self._optional_int_from_text(
                        self._cell_text(row, COL_TIMEOUT), "Timeout", row=row
                    )
                    max_size_ok, max_size_val = self._optional_int_from_text(
                        self._cell_text(row, COL_MAX_SIZE), "Max size", row=row
                    )
                    if not interval_ok or not timeout_ok or not max_size_ok:
                        return
                    row_sub_edit = MutableSubscriptionSpec(
                        enabled=(
                            enabled_item is None
                            or enabled_item.checkState() == QtCore.Qt.CheckState.Checked
                        ),
                        name=self._cell_text(row, COL_NAME),
                        url=url,
                        filename=filename,
                        format=self._cell_text(row, COL_FORMAT) or "hosts",
                        groups=normalize_groups(self._cell_text(row, COL_GROUP)),
                        interval=interval_val,
                        interval_units=strip_or_none(
                            self._cell_text(row, COL_INTERVAL_UNITS)
                        ),
                        timeout=timeout_val,
                        timeout_units=strip_or_none(
                            self._cell_text(row, COL_TIMEOUT_UNITS)
                        ),
                        max_size=max_size_val,
                        max_size_units=strip_or_none(
                            self._cell_text(row, COL_MAX_SIZE_UNITS)
                        ),
                    )
                    target_sub = SubscriptionSpec.from_dict(
                        row_sub_edit.to_dict(),
                        plug._config.defaults,
                    )
                except Exception:
                    target_sub = None
            if target_sub is not None:
                refresh_targets.append(target_sub)

        if not refresh_targets:
            self._set_status(
                QC.translate("stats", "No subscriptions available to refresh."),
                error=True,
            )
            return

        refresh_keys = {plug._sub_key(sub) for sub in refresh_targets}
        self._track_refresh_keys(refresh_keys)
        plug.signal_in.emit(
            {
                "plugin": plug.get_name(),
                "signal": plug.REFRESH_SUBSCRIPTIONS_SIGNAL,
                "action_path": self._action_path,
                "source": "manual_refresh",
                "items": [
                    subscription_payload_dict(
                        enabled=sub.enabled,
                        name=sub.name,
                        url=sub.url,
                        filename=sub.filename,
                        list_type=sub.format,
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
        self._set_status(
            QC.translate(
                "stats", "Bulk refresh triggered for all listed subscriptions."
            ),
            error=False,
        )

    def create_rule_from_selected(self):
        rows = self._selected_rows()
        if not rows:
            row = self.table.currentRow()
            if row >= 0:
                rows = [row]
        if not rows:
            self._set_status(
                QC.translate("stats", "Select one or more subscriptions first."),
                error=True,
            )
            return

        lists_dir = normalize_lists_dir(
            self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        if len(rows) == 1:
            row = rows[0]
            url = self._cell_text(row, COL_URL)
            filename, filename_changed = self._ensure_row_final_filename(row)
            if url == "" or filename == "":
                self._set_status(
                    QC.translate("stats", "URL and filename cannot be empty."),
                    error=True,
                )
                return
            if filename_changed:
                # Persist resolved filename so subsequent plugin runs keep the same path.
                self.save_action_file()

            list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
            list_path = list_file_path(lists_dir, filename, list_type)
            rule_dir = self._prepare_rule_dir(
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
                self._set_status(
                    QC.translate(
                        "stats", "Error preparing grouped rule directory: {0}"
                    ).format(str(e)),
                    error=True,
                )
                return
            rule_name = f"00-blocklist-{rule_group}"
            desc = f"From list subscription : {rule_group}"

        if self._rules_dialog is None:
            appicon = self.windowIcon() if self.windowIcon() is not None else None
            try:
                self._rules_dialog = RulesEditorDialog(parent=None, appicon=appicon)
            except TypeError:
                self._rules_dialog = RulesEditorDialog()

        self._rules_dialog.new_rule()
        if not self._configure_rules_dialog_for_local_user():
            return

        # Rules editor expects a directory containing one or more hosts files.
        self._rules_dialog.dstListsCheck.setChecked(True)
        self._rules_dialog.dstListsLine.setText(rule_dir)
        if self._rules_dialog.ruleNameEdit.text().strip() == "":
            self._rules_dialog.ruleNameEdit.setText(rule_name)
        if self._rules_dialog.ruleDescEdit.toPlainText().strip() == "":
            self._rules_dialog.ruleDescEdit.setPlainText(desc)
        self._rules_dialog.raise_()
        self._rules_dialog.activateWindow()
        self._set_status(
            QC.translate(
                "stats", "Rules Editor opened with prefilled list directory path."
            ),
            error=False,
        )

    def create_global_rule(self):
        lists_dir = normalize_lists_dir(
            self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        rule_dir = os.path.join(lists_dir, "rules.list.d", "all")
        try:
            os.makedirs(rule_dir, mode=0o700, exist_ok=True)
        except Exception as e:
            self._set_status(
                QC.translate(
                    "stats", "Error preparing global rule directory: {0}"
                ).format(str(e)),
                error=True,
            )
            return

        if self._rules_dialog is None:
            appicon = self.windowIcon() if self.windowIcon() is not None else None
            try:
                self._rules_dialog = RulesEditorDialog(parent=None, appicon=appicon)
            except TypeError:
                self._rules_dialog = RulesEditorDialog()

        self._rules_dialog.new_rule()
        if not self._configure_rules_dialog_for_local_user():
            return
        rule_name = "00-blocklist-all"
        self._rules_dialog.dstListsCheck.setChecked(True)
        self._rules_dialog.dstListsLine.setText(rule_dir)
        if self._rules_dialog.ruleNameEdit.text().strip() == "":
            self._rules_dialog.ruleNameEdit.setText(rule_name)
        if self._rules_dialog.ruleDescEdit.toPlainText().strip() == "":
            self._rules_dialog.ruleDescEdit.setPlainText("From list subscription : all")
        self._rules_dialog.raise_()
        self._rules_dialog.activateWindow()
        self._set_status(
            QC.translate(
                "stats", "Rules Editor opened with global list directory path."
            ),
            error=False,
        )

    def _configure_rules_dialog_for_local_user(self):
        if self._rules_dialog is None:
            return False

        local_addr = None
        for addr in self._nodes.get().keys():
            try:
                if self._nodes.is_local(addr):
                    local_addr = addr
                    break
            except Exception:
                continue

        if local_addr is None:
            self._set_status(
                QC.translate(
                    "stats",
                    "No local OpenSnitch node is connected. Rules can only be created for the local user.",
                ),
                error=True,
            )
            self._rules_dialog.hide()
            return False

        nodes_combo = self._rules_dialog.nodesCombo
        node_idx = nodes_combo.findData(local_addr)
        if node_idx != -1:
            nodes_combo.setCurrentIndex(node_idx)
        nodes_combo.setEnabled(False)
        self._rules_dialog.nodeApplyAllCheck.setChecked(False)
        self._rules_dialog.nodeApplyAllCheck.setEnabled(False)
        self._rules_dialog.nodeApplyAllCheck.setVisible(False)

        uid_text = str(os.getuid())
        uid_combo = self._rules_dialog.uidCombo
        uid_idx = uid_combo.findData(int(uid_text))
        self._rules_dialog.uidCheck.setChecked(True)
        uid_combo.setEnabled(True)
        if uid_idx != -1:
            uid_combo.setCurrentIndex(uid_idx)
        else:
            uid_combo.setCurrentText(uid_text)
        return True

    def _choose_group_for_selected(self, rows: list[int]):
        if not rows:
            return None
        selected_group_sets = [
            set(normalize_groups(self._cell_text(r, COL_GROUP))) for r in rows
        ]
        common = (
            set.intersection(*selected_group_sets) if selected_group_sets else set()
        )
        known = self._known_groups()
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
            self,
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
            self._set_status(
                QC.translate("stats", "Group cannot be empty."), error=True
            )
            return None
        return group

    def _assign_group_to_rows(self, rows: list[int], group: str):
        if not rows:
            return False
        target_group = normalize_group(group)
        for row in rows:
            groups = normalize_groups(self._cell_text(row, COL_GROUP))
            groups.append(target_group)
            groups = normalize_groups(groups)
            self._set_text_item(row, COL_GROUP, ", ".join(groups))
        return True

    def _prepare_rule_dir(
        self,
        url: str,
        filename: str,
        list_path: str,
        lists_dir: str,
        list_type: str,
    ):
        _ = (url, list_path)
        rule_dir = subscription_rule_dir(
            lists_dir,
            filename,
            list_type,
        )
        try:
            os.makedirs(rule_dir, mode=0o700, exist_ok=True)
            return rule_dir
        except Exception as e:
            self._set_status(
                QC.translate(
                    "stats", "Error preparing list rule directory: {0}"
                ).format(str(e)),
                error=True,
            )
            return None

    def _apply_runtime_state(self, enabled: bool):
        old_key, _old_action, old_plugin = self._find_loaded_action()
        runtime_plugin = ListSubscriptions.get_instance()
        target_plugin = runtime_plugin if runtime_plugin is not None else old_plugin
        was_enabled = bool(getattr(target_plugin, "enabled", False))

        if target_plugin is not None:
            self._bind_runtime_plugin(target_plugin)
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
                            "action_path": self._action_path,
                        }
                    )
            except Exception:
                self._set_status(
                    QC.translate(
                        "stats", "Config saved but runtime reload failed. Restart UI."
                    ),
                    error=True,
                )
                return
            if not enabled and old_key is not None:
                self._actions.delete(old_key)
            return

        if not enabled:
            if old_key is not None:
                self._actions.delete(old_key)
            return

        obj, compiled = self._actions.load(self._action_path)
        if obj is None or compiled is None:
            self._set_status(
                QC.translate(
                    "stats", "Config saved but runtime reload failed. Restart UI."
                ),
                error=True,
            )
            return

        obj = cast(dict[str, Any], obj)
        compiled = cast(dict[str, Any], compiled)
        action_name = obj.get("name")
        if old_key is not None and old_key != action_name:
            self._actions.delete(old_key)
        if isinstance(action_name, str) and action_name != "":
            self._actions._actions_list[action_name] = compiled

        compiled_actions = cast(dict[str, Any], compiled.get("actions", {}))
        plug = cast(
            ListSubscriptions | None, compiled_actions.get("list_subscriptions")
        )
        if plug is None:
            self._set_status(
                QC.translate(
                    "stats", "Config saved but runtime reload failed. Restart UI."
                ),
                error=True,
            )
            return
        self._bind_runtime_plugin(plug)
        try:
            plug.signal_in.emit(
                {
                    "plugin": plug.get_name(),
                    "signal": PluginSignal.ENABLE,
                    "action_path": self._action_path,
                }
            )
        except Exception:
            self._set_status(
                QC.translate(
                    "stats", "Config saved but runtime reload failed. Restart UI."
                ),
                error=True,
            )

    def _bind_runtime_plugin(self, plug: ListSubscriptions | None):
        if plug is None:
            return
        try:
            plug.signal_out.disconnect(self._handle_runtime_event)
        except Exception:
            pass
        try:
            plug.signal_out.connect(self._handle_runtime_event)
            self._runtime_plugin = plug
        except Exception:
            self._runtime_plugin = None

    def _handle_runtime_event(self, event: dict[str, Any]):
        payload = event if isinstance(event, dict) else {}
        message = str(payload.get("message") or "").strip()
        error_detail = str(payload.get("error") or "").strip()
        event_keys = self._refresh_keys_from_payload(payload)
        event_value = payload.get("event")
        if isinstance(event_value, int):
            try:
                event_name = RuntimeEvent(event_value)
            except Exception:
                event_name = None
        else:
            event_name = None
        is_error = event_name in (
            RuntimeEvent.RUNTIME_ERROR,
            RuntimeEvent.DOWNLOAD_FAILED,
            RuntimeEvent.FILE_SAVE_ERROR,
            RuntimeEvent.FILE_LOAD_ERROR,
        )
        if event_name == RuntimeEvent.DOWNLOAD_STARTED:
            for key in event_keys:
                if key in self._pending_refresh_keys:
                    self._pending_refresh_keys.discard(key)
                    self._active_refresh_keys.add(key)
            self._set_refresh_busy(True)
        elif event_name in (
            RuntimeEvent.DOWNLOAD_FINISHED,
            RuntimeEvent.DOWNLOAD_FAILED,
        ):
            for key in event_keys:
                self._clear_refresh_key(key)
            if event_name in (
                RuntimeEvent.DOWNLOAD_FINISHED,
                RuntimeEvent.DOWNLOAD_FAILED,
            ):
                self.refresh_states()
                self._update_selected_actions_state()
        if event_name == RuntimeEvent.RUNTIME_ENABLED:
            self._set_runtime_state(active=True)
        elif event_name in (
            RuntimeEvent.RUNTIME_DISABLED,
            RuntimeEvent.RUNTIME_STOPPED,
        ):
            self._set_runtime_state(active=False)
        elif self._pending_runtime_reload is not None:
            self._set_runtime_state(
                active=None,
                text=QC.translate("stats", "Runtime: reloading"),
            )
        elif is_error:
            self._set_runtime_state(
                active=None, text=QC.translate("stats", "Runtime: error")
            )
        if self._pending_runtime_reload == "waiting_config_reload":
            if event_name == RuntimeEvent.CONFIG_RELOADED:
                self._pending_runtime_reload = None
                self.load_action_file()
                return
            if is_error:
                self._pending_runtime_reload = None
        if message == "":
            message = QC.translate("stats", "Plugin runtime event: {0}").format(
                str(event_value or "unknown")
            )
        if event_name in (
            RuntimeEvent.DOWNLOAD_STARTED,
            RuntimeEvent.DOWNLOAD_FINISHED,
            RuntimeEvent.DOWNLOAD_FAILED,
        ):
            message = self._runtime_download_message(event_name, payload, message)
        if is_error and error_detail != "":
            message = f"{message} {error_detail}".strip()
        self._set_status(message, error=is_error)

    def _set_runtime_state(self, active: bool | None, text: str | None = None):
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

        self.runtime_status_label.setStyleSheet(style)
        self.runtime_status_label.setText(text)
        self.start_runtime_button.setEnabled(active is not True)
        self.stop_runtime_button.setEnabled(active is not False)

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
            groups = normalize_groups(self._cell_text(row, COL_GROUP))
            filename = safe_filename(self._cell_text(row, COL_FILENAME))
            if filename == "":
                filename = self._guess_filename(name, url)
                if filename != "":
                    auto_filled += 1
            filename = ensure_filename_type_suffix(filename, list_type)
            self._set_text_item(row, COL_FILENAME, filename)
            interval_ok, interval_val = self._optional_int_from_text(
                interval, "Interval", row=row
            )
            timeout_ok, timeout_val = self._optional_int_from_text(
                timeout, "Timeout", row=row
            )
            max_size_ok, max_size_val = self._optional_int_from_text(
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
                self._set_status(
                    QC.translate(
                        "stats", "URL and filename cannot be empty (row {0})."
                    ).format(row + 1),
                    error=True,
                )
                return None
            out.append(sub)

        if auto_filled > 0:
            self._set_status(
                QC.translate(
                    "stats", "Auto-filled filename for {0} subscription(s)."
                ).format(auto_filled),
                error=False,
            )
        return out

    def _row_meta_snapshot(self, row: int):
        lists_dir = normalize_lists_dir(
            self.lists_dir_edit.text().strip() or DEFAULT_LISTS_DIR
        )
        filename = safe_filename(self._cell_text(row, COL_FILENAME))
        list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
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
                meta.get("last_result", self._cell_text(row, COL_STATE) or "never")
            ),
            "last_checked": str(
                meta.get("last_checked", self._cell_text(row, COL_LAST_CHECKED) or "")
            ),
            "last_updated": str(
                meta.get("last_updated", self._cell_text(row, COL_LAST_UPDATED) or "")
            ),
            "failures": str(
                meta.get("fail_count", self._cell_text(row, COL_FAILS) or "0")
            ),
            "error": str(meta.get("last_error", self._cell_text(row, COL_ERROR) or "")),
            "list_path": list_path,
            "meta_path": meta_path,
        }

    def _ensure_row_final_filename(self, row: int):
        name = self._cell_text(row, COL_NAME)
        url = self._cell_text(row, COL_URL)
        list_type = (self._cell_text(row, COL_FORMAT) or "hosts").strip().lower()
        original = safe_filename(self._cell_text(row, COL_FILENAME))
        final_name = original
        changed = False

        if final_name == "":
            final_name = self._guess_filename(name, url)
            changed = final_name != ""
        final_name = ensure_filename_type_suffix(final_name, list_type)
        if final_name != original:
            changed = True

        if final_name != "":
            key = final_name
            existing: set[str] = set()
            for i in range(self.table.rowCount()):
                if i == row:
                    continue
                other = safe_filename(self._cell_text(i, COL_FILENAME))
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
            self._set_text_item(row, COL_FILENAME, final_name)
        return final_name, changed

    def _append_row(self, sub: MutableSubscriptionSpec):
        row = self.table.rowCount()
        self.table.insertRow(row)
        enabled_item = self._new_enabled_item(bool(sub.enabled))
        self.table.setItem(row, COL_ENABLED, enabled_item)

        self._set_text_item(row, COL_NAME, str(sub.name))
        self._set_text_item(row, COL_URL, str(sub.url))
        self._set_text_item(row, COL_FILENAME, safe_filename(sub.filename))
        self._set_text_item(row, COL_FORMAT, str(sub.format))
        groups = normalize_groups(sub.groups)
        self._set_text_item(row, COL_GROUP, ", ".join(groups))
        interval = sub.interval
        timeout = sub.timeout
        max_size = sub.max_size
        interval_units = sub.interval_units
        timeout_units = sub.timeout_units
        max_size_units = sub.max_size_units
        self._set_text_item(row, COL_INTERVAL, display_str(interval))
        self._set_text_item(row, COL_INTERVAL_UNITS, display_str(interval_units))
        self._set_text_item(row, COL_TIMEOUT, display_str(timeout))
        self._set_text_item(row, COL_TIMEOUT_UNITS, display_str(timeout_units))
        self._set_text_item(row, COL_MAX_SIZE, display_str(max_size))
        self._set_text_item(row, COL_MAX_SIZE_UNITS, display_str(max_size_units))
        self._set_units_combo(
            row, COL_INTERVAL_UNITS, INTERVAL_UNITS, display_str(interval_units)
        )
        self._set_units_combo(
            row, COL_TIMEOUT_UNITS, TIMEOUT_UNITS, display_str(timeout_units)
        )
        self._set_units_combo(
            row, COL_MAX_SIZE_UNITS, SIZE_UNITS, display_str(max_size_units)
        )

        self._set_text_item(row, COL_FILE, "", editable=False)
        self._set_text_item(row, COL_META, "", editable=False)
        self._set_text_item(row, COL_STATE, "", editable=False)
        self._set_text_item(row, COL_LAST_CHECKED, "", editable=False)
        self._set_text_item(row, COL_LAST_UPDATED, "", editable=False)
        self._set_text_item(row, COL_FAILS, "", editable=False)
        self._set_text_item(row, COL_ERROR, "", editable=False)
        self._update_row_sort_keys(row)

    def _reload_nodes(self):
        self.nodes_combo.blockSignals(True)
        self.nodes_combo.clear()
        for addr in self._nodes.get_nodes():
            self.nodes_combo.addItem(addr, addr)
        self.nodes_combo.blockSignals(False)

    def _apply_defaults_to_widgets(self):
        self.default_interval_spin.setValue(max(1, int(self._global_defaults.interval)))
        self.default_interval_units.setCurrentText(
            normalize_unit(
                self._global_defaults.interval_units, INTERVAL_UNITS, "hours"
            )
        )
        self.default_timeout_spin.setValue(max(1, int(self._global_defaults.timeout)))
        self.default_timeout_units.setCurrentText(
            normalize_unit(
                self._global_defaults.timeout_units, TIMEOUT_UNITS, "seconds"
            )
        )
        self.default_max_size_spin.setValue(max(1, int(self._global_defaults.max_size)))
        self.default_max_size_units.setCurrentText(
            normalize_unit(self._global_defaults.max_size_units, SIZE_UNITS, "MB")
        )
        self.default_user_agent.setText(
            (self._global_defaults.user_agent or "").strip()
        )

    def _set_units_combo(
        self, row: int, col: int, allowed: tuple[str, ...], value: str | None
    ):
        combo = QtWidgets.QComboBox()
        combo.addItem("")
        combo.addItems(allowed)
        combo.setToolTip(
            QC.translate(
                "stats",
                "Leave blank to inherit the global default for this subscription.",
            )
        )
        if value is None or value.strip() == "":
            combo.setCurrentIndex(0)
        else:
            combo.setCurrentText(normalize_unit(value, allowed, allowed[0]))
        self.table.setCellWidget(row, col, combo)

    def _guess_filename(self, name: str, url: str):
        from_header = self._filename_from_headers(url)
        return safe_filename(derive_filename(name, url, "", from_header))

    def _filename_from_headers(self, url: str):
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

    def _set_text_item(self, row: int, col: int, text: str, editable: bool = True):
        item = self.table.item(row, col)
        if item is None:
            item = SortableTableWidgetItem()
            self.table.setItem(row, col, item)
        item.setText(text)
        item.setData(
            QtCore.Qt.ItemDataRole.UserRole,
            self._sort_key_for_column(col, text),
        )
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

    def _optional_int_from_text(
        self, value: Any, field_name: str, row: int | None = None
    ):
        if value == "":
            return True, None
        parsed = self._to_int_or_keep(value, field_name, row=row)
        if parsed is None:
            return False, None
        return True, parsed

    def _to_int_or_keep(self, value: Any, field_name: str, row: int | None = None):
        try:
            parsed = int(value)
        except Exception:
            row_suffix = (
                QC.translate("stats", " (row {0})").format(row + 1)
                if row is not None
                else ""
            )
            self._set_status(
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
            self._set_status(
                QC.translate("stats", "{0} must be a positive integer{1}.").format(
                    field_name, row_suffix
                ),
                error=True,
            )
            return None
        return parsed

    def _set_status(self, msg: str, error: bool = False):
        self.status_label.setStyleSheet("color: red;" if error else "color: green;")
        self.status_label.setText(msg)

    def _refresh_states_if_visible(self):
        if self.isVisible() and not self._loading:
            self.refresh_states()
