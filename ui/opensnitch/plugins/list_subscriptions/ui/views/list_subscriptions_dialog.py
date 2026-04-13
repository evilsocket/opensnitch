import logging
import os
from typing import Any, TYPE_CHECKING, Final

from opensnitch.plugins.list_subscriptions.ui import (
    QtCore,
    QtGui,
    QtWidgets,
    QC,
    load_ui_type,
)

from opensnitch.plugins.list_subscriptions.models.global_defaults import GlobalDefaults
from opensnitch.actions import Actions
from opensnitch.nodes import Nodes
from opensnitch.plugins.list_subscriptions.ui.views.helpers import (
    _section_border_color_name,
    _apply_section_bar_style,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.helpers import (
    _configure_spin_and_units,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.toggle_switch_widget import (
    _replace_checkbox_with_toggle,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.table_widgets import (
    CenteredCheckDelegate,
    KeepForegroundOnSelectionDelegate,
)
from opensnitch.plugins.list_subscriptions.ui.views.inspector_panel import (
    InspectorPanel,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.status_controller import (
    DialogStatusController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.runtime_controller import (
    RuntimeController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.inspector_controller import (
    InspectorController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.defaults_ui_controller import (
    DefaultsUiController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.selection_controller import (
    SelectionController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.context_menu_controller import (
    ContextMenuController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.bulk_edit_controller import (
    BulkEditController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.subscription_status_controller import (
    SubscriptionStatusController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.action_file_controller import (
    ActionFileController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.table_data_controller import (
    TableDataController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.table_view_controller import (
    TableViewController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.rules_attachment_controller import (
    RulesAttachmentController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.rules_editor_controller import (
    RulesEditorController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.subscription_edit_controller import (
    SubscriptionEditController,
)
from opensnitch.plugins.list_subscriptions._utils import (
    ACTION_FILE,
    DEFAULT_LISTS_DIR,
    RES_DIR,
    INTERVAL_UNITS,
    TIMEOUT_UNITS,
    SIZE_UNITS,
)
from opensnitch.plugins.list_subscriptions._annotations import RulesEditorDialogProto
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
COL_RULE_ATTACHED: Final[int] = 15
COL_LAST_CHECKED: Final[int] = 16
COL_LAST_UPDATED: Final[int] = 17
INSPECT_ERROR_PREVIEW_LIMIT: Final[int] = 48
STATUS_MESSAGE_PREVIEW_LIMIT: Final[int] = 48
STATUS_LOG_LIMIT: Final[int] = 200

logger: Final[logging.Logger] = logging.getLogger(__name__)


class ListSubscriptionsDialog(QtWidgets.QDialog, ListSubscriptionsDialogUI):
    subscription_state_refreshed = QtCore.pyqtSignal(str, str, dict)

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
        _status_inspect_button: QtWidgets.QPushButton
        _nodes: Nodes
        _actions: Actions
        _action_path: str
        _loading: bool
        _global_defaults: GlobalDefaults
        _rules_dialog: RulesEditorDialogProto | None
        _runtime_plugin: ListSubscriptions | None
        _pending_runtime_reload: str | None
        _pending_refresh_keys: set[str]
        _active_refresh_keys: set[str]
        _status_controller: DialogStatusController
        _runtime_controller: RuntimeController
        _defaults_ui_controller: DefaultsUiController
        _selection_controller: SelectionController
        _context_menu_controller: ContextMenuController
        _bulk_edit_controller: BulkEditController
        _subscription_status_controller: SubscriptionStatusController
        _action_file_controller: ActionFileController
        _inspector_controller: InspectorController
        _table_data_controller: TableDataController
        _rules_attachment_controller: RulesAttachmentController
        _rules_editor_controller: RulesEditorController
        _table_tab_bar: QtWidgets.QTabBar
        _table_inspect_splitter: QtWidgets.QSplitter
        _inspect_panel: QtWidgets.QFrame
        _inspect_header: QtWidgets.QFrame
        _inspect_title_label: QtWidgets.QLabel
        _inspect_toggle_button: QtWidgets.QToolButton
        _inspect_header_separator: QtWidgets.QFrame
        _inspect_scroll: QtWidgets.QScrollArea
        _inspect_body: QtWidgets.QWidget
        _inspect_details_widget: QtWidgets.QWidget
        _inspect_summary_widget: QtWidgets.QWidget
        _inspect_value_labels: dict[str, QtWidgets.QLabel]
        _inspect_summary_labels: dict[str, QtWidgets.QLabel]
        _inspect_error_button: QtWidgets.QPushButton | None
        _inspect_error_full_text: str
        _inspect_collapsed: bool
        _inspect_default_width: int
        _inspect_has_selection: bool
        _user_resized_columns_by_tab: dict[int, set[int]]
        _applying_table_column_sizing: bool

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
        self._rules_dialog: RulesEditorDialogProto | None = None
        self._runtime_plugin: ListSubscriptions | None = None
        self._pending_runtime_reload: str | None = None
        self._pending_refresh_keys: set[str] = set()
        self._active_refresh_keys: set[str] = set()
        self._deferred_close_pending = False
        self._user_resized_columns_by_tab: dict[int, set[int]] = {}
        self._applying_table_column_sizing = False
        self._resize_fill_timer = QtCore.QTimer(self)
        self._resize_fill_timer.setSingleShot(True)
        self._resize_fill_timer.setInterval(140)
        self._resize_fill_timer.timeout.connect(self._apply_table_fill_after_resize)
        self._build_ui()

    def showEvent(self, event: QtGui.QShowEvent | None):  # type: ignore[override]
        super().showEvent(event)
        self._action_file_controller.load_action_file()
        self._table_data_controller.start_poll()
        # Ensure equal-fill sizing runs after the first layout pass when viewport width is valid.
        QtCore.QTimer.singleShot(
            0,
            lambda: self._table_view_controller.apply_table_column_sizing(
                self._table_tab_bar.currentIndex()
            ),
        )

    def _pause_background_workers_for_focus_loss(self) -> None:
        pause_poll = getattr(self._table_data_controller, "pause_for_focus_loss", None)
        if callable(pause_poll):
            pause_poll()
        else:
            self._table_data_controller.stop_poll()
            self._table_data_controller.cancel_active_refresh()

        cancel_snapshot = getattr(
            self._rules_attachment_controller,
            "cancel_active_snapshot",
            None,
        )
        if callable(cancel_snapshot):
            cancel_snapshot()

    def _resume_background_workers_for_focus_gain(self) -> None:
        resume_poll = getattr(self._table_data_controller, "resume_for_focus_gain", None)
        if callable(resume_poll):
            resume_poll()
        elif self.isVisible() and not self._loading:
            self._table_data_controller.start_poll()

    def changeEvent(self, event: QtCore.QEvent | None):  # type: ignore[override]
        if (
            event is not None
            and event.type() == QtCore.QEvent.Type.ActivationChange
        ):
            if self.isVisible() and self.isActiveWindow():
                self._resume_background_workers_for_focus_gain()
            else:
                self._pause_background_workers_for_focus_loss()
        super().changeEvent(event)

    def hideEvent(self, event: QtGui.QHideEvent | None):  # type: ignore[override]
        self._pause_background_workers_for_focus_loss()
        super().hideEvent(event)

    def resizeEvent(self, event: QtGui.QResizeEvent | None):  # type: ignore[override]
        super().resizeEvent(event)
        if hasattr(self, "_resize_fill_timer"):
            self._resize_fill_timer.start()

    def _apply_table_fill_after_resize(self) -> None:
        if not self.isVisible():
            return
        if hasattr(self, "_table_view_controller") and hasattr(self, "_table_tab_bar"):
            self._table_view_controller.apply_table_column_sizing(
                self._table_tab_bar.currentIndex()
            )

    def _complete_deferred_close(self) -> None:
        self._deferred_close_pending = False
        self.setEnabled(True)
        self._status_controller.set_status("", error=False, log=False)
        self.close()

    def closeEvent(self, event: QtGui.QCloseEvent | None):  # type: ignore[override]
        self._table_data_controller.stop_poll()
        self._pause_background_workers_for_focus_loss()
        if self._table_data_controller.has_active_refresh():
            if not self._deferred_close_pending:
                self._deferred_close_pending = True
                self.setEnabled(False)
                self._status_controller.set_status(
                    QC.translate("stats", "Stopping background tasks..."),
                    error=False,
                    log=False,
                )
                self._table_data_controller.cancel_active_refresh()
                self._table_data_controller.on_refresh_stopped(
                    self._complete_deferred_close
                )
            if event is not None:
                event.ignore()
            return
        self._status_controller.set_status("", error=False, log=False)
        super().closeEvent(event)

    def _show_log_dialog(self) -> None:
        color = self.palette().color(QtGui.QPalette.ColorRole.WindowText)
        self._status_controller.show_log_dialog(
            self,
            title=QC.translate("stats", "Status log"),
            level_color=self._table_data_controller.status_log_level_color,
            timestamp_color=f"rgba({color.red()}, {color.green()}, {color.blue()}, 0.55)",
        )

    def _build_ui(self):
        self.setupUi(self)
        self.enable_plugin_check = _replace_checkbox_with_toggle(
            self.enable_plugin_check
        )
        self.enable_plugin_check.setChecked(True)
        self.enable_plugin_check.setEnabled(False)
        self.enable_plugin_check.setToolTip(
            QC.translate(
                "stats",
                "The plugin action must remain enabled. OpenSnitch only loads enabled action files on startup.",
            )
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
        _apply_section_bar_style(
            self,
            self.defaults_section_bar,
            self.defaults_section_label,
            expanding_label=True,
        )
        _apply_section_bar_style(
            self,
            self.table_section_bar,
            self.table_section_label,
            expanding_label=True,
        )
        _apply_section_bar_style(
            self,
            self.global_actions_bar,
            self.global_actions_label,
            expanding_label=True,
        )
        _apply_section_bar_style(
            self,
            self.selected_actions_bar,
            self.selected_actions_label,
            expanding_label=True,
        )
        self.actionsRowLayout.setStretch(0, 1)
        self.actionsRowLayout.setStretch(2, 1)
        self.actions_vertical_separator.hide()
        background_role = (
            QtGui.QPalette.ColorRole.AlternateBase
            if self.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128
            else QtGui.QPalette.ColorRole.Button
        )
        section_border_color = _section_border_color_name(self)
        self.global_actions_bar.setStyleSheet(
            "QFrame {"
            f"background-color: {self.palette().color(background_role).name()};"
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
        self._status_inspect_button = QtWidgets.QPushButton(
            QC.translate("stats", "Log"),
            self,
        )
        self._status_inspect_button.setVisible(False)
        self._status_controller = DialogStatusController(
            label=self.status_label,
            inspect_button=self._status_inspect_button,
            preview_limit=STATUS_MESSAGE_PREVIEW_LIMIT,
            log_limit=STATUS_LOG_LIMIT,
            timestamp_format="HH:mm:ss",
            ok_color="green",
            error_color="red",
            empty_button_behavior="show-if-logs",
        )

        self._status_inspect_button.clicked.connect(self._show_log_dialog)
        self._runtime_controller = RuntimeController(
            dialog=self,
            status_label=self.runtime_status_label,
            start_button=self.start_runtime_button,
            stop_button=self.stop_runtime_button,
        )
        self._defaults_ui_controller = DefaultsUiController(dialog=self)
        self._selection_controller = SelectionController(
            dialog=self,
            columns={
                "group": COL_GROUP,
            },
        )
        self._context_menu_controller = ContextMenuController(dialog=self)
        self._bulk_edit_controller = BulkEditController(
            dialog=self,
            columns={
                "enabled": COL_ENABLED,
                "group": COL_GROUP,
                "format": COL_FORMAT,
                "interval": COL_INTERVAL,
                "interval_units": COL_INTERVAL_UNITS,
                "timeout": COL_TIMEOUT,
                "timeout_units": COL_TIMEOUT_UNITS,
                "max_size": COL_MAX_SIZE,
                "max_size_units": COL_MAX_SIZE_UNITS,
            },
        )
        self._subscription_status_controller = SubscriptionStatusController(
            dialog=self,
            columns={
                "name": COL_NAME,
                "url": COL_URL,
                "filename": COL_FILENAME,
            },
        )
        self._action_file_controller = ActionFileController(
            dialog=self,
            columns={
                "name": COL_NAME,
                "filename": COL_FILENAME,
            },
        )
        self._rules_attachment_controller = RulesAttachmentController(dialog=self)
        self._rules_editor_controller = RulesEditorController(
            dialog=self,
            columns={
                "url": COL_URL,
                "format": COL_FORMAT,
                "group": COL_GROUP,
            },
        )
        self._table_data_controller = TableDataController(
            dialog=self,
            columns={
                "enabled": COL_ENABLED,
                "name": COL_NAME,
                "url": COL_URL,
                "filename": COL_FILENAME,
                "format": COL_FORMAT,
                "group": COL_GROUP,
                "interval": COL_INTERVAL,
                "interval_units": COL_INTERVAL_UNITS,
                "timeout": COL_TIMEOUT,
                "timeout_units": COL_TIMEOUT_UNITS,
                "max_size": COL_MAX_SIZE,
                "max_size_units": COL_MAX_SIZE_UNITS,
                "file": COL_FILE,
                "meta": COL_META,
                "state": COL_STATE,
                "rule_attached": COL_RULE_ATTACHED,
                "last_checked": COL_LAST_CHECKED,
                "last_updated": COL_LAST_UPDATED,
            },
        )
        status_row = QtWidgets.QWidget(self)
        status_row.setStyleSheet(
            "QWidget {"
            f"border-top: 1px solid {footer_border};"
            f"background-color: {self.palette().color(QtGui.QPalette.ColorRole.Window).name()};"
            "}"
        )
        status_row_layout = QtWidgets.QHBoxLayout(status_row)
        status_row_layout.setContentsMargins(12, 0, 12, 0)
        status_row_layout.setSpacing(8)
        self.rootLayout.removeWidget(self.status_label)
        self.status_label.setParent(status_row)
        status_row_layout.addWidget(
            self._status_inspect_button,
            0,
            QtCore.Qt.AlignmentFlag.AlignVCenter,
        )
        status_row_layout.addWidget(self.status_label, 1)
        self.rootLayout.insertWidget(4, status_row)
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
        self.node_label.hide()
        self.nodes_combo.hide()

        _configure_spin_and_units(
            self.default_interval_spin,
            self.default_interval_units,
            value=1,
            unit_value="hours",
            allowed_units=INTERVAL_UNITS,
            fallback_unit="hours",
            min_value=1,
        )
        _configure_spin_and_units(
            self.default_timeout_spin,
            self.default_timeout_units,
            value=1,
            unit_value="seconds",
            allowed_units=TIMEOUT_UNITS,
            fallback_unit="seconds",
            min_value=1,
        )
        _configure_spin_and_units(
            self.default_max_size_spin,
            self.default_max_size_units,
            value=1,
            unit_value="MB",
            allowed_units=SIZE_UNITS,
            fallback_unit="MB",
            min_value=1,
        )

        self.table.setColumnCount(18)
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
                QC.translate("stats", "Rule attached"),
                QC.translate("stats", "Last checked"),
                QC.translate("stats", "Last updated"),
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
            COL_RULE_ATTACHED,
            COL_LAST_CHECKED,
            COL_LAST_UPDATED,
        ):
            self.table.setItemDelegateForColumn(col, state_delegate)
        self._table_view_controller = TableViewController(
            dialog=self,
            columns={
                "enabled": COL_ENABLED,
                "name": COL_NAME,
                "url": COL_URL,
                "filename": COL_FILENAME,
                "format": COL_FORMAT,
                "group": COL_GROUP,
                "interval": COL_INTERVAL,
                "interval_units": COL_INTERVAL_UNITS,
                "timeout": COL_TIMEOUT,
                "timeout_units": COL_TIMEOUT_UNITS,
                "max_size": COL_MAX_SIZE,
                "max_size_units": COL_MAX_SIZE_UNITS,
                "file": COL_FILE,
                "meta": COL_META,
                "state": COL_STATE,
                "rule_attached": COL_RULE_ATTACHED,
                "last_checked": COL_LAST_CHECKED,
                "last_updated": COL_LAST_UPDATED,
            },
        )
        header = self.table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(False)
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
            header.setSectionResizeMode(COL_URL, QtWidgets.QHeaderView.ResizeMode.Interactive)
            header.sectionResized.connect(
                self._table_view_controller.on_table_section_resized
            )
        self.table.setSortingEnabled(True)
        self.table.sortItems(COL_ENABLED, QtCore.Qt.SortOrder.AscendingOrder)
        # Keep advanced tuning + verbose metadata available internally but
        # reduce visible table complexity; edit dialog exposes full details.
        # Initial column visibility is controlled by TableViewController.
        for col in (
            COL_INTERVAL,
            COL_INTERVAL_UNITS,
            COL_TIMEOUT,
            COL_TIMEOUT_UNITS,
            COL_MAX_SIZE,
            COL_MAX_SIZE_UNITS,
            COL_FILE,
            COL_META,
        ):
            self.table.setColumnHidden(col, True)

        # Switch between Config and Monitoring table views.
        self._table_tab_bar = QtWidgets.QTabBar(self)
        self._table_tab_bar.addTab(QC.translate("stats", "Monitoring"))
        self._table_tab_bar.addTab(QC.translate("stats", "Config"))
        self._table_tab_bar.setContentsMargins(12, 4, 12, 0)
        self._table_tab_bar.currentChanged.connect(
            self._table_view_controller.on_table_view_tab_changed
        )
        self.tableContentLayout.insertWidget(0, self._table_tab_bar)
        self._inspector_controller = InspectorController(
            dialog=self,
            columns={
                "enabled": COL_ENABLED,
                "name": COL_NAME,
                "url": COL_URL,
                "filename": COL_FILENAME,
                "format": COL_FORMAT,
                "group": COL_GROUP,
                "interval": COL_INTERVAL,
                "interval_units": COL_INTERVAL_UNITS,
                "timeout": COL_TIMEOUT,
                "timeout_units": COL_TIMEOUT_UNITS,
                "max_size": COL_MAX_SIZE,
                "max_size_units": COL_MAX_SIZE_UNITS,
            },
            error_preview_limit=INSPECT_ERROR_PREVIEW_LIMIT,
        )
        self._table_view_controller.on_table_view_tab_changed(0)
        InspectorPanel(dialog=self).build()
        self._subscription_edit_controller = SubscriptionEditController(
            dialog=self,
            columns={
                "enabled": COL_ENABLED,
                "name": COL_NAME,
                "url": COL_URL,
                "filename": COL_FILENAME,
                "format": COL_FORMAT,
                "group": COL_GROUP,
                "interval": COL_INTERVAL,
                "interval_units": COL_INTERVAL_UNITS,
                "timeout": COL_TIMEOUT,
                "timeout_units": COL_TIMEOUT_UNITS,
                "max_size": COL_MAX_SIZE,
                "max_size_units": COL_MAX_SIZE_UNITS,
            },
        )

        self.create_file_button.clicked.connect(
            self._action_file_controller.create_action_file
        )
        self.save_button.clicked.connect(self._action_file_controller.save_action_file)
        self.reload_button.clicked.connect(
            self._runtime_controller.reload_runtime_and_config
        )
        self.start_runtime_button.clicked.connect(
            self._runtime_controller.start_runtime_clicked
        )
        self.stop_runtime_button.clicked.connect(
            self._runtime_controller.stop_runtime_clicked
        )
        self.add_sub_button.clicked.connect(
            self._subscription_edit_controller.add_subscription_row
        )
        self.create_global_rule_button.clicked.connect(
            self._rules_editor_controller.create_global_rule
        )
        self.edit_sub_button.clicked.connect(
            self._subscription_edit_controller.edit_action_clicked
        )
        self.remove_sub_button.clicked.connect(
            self._subscription_edit_controller.remove_selected_subscription
        )
        self.refresh_state_button.clicked.connect(
            self._table_data_controller.refresh_all_now
        )
        self.refresh_now_button.clicked.connect(
            self._table_data_controller.refresh_selected_now
        )
        self.create_rule_button.clicked.connect(
            self._selection_controller.open_rules_action
        )
        self.table.itemDoubleClicked.connect(
            self._subscription_edit_controller.handle_table_item_double_clicked
        )
        self.table.clicked.connect(self._table_data_controller.handle_table_clicked)
        self.table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(
            self._context_menu_controller.open_table_context_menu
        )
        sel_model = self.table.selectionModel()
        if sel_model is not None:
            sel_model.selectionChanged.connect(
                self._inspector_controller.handle_table_selection_changed
            )
        self.subscription_state_refreshed.connect(
            self._inspector_controller.on_subscription_state_refreshed
        )
        self._runtime_controller.set_runtime_state(active=False)
        self._selection_controller.update_selected_actions_state()
        self._inspector_controller.update_inspector_panel()



