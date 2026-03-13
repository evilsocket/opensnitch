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
from opensnitch.plugins.list_subscriptions.models.subscriptions import (
    MutableSubscriptionSpec,
)
from opensnitch.plugins.list_subscriptions._utils import (
    RES_DIR,
    INTERVAL_UNITS,
    TIMEOUT_UNITS,
    SIZE_UNITS,
    normalize_group,
    normalize_groups,
)
from opensnitch.plugins.list_subscriptions.ui.views.helpers import (
    _apply_footer_separator_style,
    _apply_section_bar_style,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.helpers import (
    _configure_spin_and_units,
    _set_optional_field_tooltips,
)
from opensnitch.plugins.list_subscriptions.ui.widgets.toggle_switch_widget import (
    _replace_checkbox_with_toggle,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.status_controller import (
    DialogStatusController,
)
from opensnitch.plugins.list_subscriptions.ui.controllers.subscription_dialog_controller import (
    SubscriptionDialogController,
)

SUBSCRIPTION_DIALOG_UI_PATH: Final[str] = os.path.join(
    RES_DIR, "subscription_dialog.ui"
)

SubscriptionDialogUI: Final[Any] = load_ui_type(SUBSCRIPTION_DIALOG_UI_PATH)[0]
DIALOG_MESSAGE_PREVIEW_LIMIT: Final[int] = 48
DIALOG_MESSAGE_LOG_LIMIT: Final[int] = 200

logger: Final[logging.Logger] = logging.getLogger(__name__)


def _origin_slug_from_title(title: str) -> str:
    slug = "-".join((title or "subscription").strip().lower().split())
    return slug or "subscription"


class SubscriptionDialog(QtWidgets.QDialog, SubscriptionDialogUI):
    _url_test_finished = QtCore.pyqtSignal(bool, str)
    log_message = QtCore.pyqtSignal(str, str, str)  # (message, level, origin)

    if TYPE_CHECKING:
        rootLayout: QtWidgets.QVBoxLayout
        bodyLayout: QtWidgets.QHBoxLayout
        settings_group_layout: QtWidgets.QVBoxLayout
        settings_section_bar: QtWidgets.QFrame
        settings_section_label: QtWidgets.QLabel
        settings_group: QtWidgets.QGroupBox
        meta_grid: QtWidgets.QGridLayout
        enabled_check: QtWidgets.QCheckBox
        buttons_layout: QtWidgets.QHBoxLayout
        settings_form: QtWidgets.QFormLayout
        name_label: QtWidgets.QLabel
        name_edit: QtWidgets.QLineEdit
        name_error_label: QtWidgets.QLabel
        url_label: QtWidgets.QLabel
        url_edit: QtWidgets.QLineEdit
        url_error_label: QtWidgets.QLabel
        filename_label: QtWidgets.QLabel
        filename_edit: QtWidgets.QLineEdit
        filename_error_label: QtWidgets.QLabel
        format_label: QtWidgets.QLabel
        format_combo: QtWidgets.QComboBox
        groups_label: QtWidgets.QLabel
        group_combo: QtWidgets.QComboBox
        interval_label: QtWidgets.QLabel
        interval_layout: QtWidgets.QHBoxLayout
        interval_spin: QtWidgets.QSpinBox
        interval_units: QtWidgets.QComboBox
        timeout_label: QtWidgets.QLabel
        timeout_layout: QtWidgets.QHBoxLayout
        timeout_spin: QtWidgets.QSpinBox
        timeout_units: QtWidgets.QComboBox
        max_size_label: QtWidgets.QLabel
        max_size_layout: QtWidgets.QHBoxLayout
        max_size_spin: QtWidgets.QSpinBox
        max_size_units: QtWidgets.QComboBox
        meta_group_layout: QtWidgets.QVBoxLayout
        meta_section_bar: QtWidgets.QFrame
        meta_section_label: QtWidgets.QLabel
        meta_group: QtWidgets.QGroupBox
        meta_separator: QtWidgets.QFrame
        meta_file_present_label: QtWidgets.QLabel
        meta_file_present: QtWidgets.QLabel
        meta_meta_present_label: QtWidgets.QLabel
        meta_meta_present: QtWidgets.QLabel
        meta_state_label: QtWidgets.QLabel
        meta_state: QtWidgets.QLabel
        meta_last_checked_label: QtWidgets.QLabel
        meta_last_checked: QtWidgets.QLabel
        meta_last_updated_label: QtWidgets.QLabel
        meta_last_updated: QtWidgets.QLabel
        meta_failures_label: QtWidgets.QLabel
        meta_failures: QtWidgets.QLabel
        meta_error_label: QtWidgets.QLabel
        meta_error: QtWidgets.QLabel
        meta_list_path_label: QtWidgets.QLabel
        meta_list_path: QtWidgets.QLabel
        meta_meta_path_label: QtWidgets.QLabel
        meta_meta_path: QtWidgets.QLabel
        error_label: QtWidgets.QLabel
        footer_separator_line: QtWidgets.QFrame
        test_url_button: QtWidgets.QPushButton
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
        sub: MutableSubscriptionSpec | dict[str, Any] | None = None,
        meta: dict[str, str] | None = None,
        title: str = "Subscription",
    ):
        super().__init__(parent)
        self.setWindowTitle(QC.translate("stats", title))
        self.setWindowModality(QtCore.Qt.WindowModality.WindowModal)
        self._title = title
        self._log_origin = f"ui:{_origin_slug_from_title(title)}"
        self._defaults = defaults
        self._groups = groups or []
        try:
            if isinstance(sub, MutableSubscriptionSpec):
                self._sub = sub
            elif sub is None:
                parsed_sub = MutableSubscriptionSpec.from_dict(
                    {"enabled": True},
                    defaults=self._defaults,
                    require_url=False,
                    ensure_suffix=False,
                )
                if parsed_sub is None:
                    raise ValueError(
                        "default subscription state could not be initialized"
                    )
                self._sub = parsed_sub
            else:
                parsed_sub = MutableSubscriptionSpec.from_dict(
                    sub,
                    defaults=self._defaults,
                    require_url=False,
                    ensure_suffix=False,
                )
                if parsed_sub is None:
                    raise ValueError("subscription data could not be initialized")
                self._sub = parsed_sub
        except Exception as exc:
            QtWidgets.QMessageBox.critical(
                parent,
                QC.translate("stats", "Subscription Error"),
                QC.translate(
                    "stats", "Failed to initialize subscription data: {0}"
                ).format(str(exc)),
            )
            raise
        self._meta = meta or {}
        self._dialog_message_inspect_button: QtWidgets.QPushButton | None = None
        self._deferred_dialog_result: int | None = None
        self._build_ui()
        self.finished.connect(lambda _: self._subscription_dialog_controller.disconnect_signal())

    def hideEvent(self, event: QtGui.QHideEvent | None):  # type: ignore[override]
        self._subscription_dialog_controller.cancel_active_url_test()
        super().hideEvent(event)

    def _defer_dialog_close(self, result: int) -> bool:
        if not self._subscription_dialog_controller.has_active_url_test():
            return False
        if self._deferred_dialog_result is None:
            self._deferred_dialog_result = result
            self.setEnabled(False)
            self._dialog_message_controller.set_status(
                QC.translate("stats", "Stopping background tasks..."),
                error=False,
                log=False,
            )
            self._subscription_dialog_controller.cancel_active_url_test()
            self._subscription_dialog_controller.on_url_test_stopped(
                self._complete_deferred_dialog_close
            )
        return True

    def _complete_deferred_dialog_close(self) -> None:
        result = self._deferred_dialog_result
        if result is None:
            return
        self._deferred_dialog_result = None
        self.setEnabled(True)
        self._dialog_message_controller.set_status("", error=False, log=False)
        if result == int(QtWidgets.QDialog.DialogCode.Accepted):
            super().accept()
            return
        super().reject()

    def accept(self) -> None:
        if self._defer_dialog_close(int(QtWidgets.QDialog.DialogCode.Accepted)):
            return
        super().accept()

    def reject(self) -> None:
        if self._defer_dialog_close(int(QtWidgets.QDialog.DialogCode.Rejected)):
            return
        super().reject()

    def closeEvent(self, event: QtGui.QCloseEvent | None):  # type: ignore[override]
        if self._defer_dialog_close(int(QtWidgets.QDialog.DialogCode.Rejected)):
            if event is not None:
                event.ignore()
            return
        self._dialog_message_controller.set_status("", error=False, log=False)
        super().closeEvent(event)

    def _build_ui(self):
        self.setupUi(self)
        self.enabled_check = _replace_checkbox_with_toggle(self.enabled_check)
        self.rootLayout.setContentsMargins(0, 0, 0, 0)
        self.rootLayout.setSpacing(0)
        self.bodyLayout.setContentsMargins(0, 0, 0, 0)
        self.bodyLayout.setSpacing(0)
        self.settings_group.setStyleSheet(
            "QGroupBox { border: 0; margin: 0; padding: 0; }"
        )
        self.meta_group.setStyleSheet("QGroupBox { border: 0; margin: 0; padding: 0; }")
        self.settings_group_layout.setContentsMargins(0, 0, 0, 0)
        self.settings_group_layout.setSpacing(0)
        self.settings_form.setContentsMargins(12, 10, 12, 10)
        self.settings_form.setVerticalSpacing(14)
        self.meta_group_layout.setContentsMargins(0, 0, 0, 0)
        self.meta_group_layout.setSpacing(0)
        self.meta_grid.setContentsMargins(12, 10, 12, 10)
        self.buttons_layout.setContentsMargins(12, 10, 12, 12)
        self.buttons_layout.setSpacing(8)
        self.bodyLayout.setStretch(0, 1)
        self.bodyLayout.setStretch(1, 1)
        _apply_section_bar_style(
            self, self.settings_section_bar, self.settings_section_label
        )
        _apply_section_bar_style(
            self, self.meta_section_bar, self.meta_section_label
        )
        _apply_section_bar_style(
            self,
            self.settings_section_bar,
            self.settings_section_label,
            right_border=True,
        )
        _apply_footer_separator_style(self, self.footer_separator_line)
        footer_role = (
            QtGui.QPalette.ColorRole.Midlight
            if self.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128
            else QtGui.QPalette.ColorRole.Dark
        )
        footer_border = self.palette().color(footer_role).name()
        self.footer_separator_line.setStyleSheet(f"color: {footer_border};")
        self.error_label.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Fixed,
        )
        self.error_label.setStyleSheet(
            f"QLabel {{ background-color: {self.palette().color(QtGui.QPalette.ColorRole.Window).name()}; padding: 8px 12px 8px 12px; }}"
        )
        self.error_label.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
        self.error_label.setWordWrap(False)
        self.error_label.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self._dialog_message_controller = DialogStatusController(
            label=self.error_label,
            inspect_button=None,
            preview_limit=DIALOG_MESSAGE_PREVIEW_LIMIT,
            log_limit=DIALOG_MESSAGE_LOG_LIMIT,
            timestamp_format="yyyy-MM-ddTHH:mm:ss.zzz",
            ok_color="#2e7d32",
            error_color="red",
            empty_button_behavior="hide",
        )
        self._subscription_dialog_controller = SubscriptionDialogController(dialog=self)
        self._dialog_message_controller.set_status("", error=False)
        footer_index = self.rootLayout.indexOf(self.footer_separator_line)
        error_index = self.rootLayout.indexOf(self.error_label)
        if error_index >= 0:
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
            self.buttons_layout.removeWidget(self.error_label)
            self.error_label.setParent(status_row)
            status_row_layout.addWidget(self.error_label, 1)
            insert_index = footer_index + 1 if footer_index >= 0 else error_index
            self.rootLayout.insertWidget(insert_index, status_row)
        self.settings_form.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )
        settings_label_width = 96
        for label in (
            self.name_label,
            self.url_label,
            self.filename_label,
            self.format_label,
            self.groups_label,
            self.interval_label,
            self.timeout_label,
            self.max_size_label,
        ):
            label.setMinimumWidth(settings_label_width)
        self.enabled_check.setContentsMargins(0, 0, 0, 8)

        unit_combo_width = 132
        expanding = QtWidgets.QSizePolicy.Policy.Expanding
        fixed = QtWidgets.QSizePolicy.Policy.Fixed
        self.format_combo.setSizePolicy(expanding, fixed)
        self.group_combo.setSizePolicy(expanding, fixed)
        self.interval_spin.setSizePolicy(expanding, fixed)
        self.timeout_spin.setSizePolicy(expanding, fixed)
        self.max_size_spin.setSizePolicy(expanding, fixed)
        self.interval_units.setSizePolicy(fixed, fixed)
        self.timeout_units.setSizePolicy(fixed, fixed)
        self.max_size_units.setSizePolicy(fixed, fixed)
        self.format_combo.setMinimumWidth(0)
        self.group_combo.setMinimumWidth(0)
        self.interval_units.setMinimumWidth(unit_combo_width)
        self.timeout_units.setMinimumWidth(unit_combo_width)
        section_font = self.settings_section_label.font()
        section_font.setPointSize(13)
        section_font.setBold(True)
        self.settings_section_label.setFont(section_font)
        self.meta_section_label.setFont(section_font)
        self.settings_section_label.setMinimumHeight(32)
        self.meta_section_label.setMinimumHeight(32)
        self.max_size_units.setMinimumWidth(unit_combo_width)
        self.interval_layout.setStretch(0, 1)
        self.interval_layout.setStretch(1, 0)
        self.timeout_layout.setStretch(0, 1)
        self.timeout_layout.setStretch(1, 0)
        self.max_size_layout.setStretch(0, 1)
        self.max_size_layout.setStretch(1, 0)

        meta_label_width = 150
        window_color = self.palette().color(QtGui.QPalette.ColorRole.Window)
        is_dark_theme = window_color.lightness() < 128
        separator_role = (
            QtGui.QPalette.ColorRole.Midlight
            if is_dark_theme
            else QtGui.QPalette.ColorRole.Dark
        )
        separator_color = self.palette().color(separator_role)
        separator_css = separator_color.name()
        self.meta_separator.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.meta_separator.setFixedWidth(1)
        self.meta_separator.setStyleSheet(
            f"background-color: {separator_css}; border: 0; margin-left: 4px; margin-right: 10px;"
        )
        meta_label_style = "padding-right: 6px;"
        for label in (
            self.meta_file_present_label,
            self.meta_meta_present_label,
            self.meta_state_label,
            self.meta_last_checked_label,
            self.meta_last_updated_label,
            self.meta_failures_label,
            self.meta_error_label,
            self.meta_list_path_label,
            self.meta_meta_path_label,
        ):
            label.setMinimumWidth(meta_label_width)
            label.setStyleSheet(meta_label_style)

        for label in (
            self.name_error_label,
            self.url_error_label,
            self.filename_error_label,
        ):
            label.setStyleSheet("color: red;")
            label.setText("")
        self.group_combo.setEditable(True)
        self.group_combo.setToolTip(
            QC.translate(
                "stats",
                "Optional explicit groups. Every subscription is always included in the global 'all' rules directory.",
            )
        )
        self._url_test_finished.connect(self._subscription_dialog_controller.handle_url_test_finished)
        self.add_button.clicked.connect(self._subscription_dialog_controller.validate_then_accept)
        self.test_url_button.clicked.connect(self._subscription_dialog_controller.test_url)
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
            if ng not in ("", "all"):
                self.group_combo.addItem(ng)
        current_groups = normalize_groups(self._sub.groups)
        current_group_text = ", ".join(current_groups)
        if (
            current_group_text != ""
            and self.group_combo.findText(current_group_text) < 0
        ):
            self.group_combo.addItem(current_group_text)
        self.group_combo.setCurrentText(current_group_text)
        _configure_spin_and_units(
            self.interval_spin,
            self.interval_units,
            value=int(self._sub.interval or 0),
            unit_value=str(self._sub.interval_units or self._defaults.interval_units),
            allowed_units=INTERVAL_UNITS,
            fallback_unit="hours",
            special_value_text=QC.translate(
                "stats", "Use global default ({0} {1})"
            ).format(
                self._defaults.interval,
                self._defaults.interval_units,
            ),
        )
        _configure_spin_and_units(
            self.timeout_spin,
            self.timeout_units,
            value=int(self._sub.timeout or 0),
            unit_value=str(self._sub.timeout_units or self._defaults.timeout_units),
            allowed_units=TIMEOUT_UNITS,
            fallback_unit="seconds",
            special_value_text=QC.translate(
                "stats", "Use global default ({0} {1})"
            ).format(
                self._defaults.timeout,
                self._defaults.timeout_units,
            ),
        )
        _configure_spin_and_units(
            self.max_size_spin,
            self.max_size_units,
            value=int(self._sub.max_size or 0),
            unit_value=str(self._sub.max_size_units or self._defaults.max_size_units),
            allowed_units=SIZE_UNITS,
            fallback_unit="MB",
            special_value_text=QC.translate(
                "stats", "Use global default ({0} {1})"
            ).format(
                self._defaults.max_size,
                self._defaults.max_size_units,
            ),
        )
        self.interval_spin.valueChanged.connect(self._subscription_dialog_controller.sync_optional_fields_state)
        self.timeout_spin.valueChanged.connect(self._subscription_dialog_controller.sync_optional_fields_state)
        self.max_size_spin.valueChanged.connect(self._subscription_dialog_controller.sync_optional_fields_state)
        _set_optional_field_tooltips(
            self.interval_spin,
            self.interval_units,
            self.timeout_spin,
            self.timeout_units,
            self.max_size_spin,
            self.max_size_units,
            inherit_wording=True,
        )
        self._subscription_dialog_controller.sync_optional_fields_state()
        self.meta_file_present.setText(str(self._meta.get("file_present", "")))
        self.meta_meta_present.setText(str(self._meta.get("meta_present", "")))
        self.meta_state.setText(str(self._meta.get("state", "")))
        self._subscription_dialog_controller.apply_meta_state_color(str(self._meta.get("state", "")))
        self.meta_last_checked.setText(str(self._meta.get("last_checked", "")))
        self.meta_last_updated.setText(str(self._meta.get("last_updated", "")))
        self.meta_failures.setText(str(self._meta.get("failures", "")))
        self.meta_error.setText(str(self._meta.get("error", "")))
        self.meta_list_path.setText(str(self._meta.get("list_path", "")))
        self.meta_meta_path.setText(str(self._meta.get("meta_path", "")))
        if "new" in (self._title or "").strip().lower():
            self.meta_group.setVisible(False)
        self.resize(920, 420)

    def subscription_spec(self):
        groups = normalize_groups((self.group_combo.currentText() or "").strip())
        return MutableSubscriptionSpec(
            enabled=self.enabled_check.isChecked(),
            name=(self.name_edit.text() or "").strip(),
            url=(self.url_edit.text() or "").strip(),
            filename=(self.filename_edit.text() or "").strip(),
            format=(self.format_combo.currentText() or "hosts").strip().lower(),
            groups=groups,
            interval=int(self.interval_spin.value()) or None,
            interval_units=(
                self.interval_units.currentText()
                if self.interval_spin.value() > 0
                else None
            ),
            timeout=int(self.timeout_spin.value()) or None,
            timeout_units=(
                self.timeout_units.currentText()
                if self.timeout_spin.value() > 0
                else None
            ),
            max_size=int(self.max_size_spin.value()) or None,
            max_size_units=(
                self.max_size_units.currentText()
                if self.max_size_spin.value() > 0
                else None
            ),
        )
