import logging
import os
import sys
import threading
from typing import Any, TYPE_CHECKING, Final

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

from opensnitch.plugins.list_subscriptions.models.global_defaults import GlobalDefaults
from opensnitch.plugins.list_subscriptions.models.subscriptions import (
    MutableSubscriptionSpec,
)
from opensnitch.plugins.list_subscriptions._utils import (
    RES_DIR,
    INTERVAL_UNITS,
    TIMEOUT_UNITS,
    SIZE_UNITS,
    deslugify_filename,
    derive_filename,
    ensure_filename_type_suffix,
    is_valid_url,
    normalize_group,
    normalize_groups,
    normalize_unit,
    safe_filename,
)
from opensnitch.plugins.list_subscriptions.ui.helpers import (
    _apply_footer_separator_style,
    _apply_section_bar_style,
    _set_optional_field_tooltips,
)
from opensnitch.plugins.list_subscriptions.ui.toggle_switch_widget import (
    _replace_checkbox_with_toggle,
)
import requests

SUBSCRIPTION_DIALOG_UI_PATH: Final[str] = os.path.join(
    RES_DIR, "subscription_dialog.ui"
)

SubscriptionDialogUI: Final[Any] = load_ui_type(SUBSCRIPTION_DIALOG_UI_PATH)[0]

logger: Final[logging.Logger] = logging.getLogger(__name__)


class SubscriptionDialog(QtWidgets.QDialog, SubscriptionDialogUI):
    _url_test_finished = QtCore.pyqtSignal(bool, str)

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
        self._title = title
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
        self._build_ui()

    def _build_ui(self):
        self.setupUi(self)
        self.enabled_check = _replace_checkbox_with_toggle(self.enabled_check)
        self._set_dialog_message("", error=False)
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
        self._apply_dialog_section_bar_style(
            self.settings_section_bar, self.settings_section_label
        )
        self._apply_dialog_section_bar_style(
            self.meta_section_bar, self.meta_section_label
        )
        self._apply_dialog_split_header_style()
        self._apply_dialog_footer_style(self.footer_separator_line)
        self.error_label.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Preferred,
        )
        self.error_label.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
        )
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
        self._url_test_finished.connect(self._handle_url_test_finished)
        self.add_button.clicked.connect(self._validate_then_accept)
        self.test_url_button.clicked.connect(self._test_url)
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
        self.interval_spin.setRange(0, 999999)
        self.interval_spin.setSpecialValueText(
            QC.translate("stats", "Use global default ({0} {1})").format(
                self._defaults.interval,
                self._defaults.interval_units,
            )
        )
        self.interval_spin.setValue(max(0, int(self._sub.interval or 0)))
        self.interval_units.clear()
        self.interval_units.addItems(INTERVAL_UNITS)
        self.interval_units.setCurrentText(
            normalize_unit(
                str(self._sub.interval_units or self._defaults.interval_units),
                INTERVAL_UNITS,
                "hours",
            )
        )
        self.timeout_spin.setRange(0, 999999)
        self.timeout_spin.setSpecialValueText(
            QC.translate("stats", "Use global default ({0} {1})").format(
                self._defaults.timeout,
                self._defaults.timeout_units,
            )
        )
        self.timeout_spin.setValue(max(0, int(self._sub.timeout or 0)))
        self.timeout_units.clear()
        self.timeout_units.addItems(TIMEOUT_UNITS)
        self.timeout_units.setCurrentText(
            normalize_unit(
                str(self._sub.timeout_units or self._defaults.timeout_units),
                TIMEOUT_UNITS,
                "seconds",
            )
        )
        self.max_size_spin.setRange(0, 999999)
        self.max_size_spin.setSpecialValueText(
            QC.translate("stats", "Use global default ({0} {1})").format(
                self._defaults.max_size,
                self._defaults.max_size_units,
            )
        )
        self.max_size_spin.setValue(max(0, int(self._sub.max_size or 0)))
        self.max_size_units.clear()
        self.max_size_units.addItems(SIZE_UNITS)
        self.max_size_units.setCurrentText(
            normalize_unit(
                str(self._sub.max_size_units or self._defaults.max_size_units),
                SIZE_UNITS,
                "MB",
            )
        )
        self.interval_spin.valueChanged.connect(self._sync_optional_fields_state)
        self.timeout_spin.valueChanged.connect(self._sync_optional_fields_state)
        self.max_size_spin.valueChanged.connect(self._sync_optional_fields_state)
        self._apply_optional_field_tooltips()
        self._sync_optional_fields_state()
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

    def _apply_dialog_section_bar_style(
        self, container: QtWidgets.QFrame, label: QtWidgets.QLabel
    ):
        _apply_section_bar_style(self, container, label)

    def _apply_dialog_split_header_style(self):
        # Match the main dialog split-header pattern: the left section owns
        # the center divider, rather than leaving a visual gap between bars.
        _apply_section_bar_style(
            self,
            self.settings_section_bar,
            self.settings_section_label,
            right_border=True,
        )

    def _apply_dialog_footer_style(self, separator: QtWidgets.QFrame):
        _apply_footer_separator_style(self, separator)

    def _apply_optional_field_tooltips(self):
        _set_optional_field_tooltips(
            self.interval_spin,
            self.interval_units,
            self.timeout_spin,
            self.timeout_units,
            self.max_size_spin,
            self.max_size_units,
            inherit_wording=True,
        )

    def _sync_optional_fields_state(self):
        self.interval_units.setEnabled(self.interval_spin.value() > 0)
        self.timeout_units.setEnabled(self.timeout_spin.value() > 0)
        self.max_size_units.setEnabled(self.max_size_spin.value() > 0)

    def _clear_field_errors(self):
        self._set_dialog_message("", error=False)
        self.name_error_label.setText("")
        self.url_error_label.setText("")
        self.filename_error_label.setText("")

    def _set_dialog_message(self, message: str, error: bool):
        color = "red" if error else "#2e7d32"
        self.error_label.setStyleSheet(f"color: {color};")
        self.error_label.setText(message)

    def _test_url(self):
        self.url_error_label.setText("")
        self._set_dialog_message("", error=False)
        url = (self.url_edit.text() or "").strip()
        if url == "":
            self.url_error_label.setText(QC.translate("stats", "URL is required."))
            self._set_dialog_message(
                QC.translate("stats", "Fix the highlighted fields."), error=True
            )
            return
        if not is_valid_url(url):
            self.url_error_label.setText(
                QC.translate("stats", "Enter a valid http:// or https:// URL.")
            )
            self._set_dialog_message(
                QC.translate("stats", "Fix the highlighted fields."), error=True
            )
            return

        self.test_url_button.setEnabled(False)
        self._set_dialog_message(QC.translate("stats", "Testing URL..."), error=False)

        def _run_test():
            try:
                response = requests.head(url, allow_redirects=True, timeout=5)
                if response.status_code >= 400 and response.status_code not in (
                    403,
                    405,
                ):
                    raise requests.HTTPError(f"HTTP {response.status_code}")
                final_url = response.url or url
                response.close()
                if response.status_code in (403, 405):
                    response = requests.get(
                        url, allow_redirects=True, timeout=5, stream=True
                    )
                    if response.status_code >= 400:
                        raise requests.HTTPError(f"HTTP {response.status_code}")
                    final_url = response.url or final_url
                    response.close()
                message = QC.translate("stats", "URL reachable.")
                if final_url != url:
                    message = QC.translate(
                        "stats", "URL reachable via redirect to {0}"
                    ).format(final_url)
                self._url_test_finished.emit(True, message)
            except requests.RequestException as exc:
                self._url_test_finished.emit(False, str(exc))

        threading.Thread(target=_run_test, daemon=True).start()

    def _handle_url_test_finished(self, success: bool, message: str):
        self.test_url_button.setEnabled(True)
        if success:
            self.url_error_label.setText("")
            self._set_dialog_message(message, error=False)
            return
        self.url_error_label.setText(QC.translate("stats", "URL check failed."))
        self._set_dialog_message(
            QC.translate("stats", "URL test failed: {0}").format(message),
            error=True,
        )

    def _validate_then_accept(self):
        self._clear_field_errors()
        raw_url = (self.url_edit.text() or "").strip()
        raw_name = (self.name_edit.text() or "").strip()
        raw_filename = (self.filename_edit.text() or "").strip()
        list_type = (self.format_combo.currentText() or "hosts").strip().lower()
        name = raw_name
        filename = safe_filename(raw_filename)
        has_error = False

        if raw_url == "":
            self.url_error_label.setText(QC.translate("stats", "URL is required."))
            has_error = True
        elif not is_valid_url(raw_url):
            self.url_error_label.setText(
                QC.translate("stats", "Enter a valid http:// or https:// URL.")
            )
            has_error = True

        if raw_name == "" and raw_filename == "":
            self.name_error_label.setText(
                QC.translate("stats", "Provide a name or filename.")
            )
            self.filename_error_label.setText(
                QC.translate("stats", "Provide a filename or name.")
            )
            has_error = True
        elif raw_filename != "" and filename != raw_filename:
            self.filename_error_label.setText(
                QC.translate("stats", "Filename must not include directory components.")
            )
            has_error = True

        if has_error:
            self._set_dialog_message(
                QC.translate("stats", "Fix the highlighted fields."), error=True
            )
            return

        if filename == "" and name != "":
            filename = safe_filename(derive_filename(name, None, ""))
        filename = ensure_filename_type_suffix(filename, list_type)

        if name == "" and filename != "":
            name = deslugify_filename(filename, list_type)

        self.name_edit.setText(name)
        self.filename_edit.setText(filename)
        self.accept()

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
