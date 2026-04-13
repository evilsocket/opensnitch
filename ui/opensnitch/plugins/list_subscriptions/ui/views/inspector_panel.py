from typing import TYPE_CHECKING, cast

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtWidgets, QC
from opensnitch.plugins.list_subscriptions.ui.views.helpers import (
    _apply_section_bar_style,
    _section_border_color_name,
)

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.list_subscriptions_dialog import (
        ListSubscriptionsDialog,
    )


class InspectorPanel(QtWidgets.QFrame):
    def __init__(self, *, dialog: "ListSubscriptionsDialog") -> None:
        super().__init__(dialog)
        self._dialog: "ListSubscriptionsDialog" = dialog

    def build(self) -> None:
        dialog: "ListSubscriptionsDialog" = self._dialog
        dialog._inspect_panel = cast("InspectorPanel", self)
        dialog._inspect_collapsed = False
        dialog._inspect_default_width = 420
        dialog._inspect_has_selection = False

        dialog.tableContentLayout.removeWidget(dialog._table_tab_bar)
        dialog.tableContentLayout.removeWidget(dialog.table)

        dialog._table_inspect_splitter = QtWidgets.QSplitter(
            QtCore.Qt.Orientation.Horizontal, dialog
        )
        dialog._table_inspect_splitter.setChildrenCollapsible(False)

        left_container: QtWidgets.QWidget = QtWidgets.QWidget(
            dialog._table_inspect_splitter
        )
        left_layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)
        dialog._table_tab_bar.setParent(left_container)
        dialog.table.setParent(left_container)
        left_layout.addWidget(dialog._table_tab_bar)
        left_layout.addWidget(dialog.table, 1)

        self.setParent(dialog._table_inspect_splitter)
        self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)

        inspect_layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout(self)
        inspect_layout.setContentsMargins(0, 0, 0, 0)
        inspect_layout.setSpacing(0)

        dialog._inspect_header = QtWidgets.QFrame(self)
        tab_row_height = max(28, dialog._table_tab_bar.sizeHint().height())
        dialog._inspect_header.setMinimumHeight(tab_row_height)
        dialog._inspect_header.setMaximumHeight(tab_row_height)

        header: QtWidgets.QHBoxLayout = QtWidgets.QHBoxLayout(dialog._inspect_header)
        header.setContentsMargins(12, 0, 12, 0)
        header.setSpacing(4)
        dialog._inspect_title_label = QtWidgets.QLabel(QC.translate("stats", "Inspect"))
        dialog._inspect_title_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignVCenter)
        _apply_section_bar_style(
            dialog,
            dialog._inspect_header,
            dialog._inspect_title_label,
            expanding_label=True,
        )
        header.addWidget(dialog._inspect_title_label)
        header.addStretch(1)
        dialog._inspect_toggle_button = QtWidgets.QToolButton(self)
        dialog._inspect_toggle_button.setAutoRaise(True)
        dialog._inspect_toggle_button.clicked.connect(
            dialog._inspector_controller.toggle_inspector_collapsed
        )
        header.setAlignment(dialog._inspect_toggle_button, QtCore.Qt.AlignmentFlag.AlignVCenter)
        header.addWidget(dialog._inspect_toggle_button)
        inspect_layout.addWidget(dialog._inspect_header)

        dialog._inspect_header_separator = QtWidgets.QFrame(self)
        dialog._inspect_header_separator.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        dialog._inspect_header_separator.setFixedHeight(1)
        dialog._inspect_header_separator.setStyleSheet(
            f"background-color: {_section_border_color_name(dialog)}; border: 0;"
        )
        inspect_layout.addWidget(dialog._inspect_header_separator)

        dialog._inspect_scroll = QtWidgets.QScrollArea(self)
        dialog._inspect_scroll.setWidgetResizable(True)
        dialog._inspect_scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        dialog._inspect_scroll.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        dialog._inspect_scroll.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        dialog._inspect_body = QtWidgets.QWidget(dialog._inspect_scroll)
        body_layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout(
            dialog._inspect_body
        )
        body_layout.setContentsMargins(8, 6, 8, 8)
        body_layout.setSpacing(0)
        body_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        dialog._inspect_details_widget = QtWidgets.QWidget(dialog._inspect_body)
        details_layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout(
            dialog._inspect_details_widget
        )
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(0)

        form: QtWidgets.QFormLayout = QtWidgets.QFormLayout()
        form.setLabelAlignment(
            QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignTop
        )
        form.setFormAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(4)
        form.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )
        dialog._inspect_value_labels = {}
        dialog._inspect_error_button = None
        dialog._inspect_error_full_text = ""
        for key, label in (
            ("name", QC.translate("stats", "Name")),
            ("enabled", QC.translate("stats", "Enabled")),
            ("state", QC.translate("stats", "State")),
            ("last_checked", QC.translate("stats", "Last checked")),
            ("last_updated", QC.translate("stats", "Last updated")),
            ("failures", QC.translate("stats", "Failures")),
            ("error", QC.translate("stats", "Error")),
            ("url", QC.translate("stats", "URL")),
            ("filename", QC.translate("stats", "Filename")),
            ("format", QC.translate("stats", "Format")),
            ("groups", QC.translate("stats", "Groups")),
            ("interval", QC.translate("stats", "Interval")),
            ("timeout", QC.translate("stats", "Timeout")),
            ("max_size", QC.translate("stats", "Max size")),
            ("list_path", QC.translate("stats", "List path")),
            ("meta_path", QC.translate("stats", "Meta path")),
        ):
            key_label: QtWidgets.QLabel = QtWidgets.QLabel(label + ":")
            key_label.setAlignment(
                QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignTop
            )
            key_label.setMinimumWidth(112)
            value_label: QtWidgets.QLabel = QtWidgets.QLabel("-")
            value_label.setWordWrap(True)
            value_label.setAlignment(
                QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignTop
            )
            value_label.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Expanding,
                QtWidgets.QSizePolicy.Policy.Preferred,
            )
            value_label.setTextInteractionFlags(
                QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
            )
            dialog._inspect_value_labels[key] = value_label
            if key == "error":
                field_widget: QtWidgets.QWidget = QtWidgets.QWidget(
                    dialog._inspect_details_widget
                )
                field_layout: QtWidgets.QHBoxLayout = QtWidgets.QHBoxLayout(
                    field_widget
                )
                field_layout.setContentsMargins(0, 0, 0, 0)
                field_layout.setSpacing(6)
                field_layout.addWidget(value_label, 1)
                if key == "error":
                    inspect_button: QtWidgets.QPushButton = QtWidgets.QPushButton(
                        QC.translate("stats", "Inspect"), field_widget
                    )
                    inspect_button.setVisible(False)
                    inspect_button.clicked.connect(
                        dialog._inspector_controller.show_error_inspect_dialog
                    )
                    dialog._inspect_error_button = inspect_button
                    field_layout.addWidget(inspect_button, 0)
                form.addRow(key_label, field_widget)
            else:
                form.addRow(key_label, value_label)
        details_layout.addLayout(form)

        dialog._inspect_summary_widget = QtWidgets.QWidget(dialog._inspect_body)
        summary_layout: QtWidgets.QVBoxLayout = QtWidgets.QVBoxLayout(
            dialog._inspect_summary_widget
        )
        summary_layout.setContentsMargins(0, 0, 0, 0)
        summary_layout.setSpacing(6)
        summary_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        summary_form: QtWidgets.QFormLayout = QtWidgets.QFormLayout()
        summary_form.setLabelAlignment(
            QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignTop
        )
        summary_form.setFormAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        summary_form.setHorizontalSpacing(10)
        summary_form.setVerticalSpacing(4)
        summary_form.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )
        dialog._inspect_summary_labels = {}
        for key, label in (
            ("selected", QC.translate("stats", "Selected")),
            ("enabled", QC.translate("stats", "Enabled")),
            ("healthy", QC.translate("stats", "Healthy")),
            ("pending", QC.translate("stats", "Pending")),
            ("problematic", QC.translate("stats", "Problematic")),
            ("failures", QC.translate("stats", "Total failures")),
            ("with_errors", QC.translate("stats", "With errors")),
            ("newest_checked", QC.translate("stats", "Newest checked")),
            ("oldest_checked", QC.translate("stats", "Oldest checked")),
        ):
            key_label: QtWidgets.QLabel = QtWidgets.QLabel(label + ":")
            key_label.setAlignment(
                QtCore.Qt.AlignmentFlag.AlignRight | QtCore.Qt.AlignmentFlag.AlignTop
            )
            key_label.setMinimumWidth(112)
            value_label: QtWidgets.QLabel = QtWidgets.QLabel("-")
            value_label.setWordWrap(True)
            value_label.setAlignment(
                QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignTop
            )
            value_label.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Expanding,
                QtWidgets.QSizePolicy.Policy.Preferred,
            )
            value_label.setTextInteractionFlags(
                QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
            )
            dialog._inspect_summary_labels[key] = value_label
            summary_form.addRow(key_label, value_label)
        summary_layout.addLayout(summary_form)

        body_layout.addWidget(dialog._inspect_details_widget)
        body_layout.addWidget(dialog._inspect_summary_widget)
        dialog._inspector_controller.set_inspector_multi_selection_mode(False)
        dialog._inspect_scroll.setWidget(dialog._inspect_body)
        inspect_layout.addWidget(dialog._inspect_scroll, 1)

        dialog.tableContentLayout.addWidget(dialog._table_inspect_splitter)
        dialog._table_inspect_splitter.setStretchFactor(0, 1)
        dialog._table_inspect_splitter.setStretchFactor(1, 0)
        dialog._inspector_controller.set_inspector_visible(False)