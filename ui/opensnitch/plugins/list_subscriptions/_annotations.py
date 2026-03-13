from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from PyQt6 import QtCore, QtGui, QtWidgets


class RuleOperatorLike(Protocol):
    operand: str
    data: str | None
    list: list["RuleOperatorLike"]


class RuleLike(Protocol):
    name: str | None
    enabled: bool
    operator: RuleOperatorLike


class StatsDialogProto(Protocol):
    """Typed subset of StatsDialog used by the plugin.

    actionsButton is injected by uic from stats.ui and otherwise appears
    as unknown to static analyzers.
    """

    actionsButton: "QtWidgets.QPushButton"

    def windowIcon(self) -> "QtGui.QIcon": ...


class RulesEditorDialogProto(Protocol):
    """Typed subset of RulesEditorDialog used by the plugin controllers."""

    _old_rule_name: str
    buttonBox: "QtWidgets.QDialogButtonBox"
    ruleNameEdit: "QtWidgets.QLineEdit"
    ruleDescEdit: "QtWidgets.QPlainTextEdit"
    nodesCombo: "QtWidgets.QComboBox"
    nodeApplyAllCheck: "QtWidgets.QCheckBox"
    uidCombo: "QtWidgets.QComboBox"
    uidCheck: "QtWidgets.QCheckBox"
    enableCheck: "QtWidgets.QCheckBox"
    durationCombo: "QtWidgets.QComboBox"
    dstListsCheck: "QtWidgets.QCheckBox"
    dstListsLine: "QtWidgets.QLineEdit"

    def installEventFilter(self, filterObj: "QtCore.QObject") -> None: ...

    def hide(self) -> None: ...

    def raise_(self) -> None: ...

    def activateWindow(self) -> None: ...

    def new_rule(self) -> None: ...

    def edit_rule(self, records: Any, _addr: str | None = None) -> None: ...
