from opensnitch.plugins.list_subscriptions.ui import QtCore, QtGui, QtWidgets


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