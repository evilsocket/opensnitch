from PyQt6 import QtCore, QtWidgets, QtGui
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.dialogs.conndetails import ConnDetails
from opensnitch.firewall import Rules as FwRules
from opensnitch.utils import Message, Icons
from opensnitch.customwidgets.firewalltableview import FirewallTableModel
from . import (
    constants,
    views
)

ALL_NODES="all"

class MenusManager(views.ViewsManager):
    def __init__(self, parent):
        super().__init__(parent)

    def configure_main_btn_menu(self):
        menu = QtWidgets.QMenu(self)
        menu.addAction(
            Icons.new(self, "go-up"),
            QC.translate("stats", "Export rules")).triggered.connect(self.on_menu_node_export_clicked)
        menu.addAction(
            Icons.new(self, "go-down"),
            QC.translate("stats", "Import rules")).triggered.connect(self.on_menu_node_import_clicked)
        self.nodeActionsButton.setMenu(menu)

        menuActions = QtWidgets.QMenu(self)
        menuActions.addAction(
            Icons.new(self, "go-up"),
            QC.translate("stats", "Export rules")).triggered.connect(self.on_menu_export_clicked)
        menuActions.addAction(
            Icons.new(self, "go-down"),
            QC.translate("stats", "Import rules")).triggered.connect(self.on_menu_import_clicked)

        menuExport = QtWidgets.QMenu(QC.translate("stats", "Export to CSV"), self)
        menuExport.setIcon(Icons.new(self, "document-save"))
        for idx in range(constants.TAB_MAIN, constants.TAB_TOTAL):
            act = QtGui.QAction(
                QC.translate("stats", self.get_view_name(idx)), self
            )
            act.triggered.connect(lambda checked=False, i=idx: self.on_menu_export_csv_clicked(i))
            menuExport.addAction(act)
        menuActions.addMenu(menuExport)
        menuActions.addSeparator()

        menuActions.addAction(
            Icons.new(self, "application-exit"),
            QC.translate("stats", "Quit")).triggered.connect(self._on_menu_exit_clicked)
        self.actionsButton.setMenu(menuActions)

    def configure_header_contextual_menu(self, pos):
        cur_idx = self.get_current_view_idx()
        # TODO: allow to configure in-detail columns
        #if self.in_detail_view(cur_idx):
        #    return
        #state = "detail_" if self.in_detail_view(cur_idx) else ""
        table = self.get_active_table()
        model = table.model()

        menu = QtWidgets.QMenu(self)

        if cur_idx == constants.TAB_RULES and self.fwTable.isVisible():
            cur_idx = constants.TAB_FIREWALL
            # TODO: handle properly the hidden columns, for example when the
            # user selects a fw chain that displays the up/down buttons column.
            return
        if cur_idx == constants.TAB_RULES and self.alertsTable.isVisible():
            cur_idx = constants.TAB_ALERTS
        tbl_name = self.TABLES[cur_idx]['name']

        headers = model.headers()
        headers_sel = []
        cols = self.cfg.getSettings(Config.STATS_SHOW_COLUMNS + f"_{tbl_name}")
        if cols is None:
            cols = []
        cols_len = len(cols)
        for i, h in enumerate(headers):
            haction = menu.addAction(h)
            if h == "":
                haction.setVisible(False)
            else:
                haction.setCheckable(True)
                haction.setChecked(str(i) in cols or cols_len == 0)
            headers_sel.append(haction)

        point = QtCore.QPoint(pos.x()+10, pos.y()+5)
        action = menu.exec(table.mapToGlobal(point))
        new_cols = []
        for i, h in enumerate(headers_sel):
            if not h.isVisible():
                continue
            if h == action:
                self.TABLES[cur_idx]['view'].setColumnHidden(i, not h.isChecked())
            if h.isChecked():
                new_cols.append(str(i))
        self.cfg.setSettings(Config.STATS_SHOW_COLUMNS + f"_{tbl_name}", new_cols)

    def configure_events_contextual_menu(self, pos):
        try:
            cur_idx = self.get_current_view_idx()
            table = self.get_active_table()
            model = table.model()

            selection = table.selectionModel().selectedRows()
            if not selection:
                return False

            menu = QtWidgets.QMenu()
            _menu_details = menu.addAction(QC.translate("stats", "Details"))
            rulesMenu = QtWidgets.QMenu(QC.translate("stats", "Rules"))
            _menu_new_rule = rulesMenu.addAction(QC.translate("stats", "New"))
            _menu_edit_rule = rulesMenu.addAction(QC.translate("stats", "Edit"))
            menu.addMenu(rulesMenu)
            self.set_view_context_menu(constants.TAB_MAIN, menu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            if action == _menu_new_rule:
                self.table_menu_new_rule_from_row(cur_idx, model, selection)
            elif action == _menu_edit_rule:
                self.table_menu_edit(cur_idx, model, selection)
            elif action == _menu_details:
                coltime = model.index(selection[0].row(), constants.COL_TIME).data()
                o = ConnDetails(self)
                o.showByField("time", coltime)

        except Exception as e:
            print("_configure_events_contextual_menu() exception:", e)
        finally:
            self.clear_rows_selection()
            return True

    def configure_fwrules_contextual_menu(self, pos):
        try:
            cur_idx = self.get_current_view_idx()
            table = self.get_active_table()

            selection = table.selectionModel().selectedRows()
            if not selection:
                return False

            model = table.model()
            menu = QtWidgets.QMenu()
            exportMenu = QtWidgets.QMenu(QC.translate("stats", "Export"))
            nodesMenu = QtWidgets.QMenu(QC.translate("stats", "Apply to"))

            is_rule_enabled = model.index(selection[0].row(), FirewallTableModel.COL_ENABLED).data()
            rule_action = model.index(selection[0].row(), FirewallTableModel.COL_ACTION).data()
            rule_action = rule_action.lower()

            nodes_menu = []
            if self.nodes_count() > 1:
                nodes_menu.append(
                    [
                        nodesMenu.addAction(QC.translate("stats", "All")),
                        ALL_NODES
                    ])
                for node in self.node_list():
                    nodes_menu.append([nodesMenu.addAction(node), node])
                menu.addMenu(nodesMenu)

            if rule_action == Config.ACTION_ACCEPT or \
                    rule_action == Config.ACTION_DROP or \
                    rule_action == Config.ACTION_RETURN or \
                    rule_action == Config.ACTION_REJECT:
                actionsMenu = QtWidgets.QMenu(QC.translate("stats", "Action"))
                _action_accept = actionsMenu.addAction(Config.ACTION_ACCEPT)
                _action_drop = actionsMenu.addAction(Config.ACTION_DROP)
                _action_reject = actionsMenu.addAction(Config.ACTION_REJECT)
                _action_return = actionsMenu.addAction(Config.ACTION_RETURN)
                menu.addSeparator()
                menu.addMenu(actionsMenu)

            _menu_new = menu.addAction(QC.translate("stats", "New"))
            _label_enable = QC.translate("stats", "Disable")
            if is_rule_enabled == "False":
                _label_enable = QC.translate("stats", "Enable")
            _menu_enable = menu.addAction(_label_enable)
            _menu_delete = menu.addAction(QC.translate("stats", "Delete"))
            _menu_edit = menu.addAction(QC.translate("stats", "Edit"))

            menu.addSeparator()
            _toClipboard = exportMenu.addAction(QC.translate("stats", "To clipboard"))
            #_toDisk = exportMenu.addAction(QC.translate("stats", "To disk"))
            menu.addMenu(exportMenu)
            self.set_view_context_menu(constants.TAB_FIREWALL, menu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            if self.nodes_count() > 1:
                for nmenu in nodes_menu:
                    node_action = nmenu[0]
                    node_addr = nmenu[1]
                    if action == node_action:
                        ret = Message.yes_no(
                            QC.translate("stats", "    Apply this rule to {0}  ".format(node_addr)),
                            QC.translate("stats", "    Are you sure?"),
                            QtWidgets.QMessageBox.Icon.Warning)
                        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
                            return False
                        if node_addr == ALL_NODES:
                            self.table_menu_apply_to_all_nodes(cur_idx, model, selection, node_addr)
                        else:
                            self.table_menu_apply_to_node(cur_idx, model, selection, node_addr)
                        return False

            # block fw rules signals, to prevent reloading them per operation,
            # which can lead to race conditions.
            self._fw.rules.blockSignals(True)
            if action == _menu_new:
                self.new_fw_rule()
            elif action == _menu_delete:
                self.table_menu_delete(cur_idx, model, selection)
            elif action == _menu_enable:
                self.table_menu_enable(cur_idx, model, selection, is_rule_enabled)
            elif action == _menu_edit:
                self.table_menu_edit(cur_idx, model, selection)
            elif action == _action_accept or \
                action == _action_drop or \
                action == _action_reject or \
                action == _action_return:
                self.table_menu_change_rule_field(cur_idx, model, selection, FwRules.FIELD_TARGET, action.text())
            elif action == _toClipboard:
                self.table_menu_export_clipboard(cur_idx, model, selection)
            #elif action == _toDisk:
            #    self.table_menu_export_disk(cur_idx, model, selection)

            self._fw.rules.blockSignals(False)

        except Exception as e:
            print("fwrules contextual menu error:", e)
        finally:
            self.clear_rows_selection()
            return True

    def configure_rules_contextual_menu(self, pos):
        try:
            cur_idx = self.get_current_view_idx()
            table = self.get_active_table()
            model = table.model()

            selection = table.selectedRows()

            menu = QtWidgets.QMenu()
            durMenu = QtWidgets.QMenu(self.COL_STR_DURATION)
            actionMenu = QtWidgets.QMenu(self.COL_STR_ACTION)
            nodesMenu = QtWidgets.QMenu(QC.translate("stats", "Apply to"))
            exportMenu = QtWidgets.QMenu(QC.translate("stats", "Export"))

            nodes_menu = []
            if self.nodes_count() > 1:
                nodes_menu.append(
                    [
                        nodesMenu.addAction(QC.translate("stats", "All")),
                        ALL_NODES
                    ])
                for node in self.node_list():
                    nodes_menu.append([nodesMenu.addAction(node), node])
                menu.addMenu(nodesMenu)

            _actAllow = actionMenu.addAction(QC.translate("stats", "Allow"))
            _actDeny = actionMenu.addAction(QC.translate("stats", "Deny"))
            _actReject = actionMenu.addAction(QC.translate("stats", "Reject"))
            menu.addMenu(actionMenu)

            _durAlways = durMenu.addAction(QC.translate("stats", "Always"))
            _durUntilReboot = durMenu.addAction(QC.translate("stats", "Until reboot"))
            _dur12h = durMenu.addAction(Config.DURATION_12h)
            _dur1h = durMenu.addAction(Config.DURATION_1h)
            _dur30m = durMenu.addAction(Config.DURATION_30m)
            _dur15m = durMenu.addAction(Config.DURATION_15m)
            _dur5m = durMenu.addAction(Config.DURATION_5m)
            menu.addMenu(durMenu)

            is_rule_enabled = True
            _menu_enable = None
            # if there's more than one rule selected, we choose an action
            # based on the status of the first rule.
            if selection and len(selection) > 0:
                is_rule_enabled = selection[0][constants.COL_R_ENABLED]
                menu_label_enable = QC.translate("stats", "Disable")
                if is_rule_enabled == "False":
                    menu_label_enable = QC.translate("stats", "Enable")

                _menu_enable = menu.addAction(QC.translate("stats", menu_label_enable))

            _menu_duplicate = menu.addAction(QC.translate("stats", "Duplicate"))
            _menu_edit = menu.addAction(QC.translate("stats", "Edit"))
            _menu_delete = menu.addAction(QC.translate("stats", "Delete"))

            menu.addSeparator()
            _toClipboard = exportMenu.addAction(QC.translate("stats", "To clipboard"))
            _toDisk = exportMenu.addAction(QC.translate("stats", "To disk"))
            menu.addMenu(exportMenu)
            self.set_view_context_menu(constants.TAB_RULES, menu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            if self.nodes_count() > 1:
                for nmenu in nodes_menu:
                    node_action = nmenu[0]
                    node_addr = nmenu[1]
                    if action == node_action:
                        ret = Message.yes_no(
                            QC.translate("stats", "    Apply this rule to {0}  ".format(node_addr)),
                            QC.translate("stats", "    Are you sure?"),
                            QtWidgets.QMessageBox.Icon.Warning)
                        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
                            return False
                        if node_addr == ALL_NODES:
                            self.table_menu_apply_to_all_nodes(cur_idx, model, selection, node_addr)
                        else:
                            self.table_menu_apply_to_node(cur_idx, model, selection, node_addr)
                        return False

            if action == _menu_delete:
                self.table_menu_delete(cur_idx, model, selection)
            elif action == _menu_edit:
                self.table_menu_edit(cur_idx, model, selection)
            elif action == _menu_enable:
                self.table_menu_enable(cur_idx, model, selection, is_rule_enabled)
            elif action == _menu_duplicate:
                self.table_menu_duplicate(cur_idx, model, selection)
            elif action == _durAlways:
                self.table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_ALWAYS)
            elif action == _dur12h:
                self.table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_12h)
            elif action == _dur1h:
                self.table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_1h)
            elif action == _dur30m:
                self.table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_30m)
            elif action == _dur15m:
                self.table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_15m)
            elif action == _dur5m:
                self.table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_5m)
            elif action == _durUntilReboot:
                self.table_menu_change_rule_field(cur_idx, model, selection, "duration", Config.DURATION_UNTIL_RESTART)
            elif action == _actAllow:
                self.table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_ALLOW)
            elif action == _actDeny:
                self.table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_DENY)
            elif action == _actReject:
                self.table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_REJECT)
            elif action == _toClipboard:
                self.table_menu_export_clipboard(cur_idx, model, selection)
            elif action == _toDisk:
                self.table_menu_export_disk(cur_idx, model, selection)

        except Exception as e:
            print("rules contextual menu exception:", e)
        finally:
            return True

    def configure_alerts_contextual_menu(self, pos):
        try:
            cur_idx = self.get_current_view_idx()
            table = self.get_active_table()
            model = table.model()

            selection = table.selectionModel().selectedRows()
            if not selection:
                return False

            menu = QtWidgets.QMenu()
            exportMenu = QtWidgets.QMenu(QC.translate("stats", "Export"))

            #is_rule_enabled = model.index(selection[0].row(), constants.COL_R_ENABLED).data()
            #menu_label_enable = QC.translate("stats", "Disable")
            #if is_rule_enabled == "False":
            #    menu_label_enable = QC.translate("stats", "Enable")

            _menu_view = menu.addAction(QC.translate("stats", "View"))
            _menu_delete = menu.addAction(QC.translate("stats", "Delete"))

            menu.addSeparator()
            _toClipboard = exportMenu.addAction(QC.translate("stats", "To clipboard"))
            _toDisk = exportMenu.addAction(QC.translate("stats", "To disk"))
            menu.addMenu(exportMenu)
            self.set_view_context_menu(constants.TAB_ALERTS, menu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            if action == _menu_delete:
                self.table_menu_delete(cur_idx, model, selection)
            elif action == _menu_view:
                for idx in selection:
                    atime = model.index(idx.row(), constants.COL_TIME).data()
                    anode = model.index(idx.row(), constants.COL_NODE).data()
                    self.display_alert_info(atime, anode)

            elif action == _toClipboard:
                self.table_menu_export_clipboard(cur_idx, model, selection)
            elif action == _toDisk:
                self.table_menu_export_disk(cur_idx, model, selection)

        except Exception as e:
            print("alerts contextual menu exception:", e)
        finally:
            self.clear_rows_selection()
            return True

