import os

from PyQt6 import QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from opensnitch.customwidgets.firewalltableview import FirewallTableModel
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
from opensnitch.rules import Rule
from opensnitch.utils import (
    Message
)
from . import (
    constants,
    views
)

class MenuActions(views.ViewsManager):
    def __init__(self, parent):
        super().__init__(parent)

    def table_menu_new_rule_from_row(self, cur_idx, model, selection):
        coltime = model.index(selection[0].row(), constants.COL_TIME).data()
        if self._rules_dialog.new_rule_from_connection(coltime) is False:

            Message.ok(
                QC.translate("stats", "New rule error"),
                QC.translate("stats",
                             "Error creating new rule from event ({0})".format(coltime)
                             ),
                QtWidgets.QMessageBox.Icon.Warning
            )

    def table_menu_export_clipboard(self, cur_idx, model, selection):
        rules_list = []
        if cur_idx == constants.TAB_RULES and self.fwTable.isVisible():
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                r = self._fw.get_protorule_by_uuid(node, uuid)
                if r:
                    rules_list.append(self._fw.rule_to_json(r))

        elif cur_idx == constants.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                rule_name = row[constants.COL_R_NAME]
                node_addr = row[constants.COL_R_NODE]

                json_rule = self.node_rule_to_json(node_addr, rule_name)
                if json_rule is not None:
                    rules_list.append(json_rule)
                else:
                    print(f"export to clipboard: ERROR converting \"{rule_name}\" to json")

        elif cur_idx == constants.TAB_RULES and self.alertsTable.isVisible():
            for idx in selection:
                atime = model.index(idx.row(), constants.COL_TIME).data()
                anode = model.index(idx.row(), constants.COL_NODE).data()
                atype = model.index(idx.row(), constants.COL_ALERT_TYPE).data()
                abody = model.index(idx.row(), constants.COL_ALERT_BODY).data()
                awhat = model.index(idx.row(), constants.COL_ALERT_WHAT).data()
                aprio = model.index(idx.row(), constants.COL_ALERT_PRIO).data()

                rules_list.append(f"{atime},{anode},{atype},{abody},{awhat},{aprio}")

        cliptext=""
        for r in rules_list:
            cliptext = "{0}\n{1}".format(cliptext, r)

        QtWidgets.QApplication.clipboard().setText(cliptext)

    def table_menu_export_disk(self, cur_idx, model, selection):
        outdir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            os.path.expanduser("~"),
            QC.translate("stats", 'Select a directory to export rules'),
            QtWidgets.QFileDialog.Option.ShowDirsOnly | QtWidgets.QFileDialog.Option.DontResolveSymlinks
        )
        if outdir == "":
            return

        error_list = []
        for row in selection:
            node_addr = row[constants.COL_R_NODE]
            rule_name = row[constants.COL_R_NAME]

            ok = self.node_export_rule(node_addr, rule_name, outdir)
            if not ok:
                error_list.append(rule_name)

        if len(error_list) == 0:
            Message.ok(
                "Rules export",
                QC.translate("stats", "Rules exported to {0}".format(outdir)),
                QtWidgets.QMessageBox.Icon.Information)
        else:
            error_text = ""
            for e in error_list:
                error_text = "{0}<br>{1}".format(error_text, e)

            Message.ok(
                "Rules export error",
                QC.translate("stats",
                             "Error exporting the following rules:<br><br>".format(error_text)
                            ),
                QtWidgets.QMessageBox.Icon.Warning)

    def table_menu_duplicate(self, cur_idx, model, selection):

        for row in selection:
            node_addr = row[constants.COL_R_NODE]
            rule_name = row[constants.COL_R_NAME]
            records = self._db.get_rule(rule_name, node_addr)
            if records.next() is False:
                print(f"[stats clone] rule not found: {rule_name} {node_addr}")
                continue
            rule = Rule.new_from_records(records)

            temp_name = rule_name
            for idx in range(0,100):
                temp_name = temp_name.split("-duplicated-")[0]
                temp_name = "{0}-duplicated-{1}".format(temp_name, idx)

                rec = self._rules.get_by_name(node_addr, temp_name)
                if rec.next() is False:
                    rule.name = temp_name
                    self._rules.add_rules(node_addr, [rule])
                    break

            if records is not None and records.size() == -1:
                noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
                nid = self.send_notification(node_addr, noti, self._notification_callback)
                if nid is not None:
                    self._notifications_sent[nid] = noti

    def table_menu_apply_to_node(self, cur_idx, model, selection, node_addr):

        for row in selection:
            rule_name = row[constants.COL_R_NAME]
            records = self.get_rule(rule_name, None)
            rule = Rule.new_from_records(records)

            noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
            nid = self.send_notification(node_addr, noti, self._notification_callback)
            if nid is not None:
                self._rules.add_rules(node_addr, [rule])
                self._notifications_sent[nid] = noti

    def table_menu_change_rule_field(self, cur_idx, model, selection, field, value):
        if cur_idx == constants.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                rule_name = row[constants.COL_R_NAME]
                node_addr = row[constants.COL_R_NODE]

                records = self.get_rule(rule_name, node_addr)
                rule = Rule.new_from_records(records)

                self._db.update(table="rules", fields="{0}=?".format(field),
                                values=[value], condition="name='{0}' AND node='{1}'".format(rule_name, node_addr),
                                action_on_conflict="")

                if field == "action":
                    rule.action = value
                elif field == "duration":
                    rule.duration = value
                elif field == "precedence":
                    rule.precedence = value

                noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
                nid = self.send_notification(node_addr, noti, self._notification_callback)
                if nid is not None:
                    self._notifications_sent[nid] = noti
        elif cur_idx == constants.TAB_RULES and self.fwTable.isVisible():
            nodes_updated = []
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                updated, err = self._fw.change_rule_field(node, uuid, field, value)
                if updated:
                    nodes_updated.append(node)
                else:
                    print(f"error updating fw rule field {field}, value: {value}")

            for addr in nodes_updated:
                node = self.nodes_get(addr)
                nid, noti = self.node_reload_fw(addr, node['firewall'], self._notification_callback)
                self._notifications_sent[nid] = noti

    def table_menu_enable(self, cur_idx, model, selection, is_rule_enabled):
        rule_status = "False" if is_rule_enabled == "True" else "True"
        enable_rule = False if is_rule_enabled == "True" else True

        if cur_idx == constants.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                rule_name = row[constants.COL_R_NAME]
                node_addr = row[constants.COL_R_NODE]

                records = self.get_rule(rule_name, node_addr)
                rule = Rule.new_from_records(records)
                rule_type = ui_pb2.DISABLE_RULE if is_rule_enabled == "True" else ui_pb2.ENABLE_RULE

                self._db.update(
                    table="rules",
                    fields="enabled=?",
                    values=[rule_status], condition=f"name='{rule_name}' AND node='{node_addr}'",
                    action_on_conflict="")

                noti = ui_pb2.Notification(type=rule_type, rules=[rule])
                nid = self.send_notification(node_addr, noti, self._notification_callback)
                if nid is not None:
                    self._notifications_sent[nid] = noti

        elif cur_idx == constants.TAB_RULES and self.fwTable.isVisible():
            nodes_updated = []
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                updated, err = self._fw.enable_rule(node, uuid, enable_rule)
                if updated:
                    nodes_updated.append(node)

            for addr in nodes_updated:
                node = self.node_get_node(addr)
                nid, noti = self.node_reload_fw(addr, node['firewall'], self._notification_callback)
                self._notifications_sent[nid] = noti

    def table_menu_delete(self, cur_idx, model, selection):
        if cur_idx == constants.TAB_MAIN or cur_idx == constants.TAB_NODES or self.in_detail_view(cur_idx):
            return

        msg = QC.translate("stats", "    You are about to delete this rule.    ")
        if cur_idx != constants.TAB_RULES:
            msg = QC.translate("stats", "    You are about to delete this entry.    ")

        ret = Message.yes_no(msg,
            QC.translate("stats", "    Are you sure?"),
            QtWidgets.QMessageBox.Icon.Warning)
        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
            return False

        if cur_idx == constants.TAB_RULES and self.fwTable.isVisible():
            nodes_updated = {}
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                ok, fw_config = self._fw.delete_rule(node, uuid)
                if ok:
                    nodes_updated[node] = fw_config
                else:
                    print("error deleting fw rule:", uuid, "row:", idx.row())

            for addr in nodes_updated:
                nid, noti = self.node_reload_fw(addr, nodes_updated[addr], self._notification_callback)
                self._notifications_sent[nid] = noti

        elif cur_idx == constants.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                node = row[constants.COL_R_NODE]
                name = row[constants.COL_R_NAME]
                self.del_rule(name, node)
            self.refresh_active_table()

        elif cur_idx == constants.TAB_RULES and self.alertsTable.isVisible():
            for idx in selection:
                time = model.index(idx.row(), constants.COL_TIME).data()
                node = model.index(idx.row(), constants.COL_NODE).data()
                self._db.delete_alert(time, node)

        elif cur_idx == constants.TAB_HOSTS or cur_idx == constants.TAB_PROCS or cur_idx == constants.TAB_ADDRS or \
            cur_idx == constants.TAB_USERS or cur_idx == constants.TAB_PORTS:
            do_refresh = False
            for idx in selection:
                field = model.index(idx.row(), constants.COL_WHAT).data()
                if field == "":
                    continue
                ok = self.del_by_field(cur_idx, self.TABLES[cur_idx]['name'], field)
                do_refresh |= ok
            if do_refresh:
                self.refresh_active_table()

    def table_menu_edit(self, cur_idx, model, selection):
        if cur_idx ==  constants.TAB_MAIN:
            for row in selection:
                node = model.index(row.row(), constants.COL_NODE).data()
                name = model.index(row.row(), constants.COL_RULES).data()
                records = self.get_rule(name, node)
                if records is None or records == -1:
                    Message.ok(
                        QC.translate("stats", "New rule error"),
                        QC.translate("stats", "Rule not found by that name and node"),
                        QtWidgets.QMessageBox.Icon.Warning)
                    return
                print(node, name)
                r = RulesEditorDialog(modal=False)
                r.edit_rule(records, node)

                break
        elif cur_idx ==  constants.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                node = row[constants.COL_R_NODE]
                name = row[constants.COL_R_NAME]
                records = self.get_rule(name, node)
                if records is None or records == -1:
                    Message.ok(QC.translate("stats", "New rule error"),
                            QC.translate("stats", "Rule not found by that name and node"),
                            QtWidgets.QMessageBox.Icon.Warning)
                    return
                r = RulesEditorDialog(modal=False)
                r.edit_rule(records, node)
                break

        elif cur_idx == constants.TAB_RULES and self.fwTable.isVisible():
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                self.load_fw_rule(node, uuid)

                break

