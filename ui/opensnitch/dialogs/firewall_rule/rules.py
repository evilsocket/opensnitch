from PyQt6 import QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

import opensnitch.firewall as Fw
from opensnitch.firewall.utils import (
    Utils as FwUtils
)
from opensnitch.config import Config
from . import (
    constants,
    notifications,
    statements,
    utils
)

fw = Fw.Firewall.instance()

def new(win):
    utils.reset_widgets(win, "", win.toolBoxSimple)
    win.FORM_TYPE = constants.FORM_TYPE_SIMPLE
    win.setWindowTitle(QC.translate("firewall", "Firewall rule"))
    win.cmdDelete.setVisible(False)
    win.cmdSave.setVisible(False)
    win.cmdAdd.setVisible(True)
    win.checkEnable.setVisible(True)
    win.checkEnable.setEnabled(True)
    win.checkEnable.setChecked(True)
    win.frameDirection.setVisible(True)

    win.cmdSave.setVisible(False)
    win.cmdDelete.setVisible(False)
    win.cmdAdd.setVisible(True)

    win.hboxAdvanced.setVisible(True)
    win.tabWidget.setTabText(0, "")
    win.tabWidget.setCurrentIndex(0)
    win.add_new_statement("", win.toolBoxSimple)

def exclude_service(win, direction):
    utils.reset_widgets(win, "", win.toolBoxSimple)
    win.setWindowTitle(QC.translate("firewall", "Exclude service"))
    win.cmdDelete.setVisible(False)
    win.cmdSave.setVisible(False)
    win.cmdReset.setVisible(False)
    win.cmdAdd.setVisible(True)
    win.checkEnable.setVisible(False)
    win.checkEnable.setEnabled(True)
    win.tabWidget.setTabText(0, "")
    win.hboxAdvanced.setVisible(False)

    dirPort = statements.DPORT+1
    win.FORM_TYPE = constants.FORM_TYPE_ALLOW_IN_SERVICE
    win.lblExcludeTip.setText(QC.translate("firewall", "Allow inbound connections to the selected port."))
    if direction == constants.OUT:
        win.lblExcludeTip.setText(QC.translate("firewall", "Allow outbound connections to the selected port."))
        win.FORM_TYPE = constants.FORM_TYPE_EXCLUDE_SERVICE
        dirPort = statements.DPORT+1

    win.add_new_statement("", win.toolBoxSimple)
    statements.statem_list[0]['what'].setCurrentIndex(dirPort)
    statements.statem_list[0]['what'].setVisible(False)
    statements.statem_list[0]['op'].setVisible(False)
    statements.statem_list[0]['value'].setCurrentText("")

    win.frameDirection.setVisible(False)
    win.lblExcludeTip.setVisible(True)

    win.checkEnable.setChecked(True)

def add(win, nIdx):
    if len(statements.statem_list) == 0:
        utils.set_status_message(win, QC.translate("firewall", "Add at least one statement."))
        return
    chain, err = win.form_to_protobuf()
    if err is not None:
        utils.set_status_error(win, QC.translate("firewall", "Invalid rule: {0}".format(err)))
        return

    if nIdx == 0:
        for addr in win.nodes.get_nodes():
            node = win.nodes.get_node(addr)
            utils.set_status_message(win, QC.translate("firewall", "Adding rule, to {0}".format(addr)))
            err = add_rule(win, addr, node, chain)
            if err is not None:
                utils.set_status_error(win, err)
    else:
        node_addr = win.comboNodes.itemData(nIdx)
        node = win.nodes.get_node(node_addr)
        utils.set_status_message(win, QC.translate("firewall", "Adding rule, wait"))
        err = add_rule(win, node_addr, node, chain)
        if err is not None:
            utils.set_status_error(win, err)
            return
        utils.enable_buttons(win, False)

def is_valid(win):
    if (win.comboVerdict.currentText().lower() == Config.ACTION_REDIRECT or \
        win.comboVerdict.currentText().lower() == Config.ACTION_TPROXY or \
        win.comboVerdict.currentText().lower() == Config.ACTION_DNAT) and \
            (win.comboDirection.currentIndex() == constants.IN or win.comboDirection.currentIndex() == constants.POSTROUTING):
        utils.set_status_message(
            win,
            QC.translate(
                "firewall",
                "{0} cannot be used with IN or POSTROUTING directions.".format(win.comboVerdict.currentText().upper())
            )
        )
        return False
    elif win.comboVerdict.currentText().lower() == Config.ACTION_SNAT and \
            win.comboDirection.currentIndex() != constants.POSTROUTING:
        utils.set_status_message(
            win,
            QC.translate(
                "firewall",
                "{0} can only be used with POSTROUTING.".format(win.comboVerdict.currentText().upper())
            )
        )
        win.comboDirection.setCurrentIndex(constants.POSTROUTING)
        return False

    utils.set_status_message(win, "")
    return True

def has_verdict_parms(win, idx):
    # TODO:
    # Fw.Verdicts.values()[idx+1] == Config.ACTION_REJECT or \
    # Fw.Verdicts.values()[idx+1] == Config.ACTION_JUMP or \
    return Fw.Verdicts.values()[idx+1] == Config.ACTION_QUEUE or \
        Fw.Verdicts.values()[idx+1] == Config.ACTION_REDIRECT or \
        Fw.Verdicts.values()[idx+1] == Config.ACTION_TPROXY or \
        Fw.Verdicts.values()[idx+1] == Config.ACTION_DNAT or \
        Fw.Verdicts.values()[idx+1] == Config.ACTION_SNAT or \
        Fw.Verdicts.values()[idx+1] == Config.ACTION_MASQUERADE

def add_rule(win, addr, node, chain):
    ok, err = fw.insert_rule(addr, chain)
    if not ok:
        return QC.translate("firewall", "Error adding rule: {0}".format(err))
    notifications.send(win, addr, node['firewall'], constants.OP_NEW, chain.Rules[0].UUID)
    return None

def save(win, addr, node, chain, uuid):
    win.logger.debug("save_rule: %s", addr, uuid)
    ok, err = fw.update_rule(addr, uuid, chain)
    if not ok:
        return QC.translate("firewall", "Error saving rule {0}".format(err))
    notifications.send(win, addr, node['firewall'], constants.OP_SAVE, uuid)
    return None

def delete(win, addr, node, uuid):
    ok, fw_config = fw.delete_rule(addr, uuid)
    if not ok:
        return QC.translate("firewall", "Error deleting rule, {0}".format(addr))

    notifications.send(win, addr, node['firewall'], constants.OP_DELETE, uuid)

def configure_verdict_parms(win, idx):
    win.comboVerdictParms.clear()

    verdict = Fw.Verdicts.values()[idx+1]
    if verdict == Config.ACTION_QUEUE:
        win.comboVerdictParms.addItem(QC.translate("firewall", "num"), "num")

    elif verdict == Config.ACTION_JUMP:
        win.comboVerdictParms.setVisible(False)

    elif verdict == Config.ACTION_REDIRECT or \
        verdict == Config.ACTION_TPROXY or \
        verdict == Config.ACTION_SNAT or \
        verdict == Config.ACTION_DNAT:
        win.comboVerdictParms.addItem(QC.translate("firewall", "to"), "to")

    elif verdict == Config.ACTION_MASQUERADE:
        # for persistent,fully-random,etc, options
        win.comboVerdictParms.addItem("")
        win.comboVerdictParms.addItem(QC.translate("firewall", "to"), "to")

    # https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)#Redirect
    if (verdict == Config.ACTION_REDIRECT or verdict == Config.ACTION_DNAT) and \
            (win.comboDirection.currentIndex() != constants.OUT and win.comboDirection.currentIndex() != constants.PREROUTING):
        win.comboDirection.setCurrentIndex(constants.OUT)

    elif win.comboVerdict.currentText().lower() == Config.ACTION_SNAT and \
            win.comboDirection.currentIndex() != constants.POSTROUTING:
        win.comboDirection.setCurrentIndex(constants.POSTROUTING)

def load(win, addr, uuid):
    win.logger.debug("fw_rule.load() %s %s", addr, uuid)
    nIdx = win.comboNodes.findData(addr)
    if nIdx == -1:
        utils.set_status_message(win, f"node not found: {addr}")
        return

    win.FORM_TYPE = constants.FORM_TYPE_SIMPLE
    win.setWindowTitle(QC.translate("firewall", "Firewall rule"))
    win.cmdDelete.setVisible(True)
    win.cmdSave.setVisible(True)
    win.cmdAdd.setVisible(False)
    win.checkEnable.setVisible(True)
    win.checkEnable.setEnabled(True)
    win.checkEnable.setChecked(True)
    win.frameDirection.setVisible(True)

    win.comboNodes.blockSignals(True)
    win.comboNodes.setCurrentIndex(nIdx)
    win.comboNodes.blockSignals(False)

    utils.enable_buttons(win)

    win.uuid = uuid
    win.addr = addr

    node, rule = fw.get_rule_by_uuid(uuid, addr)
    if rule is None or \
            (rule.Hook.lower() != Fw.Hooks.INPUT.value and \
                rule.Hook.lower() != Fw.Hooks.FORWARD.value and \
                rule.Hook.lower() != Fw.Hooks.PREROUTING.value and \
                rule.Hook.lower() != Fw.Hooks.POSTROUTING.value and \
                rule.Hook.lower() != Fw.Hooks.OUTPUT.value):
        hook = "invalid" if rule is None else rule.Hook
        utils.set_status_error(
            win,
            QC.translate("firewall", "Rule hook ({0}) not supported yet".format(hook))
        )
        utils.disable_controls(win)
        return

    win.checkEnable.setChecked(rule.Rules[0].Enabled)
    win.lineDescription.setText(rule.Rules[0].Description)

    win.tabWidget.blockSignals(True)
    win.hboxAdvanced.setVisible(True)
    utils.reset_widgets(win, "", win.toolBoxSimple)
    win.tabWidget.setCurrentIndex(0)

    if len(rule.Rules[0].Expressions) <= 1:
        win.tabWidget.setTabText(0, QC.translate("firewall", "Simple"))
        win.add_new_statement("", win.toolBoxSimple)
    else:
        for i in enumerate(rule.Rules[0].Expressions):
            win.add_new_statement("", win.toolBoxSimple)
        win.tabWidget.setTabText(0, QC.translate("firewall", "Advanced"))

    win.tabWidget.blockSignals(False)

    isNotSupported = False
    idx = 0
    for exp in rule.Rules[0].Expressions:
        #print(idx, "|", exp)

        # set current page, so the title and opts of each statement is
        # configured properly.
        win.toolBoxSimple.setCurrentIndex(idx)

        if FwUtils.isExprPort(exp.Statement.Name):
            if exp.Statement.Values[0].Key == Fw.Statements.DPORT.value:
                statements.statem_list[idx]['what'].setCurrentIndex(statements.DPORT+1)
            elif exp.Statement.Values[0].Key == Fw.Statements.SPORT.value:
                statements.statem_list[idx]['what'].setCurrentIndex(statements.SPORT+1)

            pidx = win.net_srv.index_by_port(exp.Statement.Values[0].Value)
            if pidx >= 0:
                statements.statem_list[idx]['value'].setCurrentIndex(pidx)
            else:
                statements.statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

            st_name = exp.Statement.Name
            statements.statem_list[idx]['opts'].setCurrentIndex(
                Fw.PortProtocols.values().index(st_name.lower())
            )

        elif exp.Statement.Name == Fw.Statements.IP.value or exp.Statement.Name == Fw.Statements.IP6.value:
            if exp.Statement.Values[0].Key == Fw.Statements.DADDR.value:
                statements.statem_list[idx]['what'].setCurrentIndex(statements.DEST_IP+1)
            elif exp.Statement.Values[0].Key == Fw.Statements.SADDR.value:
                statements.statem_list[idx]['what'].setCurrentIndex(statements.SOURCE_IP+1)

            statements.statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

            st_name = exp.Statement.Name
            statements.statem_list[idx]['opts'].setCurrentIndex(
                Fw.Family.values().index(st_name.lower())-1 # first item does not apply
            )

        elif exp.Statement.Name == Fw.Statements.IIFNAME.value:
            statements.statem_list[idx]['what'].setCurrentIndex(statements.IIFNAME+1)
            statements.statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Key)

        elif exp.Statement.Name == Fw.Statements.OIFNAME.value:
            statements.statem_list[idx]['what'].setCurrentIndex(statements.OIFNAME+1)
            statements.statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Key)

        elif exp.Statement.Name == Fw.Statements.CT.value:
            statements.load_ct(win, exp, idx)

        elif exp.Statement.Name == Fw.Statements.META.value:
            statements.load_meta(win, exp, idx)

        elif exp.Statement.Name == Fw.Statements.ICMP.value or exp.Statement.Name == Fw.Statements.ICMPv6.value:
            if exp.Statement.Name == Fw.Statements.ICMP.value:
                statements.statem_list[idx]['what'].setCurrentIndex(statements.ICMP+1)
            else:
                statements.statem_list[idx]['what'].setCurrentIndex(statements.ICMPv6+1)

            statements.statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)
            for v in exp.Statement.Values:
                curText = statements.statem_list[idx]['value'].currentText()
                if v.Value not in curText:
                    statements.statem_list[idx]['value'].setCurrentText(
                        "{0},{1}".format(
                            curText,
                            v.Value
                        )
                    )

        elif exp.Statement.Name == Fw.Statements.LOG.value:
            statements.statem_list[idx]['what'].setCurrentIndex(statements.LOG+1)

            for v in exp.Statement.Values:
                if v.Key == Fw.ExprLog.PREFIX.value:
                    statements.statem_list[idx]['value'].setCurrentText(v.Value)
                elif v.Key == Fw.ExprLog.LEVEL.value:
                    try:
                        lvl = Fw.ExprLogLevels.values().index(v.Value)
                    except:
                        lvl = Fw.ExprLogLevels.values().index(Fw.ExprLogLevels.WARN.value)
                    statements.statem_list[idx]['opts'].setCurrentIndex(lvl)

        elif exp.Statement.Name == Fw.Statements.QUOTA.value:
            statements.statem_list[idx]['what'].setCurrentIndex(statements.QUOTA+1)
            statements.statem_list[idx]['opts'].setCurrentIndex(1)
            for v in exp.Statement.Values:
                if v.Key == Fw.ExprQuota.OVER.value:
                    statements.statem_list[idx]['opts'].setCurrentIndex(0)
                else:
                    statements.statem_list[idx]['value'].setCurrentText(
                        "{0}/{1}".format(v.Value, v.Key)
                    )

        elif exp.Statement.Name == Fw.Statements.LIMIT.value:
            statements.load_limit(win, exp, idx)

        elif exp.Statement.Name == Fw.Statements.COUNTER.value:
            statements.statem_list[idx]['what'].setCurrentIndex(statements.COUNTER+1)
            for v in exp.Statement.Values:
                if v.Key == Fw.ExprCounter.NAME.value:
                    statements.statem_list[idx]['value'].setCurrentText(v.Value)

        else:
            isNotSupported = True
            break

        # a statement may not have an operator. It's assumed that it's the
        # equal operator.
        op = Fw.Operator.EQUAL.value if exp.Statement.Op == "" else exp.Statement.Op
        statements.statem_list[idx]['op'].setCurrentIndex(
            Fw.Operator.values().index(op)
        )

        idx+=1

    if isNotSupported:
        utils.set_status_error(win, QC.translate("firewall", "This rule is not supported yet."))
        utils.disable_controls(win)
        return

    if rule.Hook.lower() == Fw.Hooks.INPUT.value:
        win.comboDirection.setCurrentIndex(constants.IN)
    elif rule.Hook.lower() == Fw.Hooks.OUTPUT.value:
        win.comboDirection.setCurrentIndex(constants.OUT)
    elif rule.Hook.lower() == Fw.Hooks.FORWARD.value:
        win.comboDirection.setCurrentIndex(constants.FORWARD)
    elif rule.Hook.lower() == Fw.Hooks.PREROUTING.value:
        win.comboDirection.setCurrentIndex(constants.PREROUTING)
    elif rule.Hook.lower() == Fw.Hooks.POSTROUTING.value:
        win.comboDirection.setCurrentIndex(constants.POSTROUTING)
    # TODO: changing the direction of an existed rule needs work, it causes
    # some nasty effects. Disabled for now.
    win.comboDirection.setEnabled(False)

    try:
        win.comboVerdict.setCurrentIndex(
            Fw.Verdicts.values().index(
                rule.Rules[0].Target.lower()
            )-1
        )
        if has_verdict_parms(win, win.comboVerdict.currentIndex()):
            tparms = rule.Rules[0].TargetParameters.lower()
            parts = tparms.split(" ")
            win.lineVerdictParms.setText(parts[1])
            if parts[1] == "":
                win.logger.warning("Firewall Rule: verdict parms error: %s", repr(parts))
    except Exception as e:
        win.logger.warning("Firewall Rule target exception: %s", repr(e))
        utils.set_status_error(
            win,
            QC.translate("firewall", "Rule target ({0}) not supported yet".format(rule.Rules[0].Target.lower()))
        )
        utils.disable_controls(win)

    utils.enable_save(win, False)


