from opensnitch.config import Config
from opensnitch.database.enums import RuleFields, ConnFields
from . import (
    constants,
    utils
)

def insert_rule_to_db(win, node_addr, rule):
    # the order of the fields doesn't matter here, as long as we use the
    # name of the field.
    win._rules.add_rules(node_addr, [rule])

def new_operator(op_type, operand, data, sensitive):
    return {
        "type": op_type,
        "operand": operand,
        "data": data,
        "sensitive": sensitive
    }

def get_duration(win, duration_idx):
    if duration_idx == 0:
        return Config.DURATION_ONCE
    elif duration_idx == 1:
        return Config.DURATION_30s
    elif duration_idx == 2:
        return Config.DURATION_5m
    elif duration_idx == 3:
        return Config.DURATION_15m
    elif duration_idx == 4:
        return Config.DURATION_30m
    elif duration_idx == 5:
        return Config.DURATION_1h
    elif duration_idx == 6:
        return Config.DURATION_12h
    elif duration_idx == 7:
        return Config.DURATION_UNTIL_RESTART
    else:
        return Config.DURATION_ALWAYS

def load_duration(win, duration):
    if duration == Config.DURATION_ONCE:
        return 0
    elif duration == Config.DURATION_30s:
        return 1
    elif duration == Config.DURATION_5m:
        return 2
    elif duration == Config.DURATION_15m:
        return 3
    elif duration == Config.DURATION_30m:
        return 4
    elif duration == Config.DURATION_1h:
        return 5
    elif duration == Config.DURATION_12h:
        return 6
    elif duration == Config.DURATION_UNTIL_RESTART:
        return 7
    else:
        # always
        return 8

def set_fields_from_connection(win, records):
    nIdx = win.nodesCombo.findData(records.value(ConnFields.Node))
    if nIdx == -1:
        win.set_status_error(win, "Unable to load connection, unknown node? ({0})".format(nIdx))
        return
    win.nodesCombo.setCurrentIndex(nIdx)
    win.protoCombo.setCurrentText(records.value(ConnFields.Protocol).upper())
    win.srcIPCombo.setCurrentText(records.value(ConnFields.SrcIP))
    win.dstIPCombo.setCurrentText(records.value(ConnFields.DstIP))
    win.dstHostLine.setText(records.value(ConnFields.DstHost))
    win.dstPortLine.setText(records.value(ConnFields.DstPort))
    win.srcPortLine.setText(records.value(ConnFields.SrcPort))
    win.uidCombo.setCurrentText(records.value(ConnFields.UID))
    win.pidLine.setText(records.value(ConnFields.PID))
    win.procLine.setText(records.value(ConnFields.Process))
    win.cmdlineLine.setText(records.value(ConnFields.Cmdline))


def load_operator(win, operator):
    win.sensitiveCheck.setChecked(operator.sensitive)
    if operator.operand == Config.OPERAND_PROTOCOL:
        win.protoCheck.setChecked(True)
        win.protoCombo.setEnabled(True)
        prots, err = utils.regexp_to_comma(win, operator.data, str)
        if err != "":
            utils.set_status_error(win, err)
        if prots is None:
            prots = operator.data
        win.protoCombo.setCurrentText(prots.upper())

    if operator.operand == Config.OPERAND_PROCESS_PATH:
        win.procCheck.setChecked(True)
        win.procLine.setEnabled(True)
        win.procLine.setText(operator.data)
        win.checkProcRegexp.setEnabled(True)
        win.checkProcRegexp.setVisible(True)
        win.checkProcRegexp.setChecked(operator.type == Config.RULE_TYPE_REGEXP)

    if operator.operand == Config.OPERAND_PROCESS_COMMAND:
        win.cmdlineCheck.setChecked(True)
        win.cmdlineLine.setEnabled(True)
        win.cmdlineLine.setText(operator.data)
        win.checkCmdlineRegexp.setEnabled(True)
        win.checkCmdlineRegexp.setVisible(True)
        win.checkCmdlineRegexp.setChecked(operator.type == Config.RULE_TYPE_REGEXP)

    if operator.operand == Config.OPERAND_USER_ID:
        win.uidCheck.setChecked(True)
        win.uidCombo.setEnabled(True)
        win.uidCombo.setCurrentText(operator.data)

    if operator.operand == Config.OPERAND_PROCESS_ID:
        win.pidCheck.setChecked(True)
        win.pidLine.setEnabled(True)
        win.pidLine.setText(operator.data)

    if operator.operand == Config.OPERAND_IFACE_OUT:
        win.ifaceCheck.setChecked(True)
        win.ifaceCombo.setEnabled(True)
        ifaces, err = utils.regexp_to_comma(win, operator.data, str)
        if err != "":
            utils.set_status_error(win, err)
        if ifaces is None:
            ifaces = operator.data
        win.ifaceCombo.setCurrentText(ifaces)

    if operator.operand == Config.OPERAND_SOURCE_PORT:
        win.srcPortCheck.setChecked(True)
        win.srcPortLine.setEnabled(True)
        ports, err = utils.regexp_to_comma(win, operator.data, int)
        if err != "":
            utils.set_status_error(win, err)
        if ports is None:
            ports = operator.data
        win.srcPortLine.setText(ports)

    if operator.operand == Config.OPERAND_DEST_PORT:
        win.dstPortCheck.setChecked(True)
        win.dstPortLine.setEnabled(True)
        ports, err = utils.regexp_to_comma(win, operator.data, int)
        if err != "":
            utils.set_status_error(win, err)
        if ports is None:
            ports = operator.data
        win.dstPortLine.setText(ports)

    if operator.operand == Config.OPERAND_SOURCE_IP or operator.operand == Config.OPERAND_SOURCE_NETWORK:
        win.srcIPCheck.setChecked(True)
        win.srcIPCombo.setEnabled(True)
        if operator.data == constants.LAN_RANGES:
            win.srcIPCombo.setCurrentText(constants.LAN_LABEL)
        elif operator.data == constants.MULTICAST_RANGE:
            win.srcIPCombo.setCurrentText(constants.MULTICAST_LABEL)
        else:
            ips, err = utils.regexp_to_comma(win, operator.data, str)
            if err != "":
                utils.set_status_error(win, err)
            if ips is None:
                ips = operator.data
            win.srcIPCombo.setCurrentText(ips)

    if operator.operand == Config.OPERAND_DEST_IP or operator.operand == Config.OPERAND_DEST_NETWORK:
        win.dstIPCheck.setChecked(True)
        win.dstIPCombo.setEnabled(True)
        if operator.data == constants.LAN_RANGES:
            win.dstIPCombo.setCurrentText(constants.LAN_LABEL)
        elif operator.data == constants.MULTICAST_RANGE:
            win.dstIPCombo.setCurrentText(constants.MULTICAST_LABEL)
        else:
            ips, err = utils.regexp_to_comma(win, operator.data, str)
            if err != "":
                utils.set_status_error(win, err)
            if ips is None:
                ips = operator.data
            win.dstIPCombo.setCurrentText(ips)

    if operator.operand == Config.OPERAND_DEST_HOST:
        win.dstHostCheck.setChecked(True)
        win.dstHostLine.setEnabled(True)
        hosts, err = utils.regexp_to_comma(win, operator.data, str)
        if err != "":
            utils.set_status_error(win, err)
        if hosts is None:
            hosts = operator.data
        win.dstHostLine.setText(hosts)

    if operator.operand == Config.OPERAND_LIST_DOMAINS:
        win.dstListsCheck.setChecked(True)
        win.dstListsCheck.setEnabled(True)
        win.dstListsLine.setText(operator.data)
        win.selectListButton.setEnabled(True)

    if operator.operand == Config.OPERAND_LIST_DOMAINS_REGEXP:
        win.dstListRegexpCheck.setChecked(True)
        win.dstListRegexpCheck.setEnabled(True)
        win.dstRegexpListsLine.setText(operator.data)
        win.selectListRegexpButton.setEnabled(True)

    if operator.operand == Config.OPERAND_LIST_IPS:
        win.dstListIPsCheck.setChecked(True)
        win.dstListIPsCheck.setEnabled(True)
        win.dstListIPsLine.setText(operator.data)
        win.selectIPsListButton.setEnabled(True)

    if operator.operand == Config.OPERAND_LIST_NETS:
        win.dstListNetsCheck.setChecked(True)
        win.dstListNetsCheck.setEnabled(True)
        win.dstListNetsLine.setText(operator.data)
        win.selectNetsListButton.setEnabled(True)

    if operator.operand == Config.OPERAND_PROCESS_HASH_MD5:
        win.md5Check.setChecked(True)
        win.md5Line.setEnabled(True)
        win.md5Line.setText(operator.data)
