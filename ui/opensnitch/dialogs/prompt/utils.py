from slugify import slugify
import os
import ipaddress

from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.dialogs.prompt import constants
from opensnitch.utils.network_aliases import NetworkAliases

def truncate_text(text, max_size=64):
    if len(text) > max_size:
        text = text[:max_size] + "..."
    return text

def set_elide_text(widget, text, max_size=64):
    text = truncate_text(text, max_size)
    widget.setText(text)

def get_rule_name(rule, is_list):
    rule_temp_name = slugify("%s %s" % (rule.action, rule.duration))
    if is_list:
        rule_temp_name = "%s-list" % rule_temp_name
    else:
        rule_temp_name = "%s-simple" % rule_temp_name
    rule_temp_name = slugify("%s %s" % (rule_temp_name, rule.operator.data))

    return rule_temp_name[:128]

def get_popup_message(is_local, node, hostname, app_name, con):
    """
    _get_popup_message helps constructing the message that is displayed on
    the pop-up dialog. Example:
        curl is connecting to www.opensnitch.io on TCP port 443
    """
    app_name = truncate_text(app_name)

    message = "<b>{0}</b>".format(app_name)
    if not is_local:
        message = QC.translate("popups", "<b>Remote</b> process {0} running on <b>{1} ({2})</b>".format(
            message,
            node.split(':')[1],
            hostname)
        )

    msg_action = QC.translate("popups", "is connecting to <b>{0}</b> on {1} port {2}".format(
        con.dst_host or con.dst_ip,
        con.protocol.upper(),
        con.dst_port )
    )

    # icmp port is 0 (i.e.: no port)
    if con.dst_port == 0:
        msg_action = QC.translate("popups", "is connecting to <b>{0}</b>, {1}".format(
            con.dst_host or con.dst_ip,
            con.protocol.upper() )
        )

    if con.dst_port == 53 and con.dst_ip != con.dst_host and con.dst_host != "":
        msg_action = QC.translate("popups", "is attempting to resolve <b>{0}</b> via {1}, {2} port {3}".format(
            con.dst_host,
            con.dst_ip,
            con.protocol.upper(),
            con.dst_port)
        )

    return "{0} {1}".format(message, msg_action)

def set_app_path(appPathLabel, app_name, app_args, con):
    # show the binary path if it's not part of the cmdline args:
    # cmdline: telnet 1.1.1.1 (path: /usr/bin/telnet.netkit)
    # cmdline: /usr/bin/telnet.netkit 1.1.1.1 (the binary path is part of the cmdline args, no need to display it)
    if con.process_path != "" and len(con.process_args) >= 1 and con.process_path not in con.process_args:
        appPathLabel.setToolTip("Process path: {0}".format(con.process_path))
        if app_name.lower() == app_args:
            set_elide_text(appPathLabel, "%s" % con.process_path)
        else:
            set_elide_text(appPathLabel, "(%s)" % con.process_path)
        appPathLabel.setVisible(True)
    elif con.process_path != "" and len(con.process_args) == 0:
        set_elide_text(appPathLabel, "%s" % con.process_path)
        appPathLabel.setVisible(True)
    else:
        appPathLabel.setVisible(False)
        appPathLabel.setText("")

    appPathLabel.setText(
        "".join(
            filter(str.isprintable, appPathLabel.text())
        )
    )

def set_app_args(argsLabel, app_name, app_args):
    # if the app name and the args are the same, there's no need to display
    # the args label (amule for example)
    if app_name.lower() != app_args:
        argsLabel.setVisible(True)
        set_elide_text(argsLabel, app_args, 256)
        argsLabel.setToolTip(app_args)
    else:
        argsLabel.setVisible(False)
        argsLabel.setText("")

    argsLabel.setText(
        "".join(
            filter(str.isprintable, argsLabel.text())
        )
    )

def set_app_description(appDescriptionLabel, description):
    if description is not None and description != "":
        appDescriptionLabel.setVisible(True)
        appDescriptionLabel.setFixedHeight(50)
        appDescriptionLabel.setToolTip(description)
        set_elide_text(appDescriptionLabel, "%s" % description)
    else:
        appDescriptionLabel.setVisible(False)
        appDescriptionLabel.setFixedHeight(0)
        appDescriptionLabel.setText("")

    appDescriptionLabel.setText(
        "".join(
            filter(str.isprintable, appDescriptionLabel.text())
        )
    )

def add_fixed_options_to_combo(combo, con, uid):
    # the order of these combobox entries must match those in the preferences dialog
    # prefs -> UI -> Default target
    combo.addItem(QC.translate("popups", "from this executable"), constants.FIELD_PROC_PATH)
    if int(con.process_id) < 0:
        combo.model().item(0).setEnabled(False)

    combo.addItem(QC.translate("popups", "from this command line"), constants.FIELD_PROC_ARGS)

    combo.addItem(QC.translate("popups", "to port {0}").format(con.dst_port), constants.FIELD_DST_PORT)
    combo.addItem(QC.translate("popups", "to {0}").format(con.dst_ip), constants.FIELD_DST_IP)

    combo.addItem(QC.translate("popups", "from user {0}").format(uid), constants.FIELD_USER_ID)
    if int(con.user_id) < 0:
        combo.model().item(4).setEnabled(False)

    combo.addItem(QC.translate("popups", "from this PID"), constants.FIELD_PROC_ID)

def add_ip_regexp_to_combo(combo, IPcombo, con):
    IPcombo.addItem(QC.translate("popups", "to {0}").format(con.dst_ip), constants.FIELD_DST_IP)

    parts = con.dst_ip.split('.')
    nparts = len(parts)
    for i in range(1, nparts):
        combo.addItem(QC.translate("popups", "to {0}.*").format('.'.join(parts[:i])), constants.FIELD_REGEX_IP)
        IPcombo.addItem(QC.translate("popups", "to {0}.*").format( '.'.join(parts[:i])), constants.FIELD_REGEX_IP)

def add_appimage_pattern_to_combo(combo, con):
    """appimages' absolute path usually starts with /tmp/.mount_<
    """
    appimage_bin = os.path.basename(con.process_path)
    appimage_path = os.path.dirname(con.process_path)
    appimage_path = appimage_path[0:len(constants.APPIMAGE_PREFIX)+6]
    combo.addItem(
        QC.translate("popups", "from {0}*/{1}").format(appimage_path, appimage_bin),
        constants.FIELD_APPIMAGE
    )

def add_snap_pattern_to_combo(combo, con):
    """snap absolute path usually starts with /snap/, followed by a revision
    number which changes after every installation or update.
    """
    snap_path = con.process_path
    snap_parts = snap_path.split('/')
    app = snap_parts[2]
    app_path = "/".join(snap_parts[4:])
    from_field = "from {0}/{1}/*/{2}".format(constants.SNAP_PREFIX, app, app_path)

    combo.addItem(
        QC.translate("popups", from_field),
        constants.FIELD_SNAP
    )


def add_dst_networks_to_combo(combo, dst_ip):
    alias = NetworkAliases.get_alias(dst_ip)
    if alias:
        combo.addItem(QC.translate("popups", f"to {alias}"), constants.FIELD_DST_NETWORK)
    if type(ipaddress.ip_address(dst_ip)) == ipaddress.IPv4Address:
        combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/24", strict=False)),  constants.FIELD_DST_NETWORK)
        combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/16", strict=False)),  constants.FIELD_DST_NETWORK)
        combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/8", strict=False)),   constants.FIELD_DST_NETWORK)
    else:
        combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/64", strict=False)),  constants.FIELD_DST_NETWORK)
        combo.addItem(QC.translate("popups", "to {0}").format(ipaddress.ip_network(dst_ip + "/128", strict=False)), constants.FIELD_DST_NETWORK)

def add_dsthost_to_combo(popup, dst_host):
    popup.whatCombo.addItem("%s" % dst_host, constants.FIELD_DST_HOST)
    popup.whatIPCombo.addItem("%s" % dst_host, constants.FIELD_DST_HOST)

    parts = dst_host.split('.')[1:]
    nparts = len(parts)
    for i in range(0, nparts - 1):
        popup.whatCombo.addItem(QC.translate("popups", "to *.{0}").format('.'.join(parts[i:])), constants.FIELD_REGEX_HOST)
        popup.whatIPCombo.addItem(QC.translate("popups", "to *.{0}").format('.'.join(parts[i:])), constants.FIELD_REGEX_HOST)

def get_duration(duration_idx):
    if duration_idx == 0:
        return Config.DURATION_ONCE
    elif duration_idx == 1:
        return constants.DURATION_30s
    elif duration_idx == 2:
        return constants.DURATION_5m
    elif duration_idx == 3:
        return constants.DURATION_15m
    elif duration_idx == 4:
        return constants.DURATION_30m
    elif duration_idx == 5:
        return constants.DURATION_1h
    elif duration_idx == 6:
        return constants.DURATION_12h
    elif duration_idx == 7:
        return Config.DURATION_UNTIL_RESTART
    else:
        return Config.DURATION_ALWAYS

def set_default_duration(cfg, durationCombo):
    if cfg.hasKey(Config.DEFAULT_DURATION_KEY):
        cur_idx = cfg.getInt(Config.DEFAULT_DURATION_KEY)
        durationCombo.setCurrentIndex(cur_idx)
    else:
        durationCombo.setCurrentIndex(Config.DEFAULT_DURATION_IDX)

def set_default_target(combo, con, cfg, app_name, app_args):
    # set appimage as default target if the process path starts with
    # /tmp/._mount
    if con.process_path.startswith(constants.APPIMAGE_PREFIX):
        idx = combo.findData(constants.FIELD_APPIMAGE)
        if idx != -1:
            combo.setCurrentIndex(idx)
            return
    elif con.process_path.startswith(constants.SNAP_PREFIX):
        idx = combo.findData(constants.FIELD_SNAP)
        if idx != -1:
            combo.setCurrentIndex(idx)
            return

    if int(con.process_id) > 0 and app_name != "" and app_args != "":
        combo.setCurrentIndex(int(cfg.getSettings(cfg.DEFAULT_TARGET_KEY)))
    else:
        combo.setCurrentIndex(2)

def get_combo_operator(data, comboText, con):
    if data == constants.FIELD_PROC_PATH:
        return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_PATH, con.process_path

    elif data == constants.FIELD_PROC_ARGS:
        # this should not happen
        if len(con.process_args) == 0 or con.process_args[0] == "":
            return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_PATH, con.process_path
        return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_COMMAND, ' '.join(con.process_args)

    elif data == constants.FIELD_PROC_ID:
        return Config.RULE_TYPE_SIMPLE, Config.OPERAND_PROCESS_ID, "{0}".format(con.process_id)

    elif data == constants.FIELD_USER_ID:
        return Config.RULE_TYPE_SIMPLE, Config.OPERAND_USER_ID, "{0}".format(con.user_id)

    elif data == constants.FIELD_DST_PORT:
        return Config.RULE_TYPE_SIMPLE, Config.OPERAND_DEST_PORT, "{0}".format(con.dst_port)

    elif data == constants.FIELD_DST_IP:
        return Config.RULE_TYPE_SIMPLE, Config.OPERAND_DEST_IP, con.dst_ip

    elif data == constants.FIELD_DST_HOST:
        return Config.RULE_TYPE_SIMPLE, Config.OPERAND_DEST_HOST, comboText

    elif data == constants.FIELD_DST_NETWORK:
        # strip "to ": "to x.x.x/20" -> "x.x.x/20"
        # we assume that to is one word in all languages
        parts = comboText.split(' ')
        text = parts[len(parts)-1]
        return Config.RULE_TYPE_NETWORK, Config.OPERAND_DEST_NETWORK, text

    elif data == constants.FIELD_REGEX_HOST:
        parts = comboText.split(' ')
        text = parts[len(parts)-1]
        # ^(|.*\.)yahoo\.com
        dsthost = r'\.'.join(text.split('.')).replace("*", "")
        dsthost = r'^(|.*\.)%s$' % dsthost[2:]
        return Config.RULE_TYPE_REGEXP, Config.OPERAND_DEST_HOST, dsthost

    elif data == constants.FIELD_REGEX_IP:
        parts = comboText.split(' ')
        text = parts[len(parts)-1]
        return Config.RULE_TYPE_REGEXP, Config.OPERAND_DEST_IP, "%s" % r'\.'.join(text.split('.')).replace("*", ".*")

    elif data == constants.FIELD_APPIMAGE:
        appimage_bin = os.path.basename(con.process_path)
        appimage_path = os.path.dirname(con.process_path).replace('.', r'\.')
        appimage_path = appimage_path[0:len(constants.APPIMAGE_PREFIX)+7]
        # usually appimages add 6 random characters after the prefix, but
        # some appimages do not follow this rule (Eden appimage for example,
        # #1377).
        return Config.RULE_TYPE_REGEXP, Config.OPERAND_PROCESS_PATH, r'^{0}[0-9A-Za-z]+\/.*{1}$'.format(appimage_path, appimage_bin)

    elif data == constants.FIELD_SNAP:
        snap_path = con.process_path
        snap_parts = snap_path.split('/')
        snap_prefix = snap_parts[1]
        app = snap_parts[2]
        app_path = r'\/'.join(snap_parts[4:])
        regexp = r'^\/{0}\/{1}\/[0-9]+\/{2}$'.format(snap_prefix, app, app_path)
        return Config.RULE_TYPE_REGEXP, Config.OPERAND_PROCESS_PATH, regexp
